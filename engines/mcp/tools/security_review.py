"""PRIMARY tool: axguard_security_review — orchestrate existing engines."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from engines.mcp.engines_bridge import (
    run_adversary_engine,
    run_flow_engine,
    run_memory_query,
    run_paths_engine,
    run_predict_engine,
    run_scan_engine,
    run_surface_engine,
    run_twin_engine,
    run_verify_engine,
    summarize_findings,
)
from engines.mcp.limits import limits_for_mode
from engines.mcp.policy import enforce
from engines.mcp.schemas.errors import McpError
from engines.mcp.schemas.results import agent_friendly_text, success_result
from engines.mcp.session import McpSession, get_session

ReviewMode = Literal["LITE", "BALANCED", "DEEP", "MAX"]
ReviewScope = Literal[
    "project",
    "changed_files",
    "file",
    "function",
    "commit",
    "branch",
    "diff",
]

MODES = frozenset({"LITE", "BALANCED", "DEEP", "MAX"})
SCOPES = frozenset(
    {"project", "changed_files", "file", "function", "commit", "branch", "diff"}
)

_SECURITY_SENSITIVE = (
    "auth",
    "authorization",
    "tenant",
    "permission",
    "password",
    "token",
    "secret",
    "ssrf",
    "sql",
    "upload",
    "webhook",
    "mcp",
    "agent",
    "eval",
    "exec",
    "subprocess",
    "deserialize",
    "redirect",
)


def _normalize_mode(mode: str | None) -> str:
    m = (mode or "BALANCED").upper()
    if m not in MODES:
        raise McpError(
            "INVALID_INPUT",
            f"Invalid mode '{mode}'. Use LITE|BALANCED|DEEP|MAX.",
        )
    return m


def _normalize_scope(scope: str | None) -> str:
    s = (scope or "project").lower()
    if s not in SCOPES:
        raise McpError(
            "INVALID_INPUT",
            f"Invalid scope '{scope}'. Use project|changed_files|file|"
            "function|commit|branch|diff.",
        )
    return s


def _resolve_target(
    session: McpSession,
    *,
    scope: str,
    path: str | None,
) -> Path:
    if scope in {"file", "function"} and not path:
        raise McpError(
            "INVALID_INPUT",
            f"scope={scope} requires path= to a file under the project root.",
        )
    if path:
        return session.resolve(path)
    return session.project_root


def _impact_hint(target: Path, findings: list[dict[str, Any]]) -> str:
    texts: list[str] = []
    if target.is_file():
        try:
            texts.append(target.read_text(encoding="utf-8", errors="replace")[:8000])
        except OSError:
            pass
    for f in findings[:20]:
        texts.append(str(f.get("title") or ""))
        texts.append(str(f.get("rule_id") or ""))
        texts.append(str(f.get("message") or ""))
    blob = " ".join(texts).lower()
    hits = [k for k in _SECURITY_SENSITIVE if k in blob]
    if any(k in hits for k in ("auth", "authorization", "tenant", "permission")):
        return "HIGH"
    if hits or findings:
        return "MEDIUM"
    return "LOW"


def _decision(risk: str, verified: list[dict[str, Any]], predictive: list[dict[str, Any]]) -> str:
    if verified:
        sev = {(f.get("severity") or "").lower() for f in verified}
        if sev & {"critical", "high"}:
            return "BLOCK"
        return "REVIEW_REQUIRED"
    if risk == "HIGH" or predictive:
        return "REVIEW_REQUIRED"
    if risk == "MEDIUM":
        return "MONITOR"
    return "PASS"


def _pick_verified(adversary: dict[str, Any] | None, scan_findings: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if adversary and isinstance(adversary.get("findings"), list):
        for f in adversary["findings"]:
            status = str(f.get("status") or "").upper()
            if status in {"FALSE_POSITIVE", "REJECTED", "INVALID"}:
                continue
            if status in {"CONFIRMED", "LIKELY", "UNVERIFIED", "REQUIRES_REVIEW", ""}:
                out.append(
                    {
                        "id": f.get("id") or f.get("from_judgment_id"),
                        "title": f.get("title")
                        or f.get("vulnerability_type")
                        or f.get("message"),
                        "severity": f.get("severity") or "UNKNOWN",
                        "confidence": f.get("confidence") or status or "UNKNOWN",
                        "status": status or "UNKNOWN",
                        "evidence_summary": _first_text(
                            f.get("surviving_evidence") or f.get("evidence")
                        ),
                        "attack_path_summary": f.get("attack_path_summary"),
                    }
                )
    if not out:
        for f in summarize_findings(scan_findings, limit=limit):
            out.append(
                {
                    **f,
                    "evidence_summary": None,
                    "attack_path_summary": None,
                }
            )
    return out[:limit]


def _first_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value[:240]
    if isinstance(value, list) and value:
        item = value[0]
        if isinstance(item, dict):
            return str(item.get("summary") or item.get("text") or item)[:240]
        return str(item)[:240]
    if isinstance(value, dict):
        return str(value.get("summary") or value.get("text") or value)[:240]
    return str(value)[:240]


def _path_summaries(graph: dict[str, Any] | None, limit: int) -> list[dict[str, Any]]:
    if not graph:
        return []
    paths = graph.get("paths") or graph.get("attack_paths") or []
    if not isinstance(paths, list):
        return []
    out = []
    for p in paths[:limit]:
        if not isinstance(p, dict):
            continue
        out.append(
            {
                "id": p.get("id") or p.get("path_id"),
                "status": p.get("status") or "UNKNOWN",
                "summary": p.get("summary") or p.get("title") or _chain_summary(p),
            }
        )
    return out


def _chain_summary(path: dict[str, Any]) -> str:
    nodes = path.get("nodes") or path.get("steps") or []
    if isinstance(nodes, list) and nodes:
        labels = []
        for n in nodes[:6]:
            if isinstance(n, dict):
                labels.append(str(n.get("label") or n.get("id") or n.get("type") or "?"))
            else:
                labels.append(str(n))
        return " → ".join(labels)
    return "attack path"


def run_security_review(
    *,
    mode: str = "BALANCED",
    scope: str = "project",
    path: str | None = None,
    approved: bool = False,
    session: McpSession | None = None,
) -> dict[str, Any]:
    """Orchestrate understand→…→predict into an agent-friendly result."""
    sess = session or get_session()
    sess.begin_tool()
    mode_u = _normalize_mode(mode)
    scope_l = _normalize_scope(scope)
    enforce("axguard_security_review", approved=approved, mode=mode_u)
    sess.limits = limits_for_mode(mode_u)
    target = _resolve_target(sess, scope=scope_l, path=path)

    stages_run: list[str] = []
    errors: list[dict[str, str]] = []
    surface: dict[str, Any] | None = None
    memory: dict[str, Any] | None = None
    twin: dict[str, Any] | None = None
    flows: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    adversary: dict[str, Any] | None = None
    paths: dict[str, Any] | None = None
    predictive: dict[str, Any] | None = None
    scan: dict[str, Any] | None = None

    def _soft(name: str, fn):
        nonlocal stages_run
        try:
            result = fn()
            stages_run.append(name)
            return result
        except McpError:
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append({"stage": name, "error": str(exc)[:200]})
            return None

    # Always: understand + scan (bounded)
    scan_root = target if target.is_dir() else target.parent
    scan = _soft("scan", lambda: run_scan_engine(sess, scan_root))
    findings = list((scan or {}).get("findings") or sess.last_findings or [])
    if scope_l in {"file", "function"} and target.is_file():
        rel = str(target)
        findings = [
            f
            for f in findings
            if rel in str(f.get("file") or f.get("path") or "")
            or target.name in str(f.get("file") or f.get("path") or "")
        ]
        sess.last_findings = findings

    if mode_u != "LITE":
        surface = _soft("surface", lambda: run_surface_engine(sess, sess.project_root))
        memory = _soft("memory", lambda: run_memory_query(sess, "state"))

    if mode_u in {"BALANCED", "DEEP", "MAX"}:
        twin = _soft("twin", lambda: run_twin_engine(sess, sess.project_root))
        flows = _soft("flow", lambda: run_flow_engine(sess, sess.project_root))

    if mode_u in {"DEEP", "MAX"}:
        verification = _soft("judge", lambda: run_verify_engine(sess, sess.project_root))
        adversary = _soft("adversary", lambda: run_adversary_engine(sess, sess.project_root))
        paths = _soft("paths", lambda: run_paths_engine(sess, sess.project_root))
        predictive = _soft(
            "predict",
            lambda: run_predict_engine(sess, mode="default", target=sess.project_root),
        )
    elif mode_u == "BALANCED":
        # Route: only escalate if impact suggests it
        risk_hint = _impact_hint(target, findings)
        if risk_hint in {"HIGH", "MEDIUM"} or findings:
            adversary = _soft("adversary", lambda: run_adversary_engine(sess, sess.project_root))
            paths = _soft("paths", lambda: run_paths_engine(sess, sess.project_root))
        if risk_hint == "HIGH" or any(
            "auth" in str(f.get("rule_id") or "").lower() for f in findings[:20]
        ):
            predictive = _soft(
                "predict",
                lambda: run_predict_engine(sess, mode="default", target=sess.project_root),
            )
    else:  # LITE — scan + impact only
        pass

    if mode_u == "MAX":
        try:
            from engines.mcp.engines_bridge import run_investigate_engine

            _soft(
                "investigate",
                lambda: run_investigate_engine(
                    sess, budget="DEEP", target=sess.project_root
                ),
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"stage": "investigate", "error": str(exc)[:200]})

    verified = _pick_verified(adversary, findings, sess.limits.max_findings)
    pred_risks = []
    if predictive and isinstance(predictive.get("risks"), list):
        for r in predictive["risks"][: sess.limits.max_findings]:
            if isinstance(r, dict):
                pred_risks.append(
                    {
                        "category": r.get("category") or "UNKNOWN",
                        "confidence": r.get("confidence") or "UNKNOWN",
                        "summary": r.get("summary") or r.get("title"),
                        "change_status": r.get("change_status"),
                    }
                )

    risk = _impact_hint(target, findings)
    if verified and any(
        str(f.get("severity") or "").lower() in {"critical", "high"} for f in verified
    ):
        risk = "HIGH"
    decision = _decision(risk, verified, pred_risks)
    path_sums = _path_summaries(paths, sess.limits.max_attack_paths)

    # Attach path summaries onto first verified findings when possible
    if path_sums and verified:
        verified[0]["attack_path_summary"] = path_sums[0].get("summary")

    recommended = None
    if decision == "BLOCK":
        recommended = "Do not ship until high/critical verified findings are fixed and re-reviewed."
    elif decision == "REVIEW_REQUIRED":
        recommended = "Address verified findings and re-run axguard_security_review before shipping."
    elif decision == "MONITOR":
        recommended = "Monitor medium-impact changes; deepen analysis if authz/data flows changed."
    else:
        recommended = "No blocking verified findings in this bounded review."

    review = {
        "decision": decision,
        "risk": risk,
        "mode": mode_u,
        "scope": scope_l,
        "target": str(target),
        "verified_findings": verified,
        "predictive_risks": pred_risks,
        "attack_paths": path_sums,
        "stages_run": stages_run,
        "stage_errors": errors,
        "unknowns": (memory or {}).get("unknowns")
        if isinstance(memory, dict)
        else [],
        "recommended_action": recommended,
        "surface_summary": _surface_brief(surface),
        "twin_present": bool(twin),
        "flow_path_count": _count_flows(flows),
        "verification_present": verification is not None,
    }
    review["agent_text"] = agent_friendly_text(review)
    sess.last_review = review
    conf = "HIGH" if verified and decision in {"BLOCK", "REVIEW_REQUIRED"} else "MEDIUM"
    if not stages_run:
        conf = "UNKNOWN"
    return success_result(
        {"review": review, "agent_text": review["agent_text"]},
        state="OBSERVED" if verified else "INFERRED",
        confidence=conf,
        summary=review["agent_text"].split("\n")[0:6] and review["agent_text"][:500],
    )


def _surface_brief(surface: dict[str, Any] | None) -> dict[str, Any] | None:
    if not surface:
        return None
    summary = surface.get("summary") if isinstance(surface.get("summary"), dict) else {}
    return {
        "route_count": summary.get("route_count")
        or len(surface.get("routes") or []),
        "sink_count": summary.get("sink_count") or len(surface.get("sinks") or []),
        "stack": summary.get("stack") or surface.get("stack"),
    }


def _count_flows(flows: dict[str, Any] | None) -> int:
    if not flows:
        return 0
    for key in ("paths", "taint_paths", "flows"):
        val = flows.get(key)
        if isinstance(val, list):
            return len(val)
    return int(flows.get("path_count") or 0)
