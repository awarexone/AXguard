"""MCP tool handlers — thin calls into engines_bridge + policy."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from engines.mcp import engines_bridge as bridge
from engines.mcp.policy import enforce
from engines.mcp.schemas.errors import McpError
from engines.mcp.schemas.results import success_result, truncate_result
from engines.mcp.session import McpSession, get_session
from engines.mcp.tools.security_review import run_security_review


def _sess() -> McpSession:
    return get_session()


def _ok(data: dict[str, Any], *, state: str = "OBSERVED", confidence: str = "MEDIUM") -> dict[str, Any]:
    sess = _sess()
    trimmed = truncate_result(
        data,
        max_bytes=sess.limits.max_output_bytes,
        max_list=sess.limits.max_list_items,
    )
    return success_result(
        trimmed if isinstance(trimmed, dict) else {"data": trimmed},
        state=state,
        confidence=confidence,
    )


def as_tool(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except McpError as exc:
            return exc.as_dict()
        except Exception as exc:  # noqa: BLE001
            return McpError(
                "ANALYSIS_FAILED",
                f"Analysis failed: {exc}",
                details={"type": type(exc).__name__},
            ).as_dict()

    return wrapper


def axguard_get_project(approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_project", approved=approved)
    root = sess.project_root
    return _ok(
        {
            "project_root": str(root),
            "findings_dir": str(sess.findings_dir()),
            "memory_dir": str(sess.memory_dir()),
            "exists": root.exists(),
            "name": root.name,
        }
    )


def axguard_get_application_model(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_application_model", approved=approved)
    target = bridge.require_path(sess, path)
    model = bridge.run_surface_engine(sess, target if target.is_dir() else sess.project_root)
    summary = model.get("summary") if isinstance(model, dict) else None
    return _ok(
        {
            "summary": summary,
            "route_count": len(model.get("routes") or []) if isinstance(model, dict) else 0,
            "sink_count": len(model.get("sinks") or []) if isinstance(model, dict) else 0,
            "stack": (summary or {}).get("stack") if isinstance(summary, dict) else model.get("stack") if isinstance(model, dict) else None,
        },
        state="OBSERVED",
    )


def axguard_get_attack_surface(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    return axguard_get_application_model(path=path, approved=approved)


def axguard_scan(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_scan", approved=approved)
    target = bridge.require_path(sess, path)
    result = bridge.run_scan_engine(sess, target if target.is_dir() else sess.project_root)
    findings = bridge.summarize_findings(
        list(result.get("findings") or []), limit=sess.limits.max_findings
    )
    return _ok(
        {
            "finding_count": result.get("finding_count", len(findings)),
            "findings": findings,
            "target": result.get("target"),
        }
    )


def axguard_audit(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_audit", approved=approved)
    target = bridge.require_path(sess, path)
    result = bridge.run_audit_engine(sess, target if target.is_dir() else sess.project_root)
    findings = bridge.summarize_findings(
        list(result.get("findings") or []), limit=sess.limits.max_findings
    )
    return _ok(
        {
            "finding_count": len(result.get("findings") or []),
            "findings": findings,
            "phases": result.get("phases") or result.get("phase_results"),
            "out_dir": str(sess.findings_dir()),
        }
    )


def axguard_threat_model(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_threat_model", approved=approved)
    target = bridge.require_path(sess, path)
    root = target if target.is_dir() else sess.project_root
    surface = bridge.run_surface_engine(sess, root)
    flows = None
    paths = None
    try:
        flows = bridge.run_flow_engine(sess, root)
    except Exception:  # noqa: BLE001
        pass
    try:
        paths = bridge.run_paths_engine(sess, root)
    except Exception:  # noqa: BLE001
        pass
    return _ok(
        {
            "surface": {
                "routes": len(surface.get("routes") or []),
                "sinks": len(surface.get("sinks") or []),
                "stack": (surface.get("summary") or {}).get("stack")
                if isinstance(surface.get("summary"), dict)
                else surface.get("stack"),
            },
            "flow_path_count": len(flows.get("paths") or flows.get("taint_paths") or [])
            if isinstance(flows, dict)
            else 0,
            "attack_path_count": len(paths.get("paths") or []) if isinstance(paths, dict) else 0,
            "note": "Threat-model sketch from surface/flows/paths — not a verified finding report.",
        },
        state="INFERRED",
    )


def axguard_trace_flow(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_trace_flow", approved=approved)
    target = bridge.require_path(sess, path)
    flows = bridge.run_flow_engine(sess, target if target.is_dir() else sess.project_root)
    paths = flows.get("paths") or flows.get("taint_paths") or []
    if not isinstance(paths, list):
        paths = []
    brief = []
    for p in paths[: sess.limits.max_attack_paths]:
        if isinstance(p, dict):
            brief.append(
                {
                    "id": p.get("id"),
                    "source": p.get("source"),
                    "sink": p.get("sink"),
                    "summary": p.get("summary") or p.get("label"),
                }
            )
    return _ok({"path_count": len(paths), "paths": brief}, state="OBSERVED")


def axguard_find_taint_paths(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    return axguard_trace_flow(path=path, approved=approved)


def axguard_find_sensitive_flows(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_find_sensitive_flows", approved=approved)
    target = bridge.require_path(sess, path)
    flows = bridge.run_flow_engine(sess, target if target.is_dir() else sess.project_root)
    paths = flows.get("paths") or flows.get("taint_paths") or []
    if not isinstance(paths, list):
        paths = []
    sensitive_keys = ("secret", "password", "token", "pii", "ssrf", "sql", "cmd", "eval")
    filtered = []
    for p in paths:
        if not isinstance(p, dict):
            continue
        blob = str(p).lower()
        if any(k in blob for k in sensitive_keys) or p.get("sensitive"):
            filtered.append(
                {
                    "id": p.get("id"),
                    "source": p.get("source"),
                    "sink": p.get("sink"),
                    "summary": p.get("summary") or p.get("label"),
                }
            )
    return _ok(
        {
            "path_count": len(filtered),
            "paths": filtered[: sess.limits.max_attack_paths],
        },
        state="INFERRED",
    )


def axguard_list_findings(refresh: bool = False, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_list_findings", approved=approved)
    if refresh or not sess.last_findings:
        bridge.run_scan_engine(sess)
    findings = bridge.summarize_findings(sess.last_findings, limit=sess.limits.max_findings)
    return _ok({"finding_count": len(sess.last_findings), "findings": findings})


def _find_by_id(findings: list[dict[str, Any]], finding_id: str) -> dict[str, Any] | None:
    for f in findings:
        for key in ("id", "rule_id", "fingerprint", "from_judgment_id"):
            if finding_id and finding_id == str(f.get(key) or ""):
                return f
            if finding_id and finding_id in str(f.get(key) or ""):
                return f
    return None


def axguard_get_finding(finding_id: str, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_finding", approved=approved)
    if not finding_id:
        raise McpError("INVALID_INPUT", "finding_id is required")
    if not sess.last_findings:
        bridge.run_scan_engine(sess)
    found = _find_by_id(sess.last_findings, finding_id)
    if not found:
        raise McpError(
            "INSUFFICIENT_EVIDENCE",
            f"Finding '{finding_id}' not found in current session cache.",
            details={"hint": "Call axguard_list_findings or axguard_security_review first."},
        )
    summary = bridge.summarize_findings([found], limit=1)[0]
    summary["verdict"] = found.get("status") or found.get("confidence") or "UNKNOWN"
    return _ok({"finding": summary})


def axguard_verify_finding(finding_id: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_verify_finding", approved=approved)
    result = bridge.run_verify_engine(sess)
    return _ok(
        {
            "finding_id": finding_id,
            "verification_summary": result.get("summary") or {
                "judgment_count": len(result.get("judgments") or result.get("findings") or [])
            },
        },
        state="INFERRED",
    )


def axguard_verify_fix(
    finding_id: str | None = None,
    fingerprint: str | None = None,
    path: str | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    from engines.mcp.tools.verify_fix import run_verify_fix

    return run_verify_fix(
        finding_id=finding_id,
        fingerprint=fingerprint,
        path=path,
        approved=approved,
        session=_sess(),
    )


def _ensure_evidence(sess: McpSession) -> dict[str, Any]:
    if sess.last_evidence:
        return sess.last_evidence
    return bridge.run_evidence_engine(sess)


def axguard_get_evidence(finding_id: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_evidence", approved=approved)
    evidence = _ensure_evidence(sess)
    items = evidence.get("evidence") or evidence.get("items") or []
    if not isinstance(items, list):
        items = []
    if finding_id:
        items = [
            i
            for i in items
            if isinstance(i, dict)
            and finding_id in str(i.get("finding_id") or i.get("id") or "")
        ]
    return _ok(
        {"items": items[: sess.limits.max_evidence_items], "total": len(items)},
        state="OBSERVED",
    )


def axguard_get_evidence_chain(finding_id: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_evidence_chain", approved=approved)
    evidence = _ensure_evidence(sess)
    chains = evidence.get("chains") or evidence.get("evidence_chains") or []
    if finding_id and isinstance(chains, list):
        chains = [
            c
            for c in chains
            if isinstance(c, dict) and finding_id in str(c.get("finding_id") or c.get("id") or "")
        ]
    return _ok({"chains": chains[: sess.limits.max_evidence_items] if isinstance(chains, list) else chains})


def axguard_get_counter_evidence(finding_id: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_counter_evidence", approved=approved)
    evidence = _ensure_evidence(sess)
    items = evidence.get("counter_evidence") or []
    if not isinstance(items, list):
        items = []
    if finding_id:
        items = [
            i
            for i in items
            if isinstance(i, dict)
            and finding_id in str(i.get("finding_id") or i.get("id") or "")
        ]
    return _ok({"items": items[: sess.limits.max_evidence_items], "total": len(items)})


def axguard_find_attack_paths(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_find_attack_paths", approved=approved)
    target = bridge.require_path(sess, path)
    graph = bridge.run_paths_engine(sess, target if target.is_dir() else sess.project_root)
    paths = graph.get("paths") or graph.get("attack_paths") or []
    if not isinstance(paths, list):
        paths = []
    brief = []
    for p in paths[: sess.limits.max_attack_paths]:
        if isinstance(p, dict):
            brief.append(
                {
                    "id": p.get("id") or p.get("path_id"),
                    "status": p.get("status"),
                    "summary": p.get("summary") or p.get("title"),
                }
            )
    return _ok({"path_count": len(paths), "paths": brief})


def axguard_get_attack_path(path_id: str, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_attack_path", approved=approved)
    if not path_id:
        raise McpError("INVALID_INPUT", "path_id is required")
    graph = sess.last_attack_graph or bridge.run_paths_engine(sess)
    paths = graph.get("paths") or graph.get("attack_paths") or []
    found = None
    for p in paths if isinstance(paths, list) else []:
        if isinstance(p, dict) and path_id in str(p.get("id") or p.get("path_id") or ""):
            found = p
            break
    if not found:
        raise McpError("INSUFFICIENT_EVIDENCE", f"Attack path '{path_id}' not found.")
    return _ok({"path": found})


def axguard_explain_attack_path(path_id: str, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_explain_attack_path", approved=approved)
    if not path_id:
        raise McpError("INVALID_INPUT", "path_id is required")
    graph = sess.last_attack_graph or bridge.run_paths_engine(sess)
    paths = graph.get("paths") or graph.get("attack_paths") or []
    found = None
    for p in paths if isinstance(paths, list) else []:
        if isinstance(p, dict) and path_id in str(p.get("id") or p.get("path_id") or ""):
            found = p
            break
    if not found:
        raise McpError("INSUFFICIENT_EVIDENCE", f"Attack path '{path_id}' not found.")
    nodes = found.get("nodes") or found.get("steps") or []
    labels = []
    for n in nodes if isinstance(nodes, list) else []:
        if isinstance(n, dict):
            labels.append(str(n.get("label") or n.get("id") or n.get("type")))
        else:
            labels.append(str(n))
    explanation = (
        " → ".join(labels)
        if labels
        else str(found.get("summary") or found.get("title") or path_id)
    )
    return _ok(
        {
            "path_id": path_id,
            "status": found.get("status") or "UNKNOWN",
            "explanation": explanation,
            "summary": found.get("summary") or found.get("title"),
        },
        state="INFERRED",
    )


def axguard_get_security_twin(path: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_security_twin", approved=approved)
    target = bridge.require_path(sess, path)
    result = bridge.run_twin_engine(sess, target if target.is_dir() else sess.project_root)
    twin = result.get("twin") if isinstance(result, dict) else result
    summary = None
    if isinstance(twin, dict):
        summary = twin.get("summary")
    return _ok(
        {
            "summary": summary,
            "entity_count": len(twin.get("entities") or []) if isinstance(twin, dict) else 0,
            "present": twin is not None,
        },
        state="SIMULATED" if twin else "UNKNOWN",
    )


def axguard_compare_security_twin(
    before: str,
    after: str,
    approved: bool = False,
) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_compare_security_twin", approved=approved)
    before_p = bridge.require_path(sess, before)
    after_p = bridge.require_path(sess, after)
    from engines.twin import run_twin, run_twin_compare

    def _load_twin(path):
        if path.is_file() and path.suffix.lower() == ".json":
            import json

            return json.loads(path.read_text(encoding="utf-8"))
        pack = run_twin(path, write_report=sess.findings_dir() / "twin")
        return pack.get("twin") if isinstance(pack, dict) else pack

    result = run_twin_compare(_load_twin(before_p), _load_twin(after_p))
    return _ok({"compare": result}, state="INFERRED")


def axguard_what_if(scenario: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_what_if", approved=approved)
    from engines.twin import run_twin_what_if

    result = run_twin_what_if(sess.project_root, scenario=scenario)
    return _ok({"what_if": result}, state="SIMULATED")


def axguard_blast_radius(entity_id: str, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_blast_radius", approved=approved)
    if not entity_id:
        raise McpError("INVALID_INPUT", "entity_id is required")
    if not sess.last_twin:
        bridge.run_twin_engine(sess)
    from engines.twin import entity_blast_radius

    result = entity_blast_radius(sess.last_twin or {}, entity_id)
    return _ok({"blast_radius": result}, state="SIMULATED")


def axguard_get_security_memory(approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_security_memory", approved=approved)
    data = bridge.run_memory_query(sess, "state")
    return _ok({"memory": data}, state="OBSERVED")


def axguard_get_security_history(approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_security_history", approved=approved)
    data = bridge.run_memory_query(sess, "history")
    return _ok(data if isinstance(data, dict) else {"history": data}, state="OBSERVED")


def axguard_find_regressions(approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_find_regressions", approved=approved)
    data = bridge.run_memory_query(sess, "regressions")
    return _ok(data if isinstance(data, dict) else {"regressions": data}, state="OBSERVED")


def axguard_investigate(
    finding_id: str | None = None,
    budget: str = "BALANCED",
    approved: bool = False,
) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_investigate", approved=approved)
    result = bridge.run_investigate_engine(
        sess, finding_id=finding_id, budget=(budget or "BALANCED").upper()
    )
    return _ok(
        {
            "investigation_summary": result.get("summary")
            or {
                "candidate_count": len(result.get("investigations") or result.get("results") or [])
            },
            "finding_id": finding_id,
            "budget": budget,
        },
        state="INFERRED",
    )


def axguard_get_investigation(finding_id: str | None = None, approved: bool = False) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_get_investigation", approved=approved)
    data = sess.last_investigation
    if not data:
        raise McpError(
            "INSUFFICIENT_EVIDENCE",
            "No investigation in session. Call axguard_investigate first.",
        )
    payload: dict[str, Any] = {"investigation": data}
    if finding_id:
        try:
            from engines.investigation import explain_investigation, find_investigation

            inv = find_investigation(data, finding_id)
            if inv is None and isinstance(data, dict):
                for item in data.get("investigations") or data.get("results") or []:
                    if isinstance(item, dict) and finding_id in str(
                        item.get("finding_id") or item.get("id") or ""
                    ):
                        inv = item
                        break
            if inv:
                payload["explanation"] = explain_investigation(inv)
                payload["matched"] = inv
        except Exception as exc:  # noqa: BLE001
            payload["lookup_error"] = str(exc)[:160]
    return _ok(payload, state="INFERRED")


def axguard_predict_security_risks(
    mode: str = "default",
    path: str | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_predict_security_risks", approved=approved)
    target = bridge.require_path(sess, path)
    result = bridge.run_predict_engine(
        sess, mode=mode or "default", target=target if target.is_dir() else sess.project_root
    )
    risks = result.get("risks") or []
    brief = []
    for r in risks[: sess.limits.max_findings] if isinstance(risks, list) else []:
        if isinstance(r, dict):
            brief.append(
                {
                    "category": r.get("category"),
                    "confidence": r.get("confidence"),
                    "summary": r.get("summary") or r.get("title"),
                    "change_status": r.get("change_status"),
                }
            )
    return _ok(
        {
            "risk_count": len(risks) if isinstance(risks, list) else 0,
            "risks": brief,
            "disclaimer": result.get("disclaimer")
            or "PREDICTIVE — not verified findings.",
        },
        state="INFERRED",
        confidence="LOW",
    )


def axguard_analyze_change_risk(
    base: str,
    path: str | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    sess = _sess()
    sess.begin_tool()
    enforce("axguard_analyze_change_risk", approved=approved)
    if not base:
        raise McpError("INVALID_INPUT", "base path is required for change-risk analysis")
    base_p = bridge.require_path(sess, base)
    target = bridge.require_path(sess, path)
    result = bridge.run_predict_engine(
        sess,
        mode="pr",
        target=target if target.is_dir() else sess.project_root,
        base=base_p,
    )
    return _ok(
        {
            "summary": result.get("summary"),
            "risk_count": len(result.get("risks") or []),
            "disclaimer": "PREDICTIVE change-risk analysis.",
        },
        state="INFERRED",
        confidence="LOW",
    )


@as_tool
def axguard_security_review_tool(
    mode: str = "BALANCED",
    scope: str = "project",
    path: str | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    return run_security_review(mode=mode, scope=scope, path=path, approved=approved)


# Map for registration (all return structured ok/error dicts)
HANDLERS: dict[str, Any] = {
    "axguard_security_review": axguard_security_review_tool,
    "axguard_get_project": as_tool(axguard_get_project),
    "axguard_get_application_model": as_tool(axguard_get_application_model),
    "axguard_get_attack_surface": as_tool(axguard_get_attack_surface),
    "axguard_scan": as_tool(axguard_scan),
    "axguard_audit": as_tool(axguard_audit),
    "axguard_threat_model": as_tool(axguard_threat_model),
    "axguard_trace_flow": as_tool(axguard_trace_flow),
    "axguard_find_taint_paths": as_tool(axguard_find_taint_paths),
    "axguard_find_sensitive_flows": as_tool(axguard_find_sensitive_flows),
    "axguard_list_findings": as_tool(axguard_list_findings),
    "axguard_get_finding": as_tool(axguard_get_finding),
    "axguard_verify_finding": as_tool(axguard_verify_finding),
    "axguard_verify_fix": as_tool(axguard_verify_fix),
    "axguard_get_evidence": as_tool(axguard_get_evidence),
    "axguard_get_evidence_chain": as_tool(axguard_get_evidence_chain),
    "axguard_get_counter_evidence": as_tool(axguard_get_counter_evidence),
    "axguard_find_attack_paths": as_tool(axguard_find_attack_paths),
    "axguard_get_attack_path": as_tool(axguard_get_attack_path),
    "axguard_explain_attack_path": as_tool(axguard_explain_attack_path),
    "axguard_get_security_twin": as_tool(axguard_get_security_twin),
    "axguard_compare_security_twin": as_tool(axguard_compare_security_twin),
    "axguard_what_if": as_tool(axguard_what_if),
    "axguard_blast_radius": as_tool(axguard_blast_radius),
    "axguard_get_security_memory": as_tool(axguard_get_security_memory),
    "axguard_get_security_history": as_tool(axguard_get_security_history),
    "axguard_find_regressions": as_tool(axguard_find_regressions),
    "axguard_investigate": as_tool(axguard_investigate),
    "axguard_get_investigation": as_tool(axguard_get_investigation),
    "axguard_predict_security_risks": as_tool(axguard_predict_security_risks),
    "axguard_analyze_change_risk": as_tool(axguard_analyze_change_risk),
}
