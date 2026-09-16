"""Thin wrappers around existing engines — no duplicated scanners."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.mcp.schemas.errors import McpError
from engines.mcp.session import McpSession


def rules_dir() -> Path:
    from engines.paths import default_rules_dir

    return default_rules_dir()


def run_scan_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.scanner import ScanOptions, run_scan

    path = target or session.project_root
    result = run_scan(ScanOptions(target=path, rules_dir=rules_dir()))
    findings = list(result.get("findings") or [])
    session.last_findings = findings
    return result


def run_audit_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.audit import AuditOptions, run_audit

    path = target or session.project_root
    return run_audit(
        AuditOptions(target=path, rules_dir=rules_dir(), out_dir=session.findings_dir())
    )


def run_surface_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.app_model import build_application_model

    path = target or session.project_root
    return build_application_model(path)


def run_flow_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.app_model import build_application_model
    from engines.dataflow import analyze_dataflow

    path = target or session.project_root
    model = build_application_model(path)
    return analyze_dataflow(path, application_model=model)


def run_paths_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.attack_graph import run_attack_graph

    path = target or session.project_root
    graph = run_attack_graph(path)
    session.last_attack_graph = graph
    return graph


def run_evidence_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.evidence import run_evidence

    path = target or session.project_root
    result = run_evidence(path)
    session.last_evidence = result
    return result


def run_verify_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.verify import run_verification

    return run_verification(target or session.project_root)


def run_adversary_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.adversary import run_adversary

    return run_adversary(target or session.project_root)


def run_twin_engine(session: McpSession, target: Path | None = None) -> dict[str, Any]:
    from engines.twin import run_twin

    out = session.findings_dir() / "twin"
    out.mkdir(parents=True, exist_ok=True)
    result = run_twin(
        target or session.project_root,
        write_report=out,
    )
    twin = result.get("twin") if isinstance(result, dict) else result
    if isinstance(twin, dict):
        session.last_twin = twin
    return result if isinstance(result, dict) else {"twin": twin}


def run_memory_query(session: McpSession, kind: str = "state") -> dict[str, Any]:
    from engines.memory import (
        get_current_state,
        get_findings,
        get_history,
        get_memory,
        get_regressions,
        get_unknowns,
    )

    mem_dir = session.memory_dir()
    if kind == "history":
        return {"history": get_history(mem_dir)}
    if kind == "findings":
        return {"findings": get_findings(mem_dir)}
    if kind == "regressions":
        return {"regressions": get_regressions(mem_dir)}
    if kind == "unknowns":
        return {"unknowns": get_unknowns(mem_dir)}
    if kind == "full":
        return get_memory(mem_dir) or {"status": "EMPTY"}
    return get_current_state(mem_dir) or {"status": "EMPTY"}


def run_investigate_engine(
    session: McpSession,
    *,
    finding_id: str | None = None,
    budget: str = "BALANCED",
    target: Path | None = None,
) -> dict[str, Any]:
    from engines.investigation import run_investigation

    session.budget.record_investigation_step()
    result = run_investigation(
        target or session.project_root,
        finding_id=finding_id,
        budget=budget,
        memory_dir=session.memory_dir(),
        out_dir=session.findings_dir() / "investigation",
        write_report=True,
    )
    session.last_investigation = result
    return result


def run_predict_engine(
    session: McpSession,
    *,
    mode: str = "default",
    target: Path | None = None,
    base: Path | str | None = None,
) -> dict[str, Any]:
    from engines.predictive import run_predict

    result = run_predict(
        target or session.project_root,
        base=base,
        mode=mode,
        memory_dir=session.memory_dir(),
        out_dir=session.findings_dir() / "predictive",
        write_report=True,
    )
    session.last_predict = result
    return result


def summarize_findings(findings: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings[:limit]:
        out.append(
            {
                "id": f.get("id") or f.get("rule_id") or f.get("fingerprint"),
                "title": f.get("title") or f.get("message") or f.get("vulnerability_type"),
                "severity": f.get("severity") or "UNKNOWN",
                "confidence": f.get("confidence") or f.get("status") or "UNKNOWN",
                "file": f.get("file") or f.get("path") or f.get("location"),
                "line": f.get("line") or f.get("start_line"),
                "rule_id": f.get("rule_id"),
                "status": f.get("status"),
            }
        )
    return out


def require_path(session: McpSession, path: str | None) -> Path:
    try:
        return session.resolve(path)
    except McpError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise McpError("INVALID_INPUT", f"Invalid path: {exc}") from exc
