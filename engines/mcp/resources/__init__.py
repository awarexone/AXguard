"""MCP resources — progressive disclosure over project artifacts."""

from __future__ import annotations

import json
from typing import Any

from engines.mcp.schemas.results import redact_result, truncate_result
from engines.mcp.session import get_session

RESOURCE_URIS = (
    "axguard://project",
    "axguard://findings",
    "axguard://memory",
    "axguard://twin",
    "axguard://attack-paths",
    "axguard://posture",
    "axguard://predictive-risks",
)


def list_resources() -> list[dict[str, str]]:
    return [
        {"uri": "axguard://project", "name": "Project", "mimeType": "application/json", "description": "Project root metadata"},
        {"uri": "axguard://findings", "name": "Findings", "mimeType": "application/json", "description": "Summarized findings (session cache)"},
        {"uri": "axguard://memory", "name": "Security Memory", "mimeType": "application/json", "description": "Longitudinal memory state"},
        {"uri": "axguard://twin", "name": "Security Twin", "mimeType": "application/json", "description": "Twin summary if built"},
        {"uri": "axguard://attack-paths", "name": "Attack Paths", "mimeType": "application/json", "description": "Attack path summaries"},
        {"uri": "axguard://posture", "name": "Security Posture", "mimeType": "application/json", "description": "Compact posture from last review"},
        {"uri": "axguard://predictive-risks", "name": "Predictive Risks", "mimeType": "application/json", "description": "Predictive risk summaries"},
    ]


def _json(data: Any) -> str:
    sess = get_session()
    payload = truncate_result(
        redact_result(data),
        max_bytes=sess.limits.max_output_bytes,
        max_list=sess.limits.max_list_items,
    )
    return json.dumps(payload, indent=2, default=str)


def read_resource(uri: str) -> str:
    sess = get_session()
    u = (uri or "").rstrip("/")
    if u == "axguard://project":
        return _json(
            {
                "project_root": str(sess.project_root),
                "findings_dir": str(sess.findings_dir()),
                "memory_dir": str(sess.memory_dir()),
            }
        )
    if u == "axguard://findings":
        from engines.mcp.engines_bridge import summarize_findings

        return _json(
            {
                "finding_count": len(sess.last_findings),
                "findings": summarize_findings(
                    sess.last_findings, limit=sess.limits.max_findings
                ),
            }
        )
    if u == "axguard://memory":
        from engines.mcp.engines_bridge import run_memory_query

        try:
            return _json(run_memory_query(sess, "state"))
        except Exception as exc:  # noqa: BLE001
            return _json({"status": "EMPTY", "error": str(exc)[:120]})
    if u == "axguard://twin":
        twin = sess.last_twin or {}
        return _json({"summary": twin.get("summary"), "present": bool(twin)})
    if u == "axguard://attack-paths":
        graph = sess.last_attack_graph or {}
        paths = graph.get("paths") or []
        brief = []
        if isinstance(paths, list):
            for p in paths[: sess.limits.max_attack_paths]:
                if isinstance(p, dict):
                    brief.append(
                        {
                            "id": p.get("id") or p.get("path_id"),
                            "status": p.get("status"),
                            "summary": p.get("summary") or p.get("title"),
                        }
                    )
        return _json({"paths": brief})
    if u == "axguard://posture":
        review = sess.last_review or {}
        return _json(
            {
                "decision": review.get("decision"),
                "risk": review.get("risk"),
                "verified_count": len(review.get("verified_findings") or []),
                "recommended_action": review.get("recommended_action"),
            }
        )
    if u == "axguard://predictive-risks":
        pred = sess.last_predict or {}
        risks = pred.get("risks") or []
        brief = []
        if isinstance(risks, list):
            for r in risks[: sess.limits.max_findings]:
                if isinstance(r, dict):
                    brief.append(
                        {
                            "category": r.get("category"),
                            "confidence": r.get("confidence"),
                            "summary": r.get("summary") or r.get("title"),
                        }
                    )
        return _json({"risks": brief, "disclaimer": "PREDICTIVE"})
    return _json({"error": {"code": "INVALID_INPUT", "message": f"Unknown resource: {uri}"}})
