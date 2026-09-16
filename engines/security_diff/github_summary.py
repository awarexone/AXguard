"""GitHub PR summary formatter for Security Diff (shared engine, not a second bot)."""

from __future__ import annotations

from typing import Any


def format_github_pr_summary(diff: dict[str, Any]) -> str:
    """Compact markdown suitable for a PR check / comment."""
    impact = diff.get("security_impact") or {}
    level = impact.get("level") or "UNKNOWN"
    summary = diff.get("summary") or {}
    paths = diff.get("attack_path_delta") or {}
    regressions = diff.get("regressions") or []
    pred = diff.get("predictive_risks") or []
    ctrl = (diff.get("control_delta") or {}).get("summary") or {}

    lines = [
        "AXGUARD SECURITY DIFF",
        "",
        f"Risk increased: {level}",
        "",
        f"+ {summary.get('new_endpoints', 0)} endpoints",
        f"+ {summary.get('privilege_changes', 0)} privileged operation(s)",
        f"- {ctrl.get('removed', summary.get('removed_controls', 0))} authorization control(s)",
        f"+ {summary.get('new_sensitive_flows', 0)} sensitive data flow(s)",
        "",
        "New attack paths:",
        str(len(paths.get("new_paths") or summary.get("new_attack_paths") or [])),
        "",
        "Security regressions:",
        str(len(regressions)),
        "",
        "Predictive risks:",
        str(len(pred)),
        "",
        f"Decision: {impact.get('decision') or 'UNKNOWN'}",
    ]
    return "\n".join(lines) + "\n"


def compact_mcp_response(diff: dict[str, Any]) -> dict[str, Any]:
    """Compact payload for AI-agent context."""
    impact = diff.get("security_impact") or {}
    ctrl = (diff.get("control_delta") or {}).get("changes") or []
    paths = diff.get("attack_path_delta") or {}
    return {
        "summary": diff.get("summary") or {},
        "security_impact": impact,
        "changed_controls": ctrl[:20],
        "new_attack_paths": (paths.get("new_paths") or [])[:10],
        "removed_attack_paths": (paths.get("removed_paths") or [])[:10],
        "regressions": (diff.get("regressions") or [])[:10],
        "privilege_changes": ((diff.get("privilege_delta") or {}).get("changes") or [])[
            :10
        ],
        "sensitive_flow_changes": (
            (diff.get("data_flow_delta") or {}).get("added") or []
        )[:10],
        "predictive_risks": (diff.get("predictive_risks") or [])[:10],
        "unknowns": (diff.get("unknowns") or [])[:10],
        "recommended_action": (diff.get("recommended_actions") or ["none"])[:5],
        "baseline": diff.get("baseline"),
        "decision": impact.get("decision"),
    }
