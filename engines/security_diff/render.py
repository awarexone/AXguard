"""Compact CLI rendering for Security Diff."""

from __future__ import annotations

from typing import Any


def render_security_diff_text(result: dict[str, Any]) -> str:
    """Render compact SECURITY DIFF text (product-style)."""
    lines: list[str] = []
    lines.append("SECURITY DIFF")
    lines.append("────────────────────────")
    lines.append("")

    baseline = result.get("baseline") or "UNKNOWN"
    if baseline == "UNKNOWN":
        lines.append("BASELINE: UNKNOWN")
        lines.append("")

    summary = result.get("summary") or {}

    def _plus(n: int, label: str) -> None:
        if n:
            lines.append(f"+ {n} {label}")

    def _minus(n: int, label: str) -> None:
        if n:
            lines.append(f"- {n} {label}")

    _plus(int(summary.get("new_endpoints") or 0), "new API endpoints")
    _minus(int(summary.get("removed_endpoints") or 0), "removed endpoints")
    _plus(int(summary.get("new_parameters") or 0), "new parameters")
    _plus(int(summary.get("new_database_flows") or 0), "new database flow")
    _plus(int(summary.get("new_external_requests") or 0), "new external HTTP request")
    _plus(int(summary.get("new_uploads") or 0), "new upload")
    _plus(int(summary.get("new_webhooks") or 0), "new webhook")
    _plus(int(summary.get("new_sensitive_flows") or 0), "new sensitive data flow")
    _minus(int(summary.get("removed_controls") or 0), "authorization/security control")
    _plus(int(summary.get("added_controls") or 0), "security control added")

    # Authz / tenant highlights
    for ch in result.get("authz_changes") or []:
        lines.append(f"! authz: {ch.get('change')}")
    for ch in result.get("tenant_changes") or []:
        lines.append(f"! tenant: {ch.get('change')}")

    if len(lines) <= 4:
        lines.append("(no structural security changes detected)")

    lines.append("")
    lines.append("Attack paths:")
    lines.append(f"+ {int(summary.get('new_attack_paths') or 0)} reachable")
    lines.append(f"- {int(summary.get('blocked_attack_paths') or 0)} blocked")
    lines.append("")
    lines.append("Security controls:")
    lines.append(f"{int(summary.get('weakened_controls') or 0)} weakened")
    lines.append(f"{int(summary.get('added_controls') or 0)} added")
    lines.append(f"{int(summary.get('removed_controls') or 0)} removed")
    lines.append(f"{int(summary.get('strengthened_controls') or 0)} strengthened")
    lines.append("")
    lines.append("Overall security change:")
    lines.append(str(result.get("overall_security_change") or "LOW"))

    notes = result.get("notes") or []
    if notes:
        lines.append("")
        lines.append("Notes:")
        for n in notes[:8]:
            lines.append(f"- {n}")

    return "\n".join(lines).rstrip() + "\n"
