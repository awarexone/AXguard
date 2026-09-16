"""Compact CLI rendering for Security Diff."""

from __future__ import annotations

from typing import Any

from engines.security_diff.schema import is_baseline_unavailable


def render_security_diff_text(result: dict[str, Any]) -> str:
    """Render compact SECURITY DIFF text (product-style)."""
    lines: list[str] = []
    lines.append("SECURITY DIFF")
    lines.append("────────────────────────")
    lines.append("")

    baseline = result.get("baseline") or "UNKNOWN"
    if is_baseline_unavailable(str(baseline)):
        lines.append(f"BASELINE: {baseline}")
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

    for ch in result.get("authz_changes") or []:
        lines.append(f"! authz: {ch.get('change')}")
    for ch in result.get("tenant_changes") or []:
        lines.append(f"! tenant: {ch.get('change')}")

    if len(lines) <= 4:
        lines.append("(no structural security changes detected)")

    lines.append("")
    overall = result.get("overall_security_change")
    if not overall:
        impact = result.get("security_impact") or {}
        overall = impact.get("level") or (
            "UNKNOWN" if is_baseline_unavailable(str(baseline)) else "NONE"
        )
    lines.append(f"Overall security change: {overall}")
    decision = (result.get("security_impact") or {}).get("decision")
    if decision:
        lines.append(f"Decision: {decision}")
    return "\n".join(lines) + "\n"
