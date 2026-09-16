"""Security Diff text / JSON / HTML rendering."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def render_text(diff: dict[str, Any]) -> str:
    """Concise CLI output (default)."""
    impact = diff.get("security_impact") or {}
    level = impact.get("level") or "UNKNOWN"
    decision = impact.get("decision") or "UNKNOWN"
    summary = diff.get("summary") or {}
    surface = diff.get("attack_surface_delta") or {}
    controls = diff.get("control_delta") or {}
    ctrl_sum = controls.get("summary") or {}
    paths = diff.get("attack_path_delta") or {}
    pred = diff.get("predictive_risks") or []
    regressions = diff.get("regressions") or []

    lines = [
        "AXGUARD SECURITY DIFF",
        "",
        f"Impact: {level}",
        "",
        "Attack Surface",
        f"+ {summary.get('new_endpoints', len(surface.get('added') or []))} endpoints",
        f"+ {summary.get('new_webhooks', 0)} webhook(s)",
        "",
        "Security Controls",
        f"- {ctrl_sum.get('removed', summary.get('removed_controls', 0))} authorization/control(s)",
        f"+ {ctrl_sum.get('added', summary.get('added_controls', 0))} control(s)",
        f"~ {ctrl_sum.get('moved', summary.get('moved_controls', 0))} moved (refactor)",
        "",
        "Data Flow",
        f"+ {summary.get('new_sensitive_flows', 0)} sensitive path(s)",
        "",
        "Privileges",
        f"+ {summary.get('privilege_changes', 0)} privileged operation change(s)",
        "",
        "Attack Paths",
        f"+ {summary.get('new_attack_paths', len(paths.get('new_paths') or []))} new reachable path(s)",
        "",
        "Regressions",
        str(len(regressions)),
        "",
        "Predictive Risk",
    ]
    if pred:
        cats = sorted(
            {
                str(p.get("category") or p.get("change_status") or "RISK")
                for p in pred[:5]
            }
        )
        lines.append(", ".join(cats) if cats else "none")
    else:
        lines.append("none")
    lines.extend(["", "Decision:", str(decision)])

    if str(diff.get("baseline")) == "BASELINE_UNAVAILABLE":
        lines.extend(
            [
                "",
                "BASELINE_SOURCE: BASELINE_UNAVAILABLE",
                "No comparison fabricated.",
            ]
        )
    else:
        base = diff.get("base") or {}
        lines.extend(
            [
                "",
                f"BASELINE_SOURCE: {diff.get('baseline') or base.get('source')}",
            ]
        )

    notes = diff.get("notes") or []
    if notes:
        lines.extend(["", "Notes:"] + [f"- {n}" for n in notes[:5]])

    return "\n".join(lines) + "\n"


def render_verbose(diff: dict[str, Any]) -> str:
    """Detailed human-readable dump of key deltas."""
    chunks = [render_text(diff), "", "--- VERBOSE ---", ""]

    def _section(title: str, items: list[Any]) -> None:
        chunks.append(title)
        if not items:
            chunks.append("  (none)")
        for it in items[:40]:
            if isinstance(it, dict):
                kind = it.get("kind") or it.get("category") or it.get("state") or it.get("title")
                detail = it.get("detail") or it.get("change") or it.get("reason") or ""
                chunks.append(f"  - {kind}: {detail}")
            else:
                chunks.append(f"  - {it}")
        chunks.append("")

    _section("Attack surface added", (diff.get("attack_surface_delta") or {}).get("added") or [])
    _section("Attack surface removed", (diff.get("attack_surface_delta") or {}).get("removed") or [])
    _section("Control changes", (diff.get("control_delta") or {}).get("changes") or [])
    _section("Authorization", (diff.get("authorization_delta") or {}).get("changes") or [])
    _section("Tenant isolation", (diff.get("tenant_isolation_delta") or {}).get("changes") or [])
    _section("Data flow added", (diff.get("data_flow_delta") or {}).get("added") or [])
    _section("New attack paths", (diff.get("attack_path_delta") or {}).get("new_paths") or [])
    _section("Regressions", diff.get("regressions") or [])
    _section("Predictive risks", diff.get("predictive_risks") or [])
    _section("Unknowns", diff.get("unknowns") or [])
    _section("Recommended actions", diff.get("recommended_actions") or [])
    return "\n".join(chunks) + "\n"


def to_json(diff: dict[str, Any]) -> str:
    return json.dumps(diff, indent=2, sort_keys=True) + "\n"


def render_html_section(diff: dict[str, Any]) -> str:
    """Fragment for embedding into AXGuard HTML reports."""
    impact = diff.get("security_impact") or {}
    level = html.escape(str(impact.get("level") or "UNKNOWN"))
    reason = html.escape(str(impact.get("reason") or ""))
    decision = html.escape(str(impact.get("decision") or ""))

    def _lis(items: list[Any], limit: int = 25) -> str:
        if not items:
            return "<li><em>none</em></li>"
        out = []
        for it in items[:limit]:
            if isinstance(it, dict):
                text = it.get("detail") or it.get("title") or it.get("kind") or json.dumps(it)[:200]
            else:
                text = str(it)
            out.append(f"<li>{html.escape(str(text))}</li>")
        return "\n".join(out)

    return f"""
<section class="axguard-security-diff">
  <h2>Security Diff</h2>
  <p><strong>Impact:</strong> {level} &mdash; {reason}</p>
  <p><strong>Decision:</strong> {decision}</p>
  <h3>Attack Surface Delta</h3>
  <ul>{_lis((diff.get("attack_surface_delta") or {}).get("added") or [])}</ul>
  <h3>Security Control Delta</h3>
  <ul>{_lis((diff.get("control_delta") or {}).get("changes") or [])}</ul>
  <h3>Authorization Delta</h3>
  <ul>{_lis((diff.get("authorization_delta") or {}).get("changes") or [])}</ul>
  <h3>Tenant Delta</h3>
  <ul>{_lis((diff.get("tenant_isolation_delta") or {}).get("changes") or [])}</ul>
  <h3>Data Flow Delta</h3>
  <ul>{_lis((diff.get("data_flow_delta") or {}).get("added") or [])}</ul>
  <h3>Attack Path Delta</h3>
  <ul>{_lis((diff.get("attack_path_delta") or {}).get("new_paths") or [])}</ul>
  <h3>Security Regressions</h3>
  <ul>{_lis(diff.get("regressions") or [])}</ul>
  <h3>Predictive Risk Delta</h3>
  <ul>{_lis(diff.get("predictive_risks") or [])}</ul>
  <h3>Recommended Actions</h3>
  <ul>{_lis(diff.get("recommended_actions") or [])}</ul>
</section>
"""


def write_security_diff_report(
    diff: dict[str, Any],
    out_dir: Path | str,
    *,
    stem: str = "security-diff",
) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out / f"{stem}.json",
        "md": out / f"{stem}.md",
        "html": out / f"{stem}.html",
        "txt": out / f"{stem}.txt",
    }
    paths["json"].write_text(to_json(diff), encoding="utf-8")
    paths["txt"].write_text(render_text(diff), encoding="utf-8")
    paths["md"].write_text(render_verbose(diff), encoding="utf-8")
    body = render_html_section(diff)
    paths["html"].write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>AXGuard Security Diff</title></head><body>"
        f"{body}</body></html>\n",
        encoding="utf-8",
    )
    return paths
