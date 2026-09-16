"""Pre-Ship report writers — JSON / Markdown / self-contained HTML."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def write_preship_reports(result: dict[str, Any], out_dir: Path) -> dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    jpath = out_dir / "preship-report.json"
    jpath.write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    paths["json"] = str(jpath)

    md = render_preship_markdown(result)
    mpath = out_dir / "preship-report.md"
    mpath.write_text(md, encoding="utf-8")
    paths["md"] = str(mpath)

    hpath = out_dir / "preship-report.html"
    hpath.write_text(render_preship_html(result), encoding="utf-8")
    paths["html"] = str(hpath)
    return paths


def render_preship_markdown(result: dict[str, Any]) -> str:
    decision = result.get("decision") or "PASS"
    lines = [
        "# AXGuard Pre-Ship Report",
        "",
        f"**Decision:** {decision}",
        "",
    ]
    if result.get("blocking_reason"):
        lines += [f"**Blocking reason:** {result['blocking_reason']}", ""]

    lines += ["## Executive Summary", ""]
    findings = result.get("findings") or []
    verified = [
        f
        for f in findings
        if str(f.get("status") or "").upper() in {"VERIFIED", "CONFIRMED"}
    ]
    lines.append(f"- Findings: {len(findings)} (verified: {len(verified)})")
    sd = result.get("security_diff") or {}
    lines.append(
        f"- Security diff overall: {sd.get('overall_security_change') or 'n/a'} "
        f"(baseline: {sd.get('baseline') or 'UNKNOWN'})"
    )
    lines.append(f"- Predictive risks: {len(result.get('predictive_risks') or [])}")
    lines.append(f"- Regressions: {len(result.get('regressions') or [])}")
    lines.append("")

    lines += ["## Security Diff", ""]
    try:
        from engines.security_diff import render_security_diff_text

        lines.append("```")
        lines.append(render_security_diff_text(sd).rstrip())
        lines.append("```")
        lines.append("")
    except Exception:  # noqa: BLE001
        lines.append("_unavailable_")
        lines.append("")

    lines += ["## Verified Findings", ""]
    if not verified:
        lines.append("_None_")
    else:
        for f in verified[:20]:
            lines.append(
                f"- **{f.get('severity', '?').upper()}** "
                f"{f.get('title') or f.get('id')} "
                f"(`{f.get('file')}:{f.get('line')}`)"
            )
    lines.append("")

    lines += ["## Attack Paths", ""]
    ap = result.get("attack_paths") or []
    if not ap:
        lines.append("_None listed_")
    else:
        for p in ap[:15]:
            lines.append(
                f"- `{p.get('id')}` status={p.get('status')} "
                f"entry={p.get('entry')} → {p.get('target')}"
            )
    lines.append("")

    lines += ["## Security Regressions", ""]
    regs = result.get("regressions") or []
    lines.append("_None_" if not regs else "\n".join(f"- {r}" for r in regs))
    lines.append("")

    lines += ["## Security Controls", ""]
    for c in (result.get("controls") or [])[:20]:
        lines.append(f"- {c.get('state')}: {c.get('id')} ({c.get('kind')})")
    if not result.get("controls"):
        lines.append("_No control deltas_")
    lines.append("")

    lines += ["## Predictive Risks", ""]
    for r in result.get("predictive_risks") or []:
        if isinstance(r, dict):
            lines.append(f"- `{r.get('label')}`: {r.get('detail')}")
        else:
            lines.append(f"- {r}")
    if not result.get("predictive_risks"):
        lines.append("_None_")
    lines.append("")

    lines += ["## Unknowns", ""]
    unk = result.get("unknowns") or []
    lines.append("_None_" if not unk else "\n".join(f"- {u}" for u in unk))
    lines.append("")

    rw = result.get("review_why")
    if rw:
        lines += ["## Why review is needed", ""]
        for k, label in (
            ("why_review_needed", "Why"),
            ("what_is_unknown", "Unknown"),
            ("evidence_present", "Evidence present"),
            ("evidence_missing", "Evidence missing"),
            ("what_could_change_verdict", "Could change verdict"),
        ):
            lines.append(f"### {label}")
            items = rw.get(k) or []
            lines.append("_None_" if not items else "\n".join(f"- {i}" for i in items))
            lines.append("")

    lines += [
        "## Remediation",
        "",
        "Run `axguard fix` / skill `axguard-remediate`, then `axguard verify`.",
        "",
        "## Coverage",
        "",
        json.dumps(result.get("coverage") or {}, indent=2),
        "",
    ]
    return "\n".join(lines)


def render_preship_html(result: dict[str, Any]) -> str:
    """Self-contained HTML with required sections (abbreviated). Reuses report_ux CSS when possible."""
    decision = html.escape(str(result.get("decision") or "PASS"))
    css = _preship_css()
    # Optional: reuse any shared report stylesheet helpers if present
    try:
        import engines.report_ux as report_ux

        for name in ("report_css", "base_css", "CSS"):
            extra = getattr(report_ux, name, None)
            if callable(extra):
                val = extra()
                if isinstance(val, str) and val:
                    css = val + "\n" + css
                    break
            elif isinstance(extra, str) and extra:
                css = extra + "\n" + css
                break
    except Exception:  # noqa: BLE001
        pass

    def section(title: str, body: str) -> str:
        return f"<section><h2>{html.escape(title)}</h2>{body}</section>"

    md_body = html.escape(render_preship_markdown(result))
    # Build structured abbreviated sections
    findings_html = "<ul>" + "".join(
        f"<li><strong>{html.escape(str(f.get('severity') or ''))}</strong> "
        f"{html.escape(str(f.get('title') or f.get('id') or ''))}</li>"
        for f in (result.get("findings") or [])[:30]
    ) + ("</ul>" if result.get("findings") else "<p><em>None</em></p>")

    sd = result.get("security_diff") or {}
    try:
        from engines.security_diff import render_security_diff_text

        sd_text = html.escape(render_security_diff_text(sd))
    except Exception:  # noqa: BLE001
        sd_text = html.escape(json.dumps(sd.get("summary") or {}, indent=2))

    rw = result.get("review_why") or {}
    review_html = ""
    if rw:
        review_html = section(
            "Human Review",
            "<pre>" + html.escape(json.dumps(rw, indent=2)) + "</pre>",
        )

    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>",
        f"<title>AXGuard Pre-Ship — {decision}</title>",
        f"<style>{css}</style></head><body>",
        "<header class='ax-preship-header'>",
        "<p class='brand'>AXGuard Pre-Ship</p>",
        f"<p class='decision decision-{decision.lower()}'>Decision: {decision}</p>",
        "</header>",
        section("Executive Summary", f"<p>Target: {html.escape(str(result.get('target') or ''))}</p>"
                f"<p>Mode: {html.escape(str(result.get('mode') or ''))}</p>"
                f"<p>Blocking: {html.escape(str(result.get('blocking_reason') or '—'))}</p>"),
        section("Decision", f"<p class='decision'>{decision}</p>"),
        section("Security Diff", f"<pre>{sd_text}</pre>"),
        section("Verified Findings", findings_html),
        section(
            "Attack Paths",
            "<pre>" + html.escape(json.dumps(result.get("attack_paths") or [], indent=2)[:4000]) + "</pre>",
        ),
        section(
            "Security Regressions",
            "<ul>" + "".join(f"<li>{html.escape(str(r))}</li>" for r in (result.get("regressions") or [])) + "</ul>"
            if result.get("regressions")
            else "<p><em>None</em></p>",
        ),
        section(
            "Security Controls",
            "<pre>" + html.escape(json.dumps(result.get("controls") or [], indent=2)[:4000]) + "</pre>",
        ),
        section(
            "Predictive Risks",
            "<pre>" + html.escape(json.dumps(result.get("predictive_risks") or [], indent=2)) + "</pre>",
        ),
        section(
            "Unknowns",
            "<ul>" + "".join(f"<li>{html.escape(str(u))}</li>" for u in (result.get("unknowns") or [])) + "</ul>"
            if result.get("unknowns")
            else "<p><em>None</em></p>",
        ),
        review_html,
        section("Evidence", "<p>See JSON report for evidence payloads (redacted upstream).</p>"),
        section("Remediation", "<p>Fix verified issues, then run <code>axguard verify</code>.</p>"),
        section("Fix Verification", "<p>Re-run <code>axguard preship</code> after patches.</p>"),
        section(
            "Coverage",
            "<pre>" + html.escape(json.dumps(result.get("coverage") or {}, indent=2)) + "</pre>",
        ),
        "<details><summary>Full markdown</summary><pre>" + md_body + "</pre></details>",
        "</body></html>",
    ]
    return "\n".join(parts)


def _preship_css() -> str:
    return """
:root { --bg:#0f1419; --fg:#e7ecf1; --mut:#9aa7b5; --fail:#e85d5d; --pass:#3ecf8e; --rev:#e6b84d; }
body { font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--fg);
  margin:0; padding:2rem; line-height:1.45; max-width:960px; }
.brand { font-size:1.4rem; letter-spacing:.04em; margin:0; }
.decision { font-size:1.2rem; font-weight:600; }
.decision-fail, .decision-FAIL { color:var(--fail); }
.decision-pass, .decision-PASS, .decision-pass_with_notes { color:var(--pass); }
.decision-review_required { color:var(--rev); }
section { margin:1.5rem 0; padding-top:.5rem; border-top:1px solid #243041; }
h2 { font-size:1.05rem; color:var(--mut); text-transform:uppercase; letter-spacing:.06em; }
pre { background:#1a2330; padding:1rem; overflow:auto; border-radius:6px; font-size:.85rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
"""


def render_preship_cli_text(result: dict[str, Any]) -> str:
    """Compact terminal output matching the product example."""
    lines = [
        "AXGUARD PRE-SHIP",
        "",
        f"Decision: {result.get('decision')}",
        "",
    ]
    findings = result.get("findings") or []
    by_sev: dict[str, int] = {}
    for f in findings:
        st = str(f.get("status") or "").upper()
        if st not in {"VERIFIED", "CONFIRMED"}:
            continue
        sev = str(f.get("severity") or "info").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    if by_sev:
        lines.append("Verified:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if by_sev.get(sev):
                lines.append(f"{by_sev[sev]} {sev}")
        lines.append("")

    sd = result.get("security_diff") or {}
    summary = sd.get("summary") or {}
    lines.append("Security changes:")
    if int(summary.get("new_endpoints") or 0):
        lines.append(f"+ {summary['new_endpoints']} endpoints")
    if int(summary.get("new_external_requests") or 0):
        lines.append(f"+ {summary['new_external_requests']} external integration")
    if int(summary.get("removed_controls") or 0):
        lines.append(f"- {summary['removed_controls']} authorization control")
    if not any(int(summary.get(k) or 0) for k in ("new_endpoints", "new_external_requests", "removed_controls")):
        lines.append("(none significant)")
    lines.append("")
    lines.append("New attack paths:")
    lines.append(str(int(summary.get("new_attack_paths") or 0)))
    lines.append("")
    lines.append("Predictive risks:")
    lines.append(str(len(result.get("predictive_risks") or [])))
    lines.append("")
    if result.get("blocking_reason"):
        lines.append("Blocking reason:")
        lines.append(str(result["blocking_reason"]))
        lines.append("")
    rw = result.get("review_why")
    if rw and result.get("decision") == "REVIEW_REQUIRED":
        lines.append("Why review is needed:")
        for item in (rw.get("why_review_needed") or [])[:5]:
            lines.append(f"- {item}")
        lines.append("")
    lines += [
        "Run:",
        "axguard report",
        "axguard fix",
        "axguard verify",
        "",
    ]
    return "\n".join(lines)
