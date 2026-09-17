"""Fix verification — re-analyze and compare finding fingerprints.

Never mark RESOLVED solely because a path string changed.
"""

from __future__ import annotations

from typing import Any

from engines.mcp import engines_bridge as bridge
from engines.mcp.policy import enforce
from engines.mcp.schemas.errors import McpError
from engines.mcp.schemas.results import success_result, truncate_result
from engines.mcp.session import McpSession, get_session

_SEV_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "med": 3,
    "moderate": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "unknown": 0,
}


def _severity_rank(value: Any) -> int:
    return _SEV_RANK.get(str(value or "unknown").strip().lower(), 0)


def _fingerprint_of(finding: dict[str, Any]) -> str:
    explicit = finding.get("fingerprint") or finding.get("finding_fingerprint")
    if explicit:
        return str(explicit)
    try:
        from engines.memory.fingerprints import finding_fingerprint

        return finding_fingerprint(finding)
    except Exception:  # noqa: BLE001
        for key in ("id", "finding_id", "rule_id"):
            if finding.get(key):
                return str(finding[key])
        return ""


def _ids_of(finding: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for key in ("id", "finding_id", "rule_id", "fingerprint", "finding_fingerprint"):
        v = finding.get(key)
        if v:
            out.add(str(v))
    return out


def _match_finding(
    findings: list[dict[str, Any]],
    *,
    finding_id: str | None,
    fingerprint: str | None,
) -> dict[str, Any] | None:
    fp_target = (fingerprint or "").strip()
    id_target = (finding_id or "").strip()
    for f in findings:
        if not isinstance(f, dict):
            continue
        fp = _fingerprint_of(f)
        if fp_target and fp == fp_target:
            return f
        ids = _ids_of(f)
        if id_target and (id_target in ids or any(id_target in x for x in ids)):
            return f
        if fp_target and fp_target in ids:
            return f
    return None


def _compare(
    before: dict[str, Any],
    after: dict[str, Any] | None,
) -> str:
    if after is None:
        return "RESOLVED"
    if _severity_rank(after.get("severity")) > _severity_rank(before.get("severity")):
        return "REGRESSED"
    return "STILL_PRESENT"


def run_verify_fix(
    *,
    finding_id: str | None = None,
    fingerprint: str | None = None,
    path: str | None = None,
    approved: bool = False,
    session: McpSession | None = None,
) -> dict[str, Any]:
    """Re-scan and classify fix status for a previously observed finding."""
    sess = session or get_session()
    sess.begin_tool()
    enforce("axguard_verify_fix", approved=approved)

    if not finding_id and not fingerprint:
        raise McpError(
            "INVALID_INPUT",
            "finding_id or fingerprint is required for fix verification.",
        )

    prior = _match_finding(
        list(sess.last_findings or []),
        finding_id=finding_id,
        fingerprint=fingerprint,
    )
    if prior is None and sess.last_review:
        review_findings = list(sess.last_review.get("verified_findings") or [])
        prior = _match_finding(
            review_findings,
            finding_id=finding_id,
            fingerprint=fingerprint,
        )

    if prior is None:
        raise McpError(
            "INSUFFICIENT_EVIDENCE",
            "No prior finding in session cache to verify against. "
            "Run axguard_security_review or axguard_list_findings first.",
            details={
                "finding_id": finding_id,
                "fingerprint": fingerprint,
                "hint": "Do not mark RESOLVED from a file edit alone.",
            },
        )

    prior_fp = fingerprint or _fingerprint_of(prior)
    target = bridge.require_path(sess, path)
    scan_root = target if target.is_dir() else sess.project_root
    result = bridge.run_scan_engine(sess, scan_root)
    after_findings = list(result.get("findings") or [])
    # Keep session findings current after re-analysis
    sess.last_findings = after_findings

    matched = _match_finding(
        after_findings,
        finding_id=finding_id or str(prior.get("id") or prior.get("finding_id") or ""),
        fingerprint=prior_fp,
    )
    # If id lookup fails but fingerprint matches any row, use that
    if matched is None and prior_fp:
        for f in after_findings:
            if isinstance(f, dict) and _fingerprint_of(f) == prior_fp:
                matched = f
                break

    status = _compare(prior, matched)
    payload = {
        "status": status,
        "verification_status": status,
        "finding_id": finding_id or prior.get("id") or prior.get("finding_id"),
        "fingerprint": prior_fp,
        "before": {
            "severity": prior.get("severity"),
            "title": prior.get("title") or prior.get("message"),
            "file": prior.get("file") or (prior.get("location") or {}).get("file")
            if isinstance(prior.get("location"), dict)
            else prior.get("file"),
        },
        "after": None
        if matched is None
        else {
            "severity": matched.get("severity"),
            "title": matched.get("title") or matched.get("message"),
            "file": matched.get("file")
            or (
                (matched.get("location") or {}).get("file")
                if isinstance(matched.get("location"), dict)
                else matched.get("file")
            ),
            "fingerprint": _fingerprint_of(matched),
        },
        "recommended_action": {
            "RESOLVED": "Finding no longer present after re-analysis. Confirm with review if high-impact.",
            "STILL_PRESENT": "Issue remains after re-scan. Continue remediation; do not mark closed.",
            "REGRESSED": "Severity worsened or issue intensified. Stop and re-investigate.",
        }.get(status, "Re-run axguard_security_review."),
        "note": "Never mark resolved solely because a file path changed.",
    }
    trimmed = truncate_result(
        payload,
        max_bytes=sess.limits.max_output_bytes,
        max_list=sess.limits.max_list_items,
    )
    return success_result(
        trimmed if isinstance(trimmed, dict) else {"data": trimmed},
        state="OBSERVED",
        confidence="HIGH" if status == "RESOLVED" else "MEDIUM",
    )
