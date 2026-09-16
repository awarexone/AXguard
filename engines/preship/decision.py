"""Final decision packaging — blocking_reason + review_why."""

from __future__ import annotations

from typing import Any

from engines.preship.policy import PreshipPolicy, default_policy, map_preship_verdict
from engines.preship.schema import (
    DECISION_FAIL,
    DECISION_PASS,
    DECISION_PASS_WITH_NOTES,
    DECISION_REVIEW_REQUIRED,
    exit_code_for,
)


def decide(
    *,
    findings: list[dict[str, Any]] | None = None,
    security_diff: dict[str, Any] | None = None,
    regressions: list[str] | None = None,
    unknowns: list[str] | None = None,
    predictive_risks: list[Any] | None = None,
    policy: PreshipPolicy | None = None,
    analysis_failed: bool = False,
) -> dict[str, Any]:
    """Produce decision, blocking_reason, review_why, exit_code."""
    pol = policy or default_policy()
    findings = findings or []
    regressions = regressions or []
    unknowns = list(unknowns or [])
    predictive_risks = predictive_risks or []
    security_diff = security_diff or {}

    decision = map_preship_verdict(
        findings,
        pol,
        regressions=regressions,
        unknowns=unknowns,
        security_diff=security_diff,
        predictive_risks=predictive_risks,
        analysis_failed=analysis_failed,
    )

    blocking_reason = _blocking_reason(decision, findings, regressions, security_diff)
    review_why = None
    if decision == DECISION_REVIEW_REQUIRED:
        review_why = _review_why(
            findings=findings,
            unknowns=unknowns,
            security_diff=security_diff,
            regressions=regressions,
            predictive_risks=predictive_risks,
        )

    return {
        "decision": decision,
        "blocking_reason": blocking_reason,
        "review_why": review_why,
        "exit_code": exit_code_for(decision, tool_error=False),
    }


def _blocking_reason(
    decision: str,
    findings: list[dict[str, Any]],
    regressions: list[str],
    security_diff: dict[str, Any],
) -> str | None:
    if decision != DECISION_FAIL:
        return None
    verified = {"VERIFIED", "CONFIRMED"}
    for f in findings:
        st = str(f.get("status") or "").upper()
        sev = str(f.get("severity") or "").upper()
        if st in verified and sev in {"CRITICAL", "HIGH"}:
            title = f.get("title") or f.get("id") or "finding"
            return f"{sev} {title}"
    if regressions:
        return f"security regression: {regressions[0]}"
    overall = security_diff.get("overall_security_change")
    if overall:
        return f"blocking security change ({overall})"
    return "policy blocking condition met"


def _review_why(
    *,
    findings: list[dict[str, Any]],
    unknowns: list[str],
    security_diff: dict[str, Any],
    regressions: list[str],
    predictive_risks: list[Any],
) -> dict[str, Any]:
    why_needed: list[str] = []
    evidence_present: list[str] = []
    evidence_missing: list[str] = []
    could_change: list[str] = []

    for f in findings:
        st = str(f.get("status") or "").upper()
        if st in {"LIKELY", "REQUIRES_REVIEW", "UNVERIFIED", "UNKNOWN"}:
            why_needed.append(
                f"{st}: {f.get('title') or f.get('id')} "
                f"({f.get('severity') or 'unknown'} severity)"
            )
            if f.get("evidence") or f.get("file"):
                evidence_present.append(
                    f"{f.get('file') or 'unknown'}:{f.get('line') or '?'}"
                )
            else:
                evidence_missing.append(str(f.get("id") or f.get("title")))
            could_change.append("verify finding → CONFIRM or FALSE_POSITIVE")

    if unknowns:
        why_needed.extend(unknowns)
        evidence_missing.extend(unknowns)
        could_change.append("establish missing control/tenant evidence")

    overall = str(security_diff.get("overall_security_change") or "")
    if overall in {"HIGH", "CRITICAL"}:
        why_needed.append(f"security diff overall change: {overall}")
        could_change.append("restore removed controls or re-verify paths")

    for ch in security_diff.get("authz_changes") or []:
        why_needed.append(f"authz: {ch.get('change')}")
    for ch in security_diff.get("tenant_changes") or []:
        why_needed.append(f"tenant: {ch.get('change')}")

    if regressions:
        why_needed.append(f"regressions: {', '.join(regressions[:5])}")

    if predictive_risks:
        why_needed.append(f"{len(predictive_risks)} predictive risk(s) (non-blocking)")

    if security_diff.get("baseline") == "UNKNOWN":
        why_needed.append("baseline UNKNOWN — cannot fully assess regressions")
        evidence_missing.append("prior attack-paths / security twin snapshot")
        could_change.append("provide --base path or git history with prior artifacts")

    return {
        "why_review_needed": why_needed,
        "what_is_unknown": unknowns
        or [w for w in why_needed if "unknown" in w.lower() or "UNKNOWN" in w],
        "evidence_present": evidence_present,
        "evidence_missing": evidence_missing,
        "what_could_change_verdict": could_change,
    }
