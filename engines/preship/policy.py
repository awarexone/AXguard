"""Pre-Ship blocking policy + FindingView adaptation for map_policy_verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engines.preship.schema import (
    DECISION_FAIL,
    DECISION_PASS,
    DECISION_PASS_WITH_NOTES,
    DECISION_REVIEW_REQUIRED,
)

DEFAULT_POLICY_YAML = """\
preship:
  blocking:
    verified_critical: true
    verified_high: true
    verified_medium: false
    likely: false
    unverified: false
    predictive_risk: false
  unknowns:
    fail: false
    review_required: true
"""


@dataclass
class PreshipBlocking:
    verified_critical: bool = True
    verified_high: bool = True
    verified_medium: bool = False
    likely: bool = False
    unverified: bool = False
    predictive_risk: bool = False


@dataclass
class PreshipUnknowns:
    fail: bool = False
    review_required: bool = True


@dataclass
class PreshipPolicy:
    blocking: PreshipBlocking = field(default_factory=PreshipBlocking)
    unknowns: PreshipUnknowns = field(default_factory=PreshipUnknowns)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


def default_policy() -> PreshipPolicy:
    return PreshipPolicy()


def load_preship_policy(path: Path | None = None) -> PreshipPolicy:
    """Load policy from .axguard.yml ``preship`` section or defaults."""
    policy = default_policy()
    candidates: list[Path] = []
    if path is not None:
        candidates.append(path)
    else:
        cwd = Path.cwd()
        for name in (".axguard.yml", ".axguard.yaml", ".axguard.json"):
            candidates.append(cwd / name)

    data: dict[str, Any] | None = None
    for cand in candidates:
        if not cand.exists():
            continue
        try:
            if cand.suffix == ".json":
                import json

                data = json.loads(cand.read_text(encoding="utf-8"))
            else:
                from engines.github.config import _simple_yaml_load

                data = _simple_yaml_load(cand.read_text(encoding="utf-8"))
            break
        except Exception:  # noqa: BLE001
            continue

    if not data:
        return policy

    section = data.get("preship") if isinstance(data, dict) else None
    if not isinstance(section, dict):
        return policy

    blocking = section.get("blocking") or {}
    unknowns = section.get("unknowns") or {}
    if isinstance(blocking, dict):
        policy.blocking = PreshipBlocking(
            verified_critical=bool(blocking.get("verified_critical", True)),
            verified_high=bool(blocking.get("verified_high", True)),
            verified_medium=bool(blocking.get("verified_medium", False)),
            likely=bool(blocking.get("likely", False)),
            unverified=bool(blocking.get("unverified", False)),
            predictive_risk=bool(blocking.get("predictive_risk", False)),
        )
    if isinstance(unknowns, dict):
        policy.unknowns = PreshipUnknowns(
            fail=bool(unknowns.get("fail", False)),
            review_required=bool(unknowns.get("review_required", True)),
        )
    policy.raw = section
    return policy


def _unused_legacy_yaml_fallback(text: str) -> dict[str, Any]:
    """Kept as last-resort if github config import fails during load."""
    out: dict[str, Any] = {"preship": {"blocking": {}, "unknowns": {}}}
    section = None
    subsection = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, _, val = line.strip().partition(":")
        key = key.strip()
        val = val.strip()
        if indent == 0 and key == "preship":
            section = "preship"
            subsection = None
            continue
        if section != "preship":
            continue
        if indent == 2 and key in {"blocking", "unknowns"} and not val:
            subsection = key
            continue
        if subsection and indent >= 4 and val:
            low = val.lower()
            if low in {"true", "yes"}:
                parsed: Any = True
            elif low in {"false", "no"}:
                parsed = False
            else:
                parsed = val
            out["preship"][subsection][key] = parsed
    return out


# alias for tests / callers that expected the old name
_parse_simple_yaml_preship = _unused_legacy_yaml_fallback


def findings_to_views(findings: list[dict[str, Any]]) -> list[Any]:
    """Convert audit/adversary finding dicts → FindingView for map_policy_verdict."""
    from engines.github.models import FindingView

    views: list[Any] = []
    for raw in findings or []:
        if not isinstance(raw, dict):
            continue
        loc = raw.get("location") if isinstance(raw.get("location"), dict) else {}
        file_ = loc.get("file") or raw.get("file")
        line = loc.get("line") or raw.get("line")
        status = str(
            raw.get("status")
            or raw.get("final_status")
            or raw.get("adversary_status")
            or raw.get("verification_status")
            or "UNVERIFIED"
        ).upper()
        # Map common aliases
        if status in {"CONFIRMED", "TRUE_POSITIVE", "TP"}:
            status = "VERIFIED"
        sev = str(raw.get("severity") or "medium").lower()
        title = str(raw.get("title") or raw.get("summary") or raw.get("id") or "finding")
        fid = str(raw.get("id") or raw.get("finding_id") or title)
        views.append(
            FindingView(
                finding_id=fid,
                title=title,
                severity=sev,
                status=status,
                confidence=str(raw.get("confidence") or "UNKNOWN"),
                file=str(file_) if file_ else None,
                line=int(line) if line else None,
                message=str(raw.get("message") or "")[:800],
                evidence=str(raw.get("evidence") or "")[:800]
                if not isinstance(raw.get("evidence"), list)
                else "",
                raw=raw,
            )
        )
    return views


def policy_to_github_config(policy: PreshipPolicy):
    """Adapt PreshipPolicy → GitHub PolicyConfig for map_policy_verdict."""
    from engines.github.config import PolicyConfig

    fail_on: list[str] = []
    if policy.blocking.verified_critical:
        fail_on.append("critical")
    if policy.blocking.verified_high:
        fail_on.append("high")
    return PolicyConfig(
        fail_on=fail_on,
        review_on=["likely"] if not policy.blocking.likely else ["likely"],
        fail_on_analysis_error=False,
        fail_on_unverified=policy.blocking.unverified,
        medium_fail=policy.blocking.verified_medium,
    )


def map_preship_verdict(
    findings: list[dict[str, Any]],
    policy: PreshipPolicy | None = None,
    *,
    regressions: list[str] | None = None,
    unknowns: list[str] | None = None,
    security_diff: dict[str, Any] | None = None,
    predictive_risks: list[Any] | None = None,
    analysis_failed: bool = False,
) -> str:
    """Map findings + diff/regressions → PASS | PASS_WITH_NOTES | REVIEW_REQUIRED | FAIL.

    Never FAIL solely on unverified suspicion. Prefer wrapping map_policy_verdict.
    """
    pol = policy or default_policy()

    # Convert + call shared map_policy_verdict
    try:
        from engines.github.models import PolicyVerdict
        from engines.github.policy import map_policy_verdict

        views = findings_to_views(findings)
        gh_cfg = policy_to_github_config(pol)
        # Regressions of verified issues
        verdict = map_policy_verdict(
            views,
            gh_cfg,
            analysis_failed=analysis_failed,
            regressions=regressions if regressions else None,
        )
        decision = verdict.value if isinstance(verdict, PolicyVerdict) else str(verdict)
    except Exception:  # noqa: BLE001 — thin local fallback
        decision = _local_verdict(findings, pol, regressions=regressions)

    # Likely findings → REVIEW when blocking.likely is false (map_policy already does)
    # but when likely=true and we want FAIL:
    if pol.blocking.likely:
        for f in findings:
            st = str(f.get("status") or "").upper()
            if st == "LIKELY":
                decision = DECISION_FAIL
                break

    # Security diff HIGH/CRITICAL control removals → at least REVIEW_REQUIRED
    if security_diff:
        overall = str(security_diff.get("overall_security_change") or "").upper()
        removed = int((security_diff.get("summary") or {}).get("removed_controls") or 0)
        weakened = int((security_diff.get("summary") or {}).get("weakened_controls") or 0)
        authz = security_diff.get("authz_changes") or []
        tenant = security_diff.get("tenant_changes") or []
        harmful_authz = any(
            any(
                x in str(c.get("impact") or c.get("change") or "").lower()
                for x in ("removed", "weakened", "broadened", "privilege")
            )
            for c in authz + tenant
        )
        if overall in {"HIGH", "CRITICAL"} or removed or weakened or harmful_authz:
            if decision == DECISION_PASS:
                decision = DECISION_REVIEW_REQUIRED
            elif decision == DECISION_PASS_WITH_NOTES:
                decision = DECISION_REVIEW_REQUIRED
            # Control removal with verified finding already FAIL stays FAIL
            ctrl_removed = any(
                c.get("state") == "REMOVED"
                and str(c.get("kind") or "") in {"authorization", "tenant", "authentication"}
                for c in (security_diff.get("control_changes") or [])
            )
            if ctrl_removed and overall == "CRITICAL" and pol.blocking.verified_high:
                # Still do not FAIL without verified finding — REVIEW is enough
                # unless regressions present
                if regressions:
                    decision = DECISION_FAIL

    # Memory regressions
    if regressions:
        if decision in {DECISION_PASS, DECISION_PASS_WITH_NOTES}:
            decision = DECISION_FAIL if pol.blocking.verified_high else DECISION_REVIEW_REQUIRED

    # Unknowns policy
    if unknowns:
        if pol.unknowns.fail:
            decision = DECISION_FAIL
        elif pol.unknowns.review_required and decision in {
            DECISION_PASS,
            DECISION_PASS_WITH_NOTES,
        }:
            decision = DECISION_REVIEW_REQUIRED

    # Predictive risks — soft unless policy says otherwise
    if predictive_risks:
        if pol.blocking.predictive_risk:
            decision = DECISION_FAIL
        elif decision == DECISION_PASS:
            decision = DECISION_PASS_WITH_NOTES

    return decision


def _local_verdict(
    findings: list[dict[str, Any]],
    policy: PreshipPolicy,
    *,
    regressions: list[str] | None = None,
) -> str:
    """Fallback when github.policy is unavailable."""
    verified = {"VERIFIED", "CONFIRMED"}
    open_f = [
        f
        for f in findings
        if str(f.get("status") or "").upper() not in {"FALSE_POSITIVE", "FP"}
    ]
    for f in open_f:
        st = str(f.get("status") or "").upper()
        sev = str(f.get("severity") or "").lower()
        if st in verified:
            if sev == "critical" and policy.blocking.verified_critical:
                return DECISION_FAIL
            if sev == "high" and policy.blocking.verified_high:
                return DECISION_FAIL
            if sev == "medium" and policy.blocking.verified_medium:
                return DECISION_FAIL
    if regressions:
        return DECISION_FAIL if policy.blocking.verified_high else DECISION_REVIEW_REQUIRED
    for f in open_f:
        st = str(f.get("status") or "").upper()
        if st in {"LIKELY", "REQUIRES_REVIEW"}:
            return DECISION_REVIEW_REQUIRED
    if any(str(f.get("status") or "").upper() in {"UNVERIFIED", "UNKNOWN", "CANDIDATE"} for f in open_f):
        if policy.blocking.unverified:
            return DECISION_FAIL
        return DECISION_PASS_WITH_NOTES
    if any(str(f.get("status") or "").upper() in verified for f in open_f):
        return DECISION_PASS_WITH_NOTES
    return DECISION_PASS
