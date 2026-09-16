"""Risk aggregation and security impact classification."""

from __future__ import annotations

from typing import Any

from engines.security_diff.schema import (
    CONTROL_MOVED,
    CONTROL_REMOVED,
    CONTROL_WEAKENED,
    DECISION_FAIL,
    DECISION_PASS,
    DECISION_REVIEW_REQUIRED,
    DECISION_UNKNOWN,
    IMPACT_CRITICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    IMPACT_NONE,
    IMPACT_UNKNOWN,
    BASELINE_UNAVAILABLE,
)

_RANK = {
    IMPACT_NONE: 0,
    IMPACT_LOW: 1,
    IMPACT_MEDIUM: 2,
    IMPACT_HIGH: 3,
    IMPACT_CRITICAL: 4,
    IMPACT_UNKNOWN: 1,
}


def _max_impact(*levels: str) -> str:
    best = IMPACT_NONE
    for level in levels:
        if _RANK.get(str(level), 0) > _RANK.get(best, 0):
            best = str(level)
    return best


def classify_impact(diff: dict[str, Any]) -> dict[str, Any]:
    """Derive overall security_impact + decision from populated deltas."""
    if str(diff.get("baseline")) in {BASELINE_UNAVAILABLE, "UNKNOWN", "BASELINE_UNAVAILABLE"}:
        return {
            "level": IMPACT_UNKNOWN,
            "reason": "No valid baseline available; comparison was not fabricated.",
            "decision": DECISION_UNKNOWN,
        }

    reasons: list[str] = []
    level = IMPACT_NONE

    control_changes = (diff.get("control_delta") or {}).get("changes") or diff.get(
        "control_changes"
    ) or []
    removed = [c for c in control_changes if c.get("state") == CONTROL_REMOVED]
    weakened = [c for c in control_changes if c.get("state") == CONTROL_WEAKENED]
    moved = [c for c in control_changes if c.get("state") == CONTROL_MOVED]

    tenant = (diff.get("tenant_isolation_delta") or {}).get("changes") or diff.get(
        "tenant_changes"
    ) or []
    authz = (diff.get("authorization_delta") or {}).get("changes") or diff.get(
        "authz_changes"
    ) or []
    path_delta = diff.get("attack_path_delta") or {}
    new_paths = path_delta.get("new_paths") or []
    reopened = path_delta.get("reopened_paths") or []
    weakened_paths = path_delta.get("weakened_paths") or []
    regressions = diff.get("regressions") or []
    priv = (diff.get("privilege_delta") or {}).get("changes") or []
    surface_added = (diff.get("attack_surface_delta") or {}).get("added") or []
    sensitive = (diff.get("data_flow_delta") or {}).get("added") or []
    mcp = (diff.get("mcp_delta") or {}).get("changes") or []
    ai = (diff.get("ai_delta") or {}).get("changes") or []

    if tenant:
        level = _max_impact(level, IMPACT_CRITICAL)
        reasons.append("Tenant isolation boundary changed.")
    if removed:
        high_types = {
            c.get("control_type")
            for c in removed
            if c.get("control_type")
            in {"authorization", "tenant_isolation", "authentication"}
        }
        if high_types:
            level = _max_impact(level, IMPACT_HIGH)
            reasons.append(
                f"Security control removed ({', '.join(sorted(high_types))})."
            )
        else:
            level = _max_impact(level, IMPACT_MEDIUM)
            reasons.append("Security control(s) removed.")
    if weakened:
        level = _max_impact(level, IMPACT_HIGH)
        reasons.append("Security control(s) weakened.")
    if authz:
        level = _max_impact(level, IMPACT_HIGH)
        reasons.append("Authorization posture changed.")
    if new_paths or reopened or weakened_paths:
        level = _max_impact(level, IMPACT_HIGH)
        reasons.append(
            f"Attack path delta: +{len(new_paths)} new, "
            f"{len(reopened)} reopened, {len(weakened_paths)} weakened."
        )
    if regressions:
        level = _max_impact(level, IMPACT_HIGH)
        reasons.append(f"{len(regressions)} security regression(s).")
    if priv:
        level = _max_impact(level, IMPACT_HIGH if len(priv) else IMPACT_MEDIUM)
        reasons.append("Privilege expansion detected.")
    if any(
        str(c.get("kind") or c.get("category") or "").endswith("PRIVILEGE_EXPANSION")
        or "PRIVILEGE" in str(c.get("kind") or "")
        for c in list(mcp) + list(ai) + list(priv)
    ):
        level = _max_impact(level, IMPACT_HIGH)
        reasons.append("AI/MCP privilege expansion.")
    if sensitive:
        level = _max_impact(level, IMPACT_MEDIUM)
        reasons.append("Sensitive data-flow changes.")
    if surface_added and level == IMPACT_NONE:
        level = IMPACT_LOW
        reasons.append("Attack surface expanded.")
    if moved and level == IMPACT_NONE:
        reasons.append("Controls moved but security meaning unchanged.")

    if not reasons:
        reasons.append(
            "No meaningful security controls, attack paths, privileges, "
            "or sensitive flows changed."
        )

    decision = DECISION_PASS
    if level in {IMPACT_HIGH, IMPACT_CRITICAL}:
        decision = DECISION_REVIEW_REQUIRED
    elif level == IMPACT_MEDIUM:
        decision = DECISION_REVIEW_REQUIRED
    elif level == IMPACT_UNKNOWN:
        decision = DECISION_UNKNOWN

    # CI fail-on uses level; decision FAIL reserved for explicit policy
    fail_on = str((diff.get("options") or {}).get("fail_on") or "none").lower()
    if fail_on != "none" and _RANK.get(level, 0) >= _RANK.get(fail_on.upper(), 99):
        decision = DECISION_FAIL

    return {
        "level": level,
        "reason": " ".join(reasons),
        "decision": decision,
    }


def should_fail(diff: dict[str, Any], fail_on: str) -> bool:
    if not fail_on or fail_on == "none":
        return False
    level = str((diff.get("security_impact") or {}).get("level") or IMPACT_NONE)
    return _RANK.get(level, 0) >= _RANK.get(fail_on.upper(), 99)
