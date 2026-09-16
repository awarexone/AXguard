"""Security control comparison with refactor / MOVED awareness."""

from __future__ import annotations

import re
from typing import Any

from engines.security_diff.schema import (
    CONTROL_ADDED,
    CONTROL_MOVED,
    CONTROL_REMOVED,
    CONTROL_STRENGTHENED,
    CONTROL_UNKNOWN,
    CONTROL_WEAKENED,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    IMPACT_NONE,
    REMOVED_SECURITY_CONTROL,
    STRENGTHENED_SECURITY_CONTROL,
    WEAKENED_SECURITY_CONTROL,
    category_record,
    control_change,
)

_AUTHZ_HINTS = re.compile(
    r"authz|authoriz|ownership|permission|rbac|policy|tenant|acl|require_admin|"
    r"is_admin|can_access|check_owner",
    re.I,
)
_AUTHN_HINTS = re.compile(
    r"authn|authenticat|login|session|jwt|oauth|mfa|bearer|require_login|"
    r"is_authenticated",
    re.I,
)
_TENANT_HINTS = re.compile(
    r"tenant|organization_id|org_id|workspace_id|account_id|row.?level|"
    r"multi.?tenant",
    re.I,
)
_VALIDATION_HINTS = re.compile(
    r"validat|sanitiz|escap|encod|parameteriz|allowlist|whitelist|csrf|"
    r"rate.?limit|normalize",
    re.I,
)


def _ctrl_text(c: dict[str, Any]) -> str:
    parts = [
        str(c.get(k) or "")
        for k in ("type", "kind", "name", "label", "id", "mechanism", "purpose")
    ]
    return " ".join(parts)


def _ctrl_type(c: dict[str, Any]) -> str:
    text = _ctrl_text(c).lower()
    if _TENANT_HINTS.search(text):
        return "tenant_isolation"
    if _AUTHZ_HINTS.search(text):
        return "authorization"
    if _AUTHN_HINTS.search(text):
        return "authentication"
    if _VALIDATION_HINTS.search(text):
        return "input_validation"
    explicit = str(c.get("type") or c.get("kind") or "security_control").lower()
    return explicit or "security_control"


def _location(c: dict[str, Any]) -> str:
    ev = c.get("evidence") if isinstance(c.get("evidence"), dict) else {}
    f = c.get("file") or ev.get("file") or ""
    ln = c.get("line") or ev.get("line") or ""
    sym = c.get("symbol") or c.get("name") or c.get("label") or ""
    if f and ln:
        return f"{f}:{ln}"
    if f:
        return str(f)
    return str(sym)


def control_fingerprint(c: dict[str, Any]) -> str:
    """Semantic fingerprint ignoring file path (refactor-aware)."""
    ctype = _ctrl_type(c)
    name = str(c.get("name") or c.get("label") or c.get("symbol") or "").lower()
    purpose = str(c.get("purpose") or c.get("mechanism") or "").lower()
    # strip path-like tokens from name
    name = re.sub(r"[\\/].*", "", name)
    name = re.sub(r"\W+", "_", name).strip("_")
    purpose = re.sub(r"\W+", "_", purpose).strip("_")
    return f"{ctype}|{name}|{purpose}"


def _effectiveness_rank(c: dict[str, Any]) -> int:
    order = {
        "ineffective": 0,
        "unknown": 1,
        "likely": 2,
        "confirmed": 3,
        "required": 3,
        "optional": 1,
        "none": 0,
    }
    raw = str(
        c.get("effectiveness") or c.get("strength") or c.get("status") or "unknown"
    ).lower()
    return order.get(raw, 1)


def compare_controls(
    before_model: dict[str, Any] | None,
    after_model: dict[str, Any] | None,
    *,
    before_dataflow: dict[str, Any] | None = None,
    after_dataflow: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Diff security controls with MOVED detection for refactors."""
    changes: list[dict[str, Any]] = []
    categories: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []

    if before_model is None or after_model is None:
        unknowns.append(
            {
                "area": "security_controls",
                "reason": "BASE authorization/control model could not be reconstructed."
                if before_model is None
                else "HEAD control model unavailable.",
            }
        )
        return {
            "changes": changes,
            "categories": categories,
            "summary": {"unknown": True},
            "unknowns": unknowns,
            "auth_changes": [],
            "authz_changes": [],
            "tenant_changes": [],
        }

    before_list = list(before_model.get("security_controls") or [])
    after_list = list(after_model.get("security_controls") or [])

    # Also fold dataflow-level controls when present
    if before_dataflow:
        before_list.extend(before_dataflow.get("controls") or [])
    if after_dataflow:
        after_list.extend(after_dataflow.get("controls") or [])

    before_by_fp: dict[str, list[dict[str, Any]]] = {}
    after_by_fp: dict[str, list[dict[str, Any]]] = {}
    for c in before_list:
        if isinstance(c, dict):
            before_by_fp.setdefault(control_fingerprint(c), []).append(c)
    for c in after_list:
        if isinstance(c, dict):
            after_by_fp.setdefault(control_fingerprint(c), []).append(c)

    before_fps = set(before_by_fp)
    after_fps = set(after_by_fp)

    removed_fps = before_fps - after_fps
    added_fps = after_fps - before_fps
    shared = before_fps & after_fps

    # MOVED: same fingerprint already handles rename/move of identical controls.
    # Additional heuristic: removed+added with same control_type and similar name tokens.
    moved_pairs: list[tuple[str, str]] = []
    remaining_removed = set(removed_fps)
    remaining_added = set(added_fps)
    for rfp in list(remaining_removed):
        r_type = rfp.split("|", 1)[0]
        r_name = rfp.split("|")[1] if "|" in rfp else ""
        best = None
        for afp in list(remaining_added):
            if afp.split("|", 1)[0] != r_type:
                continue
            a_name = afp.split("|")[1] if "|" in afp else ""
            if r_name and a_name and (r_name in a_name or a_name in r_name):
                best = afp
                break
            if r_type in {"authorization", "authentication", "tenant_isolation"} and not best:
                # same type only — weak move candidate when counts match 1:1 later
                best = afp
        if best and best in remaining_added:
            moved_pairs.append((rfp, best))
            remaining_removed.discard(rfp)
            remaining_added.discard(best)

    for rfp, afp in moved_pairs:
        bc = before_by_fp[rfp][0]
        ac = after_by_fp[afp][0]
        ch = control_change(
            control_type=_ctrl_type(bc),
            state=CONTROL_MOVED,
            detail=f"Control moved {_location(bc)} → {_location(ac)}",
            before=_ctrl_text(bc),
            after=_ctrl_text(ac),
            location_before=_location(bc),
            location_after=_location(ac),
            impact=IMPACT_NONE,
        )
        changes.append(ch)
        categories.append(
            category_record(
                "MOVED_SECURITY_CONTROL",
                detail=ch["detail"],
                severity=IMPACT_NONE,
            )
        )

    for rfp in sorted(remaining_removed):
        bc = before_by_fp[rfp][0]
        ctype = _ctrl_type(bc)
        ch = control_change(
            control_type=ctype,
            state=CONTROL_REMOVED,
            detail=f"Removed {ctype} control",
            before=_ctrl_text(bc),
            after=None,
            location_before=_location(bc),
            impact=IMPACT_HIGH
            if ctype in {"authorization", "tenant_isolation", "authentication"}
            else IMPACT_MEDIUM,
        )
        changes.append(ch)
        categories.append(
            category_record(
                REMOVED_SECURITY_CONTROL,
                detail=ch["detail"],
                severity=ch["impact"],
                evidence=_location(bc),
            )
        )

    for afp in sorted(remaining_added):
        ac = after_by_fp[afp][0]
        ctype = _ctrl_type(ac)
        ch = control_change(
            control_type=ctype,
            state=CONTROL_ADDED,
            detail=f"Added {ctype} control",
            before=None,
            after=_ctrl_text(ac),
            location_after=_location(ac),
            impact=IMPACT_LOW,
        )
        changes.append(ch)

    for fp in sorted(shared):
        bc = before_by_fp[fp][0]
        ac = after_by_fp[fp][0]
        ra = _effectiveness_rank(bc)
        rb = _effectiveness_rank(ac)
        if rb < ra:
            ch = control_change(
                control_type=_ctrl_type(bc),
                state=CONTROL_WEAKENED,
                detail=f"Weakened {_ctrl_type(bc)} control",
                before=_ctrl_text(bc),
                after=_ctrl_text(ac),
                location_before=_location(bc),
                location_after=_location(ac),
                impact=IMPACT_HIGH,
            )
            changes.append(ch)
            categories.append(
                category_record(
                    WEAKENED_SECURITY_CONTROL,
                    detail=ch["detail"],
                    severity=IMPACT_HIGH,
                )
            )
        elif rb > ra:
            ch = control_change(
                control_type=_ctrl_type(bc),
                state=CONTROL_STRENGTHENED,
                detail=f"Strengthened {_ctrl_type(bc)} control",
                before=_ctrl_text(bc),
                after=_ctrl_text(ac),
                location_before=_location(bc),
                location_after=_location(ac),
                impact=IMPACT_LOW,
            )
            changes.append(ch)
            categories.append(
                category_record(
                    STRENGTHENED_SECURITY_CONTROL,
                    detail=ch["detail"],
                    severity=IMPACT_LOW,
                )
            )

    auth_changes = [c for c in changes if c.get("control_type") == "authentication"]
    authz_changes = [c for c in changes if c.get("control_type") == "authorization"]
    tenant_changes = [c for c in changes if c.get("control_type") == "tenant_isolation"]

    summary = {
        "added": sum(1 for c in changes if c["state"] == CONTROL_ADDED),
        "removed": sum(1 for c in changes if c["state"] == CONTROL_REMOVED),
        "weakened": sum(1 for c in changes if c["state"] == CONTROL_WEAKENED),
        "strengthened": sum(1 for c in changes if c["state"] == CONTROL_STRENGTHENED),
        "moved": sum(1 for c in changes if c["state"] == CONTROL_MOVED),
        "unknown": sum(1 for c in changes if c["state"] == CONTROL_UNKNOWN),
    }
    return {
        "changes": changes,
        "categories": categories,
        "summary": summary,
        "unknowns": unknowns,
        "auth_changes": auth_changes,
        "authz_changes": authz_changes,
        "tenant_changes": tenant_changes,
    }
