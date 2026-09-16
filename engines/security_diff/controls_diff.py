"""Security control state diffs (authn/authz/tenant/validation/…)."""

from __future__ import annotations

from typing import Any

from engines.security_diff.schema import (
    CONTROL_ADDED,
    CONTROL_MOVED,
    CONTROL_REMOVED,
    CONTROL_STRENGTHENED,
    CONTROL_UNCHANGED,
    CONTROL_UNKNOWN,
    CONTROL_WEAKENED,
    REMOVED_SECURITY_CONTROL,
    STRENGTHENED_SECURITY_CONTROL,
    WEAKENED_SECURITY_CONTROL,
    category_record,
)

CONTROL_KINDS = (
    "authentication",
    "authorization",
    "tenant",
    "validation",
    "sanitization",
    "encoding",
    "parameterization",
    "csrf",
    "rate_limiting",
    "origin_validation",
    "url_allowlist",
    "signature_validation",
    "security_headers",
    "secret_handling",
    "tool_permissions",
    "agent_permissions",
    "mcp_trust",
)

_EFFECTIVENESS_RANK = {
    "ineffective": 0,
    "absent": 0,
    "none": 0,
    "unknown": 1,
    "partial": 2,
    "likely": 3,
    "confirmed": 4,
    "effective": 4,
}


def _norm_kind(raw: str) -> str:
    s = raw.lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "authn": "authentication",
        "auth": "authentication",
        "authz": "authorization",
        "rbac": "authorization",
        "abac": "authorization",
        "ownership": "authorization",
        "tenant_isolation": "tenant",
        "tenant_scoping": "tenant",
        "sanitize": "sanitization",
        "validate": "validation",
        "parameterized": "parameterization",
        "allowlist": "url_allowlist",
        "whitelist": "url_allowlist",
        "mcp": "mcp_trust",
        "agent": "agent_permissions",
        "tool": "tool_permissions",
    }
    if s in CONTROL_KINDS:
        return s
    for a, k in aliases.items():
        if a in s:
            return k
    return s or "unknown"


def _control_id(c: dict[str, Any]) -> str:
    kind = _norm_kind(str(c.get("kind") or c.get("type") or c.get("category") or ""))
    label = str(c.get("label") or c.get("name") or c.get("id") or kind)
    return f"{kind}:{label}"


def _collect_controls(
    app_model: dict[str, Any] | None,
    attack_graph: dict[str, Any] | None,
    twin: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    def add(c: dict[str, Any], source: str) -> None:
        if not isinstance(c, dict):
            return
        cid = _control_id(c)
        eff = str(
            c.get("effectiveness") or c.get("status") or c.get("strength") or "unknown"
        ).lower()
        kind = _norm_kind(str(c.get("kind") or c.get("type") or ""))
        loc = ""
        ev = c.get("evidence")
        if isinstance(ev, dict):
            loc = str(ev.get("file") or "")
        loc = loc or str(c.get("file") or "")
        prev = out.get(cid)
        if prev and _EFFECTIVENESS_RANK.get(prev.get("effectiveness", "unknown"), 1) >= _EFFECTIVENESS_RANK.get(
            eff, 1
        ):
            return
        out[cid] = {
            "id": cid,
            "kind": kind,
            "label": str(c.get("label") or c.get("name") or cid),
            "effectiveness": eff,
            "location": loc,
            "source": source,
            "raw": c,
        }

    if app_model:
        for c in app_model.get("security_controls") or []:
            add(c if isinstance(c, dict) else {}, "app_model")

    if attack_graph:
        for n in (attack_graph.get("graph") or {}).get("nodes") or []:
            if isinstance(n, dict) and n.get("type") == "control":
                add(
                    {
                        "id": n.get("id"),
                        "kind": n.get("kind") or n.get("control_kind") or "control",
                        "label": n.get("label") or n.get("id"),
                        "effectiveness": n.get("effectiveness") or "unknown",
                        "file": (n.get("evidence") or {}).get("file")
                        if isinstance(n.get("evidence"), dict)
                        else n.get("file"),
                    },
                    "attack_graph",
                )
        for p in attack_graph.get("paths") or []:
            if not isinstance(p, dict):
                continue
            for c in p.get("controls") or []:
                if isinstance(c, dict):
                    add(c, "attack_graph_path")

    if twin:
        for c in twin.get("controls") or twin.get("security_controls") or []:
            add(c if isinstance(c, dict) else {}, "twin")
        # Twin may nest under entities
        for ent in twin.get("entities") or []:
            if isinstance(ent, dict) and str(ent.get("type") or "") == "control":
                add(ent, "twin")

    return out


def compare_controls(
    *,
    before_app: dict[str, Any] | None = None,
    after_app: dict[str, Any] | None = None,
    before_ag: dict[str, Any] | None = None,
    after_ag: dict[str, Any] | None = None,
    before_twin: dict[str, Any] | None = None,
    after_twin: dict[str, Any] | None = None,
) -> dict[str, Any]:
    before = _collect_controls(before_app, before_ag, before_twin)
    after = _collect_controls(after_app, after_ag, after_twin)

    changes: list[dict[str, Any]] = []
    categories: list[dict[str, Any]] = []

    if not before and (before_app is None and before_ag is None and before_twin is None):
        return {
            "control_changes": [
                {
                    "id": "*",
                    "kind": "all",
                    "state": CONTROL_UNKNOWN,
                    "detail": "baseline UNKNOWN — no prior control inventory",
                }
            ],
            "categories": [],
            "baseline_unknown": True,
        }

    for cid, ctrl in after.items():
        if cid not in before:
            changes.append(
                {
                    "id": cid,
                    "kind": ctrl["kind"],
                    "state": CONTROL_ADDED,
                    "detail": f"control added: {ctrl['label']}",
                    "location": ctrl.get("location"),
                }
            )
        else:
            b = before[cid]
            br = _EFFECTIVENESS_RANK.get(b.get("effectiveness", "unknown"), 1)
            ar = _EFFECTIVENESS_RANK.get(ctrl.get("effectiveness", "unknown"), 1)
            bloc = (b.get("location") or "").strip()
            aloc = (ctrl.get("location") or "").strip()
            if br > ar:
                state = CONTROL_WEAKENED
                categories.append(
                    category_record(
                        WEAKENED_SECURITY_CONTROL,
                        detail=f"{cid}: {b.get('effectiveness')}→{ctrl.get('effectiveness')}",
                        severity="HIGH",
                    )
                )
            elif ar > br:
                state = CONTROL_STRENGTHENED
                categories.append(
                    category_record(
                        STRENGTHENED_SECURITY_CONTROL,
                        detail=f"{cid}: {b.get('effectiveness')}→{ctrl.get('effectiveness')}",
                    )
                )
            elif bloc and aloc and bloc != aloc:
                state = CONTROL_MOVED
            else:
                state = CONTROL_UNCHANGED
            if state != CONTROL_UNCHANGED:
                changes.append(
                    {
                        "id": cid,
                        "kind": ctrl["kind"],
                        "state": state,
                        "detail": f"{b.get('effectiveness')}→{ctrl.get('effectiveness')}",
                        "before_location": bloc or None,
                        "location": aloc or None,
                    }
                )

    for cid, ctrl in before.items():
        if cid not in after:
            changes.append(
                {
                    "id": cid,
                    "kind": ctrl["kind"],
                    "state": CONTROL_REMOVED,
                    "detail": f"control removed: {ctrl['label']}",
                    "location": ctrl.get("location"),
                }
            )
            categories.append(
                category_record(
                    REMOVED_SECURITY_CONTROL,
                    detail=f"{cid}: {ctrl['label']}",
                    severity="HIGH",
                    evidence=ctrl.get("location"),
                )
            )

    return {
        "control_changes": changes,
        "categories": categories,
        "baseline_unknown": False,
    }
