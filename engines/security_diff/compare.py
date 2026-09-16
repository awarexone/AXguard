"""Compose category diffs from two security states."""

from __future__ import annotations

from typing import Any

from engines.security_diff.app_model_diff import compare_app_models
from engines.security_diff.controls import compare_controls
from engines.security_diff.dataflow_diff import compare_dataflows
from engines.security_diff.schema import (
    AUTH_STRONGER,
    AUTH_UNCHANGED,
    AUTH_UNKNOWN,
    AUTH_WEAKER,
    CONTROL_REMOVED,
    CONTROL_WEAKENED,
    IMPACT_HIGH,
    IMPACT_MEDIUM,
    NEW_ATTACK_PATH,
    BLOCKED_ATTACK_PATH,
    REMOVED_ATTACK_PATH,
    REOPENED_ATTACK_PATH,
    WEAKENED_ATTACK_PATH,
    PRIVILEGE_EXPANSION,
    TENANT_BOUNDARY_WEAKENED,
    category_record,
    delta_item,
    regression_record,
    unknown_record,
)


def _auth_effective(auth_changes: list[dict[str, Any]]) -> str:
    if not auth_changes:
        return AUTH_UNCHANGED
    states = {c.get("state") for c in auth_changes}
    if "REMOVED" in states or "WEAKENED" in states or "BYPASSED" in states:
        return AUTH_WEAKER
    if "ADDED" in states or "STRENGTHENED" in states:
        return AUTH_STRONGER
    if "UNKNOWN" in states:
        return AUTH_UNKNOWN
    return AUTH_UNCHANGED


def _path_record(change: dict[str, Any], kind: str) -> dict[str, Any]:
    hops = change.get("hop_labels") or change.get("signature") or []
    return {
        "kind": kind,
        "entry": change.get("entry"),
        "steps": hops,
        "status": change.get("status") or change.get("status_after"),
        "detail": change.get("detail"),
        "confidence": change.get("confidence") or "MEDIUM",
        "evidence": change.get("evidence") or [],
        "impact": change.get("impact") or IMPACT_MEDIUM,
        "root_cause": change.get("root_cause"),
    }


def compare_states(
    base_state: dict[str, Any] | None,
    head_state: dict[str, Any] | None,
    *,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Semantic comparison of two built security states."""
    opts = dict(options or {})
    base_state = base_state or {}
    head_state = head_state or {}

    before_am = base_state.get("application_model")
    after_am = head_state.get("application_model")
    before_df = base_state.get("dataflow")
    after_df = head_state.get("dataflow")
    before_ag = base_state.get("attack_graph")
    after_ag = head_state.get("attack_graph")
    before_twin = base_state.get("twin")
    after_twin = head_state.get("twin")
    before_pred = base_state.get("predictive")
    after_pred = head_state.get("predictive")

    app_delta = compare_app_models(before_am, after_am)
    df_delta = compare_dataflows(before_df, after_df)
    ctrl = compare_controls(
        before_am,
        after_am,
        before_dataflow=before_df,
        after_dataflow=after_df,
    )

    categories: list[dict[str, Any]] = []
    categories.extend(app_delta.get("categories") or [])
    categories.extend(df_delta.get("categories") or [])
    categories.extend(ctrl.get("categories") or [])

    unknowns: list[dict[str, Any]] = []
    unknowns.extend(base_state.get("unknowns") or [])
    unknowns.extend(head_state.get("unknowns") or [])
    unknowns.extend(ctrl.get("unknowns") or [])
    if app_delta.get("baseline_unknown"):
        unknowns.append(
            unknown_record(
                "attack_surface",
                "BASE application model unavailable for comparison.",
            )
        )
    if df_delta.get("baseline_unknown"):
        unknowns.append(
            unknown_record(
                "data_flow",
                "BASE dataflow model unavailable for comparison.",
            )
        )

    # Attack surface lists
    surface_added = []
    surface_removed = []
    for cat in app_delta.get("categories") or []:
        kind = str(cat.get("category") or "")
        item = delta_item(
            kind,
            detail=str(cat.get("detail") or ""),
            impact=str(cat.get("severity") or IMPACT_MEDIUM),
            evidence=[cat.get("evidence")] if cat.get("evidence") else [],
        )
        if kind.startswith("REMOVED_"):
            surface_removed.append(item)
        else:
            surface_added.append(item)

    # Data flow
    df_added = []
    df_changed = []
    for cat in df_delta.get("categories") or []:
        item = delta_item(
            str(cat.get("category")),
            detail=str(cat.get("detail") or ""),
            impact=str(cat.get("severity") or IMPACT_MEDIUM),
        )
        if "REMOVED" in str(cat.get("category")) or "WEAKENED" in str(cat.get("category")):
            df_changed.append(item)
        else:
            df_added.append(item)

    # Attack path delta via existing compare_attack_graphs
    path_delta = {
        "new_paths": [],
        "removed_paths": [],
        "blocked_paths": [],
        "reopened_paths": [],
        "weakened_paths": [],
        "summary": {},
    }
    if before_ag and after_ag:
        try:
            from engines.attack_graph.diff import (
                CHANGE_NEW_ATTACK_PATH,
                CHANGE_REMOVED_ATTACK_PATH,
                CHANGE_STRENGTHENED_CONTROL,
                CHANGE_WEAKENED_CONTROL,
                compare_attack_graphs,
            )

            ag_diff = compare_attack_graphs(before_ag, after_ag)
            for ch in ag_diff.get("changes") or []:
                ctype = str(ch.get("change") or "")
                if ctype == CHANGE_NEW_ATTACK_PATH:
                    path_delta["new_paths"].append(_path_record(ch, NEW_ATTACK_PATH))
                    categories.append(
                        category_record(NEW_ATTACK_PATH, detail=str(ch.get("detail") or ""))
                    )
                elif ctype == CHANGE_REMOVED_ATTACK_PATH:
                    # blocked vs removed — treat removed as blocked if after missing
                    path_delta["removed_paths"].append(
                        _path_record(ch, REMOVED_ATTACK_PATH)
                    )
                    path_delta["blocked_paths"].append(
                        _path_record(ch, BLOCKED_ATTACK_PATH)
                    )
                    categories.append(
                        category_record(
                            BLOCKED_ATTACK_PATH, detail=str(ch.get("detail") or "")
                        )
                    )
                elif ctype == CHANGE_WEAKENED_CONTROL:
                    status_before = str(ch.get("status_before") or "")
                    status_after = str(ch.get("status_after") or "")
                    if status_before == "BLOCKED" and status_after != "BLOCKED":
                        path_delta["reopened_paths"].append(
                            _path_record(ch, REOPENED_ATTACK_PATH)
                        )
                    else:
                        path_delta["weakened_paths"].append(
                            _path_record(ch, WEAKENED_ATTACK_PATH)
                        )
                    categories.append(
                        category_record(
                            WEAKENED_ATTACK_PATH, detail=str(ch.get("detail") or "")
                        )
                    )
                elif ctype == CHANGE_STRENGTHENED_CONTROL:
                    path_delta["blocked_paths"].append(
                        _path_record(ch, BLOCKED_ATTACK_PATH)
                    )
            path_delta["summary"] = ag_diff.get("summary") or {
                "new": len(path_delta["new_paths"]),
                "removed": len(path_delta["removed_paths"]),
                "weakened": len(path_delta["weakened_paths"]),
            }
        except Exception as exc:  # noqa: BLE001
            unknowns.append(
                unknown_record("attack_paths", f"attack graph compare failed: {exc}")
            )
    elif before_ag is None or after_ag is None:
        unknowns.append(
            unknown_record(
                "attack_paths",
                "Attack graph missing on one side; path delta incomplete.",
            )
        )

    # Twin delta
    twin_delta: dict[str, Any] = {}
    if before_twin and after_twin:
        try:
            from engines.twin.pipeline import run_twin_compare

            twin_delta = run_twin_compare(before_twin, after_twin)
        except Exception as exc:  # noqa: BLE001
            unknowns.append(unknown_record("security_twin", str(exc)))
    elif opts.get("require_twin"):
        unknowns.append(
            unknown_record("security_twin", "Twin unavailable for one or both sides.")
        )

    # Predictive
    predictive_risks: list[dict[str, Any]] = []
    if before_pred or after_pred:
        try:
            from engines.predictive.compare import compare_risk_sets

            prev = (before_pred or {}).get("risks") or []
            cur = (after_pred or {}).get("risks") or []
            cmp = compare_risk_sets(prev, cur)
            predictive_risks = cmp.get("comparisons") or cur
        except Exception as exc:  # noqa: BLE001
            unknowns.append(unknown_record("predictive", str(exc)))

    # AI / MCP / privilege / identity from app model + twin entities
    ai_changes: list[dict[str, Any]] = []
    mcp_changes: list[dict[str, Any]] = []
    identity_changes: list[dict[str, Any]] = []
    privilege_changes: list[dict[str, Any]] = []
    trust_changes: list[dict[str, Any]] = []
    dep_changes: list[dict[str, Any]] = []
    secret_changes: list[dict[str, Any]] = []

    for cat in app_delta.get("categories") or []:
        kind = str(cat.get("category") or "")
        item = delta_item(kind, detail=str(cat.get("detail") or ""), impact=IMPACT_MEDIUM)
        if "MCP" in kind:
            mcp_changes.append(item)
        elif kind in {"NEW_AGENT", "NEW_AI_TOOL", "NEW_AI_AGENT", "NEW_AGENT_TOOL"}:
            ai_changes.append(item)
        elif kind == "NEW_IDENTITY":
            identity_changes.append(item)
        elif "TRUST" in kind:
            trust_changes.append(item)
        elif "DEPENDENCY" in kind:
            dep_changes.append(item)
        elif kind == "NEW_SECRET":
            secret_changes.append(
                delta_item(
                    kind,
                    detail=str(cat.get("detail") or ""),
                    impact=IMPACT_HIGH,
                    value="[REDACTED]",
                )
            )

    # Privilege expansion heuristics from twin regression
    for ch in (twin_delta.get("regression") or {}).get("changes") or []:
        ctype = str(ch.get("change") or ch.get("type") or "")
        if "PRIVILEGE" in ctype.upper() or ctype == "NEW_PRIVILEGE":
            privilege_changes.append(
                delta_item(
                    PRIVILEGE_EXPANSION,
                    detail=str(ch.get("detail") or ctype),
                    impact=IMPACT_HIGH,
                )
            )
            categories.append(
                category_record(PRIVILEGE_EXPANSION, detail=str(ch.get("detail") or ""))
            )
        if "EXTERNAL" in ctype.upper():
            trust_changes.append(
                delta_item(ctype, detail=str(ch.get("detail") or ""), impact=IMPACT_MEDIUM)
            )

    # Auth / authz / tenant from control compare
    auth_changes = ctrl.get("auth_changes") or []
    authz_changes = list(ctrl.get("authz_changes") or [])
    tenant_raw = list(ctrl.get("tenant_changes") or [])
    tenant_changes: list[dict[str, Any]] = []
    for c in tenant_raw:
        item = dict(c)
        if c.get("state") in {CONTROL_REMOVED, CONTROL_WEAKENED}:
            item["kind"] = TENANT_BOUNDARY_WEAKENED
            item["priority"] = "high"
            categories.append(
                category_record(
                    TENANT_BOUNDARY_WEAKENED,
                    detail=str(c.get("detail") or ""),
                    severity=IMPACT_HIGH,
                )
            )
        tenant_changes.append(item)

    # Regressions: removed/weakened authz/tenant + reopened paths
    regressions: list[dict[str, Any]] = []
    for c in ctrl.get("changes") or []:
        if c.get("state") in {CONTROL_REMOVED, CONTROL_WEAKENED} and c.get(
            "control_type"
        ) in {"authorization", "tenant_isolation", "authentication"}:
            regressions.append(
                regression_record(
                    title=f"{c.get('control_type')} {c.get('state')}",
                    before=str(c.get("before") or "Control present"),
                    change=str(c.get("detail") or ""),
                    now=str(c.get("after") or "Control absent or weaker"),
                    impact=str(c.get("impact") or IMPACT_HIGH),
                    evidence=c.get("evidence") or [],
                    category=str(c.get("control_type")),
                )
            )
    for p in path_delta.get("reopened_paths") or []:
        regressions.append(
            regression_record(
                title="Attack path reopened",
                before="Path blocked or controlled",
                change=str(p.get("detail") or ""),
                now="Path reachable again",
                impact=IMPACT_HIGH,
                evidence=p.get("evidence") or [],
                category="attack_path",
            )
        )

    # Recommended actions (smallest relevant fix)
    recommended: list[str] = []
    for r in regressions[:5]:
        if r.get("category") == "authorization":
            recommended.append(
                "Restore the existing ownership/authorization check. "
                "Do not introduce a second authorization implementation."
            )
        elif r.get("category") == "tenant_isolation":
            recommended.append(
                "Restore tenant scope enforcement on the affected query/path."
            )
        elif r.get("category") == "authentication":
            recommended.append("Restore authentication on the affected entrypoint.")
        else:
            recommended.append(f"Review regression: {r.get('title')}")
    if path_delta.get("new_paths") and not recommended:
        recommended.append(
            "Review new attack paths; confirm intended exposure and controls."
        )

    # Root causes (simple)
    root_causes: list[dict[str, Any]] = []
    for c in ctrl.get("changes") or []:
        if c.get("state") == CONTROL_REMOVED:
            root_causes.append(
                {
                    "observed": "Control missing in HEAD",
                    "root_cause": c.get("detail"),
                    "location": c.get("location_before"),
                }
            )

    # Summaries
    app_sum = app_delta.get("summary") or {}
    df_sum = df_delta.get("summary") or {}
    ctrl_sum = ctrl.get("summary") or {}

    return {
        "categories": categories,
        "attack_surface_delta": {
            "added": surface_added,
            "removed": surface_removed,
            "changed": [],
            "summary": {
                "added": len(surface_added),
                "removed": len(surface_removed),
                "new_endpoints": len(app_sum.get("added_endpoints") or []),
                "removed_endpoints": len(app_sum.get("removed_endpoints") or []),
                "new_parameters": len(app_sum.get("new_parameters") or []),
                "new_webhooks": len(app_sum.get("new_webhooks") or []),
                "new_uploads": len(app_sum.get("new_uploads") or []),
            },
        },
        "control_delta": {
            "changes": ctrl.get("changes") or [],
            "summary": ctrl_sum,
        },
        "auth_delta": {
            "changes": auth_changes,
            "effective": _auth_effective(auth_changes),
            "summary": {"count": len(auth_changes)},
        },
        "authorization_delta": {
            "changes": authz_changes,
            "summary": {"count": len(authz_changes)},
        },
        "tenant_isolation_delta": {
            "changes": tenant_changes,
            "summary": {"count": len(tenant_changes)},
            "priority": "high",
        },
        "data_flow_delta": {
            "added": df_added,
            "removed": [],
            "changed": df_changed,
            "summary": {
                "new_paths": len(df_sum.get("new_paths") or []),
                "new_sources": len(df_sum.get("new_sources") or []),
                "new_sinks": len(df_sum.get("new_sinks") or []),
                "removed_controls": len(df_sum.get("removed_controls") or []),
            },
        },
        "trust_boundary_delta": {
            "changes": trust_changes,
            "summary": {"count": len(trust_changes)},
        },
        "identity_delta": {
            "changes": identity_changes,
            "summary": {"count": len(identity_changes)},
        },
        "privilege_delta": {
            "changes": privilege_changes,
            "summary": {"count": len(privilege_changes)},
        },
        "secrets_delta": {
            "changes": secret_changes,
            "summary": {"count": len(secret_changes)},
        },
        "dependency_delta": {
            "changes": dep_changes,
            "summary": {"count": len(dep_changes)},
        },
        "ai_delta": {"changes": ai_changes, "summary": {"count": len(ai_changes)}},
        "mcp_delta": {"changes": mcp_changes, "summary": {"count": len(mcp_changes)}},
        "attack_path_delta": path_delta,
        "security_twin_delta": twin_delta,
        "predictive_risks": predictive_risks,
        "regressions": regressions,
        "unknowns": unknowns,
        "recommended_actions": recommended,
        "root_causes": root_causes,
        "app_model_delta": app_delta,
        "dataflow_delta": df_delta,
        "authz_changes": authz_changes,
        "tenant_changes": tenant_changes,
        "control_changes": ctrl.get("changes") or [],
        "summary": {
            "new_endpoints": len(app_sum.get("added_endpoints") or []),
            "removed_endpoints": len(app_sum.get("removed_endpoints") or []),
            "new_parameters": len(app_sum.get("new_parameters") or []),
            "new_database_flows": sum(
                1 for c in categories if c.get("category") == "NEW_DATABASE_FLOW"
            ),
            "new_external_requests": sum(
                1 for c in categories if c.get("category") == "NEW_EXTERNAL_REQUEST"
            ),
            "new_uploads": len(app_sum.get("new_uploads") or []),
            "new_webhooks": len(app_sum.get("new_webhooks") or []),
            "removed_controls": int(ctrl_sum.get("removed") or 0),
            "weakened_controls": int(ctrl_sum.get("weakened") or 0),
            "strengthened_controls": int(ctrl_sum.get("strengthened") or 0),
            "moved_controls": int(ctrl_sum.get("moved") or 0),
            "added_controls": int(ctrl_sum.get("added") or 0),
            "new_attack_paths": len(path_delta.get("new_paths") or []),
            "blocked_attack_paths": len(path_delta.get("blocked_paths") or []),
            "new_sensitive_flows": sum(
                1 for c in categories if c.get("category") == "NEW_SENSITIVE_DATA_FLOW"
            ),
            "authz_changes": len(authz_changes),
            "tenant_changes": len(tenant_changes),
            "privilege_changes": len(privilege_changes),
            "regressions": len(regressions),
            "predictive_risks": len(predictive_risks),
            "unknowns": len(unknowns),
        },
    }
