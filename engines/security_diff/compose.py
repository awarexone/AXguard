"""Compose a unified Security Diff from app model / dataflow / AG / twin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.security_diff.app_model_diff import compare_app_models
from engines.security_diff.authz_diff import compare_authz
from engines.security_diff.controls_diff import compare_controls
from engines.security_diff.dataflow_diff import compare_dataflows
from engines.security_diff.git_base import resolve_base_ref
from engines.security_diff.schema import (
    BASELINE_ARTIFACTS,
    BASELINE_GIT,
    BASELINE_PATH,
    BASELINE_UNKNOWN,
    BLOCKED_ATTACK_PATH,
    NEW_ATTACK_PATH,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    category_record,
    empty_security_diff,
)


def _load_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _build_current_artifacts(target: Path, *, cheap_twin: bool = True) -> dict[str, Any]:
    """Build app model + dataflow + attack graph (+ optional twin) for target."""
    arts: dict[str, Any] = {
        "application_model": None,
        "dataflow": None,
        "attack_graph": None,
        "twin": None,
    }
    try:
        from engines.app_model import build_application_model

        arts["application_model"] = build_application_model(target)
    except Exception:  # noqa: BLE001
        arts["application_model"] = None

    try:
        from engines.dataflow import analyze_dataflow

        arts["dataflow"] = analyze_dataflow(
            target, application_model=arts.get("application_model")
        )
    except Exception:  # noqa: BLE001
        arts["dataflow"] = None

    try:
        from engines.attack_graph import run_attack_graph

        # run_attack_graph builds evidence→adversary internally; pass-through
        # of app_model/dataflow is not part of its public signature.
        arts["attack_graph"] = run_attack_graph(target)
    except Exception:  # noqa: BLE001
        arts["attack_graph"] = None

    if cheap_twin and arts.get("attack_graph") is not None:
        try:
            from engines.twin import build_security_twin

            arts["twin"] = build_security_twin(
                target,
                application_model=arts.get("application_model"),
                attack_graph=arts.get("attack_graph"),
                dataflow=arts.get("dataflow"),
            )
        except Exception:  # noqa: BLE001
            arts["twin"] = None
    return arts


def _load_findings_artifacts(findings_dir: Path) -> dict[str, Any]:
    return {
        "application_model": _load_json(findings_dir / "application-model.json"),
        "dataflow": _load_json(findings_dir / "dataflow.json"),
        "attack_graph": _load_json(findings_dir / "attack-paths.json"),
        "twin": _load_json(findings_dir / "security-twin.json")
        or _load_json(findings_dir / "twin.json"),
    }


def _overall_severity(
    categories: list[dict[str, Any]],
    authz_changes: list[dict[str, Any]],
    tenant_changes: list[dict[str, Any]],
    control_changes: list[dict[str, Any]],
) -> str:
    score = 0
    for c in categories:
        cat = str(c.get("category") or "")
        sev = str(c.get("severity") or "").upper()
        if sev == "CRITICAL" or "CRITICAL" in cat:
            score = max(score, 4)
        elif sev == "HIGH" or cat in {
            "REMOVED_SECURITY_CONTROL",
            "WEAKENED_SECURITY_CONTROL",
            "NEW_ATTACK_PATH",
        }:
            score = max(score, 3)
        elif cat.startswith("NEW_") or cat == "CONFIGURATION_SECURITY_CHANGE":
            score = max(score, 2)
        else:
            score = max(score, 1)

    for ch in authz_changes + tenant_changes:
        impact = str(ch.get("impact") or ch.get("change") or "").lower()
        if any(
            x in impact
            for x in ("removed", "weakened", "broadened", "privilege expansion", "bypass")
        ):
            score = max(score, 3)

    for ch in control_changes:
        if ch.get("state") in {"REMOVED", "WEAKENED"}:
            score = max(score, 3)

    if score >= 4:
        return SEVERITY_CRITICAL
    if score >= 3:
        return SEVERITY_HIGH
    if score >= 2:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _count_categories(categories: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in categories:
        cat = str(c.get("category") or "UNKNOWN")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


def run_security_diff(
    current_target: str | Path,
    base_target: str | Path | None = None,
    base_ref: str | None = None,
    current_artifacts: dict[str, Any] | None = None,
    base_artifacts: dict[str, Any] | None = None,
    *,
    cheap_twin: bool = True,
) -> dict[str, Any]:
    """Run Security Diff between current and base.

    If neither base_target nor resolvable git base nor base_artifacts exist,
    baseline is UNKNOWN (never invented).
    """
    current = Path(current_target).resolve()
    result = empty_security_diff(
        current_target=str(current),
        base_target=str(Path(base_target).resolve()) if base_target else None,
        base_ref=base_ref,
        baseline=BASELINE_UNKNOWN,
    )

    # Current artifacts
    cur = dict(current_artifacts or {})
    if not cur.get("application_model") or not cur.get("attack_graph"):
        built = _build_current_artifacts(current, cheap_twin=cheap_twin)
        for k, v in built.items():
            cur.setdefault(k, v)

    # Base resolution
    base_path: Path | None = Path(base_target).resolve() if base_target else None
    base = dict(base_artifacts or {})
    git_info = resolve_base_ref(current, base_ref)
    notes: list[str] = list(git_info.get("notes") or [])

    if base_path and base_path.exists():
        result["baseline"] = BASELINE_PATH
        result["base_target"] = str(base_path)
        if not base.get("application_model"):
            built_b = _build_current_artifacts(base_path, cheap_twin=cheap_twin)
            for k, v in built_b.items():
                base.setdefault(k, v)
    elif base and any(base.get(k) for k in ("application_model", "attack_graph", "dataflow", "twin")):
        result["baseline"] = BASELINE_ARTIFACTS
    elif git_info.get("available"):
        result["baseline"] = BASELINE_GIT
        result["base_ref"] = git_info.get("base_ref")
        result["base_sha"] = git_info.get("base_sha")
        result["head_sha"] = git_info.get("head_sha")
        result["changed_files"] = git_info.get("changed_files") or []
        # Try previous artifacts under .findings
        findings = current / ".findings" / "axguard"
        if findings.is_dir():
            prev = _load_findings_artifacts(findings)
            # Only use if they look like a prior snapshot (presence of attack graph)
            if prev.get("attack_graph") or prev.get("application_model"):
                for k, v in prev.items():
                    base.setdefault(k, v)
                notes.append("base artifacts loaded from .findings/axguard (best-effort)")
        if not any(base.get(k) for k in ("application_model", "attack_graph", "dataflow")):
            notes.append(
                "git base resolved but no base checkout/artifacts; "
                "structural base UNKNOWN for missing pieces"
            )
    else:
        notes.append("baseline UNKNOWN — no git base, base path, or prior artifacts")

    result["notes"] = notes

    before_app = base.get("application_model")
    after_app = cur.get("application_model")
    before_df = base.get("dataflow")
    after_df = cur.get("dataflow")
    before_ag = base.get("attack_graph")
    after_ag = cur.get("attack_graph")
    before_twin = base.get("twin")
    after_twin = cur.get("twin")

    categories: list[dict[str, Any]] = []

    # App model
    app_delta = compare_app_models(before_app, after_app)
    categories.extend(app_delta.get("categories") or [])
    result["app_model_delta"] = app_delta.get("summary") or {}

    # Dataflow
    df_delta = compare_dataflows(before_df, after_df)
    categories.extend(df_delta.get("categories") or [])
    result["dataflow_delta"] = df_delta.get("summary") or {}

    # Controls
    ctrl = compare_controls(
        before_app=before_app,
        after_app=after_app,
        before_ag=before_ag,
        after_ag=after_ag,
        before_twin=before_twin,
        after_twin=after_twin,
    )
    categories.extend(ctrl.get("categories") or [])
    result["control_changes"] = ctrl.get("control_changes") or []

    # Authz / tenant
    authz = compare_authz(
        before_target=base_path,
        after_target=current,
        before_app=before_app,
        after_app=after_app,
    )
    result["authz_changes"] = authz.get("authz_changes") or []
    result["tenant_changes"] = authz.get("tenant_changes") or []

    # Attack graph — reuse engines.attack_graph.diff
    attack_path_delta: dict[str, Any] = {}
    if before_ag and after_ag:
        try:
            from engines.attack_graph.diff import (
                CHANGE_NEW_ATTACK_PATH,
                CHANGE_REMOVED_ATTACK_PATH,
                CHANGE_WEAKENED_CONTROL,
                compare_attack_graphs,
                get_attack_path_diff,
            )

            attack_path_delta = compare_attack_graphs(before_ag, after_ag)
            path_changes = get_attack_path_diff(before_ag, after_ag)
            for ch in path_changes:
                ctype = ch.get("change")
                if ctype == CHANGE_NEW_ATTACK_PATH:
                    categories.append(
                        category_record(
                            NEW_ATTACK_PATH,
                            detail=str(ch.get("detail") or ch.get("hop_labels") or ""),
                            severity="HIGH",
                        )
                    )
                elif ctype == CHANGE_REMOVED_ATTACK_PATH:
                    # removed path can mean blocked/fixed
                    if str(ch.get("status") or "").upper() == "BLOCKED":
                        categories.append(
                            category_record(BLOCKED_ATTACK_PATH, detail=str(ch.get("detail") or ""))
                        )
                elif ctype == CHANGE_WEAKENED_CONTROL:
                    categories.append(
                        category_record(
                            "WEAKENED_SECURITY_CONTROL",
                            detail=str(ch.get("detail") or ""),
                            severity="HIGH",
                        )
                    )
                # status changes to reachable
                if ctype and "STATUS" in str(ctype):
                    before_st = str(ch.get("before_status") or "").upper()
                    after_st = str(ch.get("after_status") or "").upper()
                    if before_st == "BLOCKED" and after_st in {"CONFIRMED", "LIKELY", "UNVERIFIED"}:
                        categories.append(
                            category_record(
                                NEW_ATTACK_PATH,
                                detail=f"path unblocked: {before_st}→{after_st}",
                                severity="HIGH",
                            )
                        )
                    if after_st == "BLOCKED" and before_st != "BLOCKED":
                        categories.append(
                            category_record(
                                BLOCKED_ATTACK_PATH,
                                detail=f"path blocked: {before_st}→{after_st}",
                            )
                        )
        except Exception as exc:  # noqa: BLE001
            notes.append(f"attack graph diff skipped: {exc}")
            attack_path_delta = {"error": str(exc)}
    else:
        attack_path_delta = {"baseline": BASELINE_UNKNOWN}
        notes.append("attack path delta baseline UNKNOWN (missing before and/or after graph)")

    result["attack_path_delta"] = attack_path_delta

    # Twin compare when both exist
    twin_delta: dict[str, Any] = {}
    if before_twin and after_twin:
        try:
            from engines.twin.pipeline import run_twin_compare

            twin_delta = run_twin_compare(before_twin, after_twin)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"twin compare skipped: {exc}")
            twin_delta = {"error": str(exc)}
    else:
        twin_delta = {"baseline": BASELINE_UNKNOWN}
    result["twin_delta"] = twin_delta

    # Summary counts
    cat_counts = _count_categories(categories)
    summary = result["summary"]
    summary["new_endpoints"] = cat_counts.get("NEW_ENDPOINT", 0)
    summary["removed_endpoints"] = cat_counts.get("REMOVED_ENDPOINT", 0)
    summary["new_parameters"] = cat_counts.get("NEW_PARAMETER", 0)
    summary["new_database_flows"] = cat_counts.get("NEW_DATABASE_FLOW", 0)
    summary["new_external_requests"] = cat_counts.get("NEW_EXTERNAL_REQUEST", 0)
    summary["new_uploads"] = cat_counts.get("NEW_UPLOAD", 0)
    summary["new_webhooks"] = cat_counts.get("NEW_WEBHOOK", 0)
    summary["removed_controls"] = cat_counts.get("REMOVED_SECURITY_CONTROL", 0) + sum(
        1 for c in result["control_changes"] if c.get("state") == "REMOVED"
    )
    summary["weakened_controls"] = cat_counts.get("WEAKENED_SECURITY_CONTROL", 0) + sum(
        1 for c in result["control_changes"] if c.get("state") == "WEAKENED"
    )
    summary["strengthened_controls"] = cat_counts.get("STRENGTHENED_SECURITY_CONTROL", 0) + sum(
        1 for c in result["control_changes"] if c.get("state") == "STRENGTHENED"
    )
    summary["added_controls"] = sum(
        1 for c in result["control_changes"] if c.get("state") == "ADDED"
    )
    summary["new_attack_paths"] = cat_counts.get("NEW_ATTACK_PATH", 0)
    summary["blocked_attack_paths"] = cat_counts.get("BLOCKED_ATTACK_PATH", 0)
    summary["new_sensitive_flows"] = cat_counts.get("NEW_SENSITIVE_DATA_FLOW", 0)
    summary["authz_changes"] = len(result["authz_changes"])
    summary["tenant_changes"] = len(result["tenant_changes"])

    result["categories"] = categories
    result["overall_security_change"] = _overall_severity(
        categories,
        result["authz_changes"],
        result["tenant_changes"],
        result["control_changes"],
    )
    result["notes"] = notes
    result["current_artifacts_present"] = {
        k: cur.get(k) is not None for k in ("application_model", "dataflow", "attack_graph", "twin")
    }
    result["base_artifacts_present"] = {
        k: base.get(k) is not None for k in ("application_model", "dataflow", "attack_graph", "twin")
    }
    return result
