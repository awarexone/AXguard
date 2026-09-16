"""Pre-Ship pipeline — compose audit + security_diff + soft predictive/memory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engines.preship.decision import decide
from engines.preship.policy import PreshipPolicy, default_policy, load_preship_policy
from engines.preship.schema import (
    DEFAULT_MODE,
    MODE_DEEP,
    MODE_MAX,
    MODE_QUICK,
    MODE_STANDARD,
    empty_preship_result,
    exit_code_for,
)


def _extract_findings(audit: dict[str, Any] | None, scan: dict[str, Any] | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if audit:
        # Prefer adversary-final when present
        adv = audit.get("adversary") or {}
        for key in ("final_findings", "findings"):
            for f in adv.get(key) or []:
                if isinstance(f, dict):
                    findings.append(f)
        if not findings:
            for f in audit.get("findings") or []:
                if isinstance(f, dict):
                    findings.append(f)
    if not findings and scan:
        for f in scan.get("findings") or []:
            if isinstance(f, dict):
                findings.append(f)
    return findings


def _load_memory_regressions(target: Path) -> list[str]:
    try:
        from engines.memory.regress import detect_regressions
        from engines.memory.store import list_snapshots, load_snapshot

        memory_dir = target / ".findings" / "axguard" / "memory"
        ids = list_snapshots(memory_dir)
        if len(ids) < 2:
            return []
        before = load_snapshot(ids[-2], memory_dir)
        after = load_snapshot(ids[-1], memory_dir)
        if not before or not after:
            return []
        reg = detect_regressions(before, after)
        out: list[str] = []
        for bucket in ("regressed", "regressions", "items"):
            for item in reg.get(bucket) or []:
                if isinstance(item, dict):
                    out.append(
                        str(
                            item.get("summary")
                            or item.get("fingerprint")
                            or item.get("id")
                            or item
                        )
                    )
                else:
                    out.append(str(item))
        return out
    except Exception:  # noqa: BLE001
        return []


def _soft_predictive(target: Path, security_diff: dict[str, Any]) -> list[dict[str, Any]]:
    risks: list[dict[str, Any]] = []
    try:
        from engines.attack_graph.predictive import predictive_report

        ag_delta = security_diff.get("attack_path_delta") or {}
        if ag_delta and ag_delta.get("baseline") != "UNKNOWN":
            # predictive_report expects before/after graphs — soft skip if missing
            pass
    except Exception:  # noqa: BLE001
        pass

    # Derive soft predictive labels from security_diff categories (no CVE claims)
    summary = security_diff.get("summary") or {}
    if int(summary.get("new_endpoints") or 0) > 0:
        risks.append(
            {
                "label": "ATTACK_SURFACE_EXPANSION",
                "detail": f"+{summary['new_endpoints']} endpoints",
                "predictive": True,
            }
        )
    if security_diff.get("authz_changes"):
        risks.append(
            {
                "label": "AUTHORIZATION_DRIFT",
                "detail": f"{len(security_diff['authz_changes'])} authz change(s)",
                "predictive": True,
            }
        )
    if security_diff.get("tenant_changes"):
        risks.append(
            {
                "label": "TENANT_ISOLATION_RISK",
                "detail": f"{len(security_diff['tenant_changes'])} tenant change(s)",
                "predictive": True,
            }
        )
    if int(summary.get("new_attack_paths") or 0) > 0:
        risks.append(
            {
                "label": "PRIVILEGE_EXPANSION",
                "detail": f"+{summary['new_attack_paths']} attack paths",
                "predictive": True,
            }
        )
    return risks


def _collect_unknowns(
    audit: dict[str, Any] | None,
    security_diff: dict[str, Any],
) -> list[str]:
    """Substantive unknowns that may trigger REVIEW (not mere missing baseline)."""
    unknowns: list[str] = []
    if audit:
        for phase in audit.get("phases") or []:
            if isinstance(phase, dict) and phase.get("status") == "error":
                unknowns.append(
                    f"phase {phase.get('id')} error: {phase.get('error') or 'unknown'}"
                )
    # Tenant/auth unknowns from harmful authz diffs only when present
    for ch in (security_diff.get("tenant_changes") or []):
        if "unknown" in str(ch.get("change") or "").lower():
            unknowns.append(str(ch.get("change")))
    return unknowns[:25]


def run_preship(
    target: str | Path,
    mode: str = DEFAULT_MODE,
    base_ref: str | None = None,
    out_dir: str | Path | None = None,
    policy: PreshipPolicy | dict[str, Any] | None = None,
    *,
    base_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run the Pre-Ship security gate.

    Modes:
    - QUICK: scan + security_diff (changed files / HEAD~1 if git)
    - STANDARD: run_audit + security_diff + predictive soft + memory soft
    - DEEP/MAX: fuller audit + investigation soft + twin (via audit/diff)
    """
    root = Path(target).resolve()
    mode_u = (mode or DEFAULT_MODE).upper()
    if mode_u not in {MODE_QUICK, MODE_STANDARD, MODE_DEEP, MODE_MAX}:
        mode_u = DEFAULT_MODE

    out = Path(out_dir) if out_dir else (root / ".findings" / "axguard" / "preship")
    out.mkdir(parents=True, exist_ok=True)

    if isinstance(policy, PreshipPolicy):
        pol = policy
    elif isinstance(policy, dict):
        pol = default_policy()
        # shallow apply
        b = policy.get("blocking") or {}
        u = policy.get("unknowns") or {}
        from engines.preship.policy import PreshipBlocking, PreshipUnknowns

        if b:
            pol.blocking = PreshipBlocking(**{**pol.blocking.__dict__, **b})
        if u:
            pol.unknowns = PreshipUnknowns(**{**pol.unknowns.__dict__, **u})
    else:
        pol = load_preship_policy(root / ".axguard.yml")

    result = empty_preship_result(target=str(root), mode=mode_u)
    notes: list[str] = []
    audit: dict[str, Any] | None = None
    scan: dict[str, Any] | None = None
    analysis_failed = False

    try:
        if mode_u == MODE_QUICK:
            from engines.paths import default_rules_dir
            from engines.scanner import ScanOptions, run_scan

            scan = run_scan(
                ScanOptions(target=root, rules_dir=default_rules_dir())
            )
            notes.append("QUICK mode: scan + security_diff only")
        else:
            from engines.audit import AuditOptions, run_audit

            audit_out = out / "audit"
            audit_out.mkdir(parents=True, exist_ok=True)
            phases: list[str] = []
            if mode_u == MODE_STANDARD:
                # Full audit — engines already gate expensive stages
                phases = []
            audit = run_audit(
                AuditOptions(target=root, out_dir=audit_out, phases=phases)
            )
            notes.append(f"{mode_u} mode: run_audit + security_diff")
    except Exception as exc:  # noqa: BLE001
        analysis_failed = True
        notes.append(f"analysis error: {exc}")

    # Security diff
    security_diff: dict[str, Any] = {}
    try:
        from engines.security_diff import run_security_diff

        # Prefer artifact-aware compose when both sides have in-memory models
        if base_path and Path(base_path).exists():
            security_diff = run_security_diff(
                project=root,
                base=str(Path(base_path).resolve()),
                head=str(root),
                write_report=False,
                incremental=mode_u == MODE_QUICK,
            )
        elif base_ref:
            security_diff = run_security_diff(
                project=root,
                base=base_ref,
                write_report=False,
                incremental=mode_u == MODE_QUICK,
            )
        else:
            # Try HEAD~1 only when target is the git worktree root; otherwise
            # subdirectory targets (fixtures) would diff the whole monorepo.
            quick_base = None
            if mode_u == MODE_QUICK:
                try:
                    from engines.security_diff.git_base import git_root

                    gr = git_root(root)
                    if gr is not None and gr.resolve() == root.resolve():
                        quick_base = "HEAD~1"
                except Exception:  # noqa: BLE001
                    quick_base = None
            security_diff = run_security_diff(
                project=root,
                base=quick_base,
                use_snapshot=mode_u != MODE_QUICK,
                write_report=False,
                incremental=True,
            )

        # Optional prior artifacts under .findings for compose enrich
        # (compose path keeps legacy baseline token "UNKNOWN" for compatibility;
        # pipeline path uses BASELINE_UNAVAILABLE — both mean the same thing.)
        base_arts: dict[str, Any] = {}
        findings_dir = root / ".findings" / "axguard"
        if findings_dir.is_dir() and not base_path:
            for name, key in (
                ("application-model.json", "application_model"),
                ("dataflow.json", "dataflow"),
                ("attack-paths.json", "attack_graph"),
                ("security-twin.json", "twin"),
            ):
                p = findings_dir / name
                if p.exists():
                    try:
                        base_arts[key] = json.loads(p.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        pass

        # Also enrich with compose when audit artifacts exist for both sides
        if audit and base_arts.get("application_model"):
            try:
                from engines.security_diff.compose import (
                    run_security_diff as run_compose_diff,
                )

                composed = run_compose_diff(
                    root,
                    base_target=base_path,
                    base_ref=base_ref,
                    current_artifacts={
                        "application_model": audit.get("application_model"),
                        "dataflow": audit.get("dataflow"),
                        "attack_graph": audit.get("attack_graph"),
                        "twin": audit.get("security_twin") or audit.get("twin"),
                    },
                    base_artifacts=base_arts,
                    cheap_twin=False,
                )
                # Merge authz/tenant/control signals if pipeline missed them
                for key in ("authz_changes", "tenant_changes", "control_changes", "categories"):
                    if composed.get(key) and not security_diff.get(key):
                        security_diff[key] = composed[key]
                if composed.get("overall_security_change") and (
                    not security_diff.get("overall_security_change")
                    or security_diff.get("overall_security_change") in {"NONE", "LOW", "UNKNOWN"}
                ):
                    # Keep the higher of the two
                    order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
                    if order.get(str(composed["overall_security_change"]), 0) > order.get(
                        str(security_diff.get("overall_security_change")), 0
                    ):
                        security_diff["overall_security_change"] = composed[
                            "overall_security_change"
                        ]
            except Exception as exc:  # noqa: BLE001
                notes.append(f"compose enrich soft-skip: {exc}")

        if security_diff.get("baseline") in {"UNKNOWN", "BASELINE_UNAVAILABLE"}:
            notes.append("Security Diff baseline UNKNOWN — prior version not available")
    except Exception as exc:  # noqa: BLE001
        notes.append(f"security_diff error: {exc}")
        security_diff = {"baseline": "UNKNOWN", "error": str(exc), "summary": {}}

    findings = _extract_findings(audit, scan)
    regressions = _load_memory_regressions(root)
    predictive = _soft_predictive(root, security_diff)
    unknowns = _collect_unknowns(audit, security_diff)

    # Soft investigation for DEEP/MAX
    investigation_summary: dict[str, Any] | None = None
    if mode_u in {MODE_DEEP, MODE_MAX} and findings:
        try:
            from engines.investigation import run_investigation

            # Soft: investigate top finding only
            top = findings[0]
            investigation_summary = run_investigation(
                root, finding_id=str(top.get("id") or ""), budget="BALANCED"
            )
            notes.append("DEEP/MAX: soft investigation on top finding")
        except Exception as exc:  # noqa: BLE001
            notes.append(f"investigation soft-skip: {exc}")

    decision_pack = decide(
        findings=findings,
        security_diff=security_diff,
        regressions=regressions,
        unknowns=unknowns if (unknowns and pol.unknowns.review_required) else [],
        predictive_risks=predictive,
        policy=pol,
        analysis_failed=analysis_failed,
    )

    # Attack paths summary from audit
    attack_paths: list[dict[str, Any]] = []
    ag = (audit or {}).get("attack_graph") or security_diff.get("attack_path_delta") or {}
    if isinstance(ag, dict):
        for p in ag.get("paths") or []:
            if isinstance(p, dict):
                attack_paths.append(
                    {
                        "id": p.get("id"),
                        "status": p.get("status"),
                        "entry": p.get("entry"),
                        "target": p.get("target"),
                        "tags": p.get("tags") or [],
                    }
                )

    coverage: dict[str, Any] = {}
    if audit:
        try:
            from engines.report_ux import analysis_coverage

            coverage = analysis_coverage(audit)
        except Exception:  # noqa: BLE001
            coverage = {"present": [], "missing": [], "limited": True}

    result.update(
        {
            "decision": decision_pack["decision"],
            "blocking_reason": decision_pack["blocking_reason"],
            "review_why": decision_pack["review_why"],
            "exit_code": decision_pack["exit_code"],
            "findings": findings,
            "security_diff": security_diff,
            "attack_paths": attack_paths[:50],
            "regressions": regressions,
            "predictive_risks": predictive,
            "unknowns": unknowns,
            "controls": security_diff.get("control_changes") or [],
            "evidence": [],
            "coverage": coverage,
            "investigation": investigation_summary,
            "notes": notes,
            "out_dir": str(out),
            "policy": {
                "blocking": pol.blocking.__dict__,
                "unknowns": pol.unknowns.__dict__,
            },
        }
    )

    if analysis_failed and not findings and not (security_diff.get("categories") or security_diff.get("summary")):
        from engines.preship.schema import EXIT_TOOL_ERROR

        result["exit_code"] = EXIT_TOOL_ERROR
    else:
        # Successful analysis path — keep decision exit code even if a soft stage failed
        result["exit_code"] = decision_pack["exit_code"]

    # Write reports
    try:
        from engines.preship.report import write_preship_reports

        paths = write_preship_reports(result, out)
        result["report_paths"] = paths
    except Exception as exc:  # noqa: BLE001
        notes.append(f"report write error: {exc}")
        result["notes"] = notes

    return result
