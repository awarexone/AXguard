"""Security Diff pipeline — reusable core API for CLI / MCP / GitHub / Pre-Ship."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engines.security_diff.compare import compare_states
from engines.security_diff.git_ops import (
    cleanup_materialized,
    materialize_ref,
    resolve_comparison,
)
from engines.security_diff.impact import classify_impact, should_fail
from engines.security_diff.report import write_security_diff_report
from engines.security_diff.schema import (
    BASELINE_AXGUARD_SNAPSHOT,
    BASELINE_GIT,
    BASELINE_PATH,
    BASELINE_UNAVAILABLE,
    DECISION_UNKNOWN,
    IMPACT_UNKNOWN,
    empty_security_diff,
    side_ref,
    utc_now,
)
from engines.security_diff.state import build_security_state
from engines.security_diff.store import load_baseline, save_baseline


def _as_path(value: Any) -> Path | None:
    if value is None:
        return None
    if isinstance(value, Path):
        return value
    text = str(value).strip()
    if not text:
        return None
    p = Path(text)
    if p.exists():
        return p.resolve()
    return None


def _looks_like_git_ref(value: str) -> bool:
    if value in {".", "./"}:
        return False
    p = Path(value)
    if p.exists():
        return False
    return True


def save_baseline_from_project(
    project: Path | str,
    name: str = "default",
    *,
    options: dict[str, Any] | None = None,
) -> Path:
    root = Path(project).resolve()
    state = build_security_state(root, options=options)
    return save_baseline(root, state, name=name)


def security_diff(
    base: Any = None,
    head: Any = None,
    project: Any = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare two application states and explain security-relevant changes.

    Parameters
    ----------
    base:
        Git ref, path, or None (auto / snapshot).
    head:
        Git ref, path, working tree, or None (defaults to project).
    project:
        Project root (default ``.``).
    options:
        verbose, fail_on, incremental, investigate, reuse_artifacts,
        baseline_name, write_report, out_dir, skip_*, range_spec, ...
    """
    opts = dict(options or {})
    project_path = _as_path(project) or Path(".").resolve()
    if not project_path.is_dir():
        project_path = project_path.parent

    range_spec = opts.get("range_spec")
    baseline_name = str(opts.get("baseline_name") or "default")
    incremental = bool(opts.get("incremental", True))
    materialized: list[Path] = []

    result = empty_security_diff(
        current_target=str(project_path),
        baseline=BASELINE_UNAVAILABLE,
    )
    result["generated_at"] = utc_now()
    result["options"] = {
        k: v
        for k, v in opts.items()
        if k
        in {
            "fail_on",
            "incremental",
            "investigate",
            "reuse_artifacts",
            "baseline_name",
            "skip_predict",
            "skip_memory",
            "skip_investigation",
        }
    }

    base_path: Path | None = _as_path(base)
    head_path: Path | None = _as_path(head) or project_path
    base_ref: str | None = None
    head_ref: str | None = None
    baseline_source = BASELINE_UNAVAILABLE
    changed_files: list[str] = []
    notes: list[str] = []

    # --- resolve baseline -------------------------------------------------
    if base_path is not None and base_path.is_dir():
        baseline_source = BASELINE_PATH
        base_ref = str(base_path)
    elif base is not None and _looks_like_git_ref(str(base)):
        base_ref = str(base)
    elif range_spec:
        base_ref = None  # resolved below
    elif opts.get("use_snapshot") or (
        base is None and opts.get("prefer_snapshot")
    ):
        snap = load_baseline(project_path, baseline_name)
        if snap and isinstance(snap.get("state"), dict):
            baseline_source = BASELINE_AXGUARD_SNAPSHOT
            base_state = snap["state"]
            head_state = build_security_state(
                head_path,
                changed_files=None,
                incremental=incremental,
                options=opts,
            )
            result = _finalize(
                result,
                base_state=base_state,
                head_state=head_state,
                baseline_source=baseline_source,
                base_side=side_ref(
                    source=BASELINE_AXGUARD_SNAPSHOT,
                    ref=baseline_name,
                    path=str(project_path),
                    label=f"snapshot:{baseline_name}",
                ),
                head_side=side_ref(
                    source=BASELINE_PATH,
                    path=str(head_path),
                    label=str(head_path),
                ),
                changed_files=[],
                notes=["BASELINE_SOURCE: AXGUARD_SNAPSHOT"],
                opts=opts,
                project_path=project_path,
            )
            return result
        notes.append("AXGuard snapshot baseline not found")
        result["baseline"] = BASELINE_UNAVAILABLE
        result["notes"] = notes
        result["security_impact"] = {
            "level": IMPACT_UNKNOWN,
            "reason": "BASELINE_UNAVAILABLE — no valid baseline for comparison.",
            "decision": DECISION_UNKNOWN,
        }
        result["unknowns"].append(
            {
                "area": "baseline",
                "reason": "No git base and no stored AXGuard snapshot.",
                "status": "UNKNOWN",
            }
        )
        return result
    else:
        # Auto: try git, else snapshot
        base_ref = None

    cmp = resolve_comparison(
        project_path,
        base=base_ref or (str(base) if base and base_path is None else None),
        head=str(head) if head and head_path == project_path and head is not None and _looks_like_git_ref(str(head)) else None,
        range_spec=range_spec or (str(base) if isinstance(base, str) and "..." in str(base) else None),
    )
    notes.extend(cmp.get("notes") or [])

    if baseline_source == BASELINE_PATH and base_path is not None:
        pass
    elif cmp.get("available"):
        baseline_source = BASELINE_GIT
        base_ref = str(cmp.get("base_ref") or base_ref)
        head_ref = str(cmp.get("head_ref") or "HEAD")
        changed_files = list(cmp.get("changed_files") or [])
        # Materialize base tree
        mat = materialize_ref(Path(cmp["repo"]), str(cmp.get("base_sha") or base_ref))
        if mat is None:
            notes.append("failed to materialize git base tree")
            result["baseline"] = BASELINE_UNAVAILABLE
            result["notes"] = notes
            result["security_impact"] = {
                "level": IMPACT_UNKNOWN,
                "reason": "BASELINE_UNAVAILABLE — git base could not be materialized.",
                "decision": DECISION_UNKNOWN,
            }
            return result
        materialized.append(mat)
        base_path = mat
        # Head: working tree unless head ref != HEAD
        if head_ref not in {"HEAD", "WORKTREE", "."} and cmp.get("head_sha"):
            code_head = materialize_ref(Path(cmp["repo"]), str(cmp["head_sha"]))
            if code_head is not None:
                materialized.append(code_head)
                head_path = code_head
    else:
        # Fall back to snapshot
        snap = load_baseline(project_path, baseline_name)
        if snap and isinstance(snap.get("state"), dict):
            baseline_source = BASELINE_AXGUARD_SNAPSHOT
            try:
                result = _finalize(
                    result,
                    base_state=snap["state"],
                    head_state=build_security_state(
                        head_path,
                        incremental=incremental,
                        options=opts,
                    ),
                    baseline_source=baseline_source,
                    base_side=side_ref(
                        source=BASELINE_AXGUARD_SNAPSHOT,
                        ref=baseline_name,
                        path=str(project_path),
                        label=f"snapshot:{baseline_name}",
                    ),
                    head_side=side_ref(
                        source=BASELINE_PATH,
                        path=str(head_path),
                        label=str(head_path),
                    ),
                    changed_files=[],
                    notes=notes + ["BASELINE_SOURCE: AXGUARD_SNAPSHOT"],
                    opts=opts,
                    project_path=project_path,
                )
            finally:
                for m in materialized:
                    cleanup_materialized(m)
            return result

        result["baseline"] = BASELINE_UNAVAILABLE
        result["notes"] = notes + [
            "BASELINE_UNAVAILABLE — no git base and no AXGuard snapshot."
        ]
        result["security_impact"] = {
            "level": IMPACT_UNKNOWN,
            "reason": "BASELINE_UNAVAILABLE — no valid baseline for comparison.",
            "decision": DECISION_UNKNOWN,
        }
        result["unknowns"].append(
            {
                "area": "baseline",
                "reason": "No valid baseline exists.",
                "status": "UNKNOWN",
            }
        )
        return result

    try:
        assert base_path is not None and head_path is not None
        base_state = build_security_state(
            base_path,
            changed_files=changed_files if incremental else None,
            incremental=incremental,
            options=opts,
        )
        head_state = build_security_state(
            head_path,
            changed_files=changed_files if incremental else None,
            incremental=incremental,
            options=opts,
        )
        result = _finalize(
            result,
            base_state=base_state,
            head_state=head_state,
            baseline_source=baseline_source,
            base_side=side_ref(
                source=baseline_source,
                ref=base_ref,
                path=str(base_path) if baseline_source == BASELINE_PATH else None,
                label=base_ref or str(base_path),
                sha=cmp.get("base_sha") if baseline_source == BASELINE_GIT else None,
            ),
            head_side=side_ref(
                source=BASELINE_PATH
                if head_path == project_path
                else baseline_source,
                ref=head_ref,
                path=str(head_path),
                label=head_ref or str(head_path),
                sha=cmp.get("head_sha") if baseline_source == BASELINE_GIT else None,
            ),
            changed_files=changed_files,
            notes=notes,
            opts=opts,
            project_path=project_path,
        )
    finally:
        for m in materialized:
            cleanup_materialized(m)

    return result


def _finalize(
    result: dict[str, Any],
    *,
    base_state: dict[str, Any],
    head_state: dict[str, Any],
    baseline_source: str,
    base_side: dict[str, Any],
    head_side: dict[str, Any],
    changed_files: list[str],
    notes: list[str],
    opts: dict[str, Any],
    project_path: Path,
) -> dict[str, Any]:
    partial = compare_states(base_state, head_state, options=opts)

    result.update(
        {
            "base": base_side,
            "head": head_side,
            "baseline": baseline_source,
            "current_target": head_side.get("path"),
            "base_target": base_side.get("path") or base_side.get("ref"),
            "base_ref": base_side.get("ref"),
            "changed_files": changed_files,
            "notes": notes,
        }
    )
    for key, value in partial.items():
        result[key] = value

    # Soft: Security Memory regressions
    if not opts.get("skip_memory"):
        try:
            from engines.memory.changes import compare_snapshots
            from engines.memory.store import load_index, load_snapshot, resolve_memory_dir

            mem_dir = resolve_memory_dir(project_path / ".findings/axguard/memory")
            index = load_index(mem_dir)
            snaps = index.get("snapshots") or index.get("history") or []
            if len(snaps) >= 2:
                before_id = (
                    snaps[-2].get("id")
                    if isinstance(snaps[-2], dict)
                    else snaps[-2]
                )
                after_id = (
                    snaps[-1].get("id")
                    if isinstance(snaps[-1], dict)
                    else snaps[-1]
                )
                before = load_snapshot(str(before_id), mem_dir)
                after = load_snapshot(str(after_id), mem_dir)
                if before and after:
                    mem_diff = compare_snapshots(before, after)
                    result["memory_delta"] = {
                        "outcomes": mem_diff.get("outcomes") or {},
                        "regressions": (mem_diff.get("outcomes") or {}).get("REGRESSED")
                        or [],
                        "summary": mem_diff.get("summary") or {},
                    }
                    for reg in result["memory_delta"]["regressions"]:
                        if reg not in result["regressions"]:
                            result["regressions"].append(reg)
        except Exception as exc:  # noqa: BLE001
            result["unknowns"].append(
                {
                    "area": "memory",
                    "reason": f"memory compare soft-failed: {exc}",
                    "status": "UNKNOWN",
                }
            )

    # Soft: investigation for control-removal candidates
    if opts.get("investigate"):
        candidates = [
            c
            for c in (result.get("control_delta") or {}).get("changes") or []
            if c.get("state") in {"REMOVED", "WEAKENED"}
        ]
        if candidates:
            try:
                from engines.investigation import investigate_candidate

                for cand in candidates[:3]:
                    inv = investigate_candidate(
                        project_path,
                        candidate={
                            "title": cand.get("detail"),
                            "control": cand,
                        },
                    )
                    result.setdefault("evidence", []).append(
                        {"kind": "investigation", "result": inv}
                    )
            except Exception as exc:  # noqa: BLE001
                result["unknowns"].append(
                    {
                        "area": "investigation",
                        "reason": str(exc),
                        "status": "UNKNOWN",
                    }
                )

    result["security_impact"] = classify_impact(result)
    result["overall_security_change"] = result["security_impact"].get("level")

    # Sync summary unknowns count
    summary = result.get("summary") or {}
    summary["unknowns"] = len(result.get("unknowns") or [])
    summary["regressions"] = len(result.get("regressions") or [])
    summary["predictive_risks"] = len(result.get("predictive_risks") or [])
    result["summary"] = summary

    if opts.get("write_report"):
        out_dir = Path(opts.get("out_dir") or (project_path / ".findings/axguard"))
        write_security_diff_report(result, out_dir)

    return result


def run_security_diff(
    *,
    project: Path | str = ".",
    base: str | None = None,
    head: str | None = None,
    range_spec: str | None = None,
    baseline_name: str = "default",
    use_snapshot: bool = False,
    verbose: bool = False,
    fail_on: str = "none",
    incremental: bool = True,
    investigate: bool = False,
    out_dir: Path | str | None = None,
    write_report: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """CLI-friendly wrapper around :func:`security_diff`."""
    options = {
        "range_spec": range_spec,
        "baseline_name": baseline_name,
        "use_snapshot": use_snapshot,
        "prefer_snapshot": use_snapshot,
        "verbose": verbose,
        "fail_on": fail_on,
        "incremental": incremental,
        "investigate": investigate,
        "out_dir": out_dir,
        "write_report": write_report,
        **kwargs,
    }
    return security_diff(base=base, head=head, project=project, options=options)


# Re-export for CI helpers
__all__ = [
    "security_diff",
    "run_security_diff",
    "save_baseline_from_project",
    "should_fail",
]
