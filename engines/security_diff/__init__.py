"""AXGuard Security Diff Engine — security-aware comparison of two app states."""

from __future__ import annotations

from typing import Any

from engines.security_diff.impact import should_fail
from engines.security_diff.pipeline import (
    run_security_diff as _pipeline_run,
    save_baseline_from_project,
    security_diff as _security_diff,
)
from engines.security_diff.render import render_security_diff_text
from engines.security_diff.schema import (
    BASELINE_UNAVAILABLE,
    BASELINE_UNKNOWN,
    CHANGE_CATEGORIES,
    CONTROL_STATES,
    SECURITY_DIFF_VERSION,
    SEVERITIES,
    empty_security_diff,
    is_baseline_unavailable,
)
from engines.security_diff.store import list_baselines, load_baseline, save_baseline
from engines.security_diff.compose import run_security_diff as run_security_diff_compose
from engines.security_diff.git_base import list_changed_files, resolve_base_ref


def security_diff(
    base: Any = None,
    head: Any = None,
    project: Any = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Primary reusable API (CLI / MCP / GitHub / Pre-Ship / CI)."""
    return _security_diff(base=base, head=head, project=project, options=options)


def run_security_diff(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Compatibility entry point for product CLI and legacy compose callers.

    - Product/CLI: ``run_security_diff(project=..., base=..., head=..., ...)``
    - Legacy compose: ``run_security_diff(path, base_target=..., base_ref=..., ...)``
      → routed to ``run_security_diff_compose`` when artifact kwargs are present.
    """
    if args or any(
        k in kwargs
        for k in (
            "current_target",
            "base_target",
            "base_ref",
            "current_artifacts",
            "base_artifacts",
            "cheap_twin",
        )
    ):
        if kwargs.get("current_artifacts") or kwargs.get("base_artifacts"):
            return run_security_diff_compose(*args, **kwargs)
        current = (
            args[0]
            if args
            else kwargs.get("current_target") or kwargs.get("project") or "."
        )
        base_target = kwargs.get("base_target")
        base_ref = kwargs.get("base_ref")
        return _pipeline_run(
            project=current,
            base=base_target or base_ref,
            head=kwargs.get("head"),
            fail_on=kwargs.get("fail_on", "none"),
            incremental=kwargs.get("incremental", True),
            investigate=kwargs.get("investigate", False),
            write_report=kwargs.get("write_report", False),
            use_snapshot=kwargs.get("use_snapshot", False),
            baseline_name=kwargs.get("baseline_name", "default"),
            out_dir=kwargs.get("out_dir"),
            skip_twin=not kwargs.get("cheap_twin", True),
        )
    return _pipeline_run(**kwargs)


__all__ = [
    "SECURITY_DIFF_VERSION",
    "empty_security_diff",
    "security_diff",
    "run_security_diff",
    "run_security_diff_compose",
    "render_security_diff_text",
    "resolve_base_ref",
    "list_changed_files",
    "save_baseline",
    "load_baseline",
    "list_baselines",
    "save_baseline_from_project",
    "should_fail",
    "CHANGE_CATEGORIES",
    "CONTROL_STATES",
    "SEVERITIES",
    "BASELINE_UNKNOWN",
    "BASELINE_UNAVAILABLE",
    "is_baseline_unavailable",
]
