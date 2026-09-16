"""AXGuard Security Diff Engine — security-aware comparison of two app states."""

from __future__ import annotations

from engines.security_diff.impact import should_fail
from engines.security_diff.pipeline import (
    run_security_diff,
    save_baseline_from_project,
    security_diff,
)
from engines.security_diff.render import render_security_diff_text
from engines.security_diff.schema import (
    BASELINE_UNKNOWN,
    CHANGE_CATEGORIES,
    CONTROL_STATES,
    SECURITY_DIFF_VERSION,
    SEVERITIES,
    empty_security_diff,
)
from engines.security_diff.store import list_baselines, load_baseline, save_baseline

# Artifact-dict compose API (MVP / tests)
from engines.security_diff.compose import run_security_diff as run_security_diff_compose
from engines.security_diff.git_base import list_changed_files, resolve_base_ref

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
]
