"""AXGuard Pre-Ship — ship / no-ship security gate."""

from __future__ import annotations

from engines.preship.decision import decide
from engines.preship.pipeline import run_preship
from engines.preship.policy import (
    PreshipPolicy,
    default_policy,
    load_preship_policy,
    map_preship_verdict,
)
from engines.preship.schema import (
    DECISION_FAIL,
    DECISION_PASS,
    DECISION_PASS_WITH_NOTES,
    DECISION_REVIEW_REQUIRED,
    DEFAULT_MODE,
    EXIT_BY_DECISION,
    MODES,
    exit_code_for,
)

__all__ = [
    "run_preship",
    "decide",
    "map_preship_verdict",
    "PreshipPolicy",
    "default_policy",
    "load_preship_policy",
    "exit_code_for",
    "DECISION_PASS",
    "DECISION_PASS_WITH_NOTES",
    "DECISION_REVIEW_REQUIRED",
    "DECISION_FAIL",
    "DEFAULT_MODE",
    "MODES",
    "EXIT_BY_DECISION",
]
