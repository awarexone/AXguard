"""Pre-Ship schema — modes, decisions, exit codes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0.0"
TOOL_NAME = "axguard"

# Modes
MODE_QUICK = "QUICK"
MODE_STANDARD = "STANDARD"
MODE_DEEP = "DEEP"
MODE_MAX = "MAX"
MODES = frozenset({MODE_QUICK, MODE_STANDARD, MODE_DEEP, MODE_MAX})
DEFAULT_MODE = MODE_STANDARD

# Decision vocabulary
DECISION_PASS = "PASS"
DECISION_PASS_WITH_NOTES = "PASS_WITH_NOTES"
DECISION_REVIEW_REQUIRED = "REVIEW_REQUIRED"
DECISION_FAIL = "FAIL"
DECISIONS = frozenset(
    {
        DECISION_PASS,
        DECISION_PASS_WITH_NOTES,
        DECISION_REVIEW_REQUIRED,
        DECISION_FAIL,
    }
)

# Exit codes
# PASS=0, PASS_WITH_NOTES=0, REVIEW_REQUIRED=1, FAIL=2, TOOL_ERROR=3
EXIT_PASS = 0
EXIT_PASS_WITH_NOTES = 0
EXIT_REVIEW_REQUIRED = 1
EXIT_FAIL = 2
EXIT_TOOL_ERROR = 3

EXIT_BY_DECISION = {
    DECISION_PASS: EXIT_PASS,
    DECISION_PASS_WITH_NOTES: EXIT_PASS_WITH_NOTES,
    DECISION_REVIEW_REQUIRED: EXIT_REVIEW_REQUIRED,
    DECISION_FAIL: EXIT_FAIL,
}


def exit_code_for(decision: str, *, tool_error: bool = False) -> int:
    if tool_error:
        return EXIT_TOOL_ERROR
    return EXIT_BY_DECISION.get(str(decision).upper(), EXIT_TOOL_ERROR)


def empty_preship_result(
    *,
    target: str | None = None,
    mode: str = DEFAULT_MODE,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "mode": mode,
        "decision": DECISION_PASS,
        "blocking_reason": None,
        "review_why": None,
        "findings": [],
        "security_diff": {},
        "attack_paths": [],
        "regressions": [],
        "predictive_risks": [],
        "unknowns": [],
        "controls": [],
        "evidence": [],
        "coverage": {},
        "exit_code": EXIT_PASS,
        "notes": [],
    }
