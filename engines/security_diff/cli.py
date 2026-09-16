"""Optional CLI helpers for Security Diff (primary registration is in cli/main.py)."""

from __future__ import annotations

import argparse
from typing import Any


def add_diff_parser(subparsers: argparse._SubParsersAction) -> None:
    """No-op when ``diff`` is already registered in ``cli.main``.

    Kept for backward compatibility with soft-import call sites.
    """
    if "diff" in getattr(subparsers, "choices", {}):
        return


def render_security_diff_text(result: dict[str, Any]) -> str:
    from engines.security_diff.report import render_text

    return render_text(result)
