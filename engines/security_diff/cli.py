"""Optional CLI helpers for Security Diff (primary registration is in cli/main.py)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def add_diff_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register ``diff`` / ``security-diff`` only if not already present."""
    choices = getattr(subparsers, "choices", {}) or {}
    if "diff" in choices or "security-diff" in choices:
        return
    diff = subparsers.add_parser(
        "diff",
        aliases=["security-diff"],
        help="Security Diff — what became more dangerous between two versions",
    )
    diff.add_argument("base_or_path", nargs="?", default=None)
    diff.add_argument("path", nargs="?", default=".")
    diff.add_argument("--base-path", default=None)
    diff.add_argument("--base", default=None)
    diff.add_argument("--json", action="store_true")
    diff.add_argument("--out", default=None)
    diff.add_argument("--no-banner", action="store_true")
    diff.add_argument("--no-twin", action="store_true")


def run_diff_command(args: argparse.Namespace) -> int:
    """Fallback runner when invoked via engines.security_diff.cli."""
    from engines.banner import print_banner
    from engines.security_diff.pipeline import run_security_diff
    from engines.security_diff.render import render_security_diff_text as render_text

    if not getattr(args, "no_banner", False):
        print_banner(compact=True)
        print()

    current = Path(getattr(args, "path", ".") or ".").resolve()
    base_ref = getattr(args, "base", None)
    base_or = getattr(args, "base_or_path", None)
    base_path = getattr(args, "base_path", None)

    if base_or and base_path is None and base_ref is None:
        candidate = Path(base_or)
        if candidate.exists():
            base_path = str(candidate.resolve())
        else:
            base_ref = base_or

    try:
        result = run_security_diff(
            project=current,
            base=base_path or base_ref,
            write_report=False,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: security diff failed: {exc}", file=sys.stderr)
        return 3

    out_path = getattr(args, "out", None)
    if out_path:
        Path(out_path).write_text(
            json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
        )

    if getattr(args, "json", False) or getattr(args, "as_json", False):
        print(json.dumps(result, indent=2, default=str))
    else:
        print(render_text(result), end="")
    return 0
