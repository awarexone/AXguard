"""CLI for ``axguard preship``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def add_preship_parser(subparsers: argparse._SubParsersAction) -> None:
    preship = subparsers.add_parser(
        "preship",
        help="Pre-Ship security gate — is this code safe enough to ship?",
    )
    preship.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Target path (default: .)",
    )
    preship.add_argument(
        "--mode",
        choices=("QUICK", "STANDARD", "DEEP", "MAX"),
        default="STANDARD",
        help="Analysis depth (default: STANDARD)",
    )
    preship.add_argument(
        "--base",
        default=None,
        help="Git base ref for Security Diff (e.g. HEAD~1, main...HEAD)",
    )
    preship.add_argument(
        "--base-path",
        default=None,
        help="Filesystem path to previous version for Security Diff",
    )
    preship.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout",
    )
    preship.add_argument(
        "--out-dir",
        default=None,
        help="Report directory (default: <target>/.findings/axguard/preship)",
    )
    preship.add_argument(
        "--fail-on-policy",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Apply blocking policy to exit codes (default: on)",
    )
    preship.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner")


def run_preship_command(args: argparse.Namespace) -> int:
    from engines.banner import print_banner
    from engines.preship import run_preship
    from engines.preship.report import render_preship_cli_text
    from engines.preship.schema import EXIT_TOOL_ERROR, exit_code_for

    if not getattr(args, "no_banner", False):
        print_banner(compact=True)
        print()

    target = Path(getattr(args, "path", ".") or ".").resolve()
    out_dir = getattr(args, "out_dir", None)
    if out_dir is None:
        out_dir = target / ".findings" / "axguard" / "preship"

    try:
        result = run_preship(
            target,
            mode=getattr(args, "mode", "STANDARD"),
            base_ref=getattr(args, "base", None),
            out_dir=out_dir,
            base_path=getattr(args, "base_path", None),
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: preship failed: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, default=str))
    else:
        print(render_preship_cli_text(result), end="")
        paths = result.get("report_paths") or {}
        if paths:
            print()
            print("Reports:")
            for k, v in paths.items():
                print(f"  {k}: {v}")

    if not getattr(args, "fail_on_policy", True):
        return 0
    return int(result.get("exit_code") or exit_code_for(str(result.get("decision") or "PASS")))
