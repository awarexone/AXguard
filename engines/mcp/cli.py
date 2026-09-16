"""CLI for ``axguard mcp …`` — local-first MCP server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def add_mcp_parser(sub: argparse._SubParsersAction) -> None:
    mcp = sub.add_parser(
        "mcp",
        help="AXGuard MCP server for AI coding agents (stdio)",
    )
    mcp.add_argument(
        "--project",
        default=None,
        help="Project root to isolate (default: cwd / AXGUARD_PROJECT_ROOT)",
    )
    mcp_sub = mcp.add_subparsers(dest="mcp_command")

    serve = mcp_sub.add_parser(
        "serve",
        help="Run MCP server over stdio (default when no subcommand)",
    )
    serve.add_argument(
        "--project",
        default=None,
        help="Project root to isolate (default: cwd / AXGUARD_PROJECT_ROOT)",
    )

    doctor = mcp_sub.add_parser("doctor", help="Diagnose MCP setup (no secrets)")
    doctor.add_argument(
        "--project",
        default=None,
        help="Project root (default: cwd)",
    )
    doctor.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON",
    )

    tools = mcp_sub.add_parser("tools", help="List MCP tools and approval tiers")
    tools.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON",
    )


def run_mcp_command(args: argparse.Namespace) -> int:
    cmd = getattr(args, "mcp_command", None) or "serve"

    if cmd in {None, "serve"}:
        return _cmd_serve(getattr(args, "project", None))

    if cmd == "doctor":
        return _cmd_doctor(
            getattr(args, "project", None),
            as_json=bool(getattr(args, "json", False)),
        )

    if cmd == "tools":
        return _cmd_tools(as_json=bool(getattr(args, "json", False)))

    print(f"Unknown mcp command: {cmd}", file=sys.stderr)
    return 2


def _cmd_serve(project: str | None) -> int:
    try:
        from engines.mcp.server import serve_stdio
    except ImportError as exc:
        print(
            "MCP server unavailable. Install with: pip install 'axguard[mcp]'\n"
            f"Detail: {exc}",
            file=sys.stderr,
        )
        return 2
    root = project
    try:
        serve_stdio(project_root=root)
    except ImportError as exc:
        print(
            "MCP SDK required. Install with: pip install 'axguard[mcp]'\n"
            f"Detail: {exc}",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        return 130
    return 0


def _cmd_doctor(project: str | None, *, as_json: bool) -> int:
    try:
        from engines.mcp.server import doctor
    except ImportError as exc:
        print(f"error: cannot import engines.mcp: {exc}", file=sys.stderr)
        return 2

    report: dict[str, Any] = doctor(project_root=project or Path.cwd())
    if as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        status = "ok" if report.get("ok") else "issues"
        print(f"AXGuard MCP doctor — {status}")
        print(f"  axguard:     {report.get('axguard_version')}")
        print(f"  project:     {report.get('project_root')}")
        print(f"  project_ok:  {report.get('project_exists')}")
        print(f"  findings_rw: {report.get('writable_findings')}")
        print(
            f"  mcp_sdk:     {report.get('mcp_sdk')} "
            f"({report.get('mcp_sdk_version')})"
        )
        print(f"  tools:       {report.get('tool_count')}")
        for issue in report.get("issues") or []:
            print(f"  issue: {issue}")
    return 0 if report.get("ok") else 1


def _cmd_tools(*, as_json: bool) -> int:
    try:
        from engines.mcp.tools.catalog import TOOL_CATALOG
    except ImportError as exc:
        print(f"error: cannot import engines.mcp: {exc}", file=sys.stderr)
        return 2

    if as_json:
        print(json.dumps(TOOL_CATALOG, indent=2))
    else:
        print(f"{'TOOL':<36} {'TIER':<20} DESCRIPTION")
        print("-" * 100)
        for t in TOOL_CATALOG:
            desc = t["description"].replace("\n", " ")
            if len(desc) > 60:
                desc = desc[:57] + "..."
            print(f"{t['name']:<36} {t['tier']:<20} {desc}")
    return 0
