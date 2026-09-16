"""Tests for engines.security_diff — authz regression + schema."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from engines.security_diff.authz_diff import compare_authz, scan_path_for_authz
from engines.security_diff.compose import run_security_diff as compose_diff
from engines.security_diff.schema import (
    CHANGE_CATEGORIES,
    NEW_ENDPOINT,
    REMOVED_SECURITY_CONTROL,
    empty_security_diff,
)

ROOT = Path(__file__).resolve().parents[1]
BEFORE = ROOT / "fixtures" / "preship" / "regression_authz" / "before"
AFTER = ROOT / "fixtures" / "preship" / "regression_authz" / "after"


def test_empty_security_diff_shape():
    empty = empty_security_diff()
    assert "categories" in empty
    assert "summary" in empty
    assert "overall_security_change" in empty
    assert "authz_changes" in empty
    assert NEW_ENDPOINT in CHANGE_CATEGORIES
    assert REMOVED_SECURITY_CONTROL in CHANGE_CATEGORIES


def test_authz_scan_detects_ownership():
    before = scan_path_for_authz(BEFORE)
    after = scan_path_for_authz(AFTER)
    assert before["has_ownership"] is True
    assert after["has_ownership"] is False


def test_regression_authz_ownership_removed():
    result = compare_authz(before_target=BEFORE, after_target=AFTER)
    changes = result.get("authz_changes") or []
    assert any(
        "ownership" in str(c.get("change") or "").lower()
        or "removed" in str(c.get("change") or "").lower()
        for c in changes
    ), changes


def test_compose_before_after_flags_control_or_authz(monkeypatch):
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *a, **k: (_ for _ in ()).throw(OSError("no net")),
    )
    # Prefer lightweight compose with text scans even if AG build is heavy
    diff = compose_diff(AFTER, base_target=BEFORE, cheap_twin=False)
    assert diff.get("baseline") in {"PATH", "GIT", "ARTIFACTS", "UNKNOWN", "BASELINE_UNAVAILABLE"}
    authz = diff.get("authz_changes") or []
    cats = [c.get("category") for c in (diff.get("categories") or [])]
    controls = diff.get("control_changes") or []
    assert (
        authz
        or REMOVED_SECURITY_CONTROL in cats
        or any(c.get("state") in {"REMOVED", "WEAKENED"} for c in controls)
        or str(diff.get("overall_security_change") or "") in {"HIGH", "CRITICAL", "MEDIUM"}
    ), {
        "authz": authz,
        "cats": cats,
        "controls": controls,
        "overall": diff.get("overall_security_change"),
    }


def test_pipeline_run_security_diff_no_socket(monkeypatch, tmp_path):
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *a, **k: (_ for _ in ()).throw(OSError("no net")),
    )
    from engines.security_diff import run_security_diff

    result = run_security_diff(
        project=AFTER,
        base=str(BEFORE),
        write_report=False,
    )
    assert isinstance(result, dict)
    assert "summary" in result
    assert result.get("overall_security_change") is not None


def test_compare_states_endpoint_and_control():
    from engines.security_diff.compare import compare_states
    from engines.security_diff.schema import NEW_ENDPOINT

    before = {
        "application_model": {
            "entrypoints": [{"method": "GET", "path": "/a"}],
            "security_controls": [
                {"type": "authorization", "name": "own", "file": "a.py"}
            ],
        },
        "dataflow": {"paths": []},
        "attack_graph": {"paths": [], "graph": {"nodes": [], "edges": []}},
        "twin": None,
        "predictive": None,
        "unknowns": [],
    }
    after = {
        "application_model": {
            "entrypoints": [
                {"method": "GET", "path": "/a"},
                {"method": "POST", "path": "/api/export"},
            ],
            "security_controls": [],
        },
        "dataflow": {"paths": []},
        "attack_graph": {"paths": [], "graph": {"nodes": [], "edges": []}},
        "twin": None,
        "predictive": None,
        "unknowns": [],
    }
    partial = compare_states(before, after)
    assert partial["summary"]["new_endpoints"] == 1
    assert partial["summary"]["removed_controls"] == 1
    assert NEW_ENDPOINT in {c["category"] for c in partial["categories"]}


def test_control_fingerprint_ignores_path():
    from engines.security_diff.controls import control_fingerprint

    a = {"type": "authorization", "name": "check_ownership", "file": "a.py"}
    b = {"type": "authorization", "name": "check_ownership", "file": "b.py"}
    assert control_fingerprint(a) == control_fingerprint(b)


def test_baseline_unavailable_no_fabricate(tmp_path):
    from engines.security_diff import security_diff

    result = security_diff(project=tmp_path, options={"use_snapshot": True})
    assert result["baseline"] in {
        "BASELINE_UNAVAILABLE",
        "UNKNOWN",
    }
    assert result["security_impact"]["decision"] in {"UNKNOWN", "PASS"}


def test_mcp_compact_and_github_summary():
    from engines.security_diff.github_summary import (
        compact_mcp_response,
        format_github_pr_summary,
    )
    from engines.security_diff.schema import empty_security_diff

    d = empty_security_diff()
    d["security_impact"] = {"level": "HIGH", "decision": "REVIEW_REQUIRED", "reason": "x"}
    compact = compact_mcp_response(d)
    assert "new_attack_paths" in compact
    text = format_github_pr_summary(d)
    assert "AXGUARD SECURITY DIFF" in text


def test_cli_parses_diff_head_tilde():
    """Documented `axguard diff HEAD~1` must parse (no subparser collision)."""
    from cli.main import build_parser

    parser = build_parser()
    args = parser.parse_args(["diff", "HEAD~1", "--no-banner"])
    assert args.command == "diff"
    assert args.tokens == ["HEAD~1"]


def test_cli_parses_diff_range_and_baseline_save():
    from cli.main import build_parser

    parser = build_parser()
    args = parser.parse_args(["diff", "main...HEAD", "--json", "--no-banner"])
    assert args.tokens == ["main...HEAD"]
    assert args.as_json is True

    args2 = parser.parse_args(["diff", "baseline", "save", ".", "--name", "ci"])
    assert args2.tokens == ["baseline", "save", "."]
    assert args2.name == "ci"


def test_unavailable_baseline_sets_overall_unknown(tmp_path):
    from engines.security_diff import security_diff

    result = security_diff(project=tmp_path, options={"use_snapshot": True})
    assert result["baseline"] in {"BASELINE_UNAVAILABLE", "UNKNOWN"}
    assert result["overall_security_change"] in {"UNKNOWN", "BASELINE_UNAVAILABLE"}
    assert (result.get("security_impact") or {}).get("level") == "UNKNOWN"
