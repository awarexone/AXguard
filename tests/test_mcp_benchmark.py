"""AXGuard MCP Benchmark — fixture contracts + policy rejection harness.

No live network. Soft-skips if engines.mcp missing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "mcp_benchmark"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _catalog() -> dict:
    return _load(FIXTURE / "expected.json")


def test_benchmark_catalog_shape():
    cat = _catalog()
    assert cat["kind"] == "mcp_benchmark_fixture"
    assert set(cat["labels"]) >= {
        "SHOULD_CALL",
        "SHOULD_NOT_CALL",
        "SHOULD_RETURN_UNKNOWN",
        "SHOULD_REJECT",
    }
    for case_id in cat["cases"]:
        case_path = FIXTURE / "cases" / case_id / "case.json"
        assert case_path.is_file(), case_id
        data = _load(case_path)
        assert data["id"] == case_id


def test_tool_discovery_fixture_matches_catalog():
    pytest.importorskip("engines.mcp.tools.catalog")
    from engines.mcp.tools.catalog import tool_names

    case = _load(FIXTURE / "cases" / "01_tool_discovery" / "case.json")
    names = set(tool_names())
    for t in case["expected"]["must_include_tools"]:
        assert t in names
    assert case["expected"]["primary_tool"] in names


def test_selection_accuracy_primary_is_security_review():
    case = _load(FIXTURE / "cases" / "02_selection_accuracy" / "case.json")
    assert case["expected"]["primary_tool"] == "axguard_security_review"
    assert "shell" in case["expected"]["avoid_tools"]


def test_when_to_call_and_not_call_labels():
    call = _load(FIXTURE / "cases" / "03_when_to_call" / "case.json")
    skip = _load(FIXTURE / "cases" / "04_when_not_to_call" / "case.json")
    assert call["expected"]["label"] == "SHOULD_CALL"
    assert skip["expected"]["label"] == "SHOULD_NOT_CALL"


def test_unknown_case_forbids_certainty():
    case = _load(FIXTURE / "cases" / "05_unknown_cases" / "case.json")
    assert case["expected"]["label"] == "SHOULD_RETURN_UNKNOWN"
    assert "SAFE" in case["expected"]["forbidden_claims"]


def test_reject_malicious_against_policy(tmp_path: Path):
    pytest.importorskip("engines.mcp.security.sandbox")
    from engines.mcp.policy import enforce
    from engines.mcp.schemas.errors import McpError
    from engines.mcp.security.sandbox import resolve_in_project

    project = tmp_path / "proj"
    project.mkdir()
    case = _load(FIXTURE / "cases" / "06_reject_malicious" / "case.json")
    for item in case["cases"]:
        expected_codes = set(item["expected"]["error_codes"])
        args = item["args"]
        with pytest.raises(McpError) as ei:
            if "operation" in args:
                enforce("axguard_scan", operation=args["operation"])
            else:
                resolve_in_project(project, args["path"])
        assert ei.value.code in expected_codes, item["prompt"]


def test_security_regression_scenarios_listed():
    case = _load(FIXTURE / "cases" / "07_security_regressions" / "case.json")
    names = {s["name"] for s in case["scenarios"]}
    assert "authorization_removed" in names
    assert "new_mcp_tool" in names
    assert case["expected"]["predictive_is_not_verified"] is True


def test_fix_verification_fixture():
    case = _load(FIXTURE / "cases" / "08_fix_verification" / "case.json")
    assert case["expected"]["primary_tool"] == "axguard_verify_fix"
    outcomes = set(case["expected"]["outcomes"])
    assert outcomes >= {"RESOLVED", "STILL_PRESENT", "REGRESSED"}
    pytest.importorskip("engines.mcp.tools.catalog")
    from engines.mcp.tools.catalog import tool_names

    assert "axguard_verify_fix" in tool_names()


def test_skill_tool_selection_fixture():
    case = _load(FIXTURE / "cases" / "09_skill_tool_selection" / "case.json")
    assert case["expected"]["after_security_sensitive_change"] == "axguard_security_review"
    assert case["expected"]["after_fix"] == "axguard_verify_fix"
