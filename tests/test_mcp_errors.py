"""Structured MCP errors, marketing bans, and never-execute guards."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("engines.mcp.schemas.errors")

from engines.mcp.policy import BLOCKED_OPERATIONS, enforce, policy_snapshot
from engines.mcp.schemas.errors import ERROR_CODES, McpError, error_result
from engines.mcp.schemas.results import agent_friendly_text, success_result
from engines.mcp.security.untrusted import assert_never_execute_repo
from engines.mcp.tools.catalog import TOOL_CATALOG

MARKETING_MARKERS = (
    "star us on github",
    "⭐",
    "github stars",
    "follow the founder",
    "awarexone cloud",
    "sign up for awarexone",
    "upgrade to pro",
    "leave a star",
    "buy now",
)


def test_error_codes_cover_brief():
    required = {
        "INVALID_INPUT",
        "PROJECT_NOT_FOUND",
        "ANALYSIS_TIMEOUT",
        "RESOURCE_LIMIT",
        "APPROVAL_REQUIRED",
        "PERMISSION_DENIED",
        "UNSUPPORTED_OPERATION",
        "INSUFFICIENT_EVIDENCE",
        "ANALYSIS_FAILED",
        "TOOL_BUDGET_EXCEEDED",
    }
    assert required <= set(ERROR_CODES)


def test_mcp_error_as_dict():
    err = McpError("RESOURCE_LIMIT", "too big", details={"max": 1})
    d = err.as_dict()
    assert d["ok"] is False
    assert d["error"]["code"] == "RESOURCE_LIMIT"
    assert d["error"]["details"]["max"] == 1


@pytest.mark.parametrize("code", list(ERROR_CODES))
def test_each_error_code_serializes(code: str):
    d = error_result(code, f"msg for {code}")
    raw = json.dumps(d)
    assert code in raw
    assert json.loads(raw)["error"]["code"] == code


def test_catalog_and_agent_text_have_no_marketing():
    blob = json.dumps(TOOL_CATALOG).lower()
    for m in MARKETING_MARKERS:
        assert m not in blob
    text = agent_friendly_text(
        {
            "decision": "PASS",
            "risk": "LOW",
            "verified_findings": [],
            "recommended_action": "Ship with notes.",
        }
    )
    low = text.lower()
    for m in MARKETING_MARKERS:
        assert m not in low


def test_blocked_ops_include_exec_and_network():
    assert "execute_repo_code" in BLOCKED_OPERATIONS
    assert "shell" in BLOCKED_OPERATIONS
    assert "network" in BLOCKED_OPERATIONS
    assert "exploit" in BLOCKED_OPERATIONS
    snap = policy_snapshot()
    assert "blocked_operations" in snap
    with pytest.raises(McpError) as ei:
        enforce("axguard_scan", operation="execute_repo_code")
    assert ei.value.code == "UNSUPPORTED_OPERATION"


def test_assert_never_execute():
    with pytest.raises(McpError) as ei:
        assert_never_execute_repo()
    assert ei.value.code == "UNSUPPORTED_OPERATION"


def test_success_envelope_stable():
    out = success_result({"x": 1}, state="UNKNOWN", confidence="LOW", summary="s")
    assert out["ok"] is True
    assert out["x"] == 1
    assert out["provenance"]["state"] == "UNKNOWN"
    assert out["summary"] == "s"


def test_no_network_imports_in_mcp_core():
    """MCP core must not import requests/httpx for default analysis path."""
    root = Path(__file__).resolve().parents[1] / "engines" / "mcp"
    banned = ("import requests", "import httpx", "from requests", "from httpx")
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        src = path.read_text(encoding="utf-8", errors="replace")
        for b in banned:
            if b in src:
                offenders.append(f"{path.relative_to(root.parent.parent)}:{b}")
    assert offenders == []
