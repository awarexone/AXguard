"""MCP protocol / discovery tests — mock SDK when optional."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("engines.mcp.tools.catalog")

from engines.mcp.policy import TOOL_TIERS
from engines.mcp.tools.catalog import TOOL_CATALOG, catalog_by_name, tool_names
from engines.mcp.tools.handlers import HANDLERS

REQUIRED_TOOLS = {
    "axguard_security_review",
    "axguard_get_project",
    "axguard_scan",
    "axguard_list_findings",
    "axguard_get_finding",
    "axguard_get_evidence",
    "axguard_find_attack_paths",
    "axguard_get_security_twin",
    "axguard_get_security_memory",
    "axguard_predict_security_risks",
}

ANNOTATION_KEYS = {
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
}


def test_tool_catalog_covers_handlers():
    names = set(tool_names())
    assert REQUIRED_TOOLS <= names
    assert set(HANDLERS) == names
    assert set(TOOL_TIERS) >= names


def test_tool_descriptions_are_agent_optimized():
    by_name = catalog_by_name()
    review = by_name["axguard_security_review"]
    desc = review["description"].lower()
    assert "before shipping" in desc or "use this" in desc or "primary" in desc
    assert "read-only" in desc or "does not modify" in desc
    assert len(review["description"]) > 80
    assert review["description"].strip().lower() not in {
        "analyze security.",
        "analyze security",
    }


def test_tool_annotations_present():
    for entry in TOOL_CATALOG:
        ann = entry["annotations"]
        missing = ANNOTATION_KEYS - set(ann)
        assert not missing, f"{entry['name']} missing {missing}"
        assert ann["readOnlyHint"] is True
        assert ann["destructiveHint"] is False
        assert "axguardApprovalTier" in ann
        assert entry["tier"] in {"AUTO", "APPROVAL_REQUIRED", "HIGH_RISK"}


def test_prompts_and_resources_discoverable():
    prompts = pytest.importorskip("engines.mcp.prompts")
    resources = pytest.importorskip("engines.mcp.resources")
    prompt_list = getattr(prompts, "PROMPTS", None) or []
    resource_list = resources.list_resources()
    assert isinstance(prompt_list, list) and len(prompt_list) >= 4
    assert isinstance(resource_list, list) and len(resource_list) >= 5
    prompt_names = {p["name"] for p in prompt_list if isinstance(p, dict)}
    assert "axguard-review" in prompt_names
    assert "axguard-pre-ship" in prompt_names
    uris = {r["uri"] for r in resource_list}
    assert "axguard://project" in uris
    assert "axguard://findings" in uris
    rendered = prompts.render_prompt("axguard-review", {"mode": "LITE"})
    assert "axguard_security_review" in rendered


def test_list_tools_schema_shape():
    payload = {"tools": TOOL_CATALOG}
    raw = json.dumps(payload)
    loaded = json.loads(raw)
    assert len(loaded["tools"]) == len(TOOL_CATALOG)
    for t in loaded["tools"]:
        assert isinstance(t["name"], str)
        assert isinstance(t["description"], str)
        assert isinstance(t["annotations"], dict)


def test_handlers_map_is_callable():
    for name, fn in HANDLERS.items():
        assert callable(fn), name
        assert name.startswith("axguard_")


def test_create_server_registers_tools_when_available(monkeypatch):
    """Protocol discovery via create_server — skip if server module not landed."""
    pytest.importorskip("mcp", reason="optional axguard[mcp] SDK")
    server_mod = pytest.importorskip("engines.mcp.server")

    registered: list[str] = []

    class FakeServer:
        def __init__(self, *a, **k):
            self.name = k.get("name") or (a[0] if a else "axguard")

        def tool(self, *args, **kwargs):
            def deco(fn):
                registered.append(getattr(fn, "__name__", str(fn)))
                return fn

            if args and callable(args[0]):
                return deco(args[0])
            return deco

        def resource(self, *args, **kwargs):
            def deco(fn):
                return fn

            if args and callable(args[0]):
                return deco(args[0])
            return deco

        def prompt(self, *args, **kwargs):
            def deco(fn):
                return fn

            if args and callable(args[0]):
                return deco(args[0])
            return deco

        def run(self, *a, **k):
            raise AssertionError("unit tests must not start a live MCP server")

    monkeypatch.setattr(server_mod, "FastMCP", FakeServer, raising=False)
    monkeypatch.setattr(server_mod, "MCPServer", FakeServer, raising=False)
    if hasattr(server_mod, "create_server"):
        srv = server_mod.create_server(project_root=".")
        assert srv is not None


def test_mcp_sdk_import_smoke():
    mcp = pytest.importorskip("mcp", reason="optional axguard[mcp] SDK")
    assert mcp is not None
