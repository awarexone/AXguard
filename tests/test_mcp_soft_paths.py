"""Soft paths for findings / evidence / paths / twin / memory / predictive.

Engines are mocked — unit tests never touch live network or untrusted exec.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("engines.mcp.tools.handlers")

from engines.mcp.schemas.errors import McpError
from engines.mcp.session import reset_session
from engines.mcp.tools import handlers as H


@pytest.fixture()
def session(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "main.py").write_text("print('hi')\n", encoding="utf-8")
    return reset_session(root)


def test_list_and_get_finding_soft(session):
    session.last_findings = [
        {
            "id": "f-42",
            "rule_id": "ssrf-1",
            "title": "SSRF candidate",
            "severity": "medium",
            "status": "UNVERIFIED",
        }
    ]
    listed = H.axguard_list_findings(refresh=False)
    assert listed["ok"] is True
    assert listed["finding_count"] == 1
    got = H.axguard_get_finding("f-42")
    assert got["ok"] is True
    assert got["finding"]["id"] == "f-42"


def test_get_finding_missing_structured_error(session):
    session.last_findings = []
    with patch(
        "engines.mcp.tools.handlers.bridge.run_scan_engine",
        return_value={"findings": []},
    ):
        with pytest.raises(McpError) as ei:
            H.axguard_get_finding("missing-id")
    assert ei.value.code == "INSUFFICIENT_EVIDENCE"


def test_evidence_soft_paths(session):
    session.last_evidence = {
        "evidence": [
            {"id": "e1", "finding_id": "f-42", "summary": "observed sink"},
            {"id": "e2", "finding_id": "other", "summary": "noise"},
        ],
        "chains": [{"id": "c1", "finding_id": "f-42", "steps": []}],
        "counter_evidence": [{"id": "ce1", "finding_id": "f-42", "summary": "sanitizer"}],
    }
    ev = H.axguard_get_evidence(finding_id="f-42")
    assert ev["ok"] is True
    assert len(ev["items"]) == 1
    chain = H.axguard_get_evidence_chain(finding_id="f-42")
    assert chain["ok"] is True
    counter = H.axguard_get_counter_evidence(finding_id="f-42")
    assert counter["ok"] is True
    assert counter["total"] == 1


def test_attack_paths_soft(session):
    graph = {
        "paths": [
            {
                "id": "ap-1",
                "status": "LIKELY",
                "summary": "entry → sink",
                "nodes": [{"label": "entry"}, {"label": "sink"}],
            }
        ]
    }
    with patch(
        "engines.mcp.tools.handlers.bridge.run_paths_engine",
        return_value=graph,
    ):
        found = H.axguard_find_attack_paths()
    assert found["ok"] is True
    assert found["path_count"] == 1
    session.last_attack_graph = graph
    one = H.axguard_get_attack_path("ap-1")
    assert one["ok"] is True
    explained = H.axguard_explain_attack_path("ap-1")
    assert explained["ok"] is True
    assert "→" in explained["explanation"] or explained["summary"]


def test_twin_memory_predictive_soft(session):
    with patch(
        "engines.mcp.tools.handlers.bridge.run_twin_engine",
        return_value={"twin": {"entities": [{"id": "e1"}], "summary": {"n": 1}}},
    ):
        twin = H.axguard_get_security_twin()
    assert twin["ok"] is True
    assert twin["present"] is True

    with patch(
        "engines.mcp.tools.handlers.bridge.run_memory_query",
        return_value={"status": "EMPTY"},
    ):
        mem = H.axguard_get_security_memory()
        hist = H.axguard_get_security_history()
        regs = H.axguard_find_regressions()
    assert mem["ok"] and hist["ok"] and regs["ok"]

    with patch(
        "engines.mcp.tools.handlers.bridge.run_predict_engine",
        return_value={
            "risks": [
                {
                    "category": "NEW_MCP_PERMISSION",
                    "confidence": "MEDIUM",
                    "summary": "new tool added",
                }
            ],
            "disclaimer": "PREDICTIVE — not verified findings.",
        },
    ):
        pred = H.axguard_predict_security_risks()
    assert pred["ok"] is True
    assert pred["risk_count"] == 1
    assert "PREDICTIVE" in (pred.get("disclaimer") or "").upper()
    # Predictive must not be framed as confirmed CVE
    blob = json.dumps(pred).lower()
    assert "cve-" not in blob
    assert "verified vulnerability" not in blob


def test_audit_and_investigate_require_approval(session):
    with pytest.raises(McpError) as ei:
        H.axguard_audit()
    assert ei.value.code == "APPROVAL_REQUIRED"
    with pytest.raises(McpError) as ei2:
        H.axguard_investigate(finding_id="f1")
    assert ei2.value.code == "APPROVAL_REQUIRED"


def test_get_project_ok(session):
    out = H.axguard_get_project()
    assert out["ok"] is True
    assert out["exists"] is True
    assert Path(out["project_root"]).exists()


def test_resources_progressive_disclosure(session):
    resources = pytest.importorskip("engines.mcp.resources")
    session.last_findings = [{"id": "f1", "title": "t", "severity": "low"}]
    session.last_review = {
        "decision": "PASS",
        "risk": "LOW",
        "verified_findings": [],
        "recommended_action": "ok",
    }
    listed = resources.list_resources()
    uris = {r["uri"] for r in listed}
    assert "axguard://project" in uris
    assert "axguard://findings" in uris
    proj = json.loads(resources.read_resource("axguard://project"))
    assert "project_root" in proj
    findings = json.loads(resources.read_resource("axguard://findings"))
    assert findings["finding_count"] == 1
    posture = json.loads(resources.read_resource("axguard://posture"))
    assert posture.get("decision") == "PASS"


def test_prompts_render_without_marketing():
    prompts = pytest.importorskip("engines.mcp.prompts")
    text = prompts.render_prompt("axguard-pre-ship", {"mode": "BALANCED"})
    low = text.lower()
    assert "axguard_security_review" in low
    assert "star us" not in low
    assert "awarexone cloud" not in low
