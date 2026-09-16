"""axguard_security_review orchestration with mocked engines (no live network)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("engines.mcp.tools.security_review")

from engines.mcp.schemas.errors import McpError
from engines.mcp.session import reset_session
from engines.mcp.tools.security_review import run_security_review

MARKETING = (
    "star us",
    "github stars",
    "awarexone cloud",
    "sign up",
    "upgrade to pro",
)


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "api.py").write_text(
        "def get_user(user_id):\n"
        "    # authorization intentionally missing\n"
        "    return db.users[user_id]\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture()
def session(project: Path):
    return reset_session(project, mode="BALANCED")


def _scan_result(findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    findings = findings or [
        {
            "id": "f1",
            "rule_id": "auth-idor",
            "title": "Missing object-level authorization",
            "severity": "high",
            "status": "UNVERIFIED",
            "message": "user_id reaches db without ownership check",
            "file": "api.py",
            "line": 2,
        }
    ]
    return {"findings": findings, "finding_count": len(findings), "target": "api.py"}


def test_security_review_lite_mocked(session, project: Path):
    with patch(
        "engines.mcp.tools.security_review.run_scan_engine",
        return_value=_scan_result(),
    ) as scan:
        out = run_security_review(
            mode="LITE", scope="project", session=session, approved=False
        )
    assert out["ok"] is True
    review = out["review"]
    assert review["mode"] == "LITE"
    assert "scan" in review["stages_run"]
    assert review["decision"] in {"PASS", "MONITOR", "REVIEW_REQUIRED", "BLOCK"}
    assert "agent_text" in out
    assert "SECURITY REVIEW" in out["agent_text"]
    blob = json.dumps(out).lower()
    for m in MARKETING:
        assert m not in blob
    scan.assert_called()
    # LITE should not have called twin/paths via real engines (mocked path only scan)


def test_security_review_deep_requires_approval(session):
    with pytest.raises(McpError) as ei:
        run_security_review(mode="DEEP", session=session, approved=False)
    assert ei.value.code == "APPROVAL_REQUIRED"


def test_security_review_balanced_orchestrates_with_mocks(session):
    adv = {
        "findings": [
            {
                "id": "f1",
                "title": "Missing object-level authorization",
                "severity": "high",
                "status": "CONFIRMED",
                "surviving_evidence": [{"summary": "ownership not checked"}],
            }
        ]
    }
    paths = {
        "paths": [
            {
                "id": "p1",
                "status": "LIKELY",
                "summary": "user → /api/users/{id} → db",
                "nodes": [
                    {"label": "Authenticated user"},
                    {"label": "/api/users/{id}"},
                    {"label": "database"},
                ],
            }
        ]
    }
    with (
        patch(
            "engines.mcp.tools.security_review.run_scan_engine",
            return_value=_scan_result(),
        ),
        patch(
            "engines.mcp.tools.security_review.run_surface_engine",
            return_value={"routes": [], "sinks": [], "summary": {"route_count": 1}},
        ),
        patch(
            "engines.mcp.tools.security_review.run_memory_query",
            return_value={"status": "EMPTY", "unknowns": []},
        ),
        patch(
            "engines.mcp.tools.security_review.run_twin_engine",
            return_value={"twin": {"entities": []}},
        ),
        patch(
            "engines.mcp.tools.security_review.run_flow_engine",
            return_value={"paths": []},
        ),
        patch(
            "engines.mcp.tools.security_review.run_adversary_engine",
            return_value=adv,
        ),
        patch(
            "engines.mcp.tools.security_review.run_paths_engine",
            return_value=paths,
        ),
        patch(
            "engines.mcp.tools.security_review.run_predict_engine",
            return_value={
                "risks": [
                    {
                        "category": "AUTHORIZATION_DRIFT",
                        "confidence": "MEDIUM",
                        "summary": "authz points increased",
                    }
                ]
            },
        ),
    ):
        out = run_security_review(
            mode="BALANCED", scope="file", path="api.py", session=session
        )

    assert out["ok"] is True
    review = out["review"]
    assert review["decision"] in {"BLOCK", "REVIEW_REQUIRED"}
    assert review["risk"] == "HIGH"
    assert review["verified_findings"]
    assert review["verified_findings"][0]["title"]
    assert review["attack_paths"]
    assert "provenance" in out
    assert out["provenance"]["source"] == "AXGuard"


def test_security_review_invalid_mode(session):
    with pytest.raises(McpError) as ei:
        run_security_review(mode="ULTRA", session=session)
    assert ei.value.code == "INVALID_INPUT"


def test_security_review_file_scope_requires_path(session):
    with pytest.raises(McpError) as ei:
        run_security_review(mode="LITE", scope="file", path=None, session=session)
    assert ei.value.code == "INVALID_INPUT"


def test_security_review_path_escape_rejected(session, tmp_path: Path):
    with pytest.raises(McpError) as ei:
        run_security_review(
            mode="LITE",
            scope="file",
            path="../outside.py",
            session=session,
        )
    assert ei.value.code == "PERMISSION_DENIED"


def test_security_review_soft_engine_failure_still_returns(session):
    """Engine ImportError / runtime failure must soft-degrade, not crash."""

    def boom(*a, **k):
        raise RuntimeError("engine offline")

    with (
        patch(
            "engines.mcp.tools.security_review.run_scan_engine",
            side_effect=boom,
        ),
        patch(
            "engines.mcp.tools.security_review.run_surface_engine",
            side_effect=boom,
        ),
        patch(
            "engines.mcp.tools.security_review.run_memory_query",
            side_effect=boom,
        ),
        patch(
            "engines.mcp.tools.security_review.run_twin_engine",
            side_effect=boom,
        ),
        patch(
            "engines.mcp.tools.security_review.run_flow_engine",
            side_effect=boom,
        ),
    ):
        out = run_security_review(mode="BALANCED", session=session)
    assert out["ok"] is True
    review = out["review"]
    assert isinstance(review["stage_errors"], list)
    # May have empty stages_run if all soft-failed
    assert review["decision"] in {"PASS", "MONITOR", "REVIEW_REQUIRED", "BLOCK"}


def test_security_review_unknown_is_valid_when_no_evidence(session):
    with patch(
        "engines.mcp.tools.security_review.run_scan_engine",
        return_value={"findings": [], "finding_count": 0},
    ):
        out = run_security_review(mode="LITE", session=session)
    review = out["review"]
    # No verified findings → not forced VULNERABLE
    assert review["verified_findings"] == [] or all(
        f.get("status") != "FAKE_CERTAIN" for f in review["verified_findings"]
    )
    assert review["decision"] in {"PASS", "MONITOR", "REVIEW_REQUIRED"}
