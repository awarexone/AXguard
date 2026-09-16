"""Unit tests for axguard_verify_fix — mocked engines, no live network."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("engines.mcp.tools.handlers")
pytest.importorskip("engines.mcp.session")
pytest.importorskip("engines.mcp.policy")

from engines.mcp.policy import ApprovalTier, enforce, tier_for
from engines.mcp.schemas.errors import McpError
from engines.mcp.session import reset_session
from engines.mcp.tools import handlers as handlers_mod
from engines.mcp.tools.handlers import HANDLERS

TOOL = "axguard_verify_fix"


def _resolve_handler():
    fn = getattr(handlers_mod, TOOL, None)
    if callable(fn):
        return fn, True
    wrapped = HANDLERS.get(TOOL)
    if callable(wrapped):
        return wrapped, False
    pytest.fail(f"{TOOL} handler not registered")


def _status_of(out: dict[str, Any]) -> str:
    if not isinstance(out, dict):
        raise AssertionError(f"expected dict result, got {type(out)}")
    if out.get("ok") is False:
        err = out.get("error") or {}
        code = err.get("code") if isinstance(err, dict) else None
        raise AssertionError(f"tool returned error: {code or out}")
    candidates: list[Any] = [
        out.get("status"),
        out.get("verification_status"),
        out.get("result"),
        out.get("outcome"),
        out.get("verdict"),
    ]
    nested = out.get("verification") or out.get("fix_verification") or out.get("data")
    if isinstance(nested, dict):
        candidates.extend(
            [
                nested.get("status"),
                nested.get("verification_status"),
                nested.get("result"),
                nested.get("outcome"),
            ]
        )
    for key in ("payload", "result", "review"):
        blob = out.get(key)
        if isinstance(blob, dict):
            candidates.extend(
                [
                    blob.get("status"),
                    blob.get("verification_status"),
                    blob.get("result"),
                    blob.get("outcome"),
                ]
            )
    for c in candidates:
        if isinstance(c, str) and c.strip():
            return c.strip().upper()
    blob = str(out).upper()
    for token in ("STILL_PRESENT", "REGRESSED", "RESOLVED"):
        if token in blob:
            return token
    raise AssertionError(f"could not find verification status in: {out!r}")


def _finding(
    *,
    fid: str = "f-authz-1",
    fingerprint: str = "fp.authz.idor.v1",
    severity: str = "high",
    path: str = "api.py",
    title: str = "Missing object-level authorization",
) -> dict[str, Any]:
    return {
        "id": fid,
        "finding_id": fid,
        "fingerprint": fingerprint,
        "rule_id": "auth-idor",
        "title": title,
        "severity": severity,
        "status": "CONFIRMED",
        "file": path,
        "path": path,
        "line": 2,
        "message": "user_id reaches db without ownership check",
    }


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "api.py").write_text(
        "def get_user(user_id):\n    return db.users[user_id]\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture()
def session(project: Path):
    return reset_session(project, mode="BALANCED")


def _call_verify(fn, raises: bool, **kwargs):
    try:
        out = fn(**kwargs)
    except McpError:
        raise
    if isinstance(out, dict) and out.get("ok") is False and not raises:
        err = out.get("error") or {}
        code = err.get("code") if isinstance(err, dict) else "ANALYSIS_FAILED"
        msg = err.get("message") if isinstance(err, dict) else str(out)
        details = err.get("details") if isinstance(err, dict) else {}
        raise McpError(code or "ANALYSIS_FAILED", msg or "error", details=details or {})
    return out


def _invoke(session, **kwargs):
    fn, raises = _resolve_handler()
    reset_session(session.project_root, mode="BALANCED")
    from engines.mcp.session import get_session

    sess = get_session()
    if getattr(session, "last_findings", None):
        sess.last_findings = list(session.last_findings)
    kwargs.setdefault("approved", True)
    try:
        return _call_verify(fn, raises, **kwargs), sess
    except TypeError:
        slim = dict(kwargs)
        for drop in ("fingerprint", "path", "mode"):
            slim.pop(drop, None)
            try:
                return _call_verify(fn, raises, **slim), sess
            except TypeError:
                continue
        raise


def test_verify_fix_requires_approval_without_flag():
    tier = tier_for(TOOL)
    assert tier == ApprovalTier.APPROVAL_REQUIRED
    with pytest.raises(McpError) as ei:
        enforce(TOOL, approved=False)
    assert ei.value.code == "APPROVAL_REQUIRED"


def test_verify_fix_handler_rejects_unapproved(session):
    fn, raises = _resolve_handler()
    sess = reset_session(session.project_root)
    sess.last_findings = [_finding()]
    with pytest.raises(McpError) as ei:
        _call_verify(fn, raises, finding_id="f-authz-1", approved=False)
    assert ei.value.code == "APPROVAL_REQUIRED"


def test_resolved_when_fingerprint_gone_after_rescan(session):
    session.last_findings = [_finding()]
    empty = {"findings": [], "finding_count": 0}
    with patch("engines.mcp.tools.verify_fix.bridge.run_scan_engine", return_value=empty) as scan:
        out, _sess = _invoke(session, finding_id="f-authz-1", fingerprint="fp.authz.idor.v1")
    assert _status_of(out) == "RESOLVED"
    scan.assert_called()


def test_still_present_when_same_finding_remains(session):
    prior = _finding()
    session.last_findings = [prior]
    same = {"findings": [dict(prior)], "finding_count": 1}
    with patch("engines.mcp.tools.verify_fix.bridge.run_scan_engine", return_value=same) as scan:
        out, _sess = _invoke(session, finding_id="f-authz-1", fingerprint="fp.authz.idor.v1")
    assert _status_of(out) == "STILL_PRESENT"
    scan.assert_called()


def test_regressed_when_severity_worsens(session):
    prior = _finding(severity="medium")
    session.last_findings = [prior]
    worse = _finding(severity="critical")
    rescan = {"findings": [worse], "finding_count": 1}
    with patch("engines.mcp.tools.verify_fix.bridge.run_scan_engine", return_value=rescan) as scan:
        out, _sess = _invoke(session, finding_id="f-authz-1", fingerprint="fp.authz.idor.v1")
    assert _status_of(out) == "REGRESSED"
    scan.assert_called()


def test_never_resolved_solely_from_path_string_change(session):
    prior = _finding(path="api.py")
    session.last_findings = [prior]
    renamed = _finding(path="handlers/api.py")
    rescan = {"findings": [renamed], "finding_count": 1}

    with patch("engines.mcp.tools.verify_fix.bridge.run_scan_engine", return_value=rescan) as scan:
        out, _sess = _invoke(session, finding_id="f-authz-1", fingerprint="fp.authz.idor.v1")
    status = _status_of(out)
    assert status != "RESOLVED"
    assert status in {"STILL_PRESENT", "REGRESSED"}
    scan.assert_called()
