"""Tests for engines.preship — decisions, exit codes, CLI smoke."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from engines.preship.decision import decide
from engines.preship.policy import (
    PreshipBlocking,
    PreshipPolicy,
    PreshipUnknowns,
    map_preship_verdict,
)
from engines.preship.schema import (
    DECISION_FAIL,
    DECISION_PASS,
    DECISION_PASS_WITH_NOTES,
    DECISION_REVIEW_REQUIRED,
    EXIT_FAIL,
    EXIT_PASS,
    EXIT_REVIEW_REQUIRED,
    EXIT_TOOL_ERROR,
    exit_code_for,
)

ROOT = Path(__file__).resolve().parents[1]
PASS_SAFE = ROOT / "fixtures" / "preship" / "pass_safe"
FAIL_AUTHZ = ROOT / "fixtures" / "preship" / "fail_authz"


def test_exit_code_mapping():
    assert exit_code_for(DECISION_PASS) == EXIT_PASS
    assert exit_code_for(DECISION_PASS_WITH_NOTES) == EXIT_PASS
    assert exit_code_for(DECISION_REVIEW_REQUIRED) == EXIT_REVIEW_REQUIRED
    assert exit_code_for(DECISION_FAIL) == EXIT_FAIL
    assert exit_code_for("PASS", tool_error=True) == EXIT_TOOL_ERROR


def test_verified_high_fails():
    findings = [
        {
            "id": "auth.1",
            "title": "IDOR",
            "severity": "high",
            "status": "VERIFIED",
        }
    ]
    assert map_preship_verdict(findings) == DECISION_FAIL
    pack = decide(findings=findings)
    assert pack["decision"] == DECISION_FAIL
    assert pack["exit_code"] == EXIT_FAIL
    assert pack["blocking_reason"]


def test_unverified_never_fails_by_default():
    findings = [
        {
            "id": "x.1",
            "title": "maybe",
            "severity": "critical",
            "status": "UNVERIFIED",
        }
    ]
    assert map_preship_verdict(findings) == DECISION_PASS_WITH_NOTES


def test_likely_is_review():
    findings = [
        {
            "id": "x.1",
            "title": "likely idor",
            "severity": "high",
            "status": "LIKELY",
        }
    ]
    assert map_preship_verdict(findings) == DECISION_REVIEW_REQUIRED


def test_false_positive_is_pass():
    findings = [
        {
            "id": "x.1",
            "title": "fp",
            "severity": "high",
            "status": "FALSE_POSITIVE",
        }
    ]
    assert map_preship_verdict(findings) == DECISION_PASS


def test_security_diff_control_removal_review():
    findings: list = []
    sd = {
        "overall_security_change": "HIGH",
        "summary": {"removed_controls": 1, "weakened_controls": 0},
        "authz_changes": [{"change": "ownership check removed", "impact": "authorization weakened"}],
        "tenant_changes": [],
        "control_changes": [{"state": "REMOVED", "kind": "authorization"}],
    }
    decision = map_preship_verdict(findings, security_diff=sd)
    assert decision == DECISION_REVIEW_REQUIRED


def test_unknowns_policy_review():
    pol = PreshipPolicy(
        blocking=PreshipBlocking(),
        unknowns=PreshipUnknowns(fail=False, review_required=True),
    )
    decision = map_preship_verdict(
        [],
        pol,
        unknowns=["Tenant isolation implementation could not be established."],
    )
    assert decision == DECISION_REVIEW_REQUIRED


def test_predictive_soft_notes():
    decision = map_preship_verdict(
        [],
        predictive_risks=[{"label": "ATTACK_SURFACE_EXPANSION"}],
    )
    assert decision == DECISION_PASS_WITH_NOTES


def test_cli_preship_pass_safe_exit(monkeypatch, tmp_path):
    """Smoke: axguard preship fixtures/preship/pass_safe --json exits 0/1/2 not 3."""
    # Block sockets
    real_socket = socket.socket

    def no_net(*a, **k):
        raise OSError("network disabled in test")

    monkeypatch.setattr(socket, "socket", no_net)

    from cli.main import main

    out = tmp_path / "preship-out"
    code = main(
        [
            "preship",
            str(PASS_SAFE),
            "--mode",
            "QUICK",
            "--json",
            "--no-banner",
            "--out-dir",
            str(out),
        ]
    )
    assert code in {0, 1, 2}
    assert code != 3
    # restore for safety
    monkeypatch.setattr(socket, "socket", real_socket)


def test_fail_authz_decision_bucket(monkeypatch, tmp_path):
    """fail_authz tends FAIL/REVIEW, or security_diff detects authz weakening vs pass_safe."""
    monkeypatch.setattr(socket, "socket", lambda *a, **k: (_ for _ in ()).throw(OSError("no net")))

    from engines.preship import run_preship
    from engines.security_diff.compose import run_security_diff as compose_diff

    result = run_preship(
        FAIL_AUTHZ,
        mode="QUICK",
        out_dir=tmp_path / "fail",
    )
    if result["decision"] in {DECISION_FAIL, DECISION_REVIEW_REQUIRED}:
        return

    # Fallback: compare to pass_safe via compose
    diff = compose_diff(
        FAIL_AUTHZ,
        base_target=PASS_SAFE,
        cheap_twin=False,
    )
    authz = diff.get("authz_changes") or []
    cats = [c.get("category") for c in (diff.get("categories") or [])]
    assert authz or "REMOVED_SECURITY_CONTROL" in cats or diff.get(
        "overall_security_change"
    ) in {"HIGH", "CRITICAL", "MEDIUM"}
