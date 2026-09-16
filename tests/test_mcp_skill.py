"""Contract tests for skills/axguard-security (Agent Skill over MCP).

The Skill teaches when/which MCP tool to call — it must not embed a second scanner.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "axguard-security" / "SKILL.md"

_SCANNER_ALGORITHM_MARKERS = (
    "def run_scan",
    "def scan_",
    "class Scanner",
    "semgrep",
    "bandit.run",
    "regex = r\"",
    "AST visitor",
    "taint_propagate(",
    "own scanner algorithm",
)


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    assert end != -1, "SKILL.md frontmatter not closed"
    raw = text[3:end].strip()
    body = text[end + 4 :]
    meta: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        meta[key.strip()] = val.strip().strip("\"'")
    return meta, body


@pytest.fixture(scope="module")
def skill_parts() -> tuple[dict[str, str], str, str]:
    assert SKILL.is_file(), f"missing skill file: {SKILL}"
    text = SKILL.read_text(encoding="utf-8")
    meta, body = _parse_frontmatter(text)
    return meta, body, text


def test_skill_file_exists():
    assert SKILL.is_file()


def test_skill_frontmatter_name_and_description(skill_parts):
    meta, _body, _text = skill_parts
    assert meta.get("name") == "axguard-security"
    desc = meta.get("description") or ""
    assert len(desc) >= 40
    low = desc.lower()
    assert "security" in low
    assert any(
        tok in low
        for tok in ("axguard", "mcp", "vulnerabilit", "review", "verify")
    )


def test_skill_teaches_when_to_use_and_not_use(skill_parts):
    _meta, body, text = skill_parts
    low = text.lower()
    assert any(
        tok in low
        for tok in (
            "auth",
            "authorization",
            "ship",
            "deploy",
            "security-sensitive",
            "meaningful",
        )
    ), "skill should teach when to call AXGuard"
    assert any(
        tok in low
        for tok in ("do not", "don't", "skip", "trivial", "typo", "rename", "comment")
    ), "skill should teach when not to call AXGuard"
    assert "when" in low


def test_skill_mentions_security_review_and_verify_fix(skill_parts):
    _meta, _body, text = skill_parts
    assert "axguard_security_review" in text
    assert "axguard_verify_fix" in text


def test_skill_verdict_rules(skill_parts):
    _meta, _body, text = skill_parts
    upper = text.upper()
    for label in ("VERIFIED", "UNKNOWN", "FALSE_POSITIVE"):
        assert label in upper, f"skill must teach verdict rule {label}"
    assert "PREDICTIVE" in upper, "skill must teach PREDICTIVE / PREDICTIVE_RISK"


def test_skill_does_not_embed_second_scanner(skill_parts):
    _meta, body, text = skill_parts
    low = text.lower()
    assert any(
        phrase in low
        for phrase in (
            "does not implement",
            "do not implement",
            "not implement security",
            "prefer mcp",
            "primary interface",
            "does **not** implement",
            "thin behavioral",
            "instead of inventing",
            "second scanner",
            "does not reimplement",
        )
    ), "skill should state it wraps MCP rather than scanning itself"
    for marker in _SCANNER_ALGORITHM_MARKERS:
        assert marker.lower() not in low, f"skill embeds scanner marker: {marker}"
    assert body.count("```") <= 6
    assert len(text) < 20_000
