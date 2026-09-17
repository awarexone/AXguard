"""Skill registry and validator smoke tests."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_validate_skills_script_ok():
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_skills.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OK" in r.stdout


def test_core_skill_count():
    """Skills are top-level directories; domain skills are the non-axguard-* ones."""
    skills = [p for p in ROOT.glob("*/SKILL.md") if not p.parent.name.startswith("axguard-")]
    assert len(skills) >= 30


def test_index_lists_every_skill_on_disk():
    text = (ROOT / "skills-index.yaml").read_text(encoding="utf-8")
    on_disk = sorted(p.parent.name for p in ROOT.glob("*/SKILL.md"))
    assert len(on_disk) == 38
    for name in on_disk:
        assert f"path: {name}/SKILL.md" in text, f"{name} missing from skills-index.yaml"
