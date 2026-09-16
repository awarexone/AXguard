"""Resolve git base refs for Security Diff. Never invent a baseline."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


def _run_git(cwd: Path, *args: str, timeout: float = 15.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return 1, "", "git unavailable"


def is_git_repo(path: Path) -> bool:
    root = path if path.is_dir() else path.parent
    code, out, _ = _run_git(root, "rev-parse", "--is-inside-work-tree")
    return code == 0 and out.lower() == "true"


def git_root(path: Path) -> Path | None:
    root = path if path.is_dir() else path.parent
    code, out, _ = _run_git(root, "rev-parse", "--show-toplevel")
    if code != 0 or not out:
        return None
    return Path(out)


def resolve_base_ref(
    target: Path,
    base_ref: str | None = None,
) -> dict[str, Any]:
    """Resolve a comparable git base.

    Returns keys: available (bool), base_ref, base_sha, head_sha, range_files,
    baseline ("GIT" | "UNKNOWN"), notes.
    """
    result: dict[str, Any] = {
        "available": False,
        "base_ref": base_ref,
        "base_sha": None,
        "head_sha": None,
        "changed_files": [],
        "baseline": "UNKNOWN",
        "notes": [],
    }
    root = git_root(target)
    if root is None or not is_git_repo(root):
        result["notes"].append("no git repository; baseline UNKNOWN")
        return result

    code, head, _ = _run_git(root, "rev-parse", "HEAD")
    if code != 0 or not head:
        result["notes"].append("unable to resolve HEAD; baseline UNKNOWN")
        return result
    result["head_sha"] = head

    ref = (base_ref or "HEAD~1").strip()
    # Support main...HEAD / origin/main...HEAD range syntax → left side is base
    if "..." in ref:
        left, _, right = ref.partition("...")
        ref_base = left.strip() or "HEAD~1"
        ref_head = right.strip() or "HEAD"
    elif ".." in ref and "..." not in ref:
        left, _, right = ref.partition("..")
        ref_base = left.strip() or "HEAD~1"
        ref_head = right.strip() or "HEAD"
    else:
        ref_base = ref
        ref_head = "HEAD"

    code, base_sha, err = _run_git(root, "rev-parse", "--verify", ref_base)
    if code != 0 or not base_sha:
        # Fall back to HEAD~1 when explicit ref missing
        if ref_base != "HEAD~1":
            code2, base_sha2, _ = _run_git(root, "rev-parse", "--verify", "HEAD~1")
            if code2 == 0 and base_sha2:
                result["notes"].append(
                    f"base ref '{ref_base}' unavailable ({err or 'missing'}); using HEAD~1"
                )
                ref_base = "HEAD~1"
                base_sha = base_sha2
            else:
                result["notes"].append(
                    f"base ref '{ref_base}' unavailable; baseline UNKNOWN"
                )
                return result
        else:
            result["notes"].append("HEAD~1 unavailable (single commit?); baseline UNKNOWN")
            return result

    result["available"] = True
    result["baseline"] = "GIT"
    result["base_ref"] = ref_base
    result["base_sha"] = base_sha

    # Changed files between base and head
    code, diff_out, _ = _run_git(
        root, "diff", "--name-only", f"{base_sha}...{ref_head}"
    )
    if code == 0 and diff_out:
        result["changed_files"] = [ln for ln in diff_out.splitlines() if ln.strip()]
    return result


def list_changed_files(target: Path, base_ref: str | None = None) -> list[str]:
    info = resolve_base_ref(target, base_ref)
    return list(info.get("changed_files") or [])
