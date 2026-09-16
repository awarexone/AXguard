"""Git helpers for Security Diff — materialize refs without mutating the worktree."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from engines.security_diff.git_base import (
    git_root,
    is_git_repo,
    list_changed_files,
    resolve_base_ref,
)


def _run_git(cwd: Path, *args: str, timeout: float = 60.0) -> tuple[int, str, str]:
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def parse_range_spec(spec: str | None) -> tuple[str | None, str | None]:
    """Parse HEAD~1 / main...HEAD / commit into (base, head)."""
    if not spec:
        return None, None
    text = spec.strip()
    if "..." in text:
        left, _, right = text.partition("...")
        return (left.strip() or None), (right.strip() or "HEAD")
    if ".." in text:
        left, _, right = text.partition("..")
        return (left.strip() or None), (right.strip() or "HEAD")
    return text, "HEAD"


def resolve_comparison(
    project: Path,
    *,
    base: str | None = None,
    head: str | None = None,
    range_spec: str | None = None,
) -> dict[str, Any]:
    """Resolve git comparison endpoints. Never fabricates a base SHA."""
    out: dict[str, Any] = {
        "available": False,
        "repo": None,
        "base_ref": base,
        "head_ref": head or "HEAD",
        "base_sha": None,
        "head_sha": None,
        "changed_files": [],
        "notes": [],
    }
    root = git_root(project)
    if root is None or not is_git_repo(root):
        out["notes"].append("not a git repository")
        return out
    out["repo"] = str(root)

    if range_spec:
        b, h = parse_range_spec(range_spec)
        base = base or b
        head = head or h

    info = resolve_base_ref(root, base)
    out["notes"].extend(info.get("notes") or [])
    if not info.get("available"):
        return out

    head_ref = head or "HEAD"
    code, head_sha, err = _run_git(root, "rev-parse", "--verify", head_ref)
    if code != 0 or not head_sha:
        # Working tree comparison: allow HEAD as conceptual head
        if head_ref in {None, "HEAD", "WORKTREE", "."}:
            code2, head_sha2, _ = _run_git(root, "rev-parse", "HEAD")
            if code2 != 0:
                out["notes"].append(f"unable to resolve head '{head_ref}': {err}")
                return out
            head_sha = head_sha2
            head_ref = "HEAD"
        else:
            out["notes"].append(f"unable to resolve head '{head_ref}': {err}")
            return out

    out["available"] = True
    out["base_ref"] = info.get("base_ref")
    out["base_sha"] = info.get("base_sha")
    out["head_ref"] = head_ref
    out["head_sha"] = head_sha
    out["changed_files"] = list(
        info.get("changed_files")
        or list_changed_files(root, str(info.get("base_ref") or base))
    )
    return out


def materialize_ref(repo: Path, ref: str, dest_dir: Path | None = None) -> Path | None:
    """Export ``ref`` into a temp directory via ``git archive`` (no checkout)."""
    root = git_root(repo) or Path(repo)
    code, sha, err = _run_git(root, "rev-parse", "--verify", ref)
    if code != 0 or not sha:
        return None

    dest = Path(dest_dir) if dest_dir else Path(tempfile.mkdtemp(prefix="axguard-diff-"))
    dest.mkdir(parents=True, exist_ok=True)

    # Prefer git archive | tar
    try:
        archive = subprocess.Popen(
            ["git", "archive", "--format=tar", sha],
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        extract = subprocess.run(
            ["tar", "-xf", "-"],
            cwd=str(dest),
            stdin=archive.stdout,
            capture_output=True,
            check=False,
        )
        if archive.stdout:
            archive.stdout.close()
        archive.wait(timeout=120)
        if archive.returncode != 0 or extract.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            return None
        return dest
    except (OSError, subprocess.TimeoutExpired):
        shutil.rmtree(dest, ignore_errors=True)
        return None


def cleanup_materialized(path: Path | None) -> None:
    if path is None:
        return
    try:
        if path.is_dir() and "axguard-diff-" in path.name:
            shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass
