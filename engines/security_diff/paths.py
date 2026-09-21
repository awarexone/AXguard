"""Path guards for Security Diff — block traversal / null-byte / system escapes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_FORBIDDEN_PREFIXES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
)


class UnsafePathError(ValueError):
    """Raised when a path fails Security Diff safety checks."""


def _normalize_raw(value: str | Path) -> str:
    text = str(value)
    if "\x00" in text:
        raise UnsafePathError("null byte in path is not allowed")
    return text.strip()


def _reject_system_paths(resolved: Path) -> None:
    posix = resolved.as_posix()
    for prefix in _FORBIDDEN_PREFIXES:
        if posix == prefix or posix.startswith(prefix + "/"):
            raise UnsafePathError(f"access to system path blocked: {prefix}")


def resolve_local_path(
    value: str | Path | None,
    *,
    must_exist: bool = False,
    expect_dir: bool = False,
) -> Path | None:
    """Resolve a local path with basic injection defenses.

    Intended for CLI/API local analysis roots (not remote untrusted uploads).
    Rejects null bytes and sensitive system prefixes. Returns ``None`` when
    ``value`` is empty.
    """
    if value is None:
        return None
    raw = _normalize_raw(value)
    if not raw:
        return None
    candidate = Path(raw).expanduser()
    # Realpath-style resolve so symlink escapes are visible to later checks.
    resolved = Path(os.path.realpath(candidate)) if candidate.exists() else candidate.resolve()
    _reject_system_paths(resolved)
    if must_exist and not resolved.exists():
        raise UnsafePathError(f"path does not exist: {resolved}")
    if expect_dir and resolved.exists() and not resolved.is_dir():
        raise UnsafePathError(f"path is not a directory: {resolved}")
    return resolved


def resolve_under_root(root: Path | str, *parts: str) -> Path:
    """Join ``parts`` under ``root`` and reject escapes outside the root."""
    base = resolve_local_path(root, expect_dir=False)
    if base is None:
        raise UnsafePathError("project root is required")
    # Normalize each part — reject absolute segments / empty traversal
    clean: list[str] = []
    for part in parts:
        text = _normalize_raw(part)
        if not text or text in {".", "./"}:
            continue
        p = Path(text)
        if p.is_absolute() or ".." in p.parts:
            raise UnsafePathError("path segment escapes project root")
        clean.append(text)
    candidate = base.joinpath(*clean).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise UnsafePathError("path escapes project root") from exc
    _reject_system_paths(candidate)
    return candidate


def as_existing_path(value: Any) -> Path | None:
    """Return a resolved path only when it exists (dir or file); else ``None``."""
    try:
        resolved = resolve_local_path(value)
    except UnsafePathError:
        return None
    if resolved is None:
        return None
    if resolved.exists():
        return resolved
    return None
