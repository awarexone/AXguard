"""Local Security Diff baseline snapshots (no cloud)."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from engines.security_diff.paths import (
    UnsafePathError,
    resolve_local_path,
    resolve_under_root,
)

DEFAULT_REL_PARTS = (".findings", "axguard", "security_diff", "baselines")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def resolve_baseline_dir(project_root: Path | str) -> Path:
    root = resolve_local_path(project_root)
    if root is None:
        raise UnsafePathError("project root is required")
    return resolve_under_root(root, *DEFAULT_REL_PARTS)


def _safe_name(name: str) -> str:
    cleaned = _SAFE.sub("_", str(name or "default")).strip("._") or "default"
    return cleaned


def _atomic_write(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = deepcopy(payload)
    try:
        from engines.dataflow.schema import ensure_no_secret_values

        ensure_no_secret_values(data)
    except Exception:  # noqa: BLE001
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def save_baseline(
    project_root: Path | str,
    state: dict[str, Any],
    name: str = "default",
) -> Path:
    """Persist a security state snapshot for later non-git diffs."""
    root = resolve_local_path(project_root)
    if root is None:
        raise UnsafePathError("project root is required")
    out = resolve_under_root(root, *DEFAULT_REL_PARTS, f"{_safe_name(name)}.json")
    payload = {
        "kind": "axguard_security_diff_baseline",
        "name": _safe_name(name),
        "project": str(root),
        "state": state,
    }
    return _atomic_write(out, payload)


def load_baseline(
    project_root: Path | str,
    name: str = "default",
) -> dict[str, Any] | None:
    try:
        path = resolve_under_root(
            project_root, *DEFAULT_REL_PARTS, f"{_safe_name(name)}.json"
        )
    except UnsafePathError:
        return None
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def list_baselines(project_root: Path | str) -> list[dict[str, Any]]:
    try:
        base = resolve_baseline_dir(project_root)
    except UnsafePathError:
        return []
    if not base.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for path in sorted(base.glob("*.json")):
        # Defense: only list files that remain under the baseline dir
        try:
            path.resolve().relative_to(base.resolve())
        except ValueError:
            continue
        items.append(
            {
                "name": path.stem,
                "path": str(path),
                "mtime": path.stat().st_mtime,
            }
        )
    return items
