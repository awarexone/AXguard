"""Workspace isolation — block path traversal and symlink escapes."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote

from engines.mcp.schemas.errors import McpError

_FORBIDDEN_PREFIXES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
)


class ProjectSandbox:
    """Confine filesystem access to a single configured project root."""

    def __init__(self, project_root: Path | str) -> None:
        root = Path(project_root).expanduser()
        if not root.exists():
            raise McpError(
                "PROJECT_NOT_FOUND",
                f"Project root does not exist: {root}",
                details={"path": str(root)},
            )
        if not root.is_dir():
            raise McpError(
                "INVALID_INPUT",
                f"Project root is not a directory: {root}",
                details={"path": str(root)},
            )
        self.root = root.resolve()

    def resolve(self, path: str | Path | None = None) -> Path:
        return resolve_in_project(self.root, path)

    def relative(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root))
        except ValueError as exc:
            raise McpError(
                "PERMISSION_DENIED",
                "Path is outside the configured project root.",
                details={"path": str(path), "root": str(self.root)},
            ) from exc


def _normalize_user_path(raw: str | Path) -> str:
    text = str(raw)
    # Reject encoded traversal tricks early
    if "\x00" in text:
        raise McpError(
            "PERMISSION_DENIED",
            "Null byte in path is not allowed.",
            details={"path": text},
        )
    decoded = unquote(text)
    if "%2e" in text.lower() or "%2f" in text.lower():
        # Double-decode once more for nested encoding
        decoded = unquote(decoded)
    return decoded


def resolve_in_project(project_root: Path | str, path: str | Path | None = None) -> Path:
    """Resolve ``path`` under ``project_root`` without leaving the workspace.

    Blocks absolute escapes, ``..`` traversal, and symlink escapes that resolve
    outside the project root.
    """
    root = Path(project_root).expanduser().resolve()
    if path is None or str(path).strip() in {"", ".", "./"}:
        return root

    raw = _normalize_user_path(path)
    candidate = Path(raw).expanduser()

    # Absolute paths must still land under root
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        # Join then resolve — catches .. components
        resolved = (root / candidate).resolve()

    # Hard denylist for sensitive system locations (defense in depth)
    posix = resolved.as_posix()
    for prefix in _FORBIDDEN_PREFIXES:
        if posix == prefix or posix.startswith(prefix + "/"):
            raise McpError(
                "PERMISSION_DENIED",
                "Access to system paths is blocked.",
                details={"path": str(resolved)},
            )

    home = Path.home().resolve()
    sensitive_home = {
        home / ".ssh",
        home / ".aws",
        home / ".gnupg",
        home / ".config" / "gcloud",
    }
    for sens in sensitive_home:
        try:
            resolved.relative_to(sens)
            raise McpError(
                "PERMISSION_DENIED",
                "Access to credential directories is blocked.",
                details={"path": str(resolved)},
            )
        except ValueError:
            pass
        except McpError:
            raise

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise McpError(
            "PERMISSION_DENIED",
            "Path escapes the configured project root "
            "(absolute path, traversal, or symlink).",
            details={"path": str(resolved), "root": str(root)},
        ) from exc

    # Symlink-aware: if any parent is a symlink leaving root, reject
    try:
        if resolved.exists() or resolved.parent.exists():
            real = Path(os.path.realpath(resolved))
            real.relative_to(root)
    except ValueError as exc:
        raise McpError(
            "PERMISSION_DENIED",
            "Symlink resolves outside the configured project root.",
            details={"path": str(resolved), "root": str(root)},
        ) from exc
    except OSError:
        pass

    return resolved
