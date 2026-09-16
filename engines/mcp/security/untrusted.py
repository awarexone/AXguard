"""Treat repository content as untrusted data — never as policy."""

from __future__ import annotations

from typing import Any

from engines.mcp.security.redact import redact_text


def sanitize_repo_text(text: str, *, max_len: int = 4000) -> str:
    """Normalize untrusted repo strings for inclusion in tool output."""
    try:
        from engines.github.untrusted import sanitize_untrusted_text

        return sanitize_untrusted_text(text, max_len=max_len)
    except Exception:  # noqa: BLE001
        cleaned = redact_text(str(text or ""))
        if len(cleaned) > max_len:
            cleaned = cleaned[: max_len - 3] + "..."
        return cleaned


def as_untrusted_data(label: str, value: Any) -> dict[str, Any]:
    """Wrap repo-sourced values so agents treat them as data, not instructions."""
    try:
        from engines.github.untrusted import as_data_context

        return as_data_context(label, value)
    except Exception:  # noqa: BLE001
        text = sanitize_repo_text(str(value) if value is not None else "")
        return {
            "kind": "untrusted_repo_data",
            "label": label,
            "value": text,
            "provenance": {
                "source": "repository",
                "state": "EXTERNAL",
                "trust": "UNTRUSTED",
            },
        }


def assert_never_execute_repo() -> None:
    """Hard guard — MCP must not execute repository scripts/builds."""
    from engines.mcp.schemas.errors import McpError

    raise McpError(
        "UNSUPPORTED_OPERATION",
        "AXGuard MCP refuses to execute repository code. "
        "Repository contents are analysis data only.",
    )
