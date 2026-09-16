"""Structured MCP results and error codes."""

from __future__ import annotations

from engines.mcp.schemas.errors import (
    ERROR_CODES,
    McpError,
    error_result,
)
from engines.mcp.schemas.results import (
    PROVENANCE_STATES,
    ProvenanceState,
    agent_friendly_text,
    attach_provenance,
    redact_result,
    success_result,
    truncate_result,
)

__all__ = [
    "ERROR_CODES",
    "McpError",
    "error_result",
    "PROVENANCE_STATES",
    "ProvenanceState",
    "attach_provenance",
    "success_result",
    "redact_result",
    "truncate_result",
    "agent_friendly_text",
]
