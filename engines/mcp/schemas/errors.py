"""Machine-readable MCP error envelopes."""

from __future__ import annotations

import secrets
from typing import Any

ERROR_CODES = (
    "INVALID_INPUT",
    "PROJECT_NOT_FOUND",
    "ANALYSIS_TIMEOUT",
    "RESOURCE_LIMIT",
    "APPROVAL_REQUIRED",
    "PERMISSION_DENIED",
    "UNSUPPORTED_OPERATION",
    "INSUFFICIENT_EVIDENCE",
    "ANALYSIS_FAILED",
    "TOOL_BUDGET_EXCEEDED",
)


def new_request_id() -> str:
    return "req_" + secrets.token_hex(8)


def error_result(
    code: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    if code not in ERROR_CODES:
        code = "ANALYSIS_FAILED"
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id or new_request_id(),
            "details": details or {},
        },
    }


class McpError(Exception):
    """Raised inside tool handlers; converted to structured error results."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code if code in ERROR_CODES else "ANALYSIS_FAILED"
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return error_result(self.code, self.message, details=self.details)
