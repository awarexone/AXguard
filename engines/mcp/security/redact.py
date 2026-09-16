"""Secret redaction for MCP tool outputs and logs."""

from __future__ import annotations

from typing import Any


def redact_text(text: str) -> str:
    if not text:
        return text
    try:
        from engines.github.privacy import redact_text as _redact

        return _redact(text)
    except Exception:  # noqa: BLE001
        try:
            from engines.data.scrub import scrub_text

            cleaned, _ = scrub_text(text)
            return cleaned
        except Exception:  # noqa: BLE001
            return text


def redact_value(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        out = {k: redact_value(v) for k, v in obj.items()}
        try:
            from engines.dataflow.schema import ensure_no_secret_values

            ensure_no_secret_values(out)
        except Exception:  # noqa: BLE001
            pass
        return out
    if isinstance(obj, list):
        return [redact_value(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_value(v) for v in obj)
    return obj
