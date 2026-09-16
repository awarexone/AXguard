"""Structured tool results with provenance and redaction."""

from __future__ import annotations

from typing import Any, Literal

from engines.mcp.security.redact import redact_value

ProvenanceState = Literal[
    "OBSERVED",
    "INFERRED",
    "SIMULATED",
    "ASSUMED",
    "UNKNOWN",
]

PROVENANCE_STATES = frozenset(
    {"OBSERVED", "INFERRED", "SIMULATED", "ASSUMED", "UNKNOWN", "EXTERNAL"}
)


def attach_provenance(
    payload: dict[str, Any],
    *,
    state: ProvenanceState | str = "OBSERVED",
    confidence: str = "UNKNOWN",
    source: str = "AXGuard",
    trust: str | None = None,
) -> dict[str, Any]:
    state_u = str(state or "UNKNOWN").upper()
    if state_u not in PROVENANCE_STATES:
        state_u = "UNKNOWN"
    prov: dict[str, Any] = {
        "source": source,
        "state": state_u,
        "confidence": str(confidence or "UNKNOWN").upper(),
    }
    if trust is not None:
        prov["trust"] = trust
    elif source.lower() != "axguard":
        prov["trust"] = "UNTRUSTED"
    out = dict(payload)
    out["provenance"] = prov
    return out


def success_result(
    data: dict[str, Any],
    *,
    state: ProvenanceState | str = "OBSERVED",
    confidence: str = "UNKNOWN",
    summary: str | None = None,
) -> dict[str, Any]:
    body = attach_provenance(
        {"ok": True, **data},
        state=state,
        confidence=confidence,
    )
    if summary:
        body["summary"] = summary
    return redact_result(body)


def redact_result(obj: Any) -> Any:
    return redact_value(obj)


def truncate_result(
    obj: Any,
    *,
    max_bytes: int,
    max_list: int | None = None,
) -> Any:
    """Shallow size guard for agent context budgets."""
    if max_list is not None and isinstance(obj, list) and len(obj) > max_list:
        return {
            "items": obj[:max_list],
            "truncated": True,
            "total": len(obj),
        }
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            out[k] = truncate_result(v, max_bytes=max_bytes, max_list=max_list)
        return out
    if isinstance(obj, list):
        limit = max_list if max_list is not None else len(obj)
        return [
            truncate_result(v, max_bytes=max_bytes, max_list=max_list)
            for v in obj[:limit]
        ]
    if isinstance(obj, str) and len(obj) > max_bytes:
        return obj[: max(0, max_bytes - 3)] + "..."
    return obj


def agent_friendly_text(review: dict[str, Any]) -> str:
    """Compact text block for coding agents (no marketing)."""
    lines = [
        "SECURITY REVIEW",
        "",
        f"Decision: {review.get('decision', 'UNKNOWN')}",
        f"Risk: {review.get('risk', 'UNKNOWN')}",
    ]
    verified = review.get("verified_findings") or []
    lines.append(f"Verified Findings: {len(verified)}")
    for i, f in enumerate(verified[:5], 1):
        title = f.get("title") or f.get("vulnerability_type") or f.get("id") or "finding"
        lines.append(f"{i}. {title}")
        if f.get("evidence_summary"):
            lines.append(f"   Evidence: {f['evidence_summary']}")
        if f.get("attack_path_summary"):
            lines.append(f"   Attack Path: {f['attack_path_summary']}")
    pred = review.get("predictive_risks") or []
    if pred:
        cats = ", ".join(
            sorted({str(p.get("category") or "UNKNOWN") for p in pred[:8]})
        )
        lines.append(f"Predictive Risk: {cats}")
    action = review.get("recommended_action")
    if action:
        lines.append(f"Recommended Action: {action}")
    unknowns = review.get("unknowns") or []
    if unknowns:
        lines.append(f"Unknowns: {len(unknowns)}")
    return "\n".join(lines)
