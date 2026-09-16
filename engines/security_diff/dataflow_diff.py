"""Compare dataflow results for new sources/sinks/paths and removed controls."""

from __future__ import annotations

from typing import Any

from engines.security_diff.schema import (
    NEW_DATABASE_FLOW,
    NEW_SENSITIVE_DATA_FLOW,
    REMOVED_SECURITY_CONTROL,
    WEAKENED_SECURITY_CONTROL,
    category_record,
)

_CONTROL_LABELS = frozenset(
    {
        "sanitize",
        "sanitization",
        "validate",
        "validation",
        "authorize",
        "authorization",
        "authz",
        "parameterize",
        "parameterization",
        "encode",
        "encoding",
        "escape",
        "csrf",
        "allowlist",
        "whitelist",
    }
)


def _path_sig(path: dict[str, Any]) -> str:
    hops = path.get("hops") or path.get("steps") or []
    if hops:
        parts = []
        for h in hops:
            if isinstance(h, dict):
                parts.append(str(h.get("id") or h.get("label") or h.get("kind") or ""))
            else:
                parts.append(str(h))
        return "→".join(parts)
    src = path.get("source") or {}
    sink = path.get("sink") or {}
    if isinstance(src, dict):
        src_s = str(src.get("id") or src.get("label") or src.get("kind") or "")
    else:
        src_s = str(src)
    if isinstance(sink, dict):
        sink_s = str(sink.get("id") or sink.get("label") or sink.get("kind") or sink.get("type") or "")
    else:
        sink_s = str(sink)
    return f"{src_s}→{sink_s}"


def _entity_keys(items: list[Any]) -> set[str]:
    out: set[str] = set()
    for it in items or []:
        if isinstance(it, dict):
            out.add(
                str(
                    it.get("id")
                    or it.get("label")
                    or f"{it.get('kind') or it.get('type')}:{it.get('file')}:{it.get('line')}"
                )
            )
        else:
            out.add(str(it))
    return out


def _control_labels_from_path(path: dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for key in ("controls", "sanitizers", "validators", "transforms", "barriers"):
        for c in path.get(key) or []:
            if isinstance(c, dict):
                raw = " ".join(
                    str(c.get(k) or "")
                    for k in ("kind", "type", "label", "name", "effectiveness")
                ).lower()
            else:
                raw = str(c).lower()
            for token in _CONTROL_LABELS:
                if token in raw:
                    labels.add(token)
    # Also scan step annotations
    for step in path.get("hops") or path.get("steps") or []:
        if not isinstance(step, dict):
            continue
        raw = " ".join(
            str(step.get(k) or "") for k in ("kind", "type", "label", "taint_state")
        ).lower()
        for token in _CONTROL_LABELS:
            if token in raw:
                labels.add(token)
    taint = str(path.get("taint_state") or path.get("state") or "").upper()
    if taint in {"SANITIZED", "VALIDATED", "TRUSTED"}:
        labels.add(taint.lower())
    return labels


def _is_sensitive(path: dict[str, Any]) -> bool:
    if path.get("sensitive") or path.get("is_sensitive"):
        return True
    tags = [str(t).lower() for t in (path.get("tags") or [])]
    if any(t in tags for t in ("sensitive", "pii", "secret", "credential")):
        return True
    sink = path.get("sink") or {}
    st = str(sink.get("type") or sink.get("kind") or "").lower() if isinstance(sink, dict) else ""
    return st in {"sql", "html", "cmd", "exec", "eval", "ai_tool"}


def compare_dataflows(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, Any]:
    categories: list[dict[str, Any]] = []
    summary: dict[str, Any] = {
        "new_sources": [],
        "new_sinks": [],
        "new_paths": [],
        "removed_controls": [],
        "baseline_unknown": before is None,
    }

    if before is None or after is None:
        return {"categories": categories, "summary": summary, "baseline_unknown": True}

    before_sources = _entity_keys(before.get("sources") or [])
    after_sources = _entity_keys(after.get("sources") or [])
    for s in sorted(after_sources - before_sources):
        summary["new_sources"].append(s)

    before_sinks = _entity_keys(before.get("sinks") or [])
    after_sinks = _entity_keys(after.get("sinks") or [])
    for s in sorted(after_sinks - before_sinks):
        summary["new_sinks"].append(s)

    def _paths_of(df: dict[str, Any]) -> list[dict[str, Any]]:
        raw = df.get("taint_paths") or df.get("paths") or df.get("flows") or []
        return [p for p in raw if isinstance(p, dict)]

    before_paths = {_path_sig(p): p for p in _paths_of(before)}
    after_paths = {_path_sig(p): p for p in _paths_of(after)}

    for sig, path in after_paths.items():
        if sig not in before_paths:
            summary["new_paths"].append(sig)
            if _is_sensitive(path):
                categories.append(
                    category_record(NEW_SENSITIVE_DATA_FLOW, detail=sig)
                )
            sink = path.get("sink") or {}
            st = (
                str(sink.get("type") or sink.get("kind") or "").lower()
                if isinstance(sink, dict)
                else ""
            )
            if st in {"sql", "db"}:
                categories.append(category_record(NEW_DATABASE_FLOW, detail=sig))
        else:
            # Control label diffs on shared paths
            before_ctrl = _control_labels_from_path(before_paths[sig])
            after_ctrl = _control_labels_from_path(path)
            removed = before_ctrl - after_ctrl
            for label in sorted(removed):
                detail = f"{sig}: removed {label}"
                summary["removed_controls"].append(detail)
                categories.append(
                    category_record(
                        REMOVED_SECURITY_CONTROL,
                        detail=detail,
                        severity="HIGH",
                    )
                )
            # Weakened: was sanitized/validated, now tainted
            before_state = str(
                before_paths[sig].get("taint_state")
                or before_paths[sig].get("state")
                or ""
            ).upper()
            after_state = str(path.get("taint_state") or path.get("state") or "").upper()
            if before_state in {"SANITIZED", "VALIDATED", "TRUSTED"} and after_state in {
                "TAINTED",
                "PARTIALLY_SANITIZED",
                "UNKNOWN",
            }:
                categories.append(
                    category_record(
                        WEAKENED_SECURITY_CONTROL,
                        detail=f"{sig}: {before_state}→{after_state}",
                        severity="HIGH",
                    )
                )

    return {
        "categories": categories,
        "summary": summary,
        "baseline_unknown": False,
    }
