"""Compare two application models for endpoint/route/method/param deltas."""

from __future__ import annotations

from typing import Any

from engines.security_diff.schema import (
    NEW_AI_TOOL,
    NEW_AGENT,
    NEW_COMMAND_EXECUTION,
    NEW_DATABASE_FLOW,
    NEW_ENDPOINT,
    NEW_EXTERNAL_INTEGRATION,
    NEW_EXTERNAL_REQUEST,
    NEW_FILE_ACCESS,
    NEW_IDENTITY,
    NEW_MCP_TOOL,
    NEW_PARAMETER,
    NEW_TRUST_BOUNDARY,
    NEW_UPLOAD,
    NEW_WEBHOOK,
    REMOVED_ENDPOINT,
    category_record,
)


def _ep_key(ep: dict[str, Any]) -> str:
    method = str(ep.get("method") or ep.get("http_method") or "*").upper()
    path = str(ep.get("path") or ep.get("route") or ep.get("name") or "")
    return f"{method} {path}".strip()


def _input_keys(ep: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for inp in ep.get("inputs") or ep.get("params") or []:
        if isinstance(inp, dict):
            name = inp.get("name") or inp.get("param") or inp.get("id")
            if name:
                keys.add(str(name))
        elif isinstance(inp, str):
            keys.add(inp)
    return keys


def _id_set(items: list[Any], *keys: str) -> set[str]:
    out: set[str] = set()
    for it in items or []:
        if not isinstance(it, dict):
            continue
        for k in keys:
            v = it.get(k)
            if v:
                out.add(str(v))
                break
        else:
            # fallback label
            label = it.get("label") or it.get("type") or it.get("kind")
            if label:
                out.add(str(label))
    return out


def _sink_keys(sinks: list[Any], kinds: set[str]) -> set[str]:
    out: set[str] = set()
    for s in sinks or []:
        if not isinstance(s, dict):
            continue
        st = str(s.get("type") or s.get("kind") or "").lower()
        if st in kinds or any(k in st for k in kinds):
            loc = s.get("file") or (s.get("evidence") or {}).get("file") or ""
            line = s.get("line") or (s.get("evidence") or {}).get("line") or ""
            out.add(f"{st}:{loc}:{line}:{s.get('symbol') or s.get('label') or ''}")
    return out


def compare_app_models(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, Any]:
    """Structural app-model delta. Empty/None before → baseline unknown for that side."""
    categories: list[dict[str, Any]] = []
    summary = {
        "added_endpoints": [],
        "removed_endpoints": [],
        "new_parameters": [],
        "new_uploads": [],
        "new_webhooks": [],
        "new_identities": [],
        "new_external": [],
        "new_ai": [],
        "new_trust_boundaries": [],
        "baseline_unknown": before is None,
    }

    if before is None or after is None:
        return {"categories": categories, "summary": summary, "baseline_unknown": True}

    before_eps = {_ep_key(e): e for e in (before.get("entrypoints") or []) if isinstance(e, dict)}
    after_eps = {_ep_key(e): e for e in (after.get("entrypoints") or []) if isinstance(e, dict)}

    for key, ep in after_eps.items():
        if key not in before_eps:
            summary["added_endpoints"].append(key)
            categories.append(
                category_record(
                    NEW_ENDPOINT,
                    detail=key,
                    evidence=_evidence_loc(ep),
                )
            )
            # uploads / webhooks heuristics on new endpoints
            path_l = key.lower()
            if "upload" in path_l or "multipart" in path_l:
                summary["new_uploads"].append(key)
                categories.append(category_record(NEW_UPLOAD, detail=key))
            if "webhook" in path_l or "hook" in path_l:
                summary["new_webhooks"].append(key)
                categories.append(category_record(NEW_WEBHOOK, detail=key))
        else:
            # new parameters on existing endpoint
            before_in = _input_keys(before_eps[key])
            after_in = _input_keys(ep)
            for p in sorted(after_in - before_in):
                summary["new_parameters"].append(f"{key}::{p}")
                categories.append(
                    category_record(NEW_PARAMETER, detail=f"{key} param={p}")
                )

    for key in before_eps:
        if key not in after_eps:
            summary["removed_endpoints"].append(key)
            categories.append(category_record(REMOVED_ENDPOINT, detail=key))

    # Identities / external / AI / trust boundaries / sinks
    for label, cat, before_key, after_key, keys in (
        ("identities", NEW_IDENTITY, "identities", "identities", ("id", "name", "role")),
        (
            "external",
            NEW_EXTERNAL_INTEGRATION,
            "external_services",
            "external_services",
            ("id", "name", "url", "host"),
        ),
        ("ai", NEW_AGENT, "ai_components", "ai_components", ("id", "name", "type")),
        (
            "trust",
            NEW_TRUST_BOUNDARY,
            "trust_boundaries",
            "trust_boundaries",
            ("id", "name", "label"),
        ),
    ):
        b = _id_set(before.get(before_key) or [], *keys)
        a = _id_set(after.get(after_key) or [], *keys)
        for item in sorted(a - b):
            categories.append(category_record(cat, detail=item))
            if label == "identities":
                summary["new_identities"].append(item)
            elif label == "external":
                summary["new_external"].append(item)
            elif label == "ai":
                summary["new_ai"].append(item)
            else:
                summary["new_trust_boundaries"].append(item)

    # AI / MCP tools
    for comp in after.get("ai_components") or []:
        if not isinstance(comp, dict):
            continue
        cid = str(comp.get("id") or comp.get("name") or "")
        before_ids = _id_set(before.get("ai_components") or [], "id", "name")
        if cid and cid not in before_ids:
            kind = str(comp.get("type") or comp.get("kind") or "").lower()
            if "mcp" in kind or "mcp" in cid.lower():
                categories.append(category_record(NEW_MCP_TOOL, detail=cid))
            elif "tool" in kind:
                categories.append(category_record(NEW_AI_TOOL, detail=cid))

    # Sink-based categories
    before_sinks = before.get("sinks") or []
    after_sinks = after.get("sinks") or []
    for kinds, cat in (
        ({"http", "net"}, NEW_EXTERNAL_REQUEST),
        ({"fs", "file"}, NEW_FILE_ACCESS),
        ({"exec", "cmd", "eval"}, NEW_COMMAND_EXECUTION),
        ({"sql", "db"}, NEW_DATABASE_FLOW),
        ({"upload"}, NEW_UPLOAD),
    ):
        b = _sink_keys(before_sinks, kinds)
        a = _sink_keys(after_sinks, kinds)
        for sk in sorted(a - b):
            categories.append(category_record(cat, detail=sk))

    return {
        "categories": categories,
        "summary": summary,
        "baseline_unknown": False,
    }


def _evidence_loc(ep: dict[str, Any]) -> str | None:
    ev = ep.get("evidence")
    if isinstance(ev, dict):
        f = ev.get("file")
        ln = ev.get("line")
        if f:
            return f"{f}:{ln}" if ln else str(f)
    f = ep.get("file")
    return str(f) if f else None
