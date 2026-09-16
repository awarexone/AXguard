"""Authorization and tenant-isolation special-case diffs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

TENANT_TOKENS = (
    "tenant_id",
    "organization_id",
    "org_id",
    "workspace_id",
    "account_id",
    "owner_id",
)

_OWNERSHIP_PATTERNS = (
    re.compile(r"\b\.owner\b", re.I),
    re.compile(r"user[_]?id\s*==", re.I),
    re.compile(r"\bcurrent_user_id\b", re.I),
    re.compile(r"belongs_to", re.I),
    re.compile(r"check_object_permissions", re.I),
    re.compile(r"has_perm(?:ission)?\b", re.I),
    re.compile(r"is_owner\b", re.I),
    re.compile(r"filter\(\s*owner", re.I),
    re.compile(r"\.filter\(.*user", re.I),
    # Comparisons / checks involving owner_id (not mere dict keys or comments)
    re.compile(r"owner[_]?id\s*[!=]=", re.I),
    re.compile(r"[!=]=\s*.*owner[_]?id", re.I),
    re.compile(r"\[['\"]owner_id['\"]\]\s*[!=]=", re.I),
    re.compile(r"check_ownership\b", re.I),
    re.compile(r"\bdef\s+check_ownership\b", re.I),
)

_AUTHZ_DECORATORS = (
    re.compile(r"@\s*login_required\b", re.I),
    re.compile(r"@\s*permission_required\b", re.I),
    re.compile(r"@\s*require[_]?auth", re.I),
    re.compile(r"@\s*authorize\b", re.I),
    re.compile(r"@\s*roles_required\b", re.I),
    re.compile(r"Depends\(\s*[^)]*auth", re.I),
)

_TENANT_PATTERNS = tuple(
    re.compile(rf"\b{re.escape(t)}\b", re.I) for t in TENANT_TOKENS
) + (
    re.compile(r"tenant[_ ]?(?:check|scope|isolation|middleware)", re.I),
    re.compile(r"row[_ -]?level[_ ]?security|\brls\b", re.I),
)


def _scan_text(text: str) -> dict[str, Any]:
    ownership_hits = sum(1 for p in _OWNERSHIP_PATTERNS if p.search(text))
    authz_hits = sum(1 for p in _AUTHZ_DECORATORS if p.search(text))
    tenant_hits = sum(1 for p in _TENANT_PATTERNS if p.search(text))
    tokens_present = [t for t in TENANT_TOKENS if re.search(rf"\b{t}\b", text, re.I)]
    return {
        "ownership_hits": ownership_hits,
        "authz_decorator_hits": authz_hits,
        "tenant_hits": tenant_hits,
        "tenant_tokens": tokens_present,
        "has_ownership": ownership_hits > 0,
        "has_authz": authz_hits > 0 or ownership_hits > 0,
        "has_tenant": tenant_hits > 0,
    }


def scan_path_for_authz(path: Path) -> dict[str, Any]:
    """Scan source files under path for ownership/authz/tenant heuristics."""
    aggregate = {
        "ownership_hits": 0,
        "authz_decorator_hits": 0,
        "tenant_hits": 0,
        "tenant_tokens": set(),
        "files": [],
    }
    if not path.exists():
        return {
            **aggregate,
            "tenant_tokens": [],
            "has_ownership": False,
            "has_authz": False,
            "has_tenant": False,
        }

    files = [path] if path.is_file() else list(path.rglob("*.py")) + list(
        path.rglob("*.js")
    ) + list(path.rglob("*.ts"))
    for f in files:
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        hit = _scan_text(text)
        if hit["has_ownership"] or hit["has_authz"] or hit["has_tenant"]:
            aggregate["files"].append(
                {"file": str(f), **{k: v for k, v in hit.items() if k != "tenant_tokens"}}
            )
        aggregate["ownership_hits"] += hit["ownership_hits"]
        aggregate["authz_decorator_hits"] += hit["authz_decorator_hits"]
        aggregate["tenant_hits"] += hit["tenant_hits"]
        aggregate["tenant_tokens"].update(hit["tenant_tokens"])

    tokens = sorted(aggregate["tenant_tokens"])
    return {
        "ownership_hits": aggregate["ownership_hits"],
        "authz_decorator_hits": aggregate["authz_decorator_hits"],
        "tenant_hits": aggregate["tenant_hits"],
        "tenant_tokens": tokens,
        "files": aggregate["files"],
        "has_ownership": aggregate["ownership_hits"] > 0,
        "has_authz": aggregate["authz_decorator_hits"] > 0
        or aggregate["ownership_hits"] > 0,
        "has_tenant": aggregate["tenant_hits"] > 0,
    }


def _auth_status(ep: dict[str, Any]) -> str:
    authn = ep.get("authentication") or {}
    authz = ep.get("authorization") or {}
    if isinstance(authn, dict):
        st = str(authn.get("status") or "").lower()
        if st:
            return st
    if isinstance(authz, dict):
        st = str(authz.get("status") or "").lower()
        if st:
            return st
    return "unknown"


def compare_authz(
    *,
    before_target: Path | None = None,
    after_target: Path | None = None,
    before_app: dict[str, Any] | None = None,
    after_app: dict[str, Any] | None = None,
    before_text_scan: dict[str, Any] | None = None,
    after_text_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce authz_changes and tenant_changes lists."""
    authz_changes: list[dict[str, Any]] = []
    tenant_changes: list[dict[str, Any]] = []

    before_scan = before_text_scan
    after_scan = after_text_scan
    if before_scan is None and before_target is not None:
        before_scan = scan_path_for_authz(before_target)
    if after_scan is None and after_target is not None:
        after_scan = scan_path_for_authz(after_target)

    if before_scan is not None and after_scan is not None:
        if before_scan.get("has_ownership") and not after_scan.get("has_ownership"):
            authz_changes.append(
                {
                    "change": "ownership check removed",
                    "impact": "authorization weakened",
                    "evidence": "heuristic: ownership patterns present in base, absent in current",
                }
            )
        if before_scan.get("has_authz") and not after_scan.get("has_authz"):
            authz_changes.append(
                {
                    "change": "authorization removed",
                    "impact": "authorization weakened",
                    "evidence": "heuristic: authz decorators/checks removed",
                }
            )
        if not before_scan.get("has_authz") and after_scan.get("has_authz"):
            authz_changes.append(
                {
                    "change": "authorization added",
                    "impact": "authorization strengthened",
                }
            )
        if before_scan.get("has_tenant") and not after_scan.get("has_tenant"):
            tenant_changes.append(
                {
                    "change": "tenant boundary removed",
                    "impact": "tenant isolation weakened",
                    "tokens_before": before_scan.get("tenant_tokens") or [],
                }
            )
        before_tok = set(before_scan.get("tenant_tokens") or [])
        after_tok = set(after_scan.get("tenant_tokens") or [])
        lost = before_tok - after_tok
        if lost:
            tenant_changes.append(
                {
                    "change": "tenant validation bypassed",
                    "impact": "tenant isolation weakened",
                    "tokens_removed": sorted(lost),
                }
            )

    # Entrypoint auth status broadening
    if before_app and after_app:
        def ep_map(model: dict[str, Any]) -> dict[str, str]:
            out = {}
            for ep in model.get("entrypoints") or []:
                if not isinstance(ep, dict):
                    continue
                method = str(ep.get("method") or "*").upper()
                path = str(ep.get("path") or "")
                out[f"{method} {path}"] = _auth_status(ep)
            return out

        bmap = ep_map(before_app)
        amap = ep_map(after_app)
        rank = {"required": 3, "optional": 2, "none": 1, "unknown": 0}
        for key, after_st in amap.items():
            before_st = bmap.get(key)
            if before_st is None:
                continue
            if rank.get(before_st, 0) > rank.get(after_st, 0) and after_st in {
                "none",
                "optional",
                "unknown",
            }:
                authz_changes.append(
                    {
                        "change": "authorization broadened",
                        "endpoint": key,
                        "previous": before_st,
                        "current": after_st,
                        "impact": "privilege expansion",
                    }
                )
            elif before_st != after_st and after_st != "unknown":
                authz_changes.append(
                    {
                        "change": "authorization scope changed",
                        "endpoint": key,
                        "previous": before_st,
                        "current": after_st,
                    }
                )

    return {
        "authz_changes": authz_changes,
        "tenant_changes": tenant_changes,
        "before_scan": before_scan,
        "after_scan": after_scan,
        "baseline_unknown": before_scan is None,
    }
