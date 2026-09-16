"""Security Diff schema — versioned result shape and vocabularies."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SECURITY_DIFF_VERSION = "1"
SCHEMA_VERSION = SECURITY_DIFF_VERSION
TOOL_NAME = "axguard"

# ---------------------------------------------------------------------------
# Impact / decision
# ---------------------------------------------------------------------------
IMPACT_NONE = "NONE"
IMPACT_LOW = "LOW"
IMPACT_MEDIUM = "MEDIUM"
IMPACT_HIGH = "HIGH"
IMPACT_CRITICAL = "CRITICAL"
IMPACT_UNKNOWN = "UNKNOWN"
IMPACTS = frozenset(
    {
        IMPACT_NONE,
        IMPACT_LOW,
        IMPACT_MEDIUM,
        IMPACT_HIGH,
        IMPACT_CRITICAL,
        IMPACT_UNKNOWN,
    }
)

DECISION_PASS = "PASS"
DECISION_REVIEW_REQUIRED = "REVIEW_REQUIRED"
DECISION_FAIL = "FAIL"
DECISION_UNKNOWN = "UNKNOWN"
DECISIONS = frozenset(
    {DECISION_PASS, DECISION_REVIEW_REQUIRED, DECISION_FAIL, DECISION_UNKNOWN}
)

# ---------------------------------------------------------------------------
# Baseline sources
# ---------------------------------------------------------------------------
BASELINE_GIT = "GIT"
BASELINE_AXGUARD_SNAPSHOT = "AXGUARD_SNAPSHOT"
BASELINE_ARTIFACTS = "ARTIFACTS"
BASELINE_PATH = "PATH"
BASELINE_UNAVAILABLE = "BASELINE_UNAVAILABLE"
# Legacy / compose / preship vocabulary
BASELINE_UNKNOWN = "UNKNOWN"
BASELINE_SOURCES = frozenset(
    {
        BASELINE_GIT,
        BASELINE_AXGUARD_SNAPSHOT,
        BASELINE_ARTIFACTS,
        BASELINE_PATH,
        BASELINE_UNAVAILABLE,
        BASELINE_UNKNOWN,
    }
)

# ---------------------------------------------------------------------------
# Control states
# ---------------------------------------------------------------------------
CONTROL_ADDED = "ADDED"
CONTROL_REMOVED = "REMOVED"
CONTROL_WEAKENED = "WEAKENED"
CONTROL_STRENGTHENED = "STRENGTHENED"
CONTROL_MOVED = "MOVED"
CONTROL_BYPASSED = "BYPASSED"
CONTROL_UNKNOWN = "UNKNOWN"
CONTROL_UNCHANGED = "UNCHANGED"
CONTROL_STATES = frozenset(
    {
        CONTROL_ADDED,
        CONTROL_REMOVED,
        CONTROL_WEAKENED,
        CONTROL_STRENGTHENED,
        CONTROL_MOVED,
        CONTROL_BYPASSED,
        CONTROL_UNKNOWN,
        CONTROL_UNCHANGED,
    }
)

# ---------------------------------------------------------------------------
# Auth effective protection
# ---------------------------------------------------------------------------
AUTH_STRONGER = "STRONGER"
AUTH_WEAKER = "WEAKER"
AUTH_UNCHANGED = "UNCHANGED"
AUTH_UNKNOWN = "UNKNOWN"

# ---------------------------------------------------------------------------
# Memory / predictive vocabularies
# ---------------------------------------------------------------------------
MEMORY_NEW = "NEW"
MEMORY_RESOLVED = "RESOLVED"
MEMORY_REGRESSED = "REGRESSED"
MEMORY_RECONFIRMED = "RECONFIRMED"
MEMORY_SUPERSEDED = "SUPERSEDED"
MEMORY_UNKNOWN = "UNKNOWN"

PRED_NEW_RISK = "NEW_RISK"
PRED_REMOVED_RISK = "REMOVED_RISK"
PRED_INCREASED_RISK = "INCREASED_RISK"
PRED_DECREASED_RISK = "DECREASED_RISK"
PRED_UNCHANGED = "UNCHANGED"

# ---------------------------------------------------------------------------
# Attack surface / category change types
# ---------------------------------------------------------------------------
NEW_ENDPOINT = "NEW_ENDPOINT"
REMOVED_ENDPOINT = "REMOVED_ENDPOINT"
NEW_HTTP_METHOD = "NEW_HTTP_METHOD"
REMOVED_HTTP_METHOD = "REMOVED_HTTP_METHOD"
NEW_PARAMETER = "NEW_PARAMETER"
REMOVED_PARAMETER = "REMOVED_PARAMETER"
NEW_WEBHOOK = "NEW_WEBHOOK"
REMOVED_WEBHOOK = "REMOVED_WEBHOOK"
NEW_UPLOAD = "NEW_UPLOAD"
NEW_GRAPHQL_RESOLVER = "NEW_GRAPHQL_RESOLVER"
NEW_WEBSOCKET = "NEW_WEBSOCKET"
NEW_PUBLIC_RESOURCE = "NEW_PUBLIC_RESOURCE"
NEW_EXTERNAL_INTEGRATION = "NEW_EXTERNAL_INTEGRATION"
NEW_NETWORK_INTERFACE = "NEW_NETWORK_INTERFACE"
NEW_SERVICE = "NEW_SERVICE"
NEW_WORKER = "NEW_WORKER"
NEW_QUEUE = "NEW_QUEUE"
NEW_AI_AGENT = "NEW_AI_AGENT"
NEW_AGENT_TOOL = "NEW_AGENT_TOOL"
NEW_MCP_SERVER = "NEW_MCP_SERVER"
NEW_MCP_TOOL = "NEW_MCP_TOOL"
NEW_EXTERNAL_REQUEST = "NEW_EXTERNAL_REQUEST"
NEW_DATABASE_FLOW = "NEW_DATABASE_FLOW"
NEW_FILE_ACCESS = "NEW_FILE_ACCESS"
NEW_COMMAND_EXECUTION = "NEW_COMMAND_EXECUTION"
NEW_SECRET = "NEW_SECRET"
NEW_IDENTITY = "NEW_IDENTITY"
NEW_PERMISSION = "NEW_PERMISSION"
NEW_PRIVILEGE = "NEW_PRIVILEGE"
NEW_AGENT = "NEW_AGENT"
NEW_AI_TOOL = "NEW_AI_TOOL"
NEW_TRUST_BOUNDARY = "NEW_TRUST_BOUNDARY"
REMOVED_TRUST_BOUNDARY = "REMOVED_TRUST_BOUNDARY"
REMOVED_SECURITY_CONTROL = "REMOVED_SECURITY_CONTROL"
WEAKENED_SECURITY_CONTROL = "WEAKENED_SECURITY_CONTROL"
STRENGTHENED_SECURITY_CONTROL = "STRENGTHENED_SECURITY_CONTROL"
MOVED_SECURITY_CONTROL = "MOVED_SECURITY_CONTROL"
NEW_SENSITIVE_DATA_FLOW = "NEW_SENSITIVE_DATA_FLOW"
NEW_ATTACK_PATH = "NEW_ATTACK_PATH"
BLOCKED_ATTACK_PATH = "BLOCKED_ATTACK_PATH"
REMOVED_ATTACK_PATH = "REMOVED_ATTACK_PATH"
REOPENED_ATTACK_PATH = "REOPENED_ATTACK_PATH"
WEAKENED_ATTACK_PATH = "WEAKENED_ATTACK_PATH"
NEW_DEPENDENCY = "NEW_DEPENDENCY"
REMOVED_DEPENDENCY = "REMOVED_DEPENDENCY"
DEPENDENCY_RISK_CHANGE = "DEPENDENCY_RISK_CHANGE"
CONFIGURATION_SECURITY_CHANGE = "CONFIGURATION_SECURITY_CHANGE"
PRIVILEGE_EXPANSION = "PRIVILEGE_EXPANSION"
TENANT_BOUNDARY_WEAKENED = "TENANT_BOUNDARY_WEAKENED"
AI_AGENT_PRIVILEGE_EXPANSION = "AI_AGENT_PRIVILEGE_EXPANSION"
MCP_PRIVILEGE_EXPANSION = "MCP_PRIVILEGE_EXPANSION"

# Back-compat aliases used by early modules
SEVERITY_LOW = IMPACT_LOW
SEVERITY_MEDIUM = IMPACT_MEDIUM
SEVERITY_HIGH = IMPACT_HIGH
SEVERITY_CRITICAL = IMPACT_CRITICAL
SEVERITIES = IMPACTS
BASELINE_UNKNOWN = "UNKNOWN"

CHANGE_CATEGORIES = frozenset(
    {
        NEW_ENDPOINT,
        REMOVED_ENDPOINT,
        NEW_PARAMETER,
        NEW_EXTERNAL_REQUEST,
        NEW_DATABASE_FLOW,
        NEW_FILE_ACCESS,
        NEW_COMMAND_EXECUTION,
        NEW_UPLOAD,
        NEW_WEBHOOK,
        NEW_SECRET,
        NEW_IDENTITY,
        NEW_PERMISSION,
        NEW_PRIVILEGE,
        NEW_AGENT,
        NEW_AI_TOOL,
        NEW_MCP_TOOL,
        NEW_EXTERNAL_INTEGRATION,
        NEW_TRUST_BOUNDARY,
        REMOVED_SECURITY_CONTROL,
        WEAKENED_SECURITY_CONTROL,
        STRENGTHENED_SECURITY_CONTROL,
        NEW_SENSITIVE_DATA_FLOW,
        NEW_ATTACK_PATH,
        BLOCKED_ATTACK_PATH,
        NEW_DEPENDENCY,
        DEPENDENCY_RISK_CHANGE,
        CONFIGURATION_SECURITY_CHANGE,
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def side_ref(
    *,
    source: str = BASELINE_UNAVAILABLE,
    ref: str | None = None,
    path: str | None = None,
    label: str | None = None,
    sha: str | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "ref": ref,
        "path": path,
        "label": label or ref or path,
        "sha": sha,
    }


def empty_security_diff(
    *,
    base: dict[str, Any] | None = None,
    head: dict[str, Any] | None = None,
    current_target: str | None = None,
    base_target: str | None = None,
    base_ref: str | None = None,
    baseline: str = BASELINE_UNAVAILABLE,
) -> dict[str, Any]:
    """Stable empty result for consumers and tests."""
    base_side = base or side_ref(
        source=baseline,
        ref=base_ref,
        path=base_target,
    )
    head_side = head or side_ref(
        source=BASELINE_PATH if current_target else BASELINE_UNAVAILABLE,
        path=current_target,
        label=current_target,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "generated_at": utc_now(),
        "base": base_side,
        "head": head_side,
        # legacy mirrors
        "current_target": current_target or head_side.get("path"),
        "base_target": base_target or base_side.get("path"),
        "base_ref": base_ref or base_side.get("ref"),
        "baseline": baseline,
        "security_impact": {
            "level": IMPACT_NONE,
            "reason": "No meaningful security changes detected.",
            "decision": DECISION_PASS,
        },
        "attack_surface_delta": {
            "added": [],
            "removed": [],
            "changed": [],
            "summary": {},
        },
        "control_delta": {"changes": [], "summary": {}},
        "auth_delta": {
            "changes": [],
            "effective": AUTH_UNCHANGED,
            "summary": {},
        },
        "authorization_delta": {"changes": [], "summary": {}},
        "tenant_isolation_delta": {
            "changes": [],
            "summary": {},
            "priority": "high",
        },
        "data_flow_delta": {
            "added": [],
            "removed": [],
            "changed": [],
            "summary": {},
        },
        "trust_boundary_delta": {"changes": [], "summary": {}},
        "identity_delta": {"changes": [], "summary": {}},
        "privilege_delta": {"changes": [], "summary": {}},
        "secrets_delta": {"changes": [], "summary": {}},
        "dependency_delta": {"changes": [], "summary": {}},
        "ai_delta": {"changes": [], "summary": {}},
        "mcp_delta": {"changes": [], "summary": {}},
        "attack_path_delta": {
            "new_paths": [],
            "removed_paths": [],
            "blocked_paths": [],
            "reopened_paths": [],
            "weakened_paths": [],
            "summary": {},
        },
        "security_twin_delta": {},
        "memory_delta": {"outcomes": {}, "regressions": [], "summary": {}},
        "predictive_risks": [],
        "regressions": [],
        "unknowns": [],
        "evidence": [],
        "recommended_actions": [],
        "root_causes": [],
        "categories": [],
        "summary": {
            "new_endpoints": 0,
            "removed_endpoints": 0,
            "new_parameters": 0,
            "new_database_flows": 0,
            "new_external_requests": 0,
            "new_uploads": 0,
            "new_webhooks": 0,
            "removed_controls": 0,
            "weakened_controls": 0,
            "strengthened_controls": 0,
            "moved_controls": 0,
            "added_controls": 0,
            "new_attack_paths": 0,
            "blocked_attack_paths": 0,
            "new_sensitive_flows": 0,
            "authz_changes": 0,
            "tenant_changes": 0,
            "privilege_changes": 0,
            "regressions": 0,
            "predictive_risks": 0,
            "unknowns": 0,
        },
        "overall_security_change": IMPACT_NONE,
        "authz_changes": [],
        "tenant_changes": [],
        "control_changes": [],
        "app_model_delta": {},
        "dataflow_delta": {},
        "twin_delta": {},
        "options": {},
        "notes": [],
        "changed_files": [],
    }


def category_record(
    category: str,
    *,
    detail: str = "",
    evidence: str | None = None,
    severity: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    rec: dict[str, Any] = {"category": category, "detail": detail}
    if evidence:
        rec["evidence"] = evidence
    if severity:
        rec["severity"] = severity
    rec.update(extra)
    return rec


def delta_item(
    kind: str,
    *,
    detail: str = "",
    impact: str = IMPACT_UNKNOWN,
    evidence: list[Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "kind": kind,
        "detail": detail,
        "impact": impact,
        "evidence": evidence or [],
    }
    rec.update(extra)
    return rec


def control_change(
    *,
    control_type: str,
    state: str,
    detail: str = "",
    before: str | None = None,
    after: str | None = None,
    location_before: str | None = None,
    location_after: str | None = None,
    impact: str = IMPACT_UNKNOWN,
    evidence: list[Any] | None = None,
) -> dict[str, Any]:
    return {
        "control_type": control_type,
        "state": state,
        "detail": detail,
        "before": before,
        "after": after,
        "location_before": location_before,
        "location_after": location_after,
        "impact": impact,
        "evidence": evidence or [],
    }


def regression_record(
    *,
    title: str,
    before: str,
    change: str,
    now: str,
    impact: str,
    evidence: list[Any] | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "before": before,
        "change": change,
        "now": now,
        "impact": impact,
        "evidence": evidence or [],
        "category": category,
        "status": MEMORY_REGRESSED,
    }


def unknown_record(area: str, reason: str) -> dict[str, Any]:
    return {"area": area, "reason": reason, "status": "UNKNOWN"}
