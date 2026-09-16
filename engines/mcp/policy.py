"""Server-side approval tiers — annotations are hints only."""

from __future__ import annotations

from enum import Enum
from typing import Any

from engines.mcp.schemas.errors import McpError


class ApprovalTier(str, Enum):
    AUTO = "AUTO"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    HIGH_RISK = "HIGH_RISK"


# Default tier per tool name. Missing tools are treated as APPROVAL_REQUIRED.
TOOL_TIERS: dict[str, ApprovalTier] = {
    # Repository understanding
    "axguard_get_project": ApprovalTier.AUTO,
    "axguard_get_application_model": ApprovalTier.AUTO,
    "axguard_get_attack_surface": ApprovalTier.AUTO,
    # Security
    "axguard_scan": ApprovalTier.AUTO,
    "axguard_audit": ApprovalTier.APPROVAL_REQUIRED,
    "axguard_threat_model": ApprovalTier.AUTO,
    "axguard_security_review": ApprovalTier.AUTO,  # DEEP/MAX escalate below
    # Data flow
    "axguard_trace_flow": ApprovalTier.AUTO,
    "axguard_find_taint_paths": ApprovalTier.AUTO,
    "axguard_find_sensitive_flows": ApprovalTier.AUTO,
    # Findings
    "axguard_list_findings": ApprovalTier.AUTO,
    "axguard_get_finding": ApprovalTier.AUTO,
    "axguard_verify_finding": ApprovalTier.APPROVAL_REQUIRED,
    # Evidence
    "axguard_get_evidence": ApprovalTier.AUTO,
    "axguard_get_evidence_chain": ApprovalTier.AUTO,
    "axguard_get_counter_evidence": ApprovalTier.AUTO,
    # Attack paths
    "axguard_find_attack_paths": ApprovalTier.AUTO,
    "axguard_get_attack_path": ApprovalTier.AUTO,
    "axguard_explain_attack_path": ApprovalTier.AUTO,
    # Twin
    "axguard_get_security_twin": ApprovalTier.AUTO,
    "axguard_compare_security_twin": ApprovalTier.AUTO,
    "axguard_what_if": ApprovalTier.APPROVAL_REQUIRED,
    "axguard_blast_radius": ApprovalTier.AUTO,
    # Memory
    "axguard_get_security_memory": ApprovalTier.AUTO,
    "axguard_get_security_history": ApprovalTier.AUTO,
    "axguard_find_regressions": ApprovalTier.AUTO,
    # Investigation
    "axguard_investigate": ApprovalTier.APPROVAL_REQUIRED,
    "axguard_get_investigation": ApprovalTier.AUTO,
    # Predictive
    "axguard_predict_security_risks": ApprovalTier.AUTO,
    "axguard_analyze_change_risk": ApprovalTier.AUTO,
    "axguard_security_diff": ApprovalTier.AUTO,
    "axguard_preship": ApprovalTier.APPROVAL_REQUIRED,
}

# Operations that must never run autonomously via MCP
BLOCKED_OPERATIONS = frozenset(
    {
        "shell",
        "network",
        "browser",
        "exploit",
        "credential_access",
        "remediate_write",
        "execute_repo_code",
    }
)


def tier_for(tool_name: str) -> ApprovalTier:
    return TOOL_TIERS.get(tool_name, ApprovalTier.APPROVAL_REQUIRED)


def escalate_review_tier(mode: str | None) -> ApprovalTier:
    m = (mode or "BALANCED").upper()
    if m in {"DEEP", "MAX"}:
        return ApprovalTier.APPROVAL_REQUIRED
    return ApprovalTier.AUTO


def enforce(
    tool_name: str,
    *,
    approved: bool = False,
    mode: str | None = None,
    operation: str | None = None,
) -> ApprovalTier:
    """Raise McpError when policy denies the call."""
    if operation and operation in BLOCKED_OPERATIONS:
        raise McpError(
            "UNSUPPORTED_OPERATION",
            f"Operation '{operation}' is not available through AXGuard MCP.",
            details={"operation": operation},
        )

    tier = tier_for(tool_name)
    if tool_name == "axguard_security_review":
        review_tier = escalate_review_tier(mode)
        if review_tier == ApprovalTier.APPROVAL_REQUIRED:
            tier = ApprovalTier.APPROVAL_REQUIRED

    if tier == ApprovalTier.HIGH_RISK:
        raise McpError(
            "PERMISSION_DENIED",
            f"Tool '{tool_name}' is HIGH_RISK and is blocked by MCP policy.",
            details={"tier": tier.value, "tool": tool_name},
        )

    if tier == ApprovalTier.APPROVAL_REQUIRED and not approved:
        raise McpError(
            "APPROVAL_REQUIRED",
            f"Tool '{tool_name}' requires explicit user approval "
            "(pass approved=true after the user consents).",
            details={"tier": tier.value, "tool": tool_name},
        )

    return tier


def policy_snapshot() -> dict[str, Any]:
    return {
        "tiers": {name: t.value for name, t in TOOL_TIERS.items()},
        "blocked_operations": sorted(BLOCKED_OPERATIONS),
        "note": "Annotations are hints; this policy is enforced server-side.",
    }
