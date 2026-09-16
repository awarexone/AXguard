"""Tool catalog metadata — agent-optimized descriptions + annotations."""

from __future__ import annotations

from typing import Any

from engines.mcp.policy import ApprovalTier, TOOL_TIERS

# (name, description, annotations_dict)
_TOOL_SPECS: list[tuple[str, str, dict[str, Any]]] = [
    (
        "axguard_security_review",
        (
            "PRIMARY entry point. Review the security impact of application code "
            "or a code change (project, changed_files, file, function, commit, "
            "branch, or diff). Orchestrates understand→memory→twin→flow→"
            "investigate→judge→adversary→paths→predict. "
            "Use before shipping, after authz/authn/tenant/HTTP/file/MCP/agent "
            "changes, or when investigating a possible vulnerability. "
            "Modes: LITE|BALANCED|DEEP|MAX. Read-only analysis — does not modify "
            "source or execute attacks. DEEP/MAX require approved=true."
        ),
        {
            "title": "AXGuard Security Review",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_project",
        (
            "Return project root metadata and AXGuard artifact locations. "
            "Call first when the workspace is unknown. Read-only."
        ),
        {
            "title": "Get Project",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_application_model",
        (
            "Build or return the application understanding model "
            "(routes, sinks, stack). Use when you need structure before "
            "deeper review. Read-only. Does not claim vulnerabilities."
        ),
        {
            "title": "Application Model",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_attack_surface",
        (
            "Summarize attack surface from the application model "
            "(entry points, sinks, trust boundaries). Read-only."
        ),
        {
            "title": "Attack Surface",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_scan",
        (
            "Run a bounded rules-based source scan. Prefer "
            "axguard_security_review for agent workflows. Read-only."
        ),
        {
            "title": "Scan",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_audit",
        (
            "Full A–Z audit with report artifacts under .findings/axguard. "
            "Expensive — requires approved=true. Prefer security_review for "
            "incremental agent use."
        ),
        {
            "title": "Audit",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_threat_model",
        (
            "Lightweight threat-model summary from surface + flows + paths. "
            "Use for new/unknown codebases before a deep review. Read-only."
        ),
        {
            "title": "Threat Model",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_trace_flow",
        (
            "Run dataflow/taint analysis. Returns diagnostic paths, not "
            "verified findings. Read-only."
        ),
        {
            "title": "Trace Flow",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_find_taint_paths",
        (
            "List taint paths from dataflow analysis (source→sink). "
            "Diagnostic only. Read-only."
        ),
        {
            "title": "Find Taint Paths",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_find_sensitive_flows",
        (
            "Filter dataflow paths that touch sensitive sinks or data. "
            "Diagnostic only. Read-only."
        ),
        {
            "title": "Sensitive Flows",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_list_findings",
        (
            "List summarized findings from the last scan/review (or run a "
            "bounded scan). Progressive disclosure — use get_finding next. "
            "Read-only."
        ),
        {
            "title": "List Findings",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_finding",
        (
            "Get a single finding summary by id. Does not dump full evidence; "
            "call evidence tools for detail. Read-only."
        ),
        {
            "title": "Get Finding",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_verify_finding",
        (
            "Run hunter→judge verification for candidates. Requires "
            "approved=true. Static/symbolic only — no exploitation."
        ),
        {
            "title": "Verify Finding",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_evidence",
        (
            "Return supporting evidence items for the last evidence run or "
            "a finding id. Read-only."
        ),
        {
            "title": "Get Evidence",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_evidence_chain",
        (
            "Return the evidence chain linking observations to a judgment. "
            "Read-only."
        ),
        {
            "title": "Evidence Chain",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_counter_evidence",
        (
            "Return counter-evidence / FP signals for a candidate. Read-only."
        ),
        {
            "title": "Counter-Evidence",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_find_attack_paths",
        (
            "Build/query attack-graph paths (entrypoint→outcome). Diagnostic "
            "chaining — not autonomous exploitation. Read-only."
        ),
        {
            "title": "Find Attack Paths",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_attack_path",
        (
            "Get one attack path by id from the last paths analysis. Read-only."
        ),
        {
            "title": "Get Attack Path",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_explain_attack_path",
        (
            "Explain an attack path in agent-friendly language with "
            "provenance. Read-only."
        ),
        {
            "title": "Explain Attack Path",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_security_twin",
        (
            "Build/return the Security Twin symbolic model. No network. "
            "Read-only."
        ),
        {
            "title": "Security Twin",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_compare_security_twin",
        (
            "Compare two twin artifacts or before/after directories. Read-only."
        ),
        {
            "title": "Compare Twin",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_what_if",
        (
            "Symbolic what-if / counterfactual on the twin (e.g. remove a "
            "control). Requires approved=true. Simulated — not live tests."
        ),
        {
            "title": "What-If",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_blast_radius",
        (
            "Compute entity blast radius from the Security Twin. Read-only."
        ),
        {
            "title": "Blast Radius",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_security_memory",
        (
            "Return Security Memory current state (longitudinal). Read-only."
        ),
        {
            "title": "Security Memory",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_security_history",
        (
            "List Security Memory snapshots / history. Read-only."
        ),
        {
            "title": "Security History",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_find_regressions",
        (
            "Detect security regressions from Memory. Read-only."
        ),
        {
            "title": "Find Regressions",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_investigate",
        (
            "Evidence-driven investigation of suspicious candidates. "
            "Requires approved=true. Static/symbolic only."
        ),
        {
            "title": "Investigate",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_get_investigation",
        (
            "Return the last investigation result or explain a finding id. "
            "Read-only."
        ),
        {
            "title": "Get Investigation",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_predict_security_risks",
        (
            "Predictive security risks from observed change (not CVEs). "
            "Labels are PREDICTIVE unless verified. Read-only."
        ),
        {
            "title": "Predict Risks",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
    (
        "axguard_analyze_change_risk",
        (
            "Analyze change/PR risk relative to a base path. Predictive. "
            "Read-only."
        ),
        {
            "title": "Analyze Change Risk",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    ),
]


def _annotations_for(name: str, base: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    tier = TOOL_TIERS.get(name, ApprovalTier.APPROVAL_REQUIRED)
    out["axguardApprovalTier"] = tier.value
    return out


TOOL_CATALOG: list[dict[str, Any]] = [
    {
        "name": name,
        "description": desc,
        "annotations": _annotations_for(name, ann),
        "tier": TOOL_TIERS.get(name, ApprovalTier.APPROVAL_REQUIRED).value,
    }
    for name, desc, ann in _TOOL_SPECS
]


def catalog_by_name() -> dict[str, dict[str, Any]]:
    return {t["name"]: t for t in TOOL_CATALOG}


def tool_names() -> list[str]:
    return [t["name"] for t in TOOL_CATALOG]
