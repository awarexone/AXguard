---
name: axguard-security
description: Analyze code for security vulnerabilities, investigate findings, verify fixes, and assess security risk before deployment. Use when reviewing security-sensitive changes, before ship/deploy, or when an agent should call AXGuard MCP instead of inventing its own scanner.
---

# AXguard Security (Agent Skill)

This skill does **not** implement security analysis. It teaches when to use AXGuard, which MCP tool to call, and how to interpret results.

**Primary interface:** AXGuard MCP tools (prefer over ad-hoc scans).  
**Fallback:** if MCP is unavailable, `axguard scan .` / `axguard audit .` — then still apply the same verdict rules below.  
Tool names: `references/mcp-tools.md` · catalog: [docs/mcp-tools.md](../../docs/mcp-tools.md).

## When to call AXGuard

**Call** after security-sensitive edits, or before ship/deploy, when changes touch:

authn / authz / tenant / identity / permissions · DB · external HTTP · file / cmd · uploads · webhooks · secrets · OAuth · GraphQL · cloud · crypto · deps · AI agents / LLM tools / MCP · privileged ops

**Do not call** for trivial non-security edits (typos, comments, pure renames with no security surface).

## Workflow

```text
Code change
    → security-sensitive?
         NO  → skip AXGuard
         YES → axguard_security_review
                 → findings?
                      NO  → done (respect UNKNOWN / predictive separately)
                      YES → axguard_investigate (suspicious)
                          → fix
                          → axguard_verify_fix
```

| Step | Tool | Notes |
|------|------|--------|
| Default entry | `axguard_security_review` | Prefer this over chaining engines manually |
| Dig deeper | `axguard_investigate` | Suspicious / incomplete candidates |
| After a fix | `axguard_verify_fix` | Do not mark resolved on edit alone |
| Evidence (optional) | `axguard_get_evidence` / `axguard_get_counter_evidence` | When debating a finding |

## Interpret results

| Label | Agent rule |
|-------|------------|
| **VERIFIED** | Do not dismiss without **new** counter-evidence. Treat as real until AXGuard says otherwise. |
| **UNKNOWN** | Do **not** call the change safe. State uncertainty; investigate or escalate. |
| **FALSE_POSITIVE** | Do **not** report as a vulnerability. |
| **PREDICTIVE_RISK** | Risk signal only — **not** a confirmed vulnerability. Do not merge into verified counts. |

Never invent evidence. Prefer AXGuard’s structured output over model speculation.

## Response discipline

- Prefer MCP when available; do not build a second scanner.
- Keep predictive risks and verified findings separate in summaries.
- Ship/go-no-go: blockers = VERIFIED (and policy-gated LIKELY if the review returns them) — not predictive-only noise.
- After fixes, call `axguard_verify_fix` (or re-review) before declaring closed.
