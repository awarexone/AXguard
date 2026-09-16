# AXGuard MCP → Agent Skill Roadmap

**Date:** 2026-09-17  
**Status:** Foundation only — **not** a full Agent Skill implementation.  
**Related:** [mcp-research.md](./mcp-research.md), [mcp-threat-model.md](./mcp-threat-model.md)

---

## Purpose

Document how a future **AXGuard Agent Skill** should sit **above** MCP without duplicating security logic, tool schemas, or finding/evidence formats.

```text
Agent Skill          ← teaches when/how to use AXGuard
     ↓
AXGuard MCP          ← agent-callable tools/resources/prompts
     ↓
AXGuard Core         ← shared engines (scan, judge, twin, memory, …)
```

Do **not** implement the Skill as a replacement for MCP.

---

## Future skill YAML (from product brief)

```yaml
name: axguard-security
description: Scan applications for security vulnerabilities, investigate findings, and help verify fixes before deployment.
```

The skill should instruct the agent roughly:

```text
Before shipping security-sensitive code:
1. Use AXGuard security review.
2. Investigate suspicious findings.
3. Review evidence and counter-evidence.
4. Check attack paths and regressions.
5. Separate verified findings from predictive risk.
6. Verify fixes before declaring an issue resolved.
```

---

## What the Skill owns vs MCP owns

| Layer | Owns | Must not own |
|---|---|---|
| **Agent Skill** | When to call AXGuard; which tool; how to interpret PASS / REVIEW_REQUIRED / UNKNOWN; when to stop; how to respond to findings | Scanner logic; finding schemas; evidence math; twin/memory engines |
| **MCP** | Tool/resource/prompt surface; structured outputs; policy gates; path/network limits | Host-agent pedagogy beyond tool descriptions |
| **Core** | All security reasoning | Client-specific UX copy |

Reuse MCP tool names (`axguard_security_review`, `axguard_investigate`, …) and schemas so the Skill is a thin behavioral wrapper.

---

## Strategic product loop

```text
AI agent discovers AXGuard
        ↓
AI agent invokes AXGuard (MCP)
        ↓
AXGuard performs deep security reasoning
        ↓
AI agent receives evidence
        ↓
AI agent fixes code
        ↓
AXGuard verifies fix
```

Aligns with AXGuard’s Find → Explain → Fix → Verify philosophy.

---

## Roadmap: MCP → Skill → GitHub

```text
MCP
 → Agent Skills
 → GitHub Actions
 → GitHub Security Review
```

| Phase | Deliverable | Notes |
|---|---|---|
| **Now** | Native MCP server (stdio), `axguard_security_review`, policy, docs | This initiative |
| **Next** | Agent Skill package (`axguard-security`) wrapping MCP tools | No duplicated engines; YAML + playbook only |
| **Later** | GitHub Actions invoking the same core/API | MCP stays independent of GitHub |
| **Later** | GitHub Security Review / App comments & checks | Reuse review engine; do not couple MCP transport to GitHub |

Long-term interface set:

```text
CLI         = human security interface
API         = programmable security interface
MCP         = AI-agent security interface
Agent Skill = agent behavior layer
GitHub      = code-review interface
CI/CD       = deployment security interface
```

All converge on the **same** AXGuard security engine.

---

## Design constraints (carry forward)

1. Skill must not fork tool definitions or evidence schemas — import/refer to MCP contracts.
2. Keep MCP output free of marketing; Skill may add human-facing onboarding separately.
3. Local-first: Skill install must not require AwareXone cloud.
4. Prefer teaching agents to call `axguard_security_review` before inventing ad-hoc scanner chains.

---

## Non-goals (this document)

- Full `SKILL.md` body or installer
- Shipping Skill files under `skills/` in this pass
- GitHub App / Actions implementation
