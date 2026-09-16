---
name: axguard-security
description: MCP-first AXGuard security interface for coding agents. Use for security review, Security Diff on meaningful changes, verification, and pre-ship gates. Prefer axguard_security_diff when comparing what became more dangerous across a change; prefer axguard_security_review for full review.
version: "1.0.0"
author: AwareXone
license: MIT
domain: operations
tags: [mcp, security-diff, review, preship]
related_commands: [axguard-diff, axguard-preship, axguard-audit]
last_reviewed: "2026-09-17"
---

# AXguard — Agent Security Skill (MCP)

## When to use Security Diff

Call **`axguard_security_diff`** (or `axguard diff`) when a **meaningful** security-sensitive change occurs:

- authentication / authorization / tenant isolation changes
- new endpoints, webhooks, uploads, GraphQL, websockets
- external integrations / network exposure
- AI agent / MCP tool permission changes
- deployment / dependency / secret-handling changes
- before shipping

Do **not** run Security Diff after every trivial edit (rename, formatting, docs-only, test-only noise).

## Flow

```text
Meaningful change
  → axguard_security_diff
  → axguard_security_review (if impact HIGH/CRITICAL or REVIEW_REQUIRED)
  → fix
  → axguard_verify / axguard diff (confirm path blocked)
```

## Primary MCP tools

| Tool | Use |
|---|---|
| `axguard_security_diff` | What became more dangerous between two states |
| `axguard_security_review` | Full orchestrated review |
| `axguard_verify_finding` | Judge a candidate |
| `axguard_find_attack_paths` | Attack path detail |
| `axguard_predict_security_risks` | Predictive (not verified) |

## Pre-Ship

```text
Security Diff → Security Review → Pre-Ship Gate
```

See [docs/security-diff.md](../../docs/security-diff.md) and [docs/preship.md](../../docs/preship.md).
