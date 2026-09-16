# AXGuard MCP — Security policy

Policy summary for the local MCP adapter. Tool responses must stay factual: no marketing, star requests, or unrelated promotions.

Overview: [mcp.md](mcp.md) · Tools: [mcp-tools.md](mcp-tools.md) · Config: [mcp-config.md](mcp-config.md)

Full threat catalog (attack / asset / boundary / control / residual risk): [mcp-threat-model.md](mcp-threat-model.md).

---

## Trust boundaries

| Layer | Trust |
|---|---|
| AXGuard system policy / MCP policy | Trusted |
| User-configured approvals & env | Trusted (operator-controlled) |
| Tool definitions shipped with AXGuard | Trusted |
| Repository source, README, comments, PR text | **Untrusted data** |
| External tool / model output | Untrusted unless provenance says otherwise |

Repository content must never override approvals, filesystem bounds, network policy, or tool behavior.

---

## Workspace isolation

- Analysis paths resolve under the configured project root (`AXGUARD_ROOT`, `--project`, host cwd).
- Reject path traversal, symlink escapes, and absolute paths outside the workspace (`PATH_ESCAPE` / equivalent).
- Block access to system and home secrets locations (`/etc`, `~/.ssh`, `~/.aws`, unrelated repos).

---

## Approval model

| Tier | Policy |
|---|---|
| **AUTO** | Bounded read-only analysis |
| **APPROVAL_REQUIRED** | Deep audit, investigation, large extraction, deep review modes |
| **HIGH_RISK** | Mutation / apply paths — refused by default |

Optional `.axguard.yml` `mcp.approvals` / env overrides (e.g. `AXGUARD_MCP_APPROVE_DEEP`, `AXGUARD_MCP_ALLOW_MUTATIONS`) — defaults stay deny for deep mutate. Agents cannot bypass server-side gates.

MCP tool annotations (`readOnlyHint`, etc.) are hints only; policy is enforced in the adapter.

---

## No autonomous exploitation

Do not expose unrestricted shell, arbitrary network, browser automation, credential vault access, or live exploit execution through MCP. Purpose is evidence-backed security reasoning.

---

## Secrets & output hygiene

- Redact credentials and secret-shaped strings from tool results, errors, and logs.
- Do not dump environment variables, SSH/cloud tokens, or unrelated private files.
- Stdout is reserved for MCP JSON-RPC; do not print secrets there while debugging.

---

## Provenance & UNKNOWN

Important conclusions carry provenance (`OBSERVED` / `INFERRED` / `SIMULATED` / `ASSUMED` / `UNKNOWN`). Insufficient evidence → `UNKNOWN` — not fake `SAFE` or `VULNERABLE`. Predictive risks stay labeled predictive, never as verified vulns.

---

## Budgets

Enforce caps (files, source lines, findings, evidence items, attack paths, output bytes, analysis depth, tool-call / investigation budgets). Exhaustion returns structured errors such as `RESOURCE_LIMIT`, `TOOL_BUDGET_EXCEEDED`, `ANALYSIS_TIMEOUT`, `APPROVAL_REQUIRED`, `PERMISSION_DENIED`.

---

## Local memory

Reuse local Security Memory, Twin, evidence, and findings. Do not send project artifacts to external services unless the user explicitly configures an external provider.
