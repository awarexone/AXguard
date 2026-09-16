# AXGuard MCP

AXGuard’s **AI-agent security interface** over the [Model Context Protocol](https://modelcontextprotocol.io/).

MCP does not duplicate scanners or security reasoning. It is a thin adapter over the shared AXGuard engines (application understanding, data flow, evidence, judge, adversary, attack graph, twin, memory, investigation, predictive).

Protocol research: [mcp-research.md](mcp-research.md) · Client setup: [mcp-config.md](mcp-config.md) · Tools: [mcp-tools.md](mcp-tools.md) · Security: [mcp-security.md](mcp-security.md)

---

## Positioning

AXGuard has three primary interfaces on one engine:

```text
                    AXGuard
                       │
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
       CLI            API            MCP
        │              │              │
     Humans       Applications     AI Agents
```

| Interface | Audience | Entry |
|---|---|---|
| **CLI** | Humans | `axguard audit`, slash commands, skills |
| **API** | Applications | `axguard api start` → local HTTP |
| **MCP** | AI coding agents | `axguard mcp` / `axguard mcp serve` |

Related surfaces (skills, GitHub, CI) should call the same core — not a second scanner.

---

## Local-first

Default path:

```text
Cursor / Claude Code / Codex / OpenCode
            ↓
       local AXGuard MCP (stdio)
            ↓
       local AXGuard engines
```

No AwareXone account, API key, hosted backend, or central telemetry is required. Users control source, infrastructure, model provider, MCP config, permissions, and data.

---

## Primary tool: `axguard_security_review`

Agents should prefer this high-level tool over manually chaining every internal engine.

**Purpose:** Analyze the security impact of the current code, diff, file, commit, or project using AXGuard’s reasoning pipeline.

**Scopes (examples):** `project` · `changed_files` · `file` · `function` · `commit` · `branch` · `diff`

**Modes:** `LITE` · `BALANCED` · `DEEP` · `MAX` (deeper modes may require approval — see [mcp-tools.md](mcp-tools.md))

Typical agent result shape: decision, risk, verified findings, evidence, attack path notes, predictive risks (separate from verified vulns), unknowns, recommended action. Outputs stay evidence-first and free of marketing.

---

## When agents should call AXGuard

**Call** when changes involve authentication, authorization, tenant isolation, identity, permissions, database queries, outbound HTTP, uploads, file access, commands, templates, deserialization, redirects, webhooks, secrets, cloud/API config, GraphQL, OAuth, AI agents / LLM tools / MCP, privileged ops, dependencies, cryptography, or network configuration — and before significant deployment.

**Do not** call after every trivial edit (typos, comments, pure renames with no security surface).

### Suggested mappings

| Situation | Tool |
|---|---|
| Before shipping / after security-sensitive edits | `axguard_security_review` |
| Possible vulnerability to dig into | `axguard_investigate` |
| Authz / agent / MCP permission changes | `axguard_security_review` |
| “What attack paths does this create?” | `axguard_find_attack_paths` / review |
| Fix applied — confirm resolved | `axguard_security_review` or `axguard_verify_finding` |

Full catalog and approval tiers: [mcp-tools.md](mcp-tools.md).

---

## Quick start

```bash
pip install -e '.[mcp]'
axguard mcp doctor
axguard mcp tools
axguard mcp serve   # or: axguard mcp
```

Host configuration (Cursor, Claude Code, Codex, OpenCode): [mcp-config.md](mcp-config.md).
