# AXGuard MCP Threat Model

**Date:** 2026-09-17  
**Scope:** Local-first AXGuard MCP server (stdio default) wrapping existing security engines.  
**Stance:** No AwareXone cloud dependency. Users control code, infra, AI provider, MCP config, and permissions.

Related: [mcp-research.md](./mcp-research.md), product brief §48–53.

---

## Trust model (local-first)

```text
┌─────────────────────────────────────────────────────────┐
│ Host IDE / agent (Cursor, Claude Code, Codex, …)        │
│  — user-trusted process; may be prompt-injected         │
└───────────────────────────┬─────────────────────────────┘
                            │ MCP stdio (JSON-RPC)
┌───────────────────────────▼─────────────────────────────┐
│ AXGuard MCP adapter                                      │
│  — thin interface; policy + path/network gates           │
└───────────────────────────┬─────────────────────────────┘
                            │ in-process / local API
┌───────────────────────────▼─────────────────────────────┐
│ AXGuard Core engines (scan, judge, twin, memory, …)      │
│  — local filesystem under configured workspace roots     │
└─────────────────────────────────────────────────────────┘

No required path to AwareXone cloud, hosted inference, or central telemetry.
```

**Assets:** workspace source; findings/evidence/memory/twin stores; env secrets; user credentials; agent context window; host OS integrity.

**Primary trust boundary:** untrusted tool arguments + untrusted repository content vs. privileged local analysis/process.

---

## Threat catalog

For each threat: attack → asset → trust boundary → control → mitigation → residual risk.

### 1. Prompt injection

| Field | Detail |
|---|---|
| **Attack** | Hostile text in repo files, issues, tool results, or agent prompts steers the model to misuse AXGuard tools (exfil, skip review, weaken policy). |
| **Asset** | Agent context; tool-invocation decisions; finding presentation. |
| **Trust boundary** | Untrusted content → LLM planner → MCP tool calls. |
| **Control** | Tool allowlists; structured results; policy independent of natural-language instructions in files. |
| **Mitigation** | Agent-optimized tool descriptions that state read-only limits; never treat repo text as authority over policy; redact secrets in outputs; prefer structured JSON over free-form “instructions.” |
| **Residual risk** | Host agent may still obey injected instructions outside AXGuard; AXGuard cannot fully police the host LLM. |

### 2. Tool poisoning

| Field | Detail |
|---|---|
| **Attack** | Malicious or compromised MCP server (or renamed AXGuard config) ships deceptive tool names/descriptions that coerce unsafe host behavior; or AXGuard tool metadata is altered in a fork. |
| **Asset** | Agent tool catalog; user consent model. |
| **Trust boundary** | MCP server install/config → client tool list. |
| **Control** | Pin AXGuard package; checksum/signature of install path; treat annotations as untrusted unless server identity is verified (per MCP spec). |
| **Mitigation** | Document official server command (`axguard mcp serve`); discourage `npx`/`uvx` floating tags for production; clients should show tool list at connect time. |
| **Residual risk** | User installs a typosquat; host client auto-approves tools. |

### 3. Malicious repository

| Field | Detail |
|---|---|
| **Attack** | Crafted source triggers path tricks, polyglot configs, or content that causes AXGuard/agent to execute or over-read. |
| **Asset** | Host FS; analysis integrity; agent context. |
| **Trust boundary** | Repo contents → parser/engines → MCP responses. |
| **Control** | Read-only analysis default; no execute-from-repo; size/time limits. |
| **Mitigation** | Never `eval`/run project build scripts from MCP tools; sandbox subprocesses if any; cap file reads; treat configs as data. |
| **Residual risk** | Parser bugs (zip bombs, pathological ASTs) remain possible — mitigate with limits. |

### 4. Malicious dependency

| Field | Detail |
|---|---|
| **Attack** | Compromised package in AXGuard’s or the target app’s dependency tree executes at install/analysis time. |
| **Asset** | Host OS; secrets in environment. |
| **Trust boundary** | Package registry → local install / import. |
| **Control** | Lockfiles; optional extras (`[mcp]`); minimal dependency surface for MCP adapter. |
| **Mitigation** | Prefer official `mcp` SDK; pin versions; review transitive deps; do not auto-install remote MCP servers from untrusted manifests. |
| **Residual risk** | Supply-chain compromise of a pinned major version until patch. |

### 5. Filesystem escape / path escape

| Field | Detail |
|---|---|
| **Attack** | Tool args use `../`, absolute paths, or symlinks to read/write outside the configured project root. |
| **Asset** | Files outside workspace (SSH keys, other projects, `/etc`). |
| **Trust boundary** | Tool `path`/`uri` args → filesystem API. |
| **Control** | Canonicalize paths; resolve symlinks; enforce allowlisted roots. |
| **Mitigation** | Reject escapes with `PERMISSION_DENIED` / `INVALID_INPUT`; no default home-directory access; tests for traversal and symlink escape. |
| **Residual risk** | Kernel/OS symlink races under concurrent moves — keep roots strict and operations read-only by default. |

### 6. Credential leakage

| Field | Detail |
|---|---|
| **Attack** | Tools dump env vars, `.env`, tokens in findings, logs, resources, or error strings into the agent context. |
| **Asset** | API keys, cloud creds, GitHub tokens, SSH keys. |
| **Trust boundary** | Local secrets store / env → MCP output channel. |
| **Control** | Redaction filters; deny-list for sensitive paths; no env dump tools. |
| **Mitigation** | Redact secrets in tool output, logs, errors, reports, caches; never expose unrelated private files; optional explicit opt-in for rare secret-scanning workflows with scoped paths. |
| **Residual risk** | Novel secret formats may evade redaction; agent may already hold secrets from the host. |

### 7. SSRF

| Field | Detail |
|---|---|
| **Attack** | Tool arguments cause outbound HTTP to internal metadata IPs, localhost admin ports, or attacker-controlled URLs. |
| **Asset** | Internal network services; cloud metadata. |
| **Trust boundary** | Tool network capability → LAN/cloud. |
| **Control** | Default **deny egress** for MCP analysis tools; openWorldHint false for local review. |
| **Mitigation** | No URL-fetch tools in the default catalog; if fetch is ever added, allowlist schemes/hosts and block link-local/metadata ranges. |
| **Residual risk** | User-configured AI provider calls are intentional egress outside MCP; document separately. |

### 8. Arbitrary command execution

| Field | Detail |
|---|---|
| **Attack** | Args smuggle shell metacharacters or request “run this command” via a privileged tool. |
| **Asset** | Host OS; all local secrets. |
| **Trust boundary** | Tool surface → `subprocess` / shell. |
| **Control** | No shell-string tools in MCP surface; engines invoke typed Python APIs. |
| **Mitigation** | Forbid free-form command tools; if a subprocess is required, fixed argv arrays, no `shell=True`, timeout + output caps. |
| **Residual risk** | Bugs in underlying engines that shell out — covered by self-audit and least privilege. |

### 9. Resource exhaustion

| Field | Detail |
|---|---|
| **Attack** | Huge scopes, tight loops of `tools/call`, or pathological projects exhaust CPU, memory, or disk. |
| **Asset** | Host availability; IDE responsiveness. |
| **Trust boundary** | Agent call rate / scope → MCP process. |
| **Control** | Timeouts; max files/bytes; concurrency limits; mode caps (LITE/BALANCED/DEEP/MAX). |
| **Mitigation** | Return `ANALYSIS_TIMEOUT` / `RESOURCE_LIMIT`; cancel support; cache safely with invalidation. |
| **Residual risk** | Coordinated flooding from a compromised agent host — OS-level process limits remain the backstop. |

### 10. Cross-workspace access

| Field | Detail |
|---|---|
| **Attack** | One agent session reads another project’s memory, twin, or source via path confusion or shared cache keys. |
| **Asset** | Isolation between projects/tenants on one machine. |
| **Trust boundary** | Workspace root configuration → storage namespaces. |
| **Control** | Bind server instance to explicit project root(s); namespace local memory/twin by project id/path. |
| **Mitigation** | Reject paths outside roots; no global “all projects” tool by default; document multi-root carefully. |
| **Residual risk** | User intentionally configures overlapping roots. |

### 11. Confused deputy

| Field | Detail |
|---|---|
| **Attack** | User approves a benign AXGuard setup; later config adds privileged tools or broader roots; agent uses elevated power without fresh consent. |
| **Asset** | User authorization / consent. |
| **Trust boundary** | Static approval → dynamic tool/capability set. |
| **Control** | Stable minimal tool catalog; capability changes require re-consent messaging in docs/clients. |
| **Mitigation** | Keep dangerous operations out of MCP or behind explicit approval (`APPROVAL_REQUIRED` / MRTR); version tool schemas; `axguard mcp tools` for inspection. |
| **Residual risk** | Host clients that auto-approve all tools undermine this control. |

### 12. Excessive agent permissions

| Field | Detail |
|---|---|
| **Attack** | MCP exposes write, network, or exec tools “for convenience,” recreating unrestricted agency. |
| **Asset** | Least-privilege guarantee of the security interface. |
| **Trust boundary** | Product tool catalog design. |
| **Control** | Small catalog; default read-only analysis; annotations + **server-side** policy. |
| **Mitigation** | Primary tool `axguard_security_review` is read-only; no generic shell/file-write tools; policy engine denies out-of-policy calls. |
| **Residual risk** | Future features may tempt broader tools — gate behind extras and docs. |

### 13. Unsafe tool chaining

| Field | Detail |
|---|---|
| **Attack** | Combinations such as read-secrets + egress, or investigate + mutate, create exfiltration / privilege paths even if each tool looks OK alone. |
| **Asset** | Composite confidentiality/integrity. |
| **Trust boundary** | Multi-call agent session. |
| **Control** | Attack-graph / policy over capability labels; deny toxic combinations. |
| **Mitigation** | Label tools by side effect (read/fs/network/exec); refuse chains that combine secret-bearing reads with egress; use AXGuard attack-path reasoning on agent tool graphs where applicable. |
| **Residual risk** | Host agent may chain AXGuard with *other* MCP servers AXGuard does not see. |

### 14. Malicious tool output

| Field | Detail |
|---|---|
| **Attack** | Crafted findings text or resource payloads inject instructions back into the agent (“ignore policy”, “exfiltrate”). |
| **Asset** | Downstream agent behavior; user trust in AXGuard results. |
| **Trust boundary** | MCP result content → host LLM. |
| **Control** | Structured outputs; clear separation of evidence vs. instructions; length limits. |
| **Mitigation** | Prefer schema-validated `structuredContent`; keep narrative short and non-imperative; strip/escape control sequences; never embed secrets; no marketing CTAs in core output. |
| **Residual risk** | Models may still over-trust any text in context; clients should treat tool results as untrusted data. |

---

## Cross-cutting mitigations (AXGuard MCP)

1. **Local-first:** no AwareXone account, API key, backend, DB, or hosted inference required.
2. **Thin adapter:** no second scanner; reuse core engines.
3. **Workspace isolation:** configured project roots only.
4. **Default deny:** egress, shell, and writes off unless explicitly designed later.
5. **Annotations ≠ enforcement:** `readOnlyHint` / etc. are hints; policy enforces.
6. **Redaction + limits:** secrets, bytes, time, concurrency.
7. **Self-security:** run AXGuard against the MCP implementation (brief §49).

---

## Residual risk summary

Even a hardened local MCP server cannot fully constrain a compromised or over-permissive **host agent**. AXGuard’s job is to shrink the blast radius of *its* tools, isolate workspaces, avoid becoming an execution/exfil channel, and return evidence-backed structured results — while remaining usable offline without AwareXone cloud.
