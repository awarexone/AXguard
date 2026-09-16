# MCP Research Brief (AXGuard)

**Research date:** 2026-09-17  
**Target protocol:** Model Context Protocol `2026-07-28`  
**Purpose:** Ground AXGuard’s native MCP server on the current official specification and SDK — not outdated handshake/session tutorials.

---

## Sources (official)

| Source | URL |
|---|---|
| Spec release blog (2026-07-28) | https://blog.modelcontextprotocol.io/posts/2026-07-28/ |
| Spec root / architecture | https://modelcontextprotocol.io/specification/2026-07-28/architecture |
| Versioning & compatibility | https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning |
| Transports overview | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports |
| Streamable HTTP | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http |
| stdio | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio |
| Tools | https://modelcontextprotocol.io/specification/2026-07-28/server/tools |
| Schema reference | https://modelcontextprotocol.io/specification/2026-07-28/schema |
| Extensions overview | https://modelcontextprotocol.io/extensions/overview |
| SEP-2133 Extensions | https://modelcontextprotocol.io/seps/2133-extensions |
| SEP-2243 Header standardization | https://modelcontextprotocol.io/seps/2243-http-standardization |
| SEP-2663 Tasks extension | https://modelcontextprotocol.io/seps/2663-tasks-extension |
| Tool annotations blog | https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/ |
| Python SDK (GitHub) | https://github.com/modelcontextprotocol/python-sdk |
| Python SDK v2.0.0 release | https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0 |
| Python SDK docs (v2) | https://py.sdk.modelcontextprotocol.io/ |
| Python SDK what’s new | https://py.sdk.modelcontextprotocol.io/whats-new/ |
| Python SDK migration | https://py.sdk.modelcontextprotocol.io/migration/ |

---

## 1. Stateless protocol core

As of `2026-07-28`, MCP is a **request/response stateless** protocol:

- The `initialize` / `initialized` handshake and `Mcp-Session-Id` are **retired** (SEP-2575, SEP-2567).
- Every request is self-describing: protocol version, client identity, and client capabilities travel in `_meta` (`io.modelcontextprotocol/protocolVersion`, `clientInfo`, `clientCapabilities`).
- Optional discovery: `server/discover` returns supported versions and capabilities; it is **not** required before other RPCs.
- Any request can land on any instance behind a plain load balancer; shared session storage is not part of the protocol.
- Application state (if needed) should be explicit handles returned by tools and passed back as arguments — not hidden transport sessions.

**AXGuard implication:** Prefer dual-era SDK support so modern clients work without sessions; do not build AXGuard MCP around session IDs.

---

## 2. Multi Round-Trip Requests (MRTR)

MRTR (SEP-2322) replaces server-initiated `elicitation/create`, `sampling/createMessage`, and `roots/list` that previously needed a held-open bidirectional stream.

Pattern:

1. Server returns `resultType: "input_required"` with `inputRequests` (and optional `requestState`).
2. Client gathers answers (user form, sampling, etc.).
3. Client **retries the original call** with `inputResponses` attached.

This is how mid-call confirmation / missing parameters work on a stateless transport.

**AXGuard implication:** Use MRTR (or SDK resolvers) for approval gates such as `APPROVAL_REQUIRED`; do not assume a long-lived server→client request channel.

---

## 3. Header-based routing (Streamable HTTP)

Streamable HTTP requests **must** include:

| Header | Source |
|---|---|
| `MCP-Protocol-Version` | Must match `_meta` protocol version |
| `Mcp-Method` | JSON-RPC `method` |
| `Mcp-Name` | `params.name` or `params.uri` for `tools/call`, `resources/read`, `prompts/get` |

Optional: tool `inputSchema` properties may use `x-mcp-header` so clients emit `Mcp-Param-{Name}` for gateway routing without body parsing (SEP-2243). Clients **must** support this on Streamable HTTP; stdio clients may ignore it.

---

## 4. Cacheable list results

`tools/list`, `prompts/list`, `resources/list`, and `resources/read` responses may include:

- `ttlMs` — cache lifetime hint
- `cacheScope` — e.g. `public` / scoped semantics (SEP-2549)

Servers **SHOULD** return list items in a **deterministic order** so clients and LLM prompt caches stay stable.

---

## 5. Authorization hardening

Notable `2026-07-28` auth changes:

- Authorization servers should return `iss` per **RFC 9207**; clients must validate before redeeming codes (SEP-2468) — closes AS mix-up.
- Clients set `application_type` during DCR for localhost CLI/desktop redirects (SEP-837).
- Client credentials bound to the minting issuer (SEP-2352).
- **Dynamic Client Registration (DCR) deprecated** in favor of **Client ID Metadata Documents (CIMD)**; DCR still works for compatibility but will be removed later.
- Formal extensions include **Enterprise Managed Authorization (EMA)** alongside Tasks and MCP Apps.

**AXGuard implication:** Default deployment is **local stdio**, no OAuth cloud. If remote Streamable HTTP is added later, follow CIMD/`iss` validation — never hard-require AwareXone auth.

---

## 6. Tasks (extension)

Tasks moved out of experimental core into the official extension:

- Identifier: `io.modelcontextprotocol/tasks` (SEP-2663)
- Client advertises the extension in per-request capabilities.
- Server **may** return `resultType: "task"` with a task handle (`taskId`, `ttlMs`, `pollIntervalMs`, etc.).
- Client polls `tasks/get`, may `tasks/update` (input while running), may `tasks/cancel`.
- Legacy `tasks/result` and per-call `task` opt-in on `tools/call` are removed for this extension.

Change notifications use opt-in `subscriptions/listen` rather than the old HTTP GET stream.

**AXGuard implication:** Deep/MAX reviews that exceed latency budgets can later use Tasks; v1 ship can stay synchronous with timeouts.

---

## 7. Extensions framework

SEP-2133 / extensions overview:

- Optional, composable capabilities beyond core.
- Advertised under `capabilities.extensions` with prefixed IDs (e.g. `io.modelcontextprotocol/tasks`, `io.modelcontextprotocol/ui`).
- **Off by default** in SDKs; explicit opt-in.
- Official vs experimental lifecycle; official repos under `ext-*` in the MCP org.

---

## 8. Versioning and deprecation

- **Modern** (`2026-07-28`+): per-request `_meta`, no handshake.
- **Legacy** (`2025-11-25` and earlier): `initialize` session.
- Version mismatch → `UnsupportedProtocolVersionError` (`-32022`) with `supported` list; client retries.
- Formal deprecation policy: **≥ twelve months** offramp.
- Deprecated in this release (still work for ≥12 months): Roots, Sampling, Logging (SEP-2577); legacy HTTP+SSE transport.

**AXGuard implication:** Pin documented protocol + SDK versions; dual-era Python SDK v2 serves both eras from one process.

---

## 9. Streamable HTTP vs stdio

| | **stdio** | **Streamable HTTP** |
|---|---|---|
| Model | Client launches server subprocess; newline-delimited JSON-RPC on stdin/stdout | Single MCP endpoint; each message is HTTP POST |
| Metadata | Body `_meta` only | Body `_meta` + mirrored headers |
| Sessions | None (modern) | None (modern); no `Mcp-Session-Id` |
| Cancellation | `notifications/cancelled` | Close response stream |
| Notifications | Shared stdout + `subscriptions/listen` | Request-scoped SSE / subscription streams |
| Best for | Local IDE agents (Cursor, Claude Code, Codex) | Remote / multi-tenant / load-balanced servers |
| Legacy note | Probe `server/discover` then fall back to `initialize` | Detect modern errors vs `400` before legacy fallback |

**AXGuard default:** **stdio**, local-first. Streamable HTTP optional later; do not require remote hosting.

---

## 10. Tool annotations (hints, not enforcement)

Stable behavior hints on tool descriptors (clients MUST treat as **untrusted** unless the server is trusted):

| Annotation | Meaning | Typical default if omitted |
|---|---|---|
| `title` | Display name | — |
| `readOnlyHint` | Tool does not modify its environment | `false` |
| `destructiveHint` | Mutations may be hard to undo (meaningful when not read-only) | `true` |
| `idempotentHint` | Same args → no further effect | `false` |
| `openWorldHint` | Interacts with external/open-world entities | `true` |

AXGuard tools should set these accurately (e.g. `axguard_security_review`: `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false` for closed local analysis). **Policy must enforce permissions independently** of annotations.

---

## 11. Python SDK v2 (current stable)

As of research date (2026-09-17):

- **`mcp` v2.x is the current stable line** (`pip install mcp` installs 2.x).
- **v2.0.0** released **2026-07-28**, implements protocol `2026-07-28` and still serves earlier revisions from the same server.
- Highlights: `FastMCP` → `MCPServer`; first-class `Client`; snake_case protocol fields; standalone `mcp-types`; Streamable HTTP + stdio dual-era; MRTR via resolvers; extensions opt-in.
- v1.x is **maintenance mode** (security fixes); pin `mcp>=1.28,<2` only if not migrating.
- Docs: https://py.sdk.modelcontextprotocol.io/

**AXGuard recommendation:** Optional dependency extra `[mcp]` on official Python SDK **v2**, targeting protocol `2026-07-28`, default transport **stdio**.

---

## 12. AXGuard mapping (research conclusions)

1. Implement against **`2026-07-28` + Python SDK v2**, not session-based tutorials.
2. Ship **stdio first** for Cursor / Claude Code / Codex / OpenCode.
3. Declare accurate **tool annotations**; enforce with local policy.
4. Keep the MCP layer a **thin agent interface** over existing engines — no second scanner.
5. Remain **local-first**: no AwareXone cloud account, API key, backend, or hosted inference required.
6. Defer Tasks / MCP Apps / remote OAuth until product needs them; document extension IDs for future use.

---

## Changelog

| Date | Note |
|---|---|
| 2026-09-17 | Initial research against official `2026-07-28` spec + Python SDK v2 docs |
