# AXGuard MCP — Install & client config

Install AXGuard with the optional MCP extra, verify with doctor, then register the **local stdio** server in your agent host. AXGuard does not require a remote MCP URL or AwareXone hosting.

Overview: [mcp.md](mcp.md) · Tools: [mcp-tools.md](mcp-tools.md) · Security: [mcp-security.md](mcp-security.md)

Official client docs change; examples below match public docs as of **2026-09-17**. Prefer the linked host docs if they diverge.

---

## Install AXGuard MCP

```bash
git clone https://github.com/Awarexone/AXguard.git
cd AXguard
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e '.[mcp]'
```

### CLI

| Command | Purpose |
|---|---|
| `axguard mcp` | Start MCP stdio server (default entry) |
| `axguard mcp serve` | Same — explicit serve |
| `axguard mcp doctor` | Health checks (SDK, install, project, transport, limits) — no secrets |
| `axguard mcp tools` | List tool specs (JSON) |
| `axguard mcp config` | Show effective MCP config (when available) |

```bash
axguard mcp doctor --project .
axguard mcp tools
axguard mcp serve --project /absolute/path/to/your/repo
```

Ensure the host’s `command` uses the same environment where `axguard[mcp]` is installed (activated venv, or absolute path to `axguard`).

Optional project policy under `.axguard.yml` → `mcp:` (approvals, limits). See [mcp-security.md](mcp-security.md).

---

## Cursor

**Docs:** [cursor.com/docs/mcp](https://cursor.com/docs/mcp) · Help: [cursor.com/help/customization/mcp](https://cursor.com/help/customization/mcp)

Config files:

- Project: `.cursor/mcp.json`
- Global: `~/.cursor/mcp.json`  
  Project overrides global when names collide.

Example (local stdio):

```json
{
  "mcpServers": {
    "axguard": {
      "command": "axguard",
      "args": ["mcp"],
      "env": {
        "AXGUARD_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

If `axguard` is not on PATH, use the venv binary or Python module form:

```json
{
  "mcpServers": {
    "axguard": {
      "command": "python",
      "args": ["-m", "engines.mcp.server"],
      "env": {
        "AXGUARD_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

Cursor interpolates `${workspaceFolder}`, `${env:NAME}`, and related variables in `command`, `args`, `env`, `url`, and `headers`. Restart Cursor (or reload MCP) after editing. Tool calls follow Cursor’s approval / Run Mode settings.

---

## Claude Code

**Docs:** [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp) · Quickstart: [mcp-quickstart](https://code.claude.com/docs/en/mcp-quickstart)

Claude Code does **not** read Claude Desktop’s `claude_desktop_config.json`. Scopes:

| Scope | File |
|---|---|
| `local` (default) | `~/.claude.json` (per-project entry) |
| `project` | `.mcp.json` at repo root (team-shared) |
| `user` | `~/.claude.json` top-level `mcpServers` |

Add a **local stdio** server (no `--transport`; default is stdio; command after `--`):

```bash
claude mcp add axguard -- axguard mcp
```

With env / project root:

```bash
claude mcp add axguard --env AXGUARD_ROOT="$(pwd)" -- axguard mcp
```

Project-scoped (writes `.mcp.json`):

```bash
claude mcp add --scope project axguard -- axguard mcp
```

Equivalent `.mcp.json` entry:

```json
{
  "mcpServers": {
    "axguard": {
      "type": "stdio",
      "command": "axguard",
      "args": ["mcp"],
      "env": {
        "AXGUARD_ROOT": "${AXGUARD_ROOT}"
      }
    }
  }
}
```

Verify: `claude mcp list` · manage in-session with `/mcp`. Project-scoped servers require explicit approval on first use.

---

## Codex

**Docs:** [developers.openai.com/codex/mcp](https://developers.openai.com/codex/mcp/) · Config reference: [codex/config-reference](https://developers.openai.com/codex/config-reference)

Config lives in TOML (not a separate `mcp.toml`):

- User: `~/.codex/config.toml`
- Project: `.codex/config.toml` (trusted projects only)

CLI:

```bash
codex mcp add axguard -- axguard mcp
codex mcp list
```

`config.toml` example:

```toml
[mcp_servers.axguard]
command = "axguard"
args = ["mcp"]
startup_timeout_sec = 20
tool_timeout_sec = 120

[mcp_servers.axguard.env]
AXGUARD_ROOT = "/absolute/path/to/your/repo"
```

Optional: `default_tools_approval_mode` / per-tool `tools.<name>.approval_mode` (`auto` · `prompt` · `approve`, etc.) — see Codex docs. In the TUI, use `/mcp`.

---

## OpenCode

**Docs:** [opencode.ai/v2/docs/mcp-servers](https://opencode.ai/v2/docs/mcp-servers)

V2 places servers under `mcp.servers` (not directly under `mcp`). Config: `opencode.json` / `opencode.jsonc` (project or `~/.config/opencode/`).

CLI:

```bash
opencode mcp add axguard -- axguard mcp
opencode mcp list
```

Config example:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "axguard": {
        "type": "local",
        "command": ["axguard", "mcp"],
        "environment": {
          "AXGUARD_ROOT": "{env:AXGUARD_ROOT}"
        }
      }
    }
  }
}
```

Notes from current OpenCode V2 docs:

- Use `disabled: true` to keep a server configured without connecting (not an `enabled` field).
- Local servers are stdio; remote uses `type: "remote"` + absolute `url` (AXGuard default is local).
- Optional `protocol`: `legacy` (default), `auto`, or `2026-07-28` for servers that speak the newer revision.
- Manage connected servers with `/mcps`.

---

## Checklist

1. `pip install -e '.[mcp]'` and `axguard mcp doctor` succeeds  
2. Host `command` resolves to that install  
3. `AXGUARD_ROOT` or `--project` points at the intended workspace  
4. Agent can list tools (`axguard mcp tools` / host MCP UI)  
5. Prefer `axguard_security_review` for pre-ship and security-sensitive changes  

Remote Streamable HTTP is a future deployment option for user-hosted AXGuard; local stdio is the supported default.
