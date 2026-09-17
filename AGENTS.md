# AXguard — Agent Skills

```bash
./install.sh --agent agents
./install.sh --agent agents --project
```

## Start here

| Doing | Command / skill |
|---|---|
| Full audit | `/axguard-audit` or skill `axguard-audit` |
| MCP-first review / investigate / verify fix | skill `axguard-security` → [docs/mcp.md](docs/mcp.md) |
| Security lead pass | skill `axguard-cso` |
| Triage | `/axguard-triage` |
| Fix | `/axguard-fix` / skill `axguard-remediate` |
| Report | `/axguard-report` |

`axguard-security` teaches when to call AXGuard and which MCP tool to use (`axguard_security_review`, `axguard_investigate`, `axguard_verify_fix`). Prefer MCP when available; CLI as fallback.

CLI:

```bash
pip install -e .
pip install -e '.[mcp]'   # agent MCP interface
axguard help
axguard audit .
axguard mcp doctor
```
