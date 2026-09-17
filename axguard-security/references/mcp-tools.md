# MCP tools (names only)

Prefer these over inventing scanner chains. Full contracts: [docs/mcp-tools.md](../../docs/mcp-tools.md).

| Tool | Role |
|------|------|
| `axguard_security_review` | Primary entry — security impact of code / change |
| `axguard_investigate` | Deepen a suspicious finding |
| `axguard_verify_fix` | Confirm a remediation resolved the issue |
| `axguard_verify_finding` | Hunter→Judge verify a candidate (pre-fix) |
| `axguard_get_evidence` | Supporting evidence for a finding |
| `axguard_get_counter_evidence` | FP / blocked signals |
| `axguard_find_attack_paths` | Credible attack paths for a change / finding |
| `axguard_find_regressions` | Prior control removed or weakened |
| `axguard_predict_security_risks` | Predictive risk only — not confirmed vulns |

**Skill preference:** MCP first. CLI fallback: `axguard scan .` / `axguard audit .`.
