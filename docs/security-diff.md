# AXGuard Security Diff

Security Diff answers: **what became more dangerous because of this change?**

It is **not** another scanner. It compares application models, data flows, controls, authz/tenant heuristics, attack graphs, and Security Twins when available.

```bash
axguard diff
axguard diff HEAD~1
axguard diff main...HEAD
axguard security-diff --base-path ./before
axguard diff --json
```

## Baseline rules

| Situation | Baseline |
|---|---|
| Git ref available | `GIT` |
| Filesystem `--base` / path | `PATH` |
| Prior `.findings` / snapshot | `ARTIFACTS` / snapshot |
| Nothing available | `UNKNOWN` — **do not invent** |

## Categories (examples)

`NEW_ENDPOINT`, `REMOVED_ENDPOINT`, `NEW_PARAMETER`, `NEW_DATABASE_FLOW`, `NEW_EXTERNAL_REQUEST`, `REMOVED_SECURITY_CONTROL`, `WEAKENED_SECURITY_CONTROL`, `NEW_ATTACK_PATH`, `BLOCKED_ATTACK_PATH`, …

Overall change: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL` (also `NONE` / `UNKNOWN` in some paths).

## AuthZ / tenant

Special-cased heuristics for ownership and tenant tokens (`tenant_id`, `org_id`, `workspace_id`, `owner_id`, …). Example signal: ownership check present in base, absent in head → authorization weakened.

## Reuse

Composes existing engines:

- `engines.app_model`
- `engines.dataflow`
- `engines.attack_graph.diff.compare_attack_graphs` / `get_attack_path_diff`
- `engines.twin.pipeline.run_twin_compare`
- Security Memory snapshots when present

No network. No exploitation. No CVE claims without evidence.

## MCP

Tool: `axguard_security_diff` — soft-fails on import/engine errors.

## Compact output example

```text
SECURITY DIFF
────────────────────────

+ 2 new API endpoints
+ 1 new database flow
- 1 authorization/security control

Attack paths:
+ 2 reachable
- 1 blocked

Overall security change:
HIGH
```

See also: [preship.md](preship.md)
