---
name: axguard-preship
description: Pre-ship security gate for the current repository. Use before publishing or opening a release PR. Prefers axguard_preship / axguard_security_diff MCP and axguard preship CLI; verifies after fixes.
---

# AXguard — Pre-ship Gate

Ship / no-ship review. Prefer real bugs over volume. Defensive static review only.

## Prefer engines

| Intent | MCP tool | CLI |
|---|---|---|
| Before shipping | `axguard_preship` | `axguard preship .` |
| After security-sensitive changes | `axguard_security_diff` | `axguard diff` / `axguard security-diff` |
| After fixing a finding | verify tools | verify, then re-run Pre-Ship |

Do **not** force Pre-Ship after every tiny edit.

```bash
axguard preship .
axguard preship . --mode QUICK --json
axguard diff HEAD~1
```

## Decision vocabulary

`PASS` · `PASS_WITH_NOTES` · `REVIEW_REQUIRED` · `FAIL`

Never fail solely on unverified suspicion. LLM alone cannot block.

## Workflow

1. Map surface: routes, auth boundaries, sinks, uploads, agent tools.
2. Run Pre-Ship (MCP `axguard_preship` or CLI `axguard preship`).
3. If Security Diff shows control removal / authz weakening, investigate before shipping.
4. Verify each high/critical lead (source → sink → missing control).
5. After patches: verify (`axguard verify`), then re-run Pre-Ship.

Load `axguard-knowledge` when a class needs root-cause / fix depth.

## Priority (ship blockers first)

| # | Class | Static sniff |
|---|--------|--------------|
| 1 | AuthZ / IDOR | get-by-id without ownership/tenant |
| 2 | RCE / cmd / deser / eval | shell=True, pickle, eval |
| 3 | SQLi / SSTI | string-built SQL; render_template_string |
| 4 | SSRF | variable URL → fetch |
| 5 | Secrets | keys/PATs in tree |
| 6 | Path / LFI | open(join), sendFile(user) |
| 7 | XSS | innerHTML + user data |
| 8 | JWT / CSRF | alg=none; csrf=False |
| 9 | Upload RCE | original filename; webroot writes |
| 10 | Crypto / TLS | hard-coded keys; verify=False |
| 11 | CORS / cloud | `*` + credentials |
| 12 | GraphQL | prod introspection |
| 13 | Supply / CI | curl\|sh |
| 14 | Debug | DEBUG=True in ship path |
| 15 | Agent tools | unrestricted shell from LLM |

## Output

Report decision, blocking reason (if FAIL), review_why (if REVIEW_REQUIRED), Security Diff summary, verified findings, and next step (fix / verify / full audit).

Docs: [docs/preship.md](../../docs/preship.md) · [docs/security-diff.md](../../docs/security-diff.md)
