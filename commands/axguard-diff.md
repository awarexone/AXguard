---
name: axguard-diff
description: Run AXGuard Security Diff — compare two versions and explain security-relevant changes (attack surface, controls, attack paths, privileges, regressions). Use after meaningful security-sensitive changes, not trivial edits.
---

# /axguard-diff

Compare BASE vs HEAD from a **security** perspective.

```bash
axguard diff
axguard diff HEAD~1
axguard diff main...HEAD
axguard diff --base main --head HEAD
axguard diff --json
axguard diff --verbose
axguard diff --fail-on high
```

MCP: `axguard_security_diff`

See [docs/security-diff.md](../docs/security-diff.md).
