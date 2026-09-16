# AXGuard Pre-Ship

Pre-Ship answers one question: **is this code safe enough to ship?**

```bash
axguard preship .
axguard preship . --mode QUICK
axguard preship . --json
axguard preship . --base HEAD~1
```

## Decisions

| Decision | Meaning | Exit |
|---|---|---|
| `PASS` | No verified blocking issue | 0 |
| `PASS_WITH_NOTES` | No blocker; notes / predictive / unverified present | 0 |
| `REVIEW_REQUIRED` | Likely findings, important unknowns, or significant security changes | 1 |
| `FAIL` | Configured blocking condition (verified critical/high by default) | 2 |
| *(tool error)* | Analysis crashed with no usable signal | 3 |

**Never FAIL solely on unverified suspicion.** LLM reasoning alone cannot block a release.

## Modes

| Mode | Behavior |
|---|---|
| `QUICK` | Scan + Security Diff (changed files / `HEAD~1` when git) |
| `STANDARD` (default) | `run_audit` + Security Diff + soft predictive + soft memory |
| `DEEP` / `MAX` | Fuller audit + soft investigation + twin via existing engines |

## Policy defaults

```yaml
preship:
  blocking:
    verified_critical: true
    verified_high: true
    verified_medium: false
    likely: false
    unverified: false
    predictive_risk: false
  unknowns:
    fail: false
    review_required: true
```

Override via `.axguard.yml`. Security Diff HIGH/CRITICAL control removals and memory regressions elevate to at least `REVIEW_REQUIRED` (or `FAIL` when policy + regressions warrant).

## Reports

Written under `<target>/.findings/axguard/preship/` (or `--out-dir`):

- `preship-report.json`
- `preship-report.md`
- `preship-report.html`

## MCP / skill

- MCP: `axguard_preship` (approval required)
- Skill: `axguard-preship` — prefer CLI/MCP before shipping; re-verify after fixes

## CI

```bash
axguard preship . --json
echo $?   # 0 / 1 / 2 / 3
```

See also: [security-diff.md](security-diff.md) · [mcp.md](mcp.md)
