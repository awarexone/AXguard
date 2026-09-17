<p align="center">
  <img src="assets/cover.jpg" alt="AXguard by AwareXone — open-source AI security tool to scan and fix vulnerabilities in vibe-coded apps before you ship" width="100%"/>
</p>

# AXguard

> **Open-source AI security tool to scan and fix vulnerabilities in your vibe-coded apps before you ship.**

[![MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.2.0-purple.svg)](#)
[![CI](https://github.com/Awarexone/AXguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Awarexone/AXguard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Awarexone/AXguard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Awarexone/AXguard/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Awarexone/AXguard/badge)](https://scorecard.dev/viewer/?uri=github.com/Awarexone/AXguard)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-black.svg)](https://claude.ai/claude-code)
[![Cursor](https://img.shields.io/badge/Cursor-skills-black.svg)](https://cursor.com/)

**CLI + AI agent plugin for Claude Code, Cursor, OpenCode, Codex, and shared Agent Skills.**

Pre-ship security gate — not a full pentest platform. Scan source, triage noise, fix what matters, and gate releases before you publish.

[Website](https://awarexone.com/) · [GitHub](https://github.com/Awarexone) · [Dev Docs](DEV.md) · [Commands](COMMANDS-QUICK-REF.md) · [Contributing](CONTRIBUTING.md)

---

## What it is

AI tools can build an app in minutes. They can also ship security bugs in minutes.

AXguard reads your source before you publish it and tells you what an attacker would reach for. It runs as a plain CLI, as slash commands inside your coding agent, and as an MCP server your agent can call directly. Everything runs on your machine.

It ships in four pieces:

| Piece | What it is |
|---|---|
| **CLI** | `axguard` — 22 commands, zero runtime dependencies, no account |
| **Agent plugin** | 31 slash commands + 38 skills for Claude Code, Cursor, OpenCode, Codex |
| **MCP server** | 31 tools your agent calls directly, approval-gated |
| **Local API** | Optional FastAPI service on `127.0.0.1` for your own tooling |

Detection is deterministic: **47 rules** across 16 JSON packs, plus five dedicated hunters for the classes that need dataflow rather than pattern matching. Everything after that — triage, verification, attack-path chaining, confidence scoring — is post-processing over those findings.

---

## Quick start

```bash
git clone https://github.com/Awarexone/AXguard.git
cd AXguard

chmod +x install.sh uninstall.sh
./install.sh                      # 1. agent skills + slash commands

python3 -m venv .venv             # 2. the CLI
source .venv/bin/activate
pip install -e .

axguard audit .                   # 3. scan this repo
open .findings/axguard/axguard-report.html
```

Four steps. Under two minutes on a warm machine.

---

## Install

### 1. Agent plugin

```bash
./install.sh                            # Claude Code, globally (~/.claude)
./install.sh --agent cursor             # Cursor
./install.sh --agent all                # every supported agent
./install.sh --agent claude --project   # this repo only (./.claude)
```

| `--agent` | Global destination | `--project` destination |
|---|---|---|
| `claude` *(default)* | `~/.claude` | `.claude` |
| `cursor` | `~/.cursor` | `.cursor` |
| `opencode` | `$OPENCODE_CONFIG_DIR` or `~/.config/opencode` | `.opencode` |
| `codex` | `$CODEX_HOME` or `~/.codex` | `.codex` |
| `agents` | `~/.agents` | `.agents` |
| `all` | all of the above | all of the above |

`--global` is the default. The `agents` target installs skills only — shared Agent Skills have no slash-command concept.

### 2. CLI

Requires **Python 3.10+**. No other runtime dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -e .
```

Optional extras:

```bash
pip install -e ".[mcp]"           # MCP server for AI agents
pip install -e ".[api]"           # local Security Intelligence API
pip install -e ".[dev]"           # pytest, for contributing
```

### 3. Verify it worked

```bash
axguard version                   # axguard 0.2.0
axguard help                      # the workflow table
axguard scan fixtures/vuln_app    # 28 findings in the bundled vulnerable app
```

If the last command prints findings, both halves are working.

---

## See it work

Against `fixtures/vuln_app`, the deliberately vulnerable app bundled with this repo:

```console
$ axguard scan fixtures/vuln_app --no-banner
AXguard scan — /path/to/AXguard/fixtures/vuln_app
Findings: 28

[CRITICAL] injection.python-pickle-loads — pickle.loads deserialization
  app.py:11
  return pickle.loads(blob)
  pickle.loads on untrusted data enables arbitrary object construction and RCE.
  Fix: Use json/msgpack for untrusted payloads; never unpickle attacker input.

[CRITICAL] sql.python-format-query — SQL built with string formatting
  app.py:29
  return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  Dynamic SQL via f-strings/format/concat is a classic SQLi sink.
  Fix: Use parameterized queries / bind variables only.

[CRITICAL] ssti.jinja-render-string — Jinja2 template string from variable
  app.py:33
  return render_template_string(user_tpl)
  Rendering attacker-influenced templates enables SSTI → RCE.
  Fix: Never render user-controlled template source; use fixed templates + autoescape.

[MEDIUM] crypto.math-random-token — Math.random used for security token
  client.js:25
  export const token = "sess-" + Math.random().toString(36);
  Math.random is not cryptographically secure.
  Fix: Use crypto.randomBytes / crypto.getRandomValues.
```

Every finding carries a rule id, a severity, the exact line, the reason it matters, and the fix.

A full audit runs the diagnostic chain on top and writes the reports:

```console
$ axguard audit fixtures/vuln_app --no-banner
audit complete — 28 finding(s)
  json  .findings/axguard/axguard-report.json
  md    .findings/axguard/axguard-report.md
  html  .findings/axguard/axguard-report.html
  model .findings/axguard/application-model.json
  flow  .findings/axguard/dataflow.json
  verify counts: candidates=12 VERIFIED=0 LIKELY=0 UNVERIFIED=12 FALSE_POSITIVE=0
  adversary counts: findings=12 CONFIRMED=0 LIKELY=0 UNVERIFIED=12 FALSE_POSITIVE=0
  evidence counts: findings=12 unique=51 reused=27 conflicts=0 UNKNOWN=12
  paths counts: paths=1 CONFIRMED=0 LIKELY=0 UNVERIFIED=1 BLOCKED=0 dead_ends=11
```

The generated Markdown report opens with the severity breakdown:

```markdown
# AXguard Audit Report

**Findings:** 28
**Mode:** audit

> **Analysis mode: READ-ONLY.** No source files were modified and no external
> requests were made.

## Severity summary

| Severity | Count |
|---|---:|
| critical | 7 |
| high | 14 |
| medium | 6 |
| low | 1 |
```

Note what the diagnostic counters say: `VERIFIED=0 UNVERIFIED=12`. AXguard reports what it can support with evidence and refuses to claim more. Verification status is information, not decoration.

---

## What it finds

Detections come from `rules/*.json` — deterministic pattern and heuristic rules.

| Area | Examples (from shipped rules) |
|---|---|
| **Secrets** | AWS access keys, hard-coded API key assignments, PEM private keys, GitHub PATs, Slack tokens |
| **Auth** | Missing ownership heuristics (IDOR-style), JWT `none`, JWT decode-without-verify, CSRF disabled |
| **Injection / RCE** | `eval` / `exec`, `pickle.loads`, `subprocess(shell=True)`, `os.system` / `popen`, JS `child_process.exec`, PHP `unserialize`, Java `ObjectInputStream` |
| **SQL / NoSQL** | String-built SQL (Python/JS/PHP), ORM raw SQL, Mongo `$where` / operator injection |
| **SSTI** | Jinja2 / Flask `render_template_string`, dynamic Pug compile |
| **Path / LFI** | User paths in `open` / `send_file` / PHP `include` |
| **SSRF** | Variable URLs in Python HTTP clients / JS `fetch` concatenation |
| **XSS** | `innerHTML`, `document.write`, React `dangerouslySetInnerHTML` |
| **Upload** | Original client filenames saved, Multer `.any()` |
| **Crypto** | Hard-coded keys/IVs, MD5/SHA1 near passwords, `Math.random` tokens, TLS verify off |
| **Supply chain** | Risky npm install scripts, pip extra indexes, `curl\|sh` |
| **GraphQL** | Introspection left on, CSRF prevention off |
| **Debug** | Django/Flask debug, Express stack handlers, Spring Actuator hints |
| **Cloud** | AWS metadata URLs, wildcard CORS + credentials, public S3 ACL |
| **AI agents** | Executing model/agent output, unrestricted shell tools, prompt/tool-arg shell execution |

Adding a rule means dropping a JSON file into `rules/` — see [docs/adding-rules.md](docs/adding-rules.md). Point at your own pack with `--rules DIR`.

## Supported languages

Rule coverage is deepest where AI code generation is most common.

| Tier | Languages |
|---|---|
| **Primary** | Python, JavaScript / TypeScript (including JSX, TSX, ESM, CJS) |
| **Secondary** | PHP, Java, Ruby, Go, Rust, Vue |
| **Config & IaC** | `.env`, YAML, JSON, Terraform / HCL, HTML |

Around 45 file extensions are read in total. Rules declare which languages they apply to, so a Python rule never fires on a `.js` file.

---

## Commands

Every slash command maps to a CLI command. Use whichever fits what you are doing.

### Core workflow

| Slash command | CLI | What it does |
|---|---|---|
| `/axguard-audit` | `axguard audit .` | Full A→Z audit. Writes JSON + Markdown + HTML |
| `/axguard-scan` | `axguard scan .` | Fast pass while coding. No report suite |
| `/axguard-triage` | — | Kill false positives, promote real bugs |
| `/axguard-fix` | — | Patch confirmed findings |
| `/axguard-report` | — | Regenerate or tighten the reports |
| `/axguard-ci` | `axguard audit . --fail-on high` | Wire up a release gate |
| `/axguard-threat-model` | — | STRIDE-lite pass on an unfamiliar codebase |

### Diagnostics

These explain *why* a finding is or is not real. They are not vulnerability reports, and they always exit `0` — they cannot gate CI.

| Slash command | CLI | What it does |
|---|---|---|
| `/axguard-surface` | `axguard surface .` | Routes, sinks, stack, AI components |
| `/axguard-flow` | `axguard flow .` | Taint and dataflow paths |
| `/axguard-verify` | `axguard verify .` | Hunter → Judge verification |
| `/axguard-adversary` | `axguard adversary .` | Argues against your findings |
| `/axguard-evidence` | `axguard evidence .` | Evidence chains and confidence |
| `/axguard-paths` | `axguard paths .` | Attack graph and vulnerability chaining |

### By vulnerability class

`/axguard-secrets` · `/axguard-auth` · `/axguard-inject` · `/axguard-sql` · `/axguard-ssti` · `/axguard-path` · `/axguard-ssrf` · `/axguard-xss` · `/axguard-upload` · `/axguard-crypto` · `/axguard-supply` · `/axguard-graphql` · `/axguard-cloud` · `/axguard-debug` · `/axguard-agent`

### Deeper analysis

| CLI | What it does |
|---|---|
| `axguard twin build .` | Symbolic security model — blast radius, counterfactuals, regression → [docs](docs/twin/README.md) |
| `axguard memory record .` | Longitudinal history — what changed, what regressed → [docs](docs/memory/README.md) |
| `axguard investigate .` | Evidence-driven investigation loop → [docs](docs/investigation/README.md) |
| `axguard predict .` | Risk signals from observable change — not confirmed findings → [docs](docs/predictive/README.md) |

### Local and operational

| Slash command | CLI | What it does |
|---|---|---|
| `/axguard-data` | `axguard data discover` | Training-data registry and license gate. No model training |
| `/axguard-contribute` | `axguard contribute suggest` | Prepare a contribution locally. Never auto-pushes |
| `/axguard-privacy` | `axguard privacy status` | Local privacy preferences |
| — | `axguard mcp serve` | MCP server for AI agents |
| — | `axguard api start` | Local Security Intelligence API |
| — | `axguard github setup .` | GitHub Security Bot adapter config |

Full cheat sheet: [COMMANDS-QUICK-REF.md](COMMANDS-QUICK-REF.md).

### Flags worth knowing

`--fail-on {critical,high,medium,low,none}` — exit `1` when a finding meets the threshold. **Available on `scan` and `audit` only.**

`--rules DIR` — use your own rule pack. `--no-banner`, `--no-engage` — quiet output, for CI.

`--format {text,json,md,html}` with `-o FILE` — **`scan` only**. `audit` always writes all three formats.

## Which workflow?

| Situation | Start here |
|---|---|
| About to ship | `/axguard-audit` |
| Quick check while coding | `/axguard-scan` |
| New or unknown codebase | `/axguard-threat-model` then `/axguard-surface` |
| Too many findings | `/axguard-triage` |
| Findings confirmed, need patches | `/axguard-fix` |
| Want a security-lead pass | skill `axguard-cso` |
| Short release checklist | skill `axguard-preship` |
| Blocking bad merges | `/axguard-ci` |

---

## Reports

Every full audit writes the primary vulnerability reports:

```text
.findings/axguard/
├── axguard-report.html   # easy to read
├── axguard-report.md     # for PRs and docs
└── axguard-report.json   # for CI and tools
```

Plus diagnostic artifacts, which explain the findings rather than adding to them:

```text
.findings/axguard/
├── application-model.{json,md}   # surface / app model
├── dataflow.{json,md}            # taint / dataflow paths
├── verification.{json,md}        # Hunter → Judge
├── adversary.{json,md}           # false-positive adversary
├── final-findings.json           # post-adversary statuses
├── evidence.{json,md}            # evidence & confidence
├── attack-paths.{json,md}        # attack graph / chaining
├── memory/                       # Security Memory snapshot (best-effort)
└── investigation/                # Investigation Agent pass (best-effort)
```

The diagnostic stages are deliberately best-effort: if one fails, the audit records the error and continues rather than losing the whole run. A completed audit with a missing diagnostic section is a stage that did not finish, not a clean result.

The HTML report is interactive and approval-gated. High-risk actions — applying a fix, active verification, external sharing — are never executed by the report.

---

## CI / release gate

```text
Code → AXguard → High/Critical?
                 ├── Yes → Fix → Re-scan
                 └── No  → Ship
```

```bash
axguard audit . --fail-on high --no-banner
```

Exit `1` when anything at or above the threshold is found, exit `0` otherwise.

### What this repository runs

[`.github/workflows/axguard.yml`](.github/workflows/axguard.yml) dogfoods **runtime code only** (`engines/` and `cli/`). Fixtures, skills, commands and rules contain deliberately vulnerable examples for regression tests, and are excluded:

```bash
axguard audit engines --fail-on high --no-banner
axguard audit cli --fail-on high --no-banner
```

To make it a required status check, see [docs/github/required-checks.md](docs/github/required-checks.md).

---

## AI agent integration

AXguard is built to be called by coding agents, not just by you.

| Layer | How the agent uses it |
|---|---|
| **Slash commands** | 31 commands — `/axguard-audit`, `/axguard-triage`, … |
| **Skills** | 38 skills: 8 orchestration + 30 security domain skills |
| **MCP** | 31 typed tools the agent calls directly |

The three tools an agent reaches for first are `axguard_security_review`, `axguard_investigate` and `axguard_verify_fix`.

```bash
pip install -e ".[mcp]"
axguard mcp doctor          # check the host connection
axguard mcp tools           # list the 31 tools
axguard mcp serve           # stdio MCP server
```

Six tools are approval-gated (`axguard_audit`, `axguard_verify_finding`, `axguard_verify_fix`, `axguard_what_if`, `axguard_investigate`, and `axguard_security_review` in DEEP/MAX mode). Unknown tools default to requiring approval.

Setup: [docs/mcp.md](docs/mcp.md) · [config](docs/mcp-config.md) · [tools](docs/mcp-tools.md) · [security](docs/mcp-security.md) · [threat model](docs/mcp-threat-model.md)

---

## GitHub Security Bot

Optional GitHub App that reviews pull requests with Check Runs and one updatable summary comment. It runs AXguard behind a thin webhook adapter (`engines/github/`). Local CLI scanning does not require it.

```bash
export AXGUARD_GITHUB_APP_ID=…
export AXGUARD_GITHUB_WEBHOOK_SECRET=…
export AXGUARD_GITHUB_PRIVATE_KEY_PATH=/path/to/app.pem

axguard github setup .        # writes .axguard.yml (never secrets)
axguard github validate .
axguard github test .         # webhook HMAC self-check
axguard github status .
```

The CLI configures and validates the adapter; it does not run the webhook listener. Serving it is a self-hosting step — see [docs/github/self-hosting.md](docs/github/self-hosting.md).

If you have no webhook host, the Actions-only path in the CI section above gives you the gate without the App.

Install & permissions: [install](docs/github/install.md) · [permissions](docs/github/permissions.md) · [config](docs/github/config.md) · [PR output](docs/github/pr-ux.md) · [security](docs/github/security.md) · [privacy](docs/github/privacy.md) · [AI providers](docs/github/ai-providers.md) · [troubleshooting](docs/github/troubleshooting.md) · [uninstall](docs/github/uninstall.md)

---

## Privacy

**AXguard sends nothing anywhere by default.**

- No telemetry, no analytics, no phone-home.
- No AwareXone account. No hosted service.
- No LLM calls in the analysis path. The default AI provider is `none` / `no-llm`.
- Findings, reports and history stay in `.findings/` in your repo; preferences stay in `~/.axguard/`.

The only outbound request anywhere in the non-optional code is to the GitHub API, and only if you configure the GitHub bot. The optional local API binds `127.0.0.1` and is yours.

Contribution packaging is opt-in, local, and never auto-pushes:

```bash
axguard privacy status
axguard privacy opt-in
axguard contribute prepare
```

Details: [docs/contributors](docs/contributors/README.md) · [docs/github/privacy.md](docs/github/privacy.md)

---

## Troubleshooting

**`axguard: command not found`** — the venv is not active. Run `source .venv/bin/activate` (Windows: `.venv\Scripts\activate`). Confirm with `which axguard`.

**Slash commands do not appear in your agent** — re-run `./install.sh --agent <name>` and restart the agent. Skills load at startup.

**Zero findings on a real project** — check you are scanning source, not a build directory. Confirm the toolchain works with `axguard scan fixtures/vuln_app`, which should report 28 findings.

**Too many findings** — that is what triage is for. Run `/axguard-triage`, or `axguard adversary .` to have AXguard argue against its own output.

**MCP tools missing in your agent** — the MCP extra is not installed. Run `pip install -e ".[mcp]"`, then `axguard mcp doctor` for a connection report. The `mcp` command is hidden entirely when the dependency is absent.

**An audit finished but a diagnostic section is empty** — that stage failed and the audit continued by design. Run the stage directly (`axguard flow .`, `axguard verify .`) to see the error.

---

## Uninstall

```bash
./uninstall.sh                          # Claude Code, global
./uninstall.sh --agent cursor
./uninstall.sh --agent all
./uninstall.sh --agent claude --project
```

Same `--agent` and `--global` / `--project` options as `install.sh`. To remove the CLI, delete the virtualenv, or `pip uninstall axguard`.

---

## Project structure

```text
AXguard/
├── cli/                 # axguard CLI entrypoint
├── engines/             # scanners, diagnostics, adapters
├── rules/               # detection rule packs (*.json)
├── skills/              # agent skills (8 orchestration + 30 security)
├── commands/            # 31 slash commands
├── fixtures/            # deliberately vulnerable test apps
├── tests/               # 438 tests
├── scripts/             # skill validation
└── docs/                # developer and feature documentation
```

## Docs

| Area | Docs |
|---|---|
| **Architecture** | [architecture](docs/architecture.md) · [plugin](docs/plugin.md) · [adding rules](docs/adding-rules.md) |
| **MCP** | [overview](docs/mcp.md) · [config](docs/mcp-config.md) · [tools](docs/mcp-tools.md) · [security](docs/mcp-security.md) · [threat model](docs/mcp-threat-model.md) · [benchmark](docs/mcp-benchmark.md) · [research](docs/mcp-research.md) |
| **Features** | [attack graph](docs/attack-graph.md) · [twin](docs/twin/README.md) · [memory](docs/memory/README.md) · [investigation](docs/investigation/README.md) · [predictive](docs/predictive/README.md) |
| **API** | [overview](docs/api/overview.md) · [quickstart](docs/api/quickstart.md) · [auth](docs/api/authentication.md) · [providers](docs/api/providers.md) · [security](docs/api/security.md) |
| **GitHub bot** | [overview](docs/github/README.md) · [install](docs/github/install.md) · [config](docs/github/config.md) · [self-hosting](docs/github/self-hosting.md) · [required checks](docs/github/required-checks.md) · [troubleshooting](docs/github/troubleshooting.md) |
| **Skills** | [schema](docs/SKILL-SCHEMA.md) · [knowledge inventory](docs/SECURITY-KNOWLEDGE-INVENTORY.md) |
| **Research** | [investigation agent](docs/research/investigation-agent.md) · [security memory](docs/research/security-memory.md) · [security twin](docs/research/security-twin.md) · [GitHub bot](docs/research/github-security-bot.md) · [predictive](docs/research/predictive-security.md) |
| **Data pipeline** | [overview](docs/data/README.md) · [AI security corpus](docs/data/research/ai-security-corpus.md) · [false-positive corpus](docs/data/research/false-positive-corpus.md) · [license gate](docs/data/research/license-gate.md) |
| **Contributors** | [engagement](docs/engagement.md) · [contributor tooling](docs/contributors/README.md) |

Developer setup lives in [DEV.md](DEV.md).

---

## Contributing

Contributions are welcome — detection rules, scanners, test fixtures, agent skills, reports, documentation, bug fixes.

```bash
pip install -e ".[dev]"
pytest -q
python scripts/validate_skills.py
axguard audit fixtures/vuln_app --no-banner
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Artifact and bytecode scanners are on the roadmap there — not claimed as current features.

## Responsible use

AXguard is for **authorized security testing and defense**.

Only scan systems, applications, repositories, and infrastructure that you own or have permission to test.

## Support

AXguard is free and open source.

If it helps you build safer software, a **star on GitHub** helps more builders find it. You can also support the project directly and help fund more open-source security tools.

**Website:** [awarexone.com](https://awarexone.com/)  
**Email:** [hello@awarexone.com](mailto:hello@awarexone.com) · [b2b@awarexone.com](mailto:b2b@awarexone.com) · [shuvon@awarexone.com](mailto:shuvon@awarexone.com)  
**Buy Me a Coffee:** [buymeacoffee.com/shuvonsec](https://www.buymeacoffee.com/shuvonsec)

| | |
|---|---|
| **Bitcoin** | `1GXwGqmLcnbZWgVNskUAZyw2cmqenkUFNY` |
| **Solana** | `4ArkPu1E7tkrt3d5X84grWzF1xjuLpScgGEy12Bp2cmE` |

---

## Credits

AXguard is built by **[Shuvonsec](https://github.com/shuvonsec)** — ethical hacker and security researcher, ranked **#1 worldwide** on the TryHackMe monthly leaderboard in 2025. He works on AI security and cybersecurity agents, and builds open-source tools to make AI-built applications safer.

<p align="center">
  <a href="https://github.com/shuvonsec">
    <img src="assets/shuvonsec-contributions.png" alt="Shuvonsec GitHub contributions — open-source security work across the year" width="100%"/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/shuvonsec"><img src="https://img.shields.io/badge/GitHub-shuvonsec-181717?style=flat-square&logo=github" alt="shuvonsec on GitHub"></a>
  <a href="https://shuvonsec.com"><img src="https://img.shields.io/badge/Web-shuvonsec.com-3dd6c6?style=flat-square" alt="shuvonsec.com"></a>
  <a href="https://awarexone.com/"><img src="https://img.shields.io/badge/AwareXone-awarexone.com-0c1117?style=flat-square" alt="AwareXone"></a>
</p>

### AwareXone

We build open-source security tools for the AI era — for people who **build** and people who **hunt**.

```text
BUILD                         HUNT
  │                             │
AXguard                 Agentic Bug Hunter
  │                             │
Secure what you create   Find bugs that are live
```

> **Same security DNA. Different job.**

<p align="center">
  <a href="https://github.com/Awarexone/Agentic-Bug-Hunter">
    <img src="assets/agentic-bug-hunter-banner.jpg" alt="Agentic Bug Hunter by AwareXone — AI-powered bug bounty hunting toolkit" width="100%"/>
  </a>
</p>

| Tool | What it is |
|---|---|
| [**Agentic Bug Hunter**](https://github.com/Awarexone/Agentic-Bug-Hunter) | AI bug bounty toolkit — recon, find, validate, report |
| [**Public Skills Builder**](https://github.com/Awarexone/public-skills-builder) | Turn public security research into reusable skills |
| [**Web3 Bug Bounty AI Skills**](https://github.com/Awarexone/web3-bug-bounty-hunting-ai-skills) | Smart-contract and DeFi security skills |

Beyond open-source tools, AwareXone builds AI-driven defenses against scams, fraud and social engineering, and provides human-risk security services for organizations.

[awarexone.com](https://awarexone.com/) · [GitHub](https://github.com/Awarexone) · [X @AwareXone](https://x.com/awarexone)

---

## License

MIT. See [LICENSE](LICENSE).

<!--
SEO: ai-security · vibe-coding · security-scanner · vulnerability-scanner ·
appsec · devsecops · ai-agent-security · llm-security · sast · owasp ·
secret-scanning · claude-code · cursor · awarexone
-->
