# OrcaRouter Cyber Inference — BYOK provider

OrcaRouter Cyber Inference is a named, OpenAI-compatible provider for security
teams. It is a *user-owned* credential path like every other AXGuard provider:
nothing is sent to OrcaRouter unless you select it explicitly and set a key.

- Provider page: [https://www.orcarouter.ai/cyber](https://www.orcarouter.ai/cyber)
- Cyber model catalog: [https://www.orcarouter.ai/models?tier=cyber](https://www.orcarouter.ai/models?tier=cyber)
- API base: `https://api.orcarouter.ai/v1`

It is aimed at teams doing **authorized, scoped** security work: red-team and
adversary-style analysis with cyber-tuned models on the red side, and the same
endpoint's gateway controls on the blue side (pre-ship review, triage, fix
verification). General-purpose gateways often reject or silently downgrade this
kind of request; this provider lets verified security teams route it to the
cyber tier. Requests outside that scope still work through the general layer.

## Configure (local API / CLI)

```bash
export AXGUARD_AI_MODE=user_key
export AXGUARD_AI_PROVIDER=orcarouter
export AXGUARD_AI_API_KEY=sk-orca-…        # never logged; masked in /v1/health
# optional:
# export AXGUARD_AI_MODEL=orcarouter/auto  # default
# export AXGUARD_AI_BASE_URL=https://api.orcarouter.ai/v1  # explicit override
```

Or in `.axguard.yml` for the GitHub bot (key still comes from the environment):

```yaml
ai:
  provider: orcarouter
  mode: user_key
  model: orcarouter/auto
```

## Models

| Role | Model id | Notes |
|---|---|---|
| Default | `orcarouter/auto` | Auto-routed; works with any OrcaRouter key |
| Recommended for security teams | `orcacyber-ultra-1.0` (OrcaCyber Ultra) | Security code scanning, large-codebase multi-step reasoning; needs business verification |
| Recommended for security teams | `orcacyber-zero-1.5` / `orcacyber-zero-1.0` (OrcaCyber Zero) | OrcaCyber Zero harness models; needs business verification |
| General fallback | `orcarouter/fusion` | Non-cyber workloads |

The provider's model list is live: `GET {base_url}/models` with your key, then
filtered per capability (see `engines/api/providers/catalog.py`). Ids keep their
`vendor/model` namespace. If the catalog fetch fails, `/v1/models` reports
`"degraded": true` with `"catalog_source": "seed"` and only the small verified
cold-start set (`engines/api/providers/orcarouter.py`); seed entries are never
mixed into a successful live result.

```bash
axguard api models --capability chat                 # text dropdown
axguard api models --capability chat --modality image # multimodal understanding
axguard api models --check                           # non-zero if degraded
curl 'http://127.0.0.1:8787/v1/models?capability=chat'
```

Capability filters (metadata only, never model names):

| `capability` | Rule |
|---|---|
| `chat` (default) | `supported_endpoint_types` includes `openai`, `anthropic`, `gemini` or `openai-response` |
| `chat&modality=image\|audio\|video` | chat model whose `architecture.input_modalities` declares the modality (undeclared = excluded) |
| `embedding` | `embeddings` endpoint |
| `image` | `image-generation` endpoint |
| `video` | `openai-video` endpoint |
| `rerank` | `jina-rerank` endpoint |

The local API keeps the key server-side; `/v1/models` and `/v1/health` return
metadata only.

## Errors

401/403 from the catalog → `/v1/models` degrades to the verified seed and reports
the error text (key redacted). A rejected completion raises
`LLM provider HTTP 401/403: …` with any `sk-orca-…`/`Bearer …` token scrubbed.
