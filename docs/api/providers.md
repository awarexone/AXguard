# AI Providers (local / BYOK)

AXGuard has **no hosted model**.

| Env | Purpose |
|---|---|
| `AXGUARD_AI_MODE` | `no-llm` (default), `local`, `user_key` |
| `AXGUARD_AI_PROVIDER` | `none`, `ollama`, `openai`, `anthropic`, `groq`, … |
| `AXGUARD_AI_API_KEY` | Your key (never logged) |
| `AXGUARD_AI_BASE_URL` | OpenAI-compatible or Anthropic base URL |
| `AXGUARD_AI_MODEL` | Model id |

`enrichment=llm` returns **422** unless a real local/BYOK provider is configured. `NoneProvider` is valid for no-llm (`available=True`) but still rejected for enrichment.

## Named provider: OrcaRouter Cyber Inference

`AXGUARD_AI_PROVIDER=orcarouter` selects the named OrcaRouter Cyber Inference
provider ([OrcaRouter](https://www.orcarouter.ai), base
`https://api.orcarouter.ai/v1`, key prefix `sk-orca-`). Default model
`orcarouter/auto`; cyber-tier models (`orcacyber-ultra-1.0`,
`orcacyber-zero-1.5`) for verified security teams; `orcarouter/fusion` as the
general fallback. The model list is discovered live per capability
(`axguard api models`, `GET /v1/models`). Full guide:
[orcarouter.md](orcarouter.md).
