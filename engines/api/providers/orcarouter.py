"""OrcaRouter Cyber Inference — named OrcaRouter provider.

OrcaRouter is an OpenAI-compatible AI gateway for security teams
(https://www.orcarouter.ai). This module is the single seam for everything
OrcaRouter-specific in AXGuard: base URL, default model, curated cyber tier
metadata, credential redaction and the model catalog.

OrcaRouter is only reached when the user selects it explicitly
(``AXGUARD_AI_PROVIDER=orcarouter`` / ``ai.provider: orcarouter``); AXGuard has
no hosted model and never silently routes to a third party.
"""

from __future__ import annotations

import re

from engines.api.providers.catalog import CatalogError, fetch_catalog, filter_models
from engines.api.providers.openai_compat import OpenAICompatProvider

PROVIDER_NAME = "orcarouter"
DISPLAY_NAME = "OrcaRouter Cyber Inference"
BASE_URL = "https://api.orcarouter.ai/v1"
KEY_PREFIX = "sk-orca-"
PROVIDER_PAGE = "https://www.orcarouter.ai/cyber"
CYBER_CATALOG_PAGE = "https://www.orcarouter.ai/models?tier=cyber"

# Default model: available to any OrcaRouter key, auto-routed.
DEFAULT_MODEL = "orcarouter/auto"
# General fallback for non-cyber workloads.
FALLBACK_MODEL = "orcarouter/fusion"
# Dedicated cyber models for verified security teams (unlocked after business
# verification). Kept as metadata only — never assume a key can call them.
CYBER_MODELS: tuple[dict[str, str], ...] = (
    {
        "id": "orcacyber-ultra-1.0",
        "name": "OrcaCyber Ultra",
        "tier": "cyber",
        "description": "Security code scanning and multi-step reasoning over large codebases.",
    },
    {
        "id": "orcacyber-zero-1.5",
        "name": "OrcaCyber Zero 1.5",
        "tier": "cyber",
        "description": "OrcaCyber Zero harness model (1.5 generation).",
    },
    {
        "id": "orcacyber-zero-1.0",
        "name": "OrcaCyber Zero 1.0",
        "tier": "cyber",
        "description": "OrcaCyber Zero harness model (1.0 generation).",
    },
)

# Cold-start seeds used only when a live catalog fetch fails. Small, verified
# metadata only; live discovery always replaces them.
VERIFIED_SEED: tuple[dict[str, object], ...] = (
    {
        "id": "orcarouter/auto",
        "name": "OrcaRouter Auto",
        "supported_endpoint_types": ["openai"],
        "input_modalities": ["text"],
        "context_length": None,
        "reasoning": False,
        "verified": True,
    },
    {
        "id": "orcarouter/fusion",
        "name": "OrcaRouter Fusion",
        "supported_endpoint_types": ["openai"],
        "input_modalities": ["text"],
        "context_length": None,
        "reasoning": False,
        "verified": True,
    },
    {
        "id": "openai/gpt-5.5",
        "name": "GPT-5.5",
        "supported_endpoint_types": ["openai", "openai-response"],
        "input_modalities": ["text", "image"],
        "context_length": None,
        "reasoning": True,
        "reasoning_effort": ["low", "medium", "high", "xhigh"],
        "verified": True,
    },
    {
        "id": "anthropic/claude-opus-4.8",
        "name": "Claude Opus 4.8",
        "supported_endpoint_types": ["anthropic", "openai"],
        "input_modalities": ["text", "image"],
        "context_length": None,
        "reasoning": True,
        "verified": True,
    },
    {
        "id": "google/gemini-3.5-flash",
        "name": "Gemini 3.5 Flash",
        "supported_endpoint_types": ["gemini", "openai"],
        "input_modalities": ["text", "image", "audio", "video"],
        "context_length": None,
        "reasoning": True,
        "verified": True,
    },
    {
        "id": "deepseek/deepseek-v4-pro",
        "name": "DeepSeek V4 Pro",
        "supported_endpoint_types": ["openai"],
        "input_modalities": ["text"],
        "context_length": None,
        "reasoning": True,
        "verified": True,
    },
)

_KEY_PATTERN = re.compile(r"sk-orca-[A-Za-z0-9_\-]+")
_BEARER_PATTERN = re.compile(r"Bearer\s+\S+", re.IGNORECASE)


def is_key_shaped(value: str | None) -> bool:
    return bool(value) and value.strip().startswith(KEY_PREFIX)


def mask_secret(value: str | None) -> str:
    """Return a display-safe hint; never the full credential."""
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 10:
        return "…" + v[-2:]
    return v[:9] + "…" + v[-2:]


def scrub(text: str, secret: str | None = None) -> str:
    """Remove credentials from provider error text before it is surfaced or stored."""
    out = text or ""
    if secret:
        out = out.replace(secret, mask_secret(secret))
    out = _KEY_PATTERN.sub(lambda m: mask_secret(m.group(0)), out)
    out = _BEARER_PATTERN.sub("Bearer sk-orca-…", out)
    return out


def seed_catalog() -> list[dict[str, object]]:
    return [dict(m) for m in VERIFIED_SEED]


class OrcaRouterProvider(OpenAICompatProvider):
    """OpenAI-compatible OrcaRouter provider with a named catalog."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        mode: str = "user_key",
        timeout: float = 60.0,
    ) -> None:
        super().__init__(
            base_url=base_url or BASE_URL,
            api_key=api_key,
            model=model or DEFAULT_MODEL,
            mode=mode,
            provider_name=PROVIDER_NAME,
            timeout=timeout,
        )

    @property
    def display_name(self) -> str:
        return DISPLAY_NAME

    @property
    def credential_hint(self) -> str:
        """Masked key for status output (never the raw value)."""
        return mask_secret(self.api_key)

    def list_models(self) -> list[dict[str, object]]:
        """Live catalog for the configured base URL (requires a key)."""
        return fetch_catalog(self.base_url, self.api_key)

    def catalog(
        self,
        *,
        capability: str | None = "chat",
        modality: str | None = None,
        discovery: bool = True,
    ) -> dict[str, object]:
        """Capability-filtered catalog with explicit degraded state on failure."""
        source = "live"
        error: str | None = None
        models: list[dict[str, object]]
        if discovery:
            try:
                models = self.list_models()
            except CatalogError as exc:
                source = "seed"
                error = scrub(str(exc), self.api_key)
                models = seed_catalog()
        else:
            models = seed_catalog()
        filtered = filter_models(models, capability=capability, modality=modality)
        return {
            "provider": PROVIDER_NAME,
            "display_name": DISPLAY_NAME,
            "catalog_source": source,
            "degraded": source != "live",
            "error": error,
            "capability": capability,
            "modality": modality,
            "model_count": len(filtered),
            "models": filtered,
        }

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout: float | None = None,
    ) -> dict[str, object]:
        previous = self.timeout
        if timeout is not None:
            self.timeout = timeout
        try:
            return super().complete(
                messages, model=model, temperature=temperature, max_tokens=max_tokens
            )
        except RuntimeError as exc:
            raise RuntimeError(scrub(str(exc), self.api_key)) from None
        except OSError as exc:  # truncated body / reset / timeout on the socket
            raise RuntimeError(
                scrub(f"OrcaRouter request failed: {type(exc).__name__}", self.api_key)
            ) from None
        finally:
            self.timeout = previous
