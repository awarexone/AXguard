"""Model catalog and capability filters for OpenAI-compatible providers.

The catalog is the provider's own ``GET {base_url}/models`` listing. Model ids
are kept verbatim (``vendor/model`` namespaces included) and capabilities are
read from directory metadata only — never guessed from model names.

Endpoints are filtered per capability:

- ``chat``: models whose ``supported_endpoint_types`` include one of
  ``openai`` / ``anthropic`` / ``gemini`` / ``openai-response``
  (or, when the listing carries no endpoint metadata, models without a
  non-text generation endpoint — fail closed for image/video/rerank-only).
- ``embedding``: ``embeddings`` endpoint type.
- ``image``: ``image-generation`` endpoint type.
- ``video``: ``openai-video`` endpoint type.
- ``rerank``: ``jina-rerank`` endpoint type.

Multimodal understanding is not an endpoint type: it is a *chat* model whose
``architecture.input_modalities`` explicitly lists the attachment modality.
Models that do not declare a modality are excluded (fail closed).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Iterable

CATALOG_TIMEOUT = 60.0

CHAT_ENDPOINT_TYPES: frozenset[str] = frozenset(
    {"openai", "anthropic", "gemini", "openai-response"}
)
NON_TEXT_ONLY_ENDPOINT_TYPES: frozenset[str] = frozenset(
    {"image-generation", "openai-video", "jina-rerank", "embeddings", "moderations", "audio"}
)
CAPABILITY_ENDPOINT_TYPES: dict[str, frozenset[str]] = {
    "embedding": frozenset({"embeddings"}),
    "image": frozenset({"image-generation"}),
    "video": frozenset({"openai-video"}),
    "rerank": frozenset({"jina-rerank"}),
}
KNOWN_CAPABILITIES: tuple[str, ...] = ("chat", "multimodal", "embedding", "image", "video", "rerank")
INPUT_MODALITIES: frozenset[str] = frozenset({"image", "audio", "video"})


class CatalogError(RuntimeError):
    """Catalog fetch failed (auth, network or malformed payload)."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [v.strip().lower() for v in value.split(",") if v.strip()]
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            if isinstance(item, dict):
                # Directory lists may carry structured entries; the endpoint
                # itself is named by ``type``.
                item = item.get("type") or item.get("name") or ""
            text = str(item).strip().lower()
            if text:
                out.append(text)
        return out
    return []


def normalize_model(entry: dict[str, Any]) -> dict[str, Any]:
    """Reduce a catalog entry to the metadata the filters need."""
    model_id = str(entry.get("id") or "").strip()
    endpoint_types = _string_list(entry.get("supported_endpoint_types"))
    architecture = entry.get("architecture")
    if not isinstance(architecture, dict):
        architecture = {}
    modalities = _string_list(architecture.get("input_modalities"))
    return {
        "id": model_id,
        "name": str(entry.get("name") or model_id),
        "supported_endpoint_types": endpoint_types,
        "input_modalities": modalities,
        "context_length": entry.get("context_length") or entry.get("context_window"),
        "reasoning": isinstance(entry.get("supported_parameters"), list)
        and "reasoning" in [str(p).lower() for p in entry["supported_parameters"]],
    }


def is_chat_model(model: dict[str, Any]) -> bool:
    endpoints = set(model.get("supported_endpoint_types") or [])
    if endpoints & CHAT_ENDPOINT_TYPES:
        return True
    if endpoints & NON_TEXT_ONLY_ENDPOINT_TYPES:
        return False
    # No text endpoint declared: fail closed unless the entry has no endpoint
    # metadata at all (older/proxied catalogs omit it).
    return not endpoints


def _endpoint_matches(model: dict[str, Any], endpoint_types: frozenset[str], *, fallback: bool) -> bool:
    endpoints = set(model.get("supported_endpoint_types") or [])
    if endpoints:
        return bool(endpoints & endpoint_types)
    # No endpoint metadata: only fall back for chat, and only when nothing
    # marks the model as a non-text generator.
    return fallback and not (endpoints & NON_TEXT_ONLY_ENDPOINT_TYPES)


def supports_modality(model: dict[str, Any], modality: str) -> bool:
    modality = modality.strip().lower()
    if modality not in INPUT_MODALITIES:
        raise ValueError(f"unsupported modality: {modality}")
    return modality in (model.get("input_modalities") or []) and is_chat_model(model)


def filter_models(
    models: Iterable[dict[str, Any]],
    *,
    capability: str | None = None,
    modality: str | None = None,
) -> list[dict[str, Any]]:
    """Return models compatible with the requested capability.

    ``capability`` must be one of ``KNOWN_CAPABILITIES``. ``modality`` narrows a
    ``chat``/``multimodal`` request to models that declare that input modality.
    """
    cap = (capability or "chat").strip().lower()
    if cap not in KNOWN_CAPABILITIES:
        raise ValueError(f"unknown capability: {cap}")
    if modality is not None and cap not in {"chat", "multimodal"}:
        raise ValueError("modality only applies to chat/multimodal")

    out: list[dict[str, Any]] = []
    for model in models:
        if not model.get("id"):
            continue
        if cap in {"chat", "multimodal"}:
            if not is_chat_model(model):
                continue
            if modality is not None and not supports_modality(model, modality):
                continue
        elif not _endpoint_matches(model, CAPABILITY_ENDPOINT_TYPES[cap], fallback=False):
            continue
        out.append(model)
    return out


def parse_catalog(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        data = payload.get("data")
        if data is None:
            data = payload.get("models")
    else:
        data = payload
    if not isinstance(data, list):
        raise CatalogError("model catalog payload is not a list")
    return [normalize_model(e) for e in data if isinstance(e, dict)]


def fetch_catalog(base_url: str, api_key: str | None, *, timeout: float = CATALOG_TIMEOUT) -> list[dict[str, Any]]:
    """Fetch ``GET {base_url}/models`` with a Bearer key. Key never leaves this process."""
    url = f"{base_url.rstrip('/')}/models"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise CatalogError(
                "model catalog rejected the credential (401/403) — check the OrcaRouter API key",
                status=exc.code,
            ) from None
        raise CatalogError(f"model catalog HTTP {exc.code}", status=exc.code) from None
    except urllib.error.URLError as exc:
        raise CatalogError(f"model catalog unreachable: {exc.reason}") from None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise CatalogError("model catalog returned non-JSON") from None
    return parse_catalog(payload)
