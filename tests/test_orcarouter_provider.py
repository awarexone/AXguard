"""OrcaRouter Cyber Inference provider: registry, catalog, redaction, live path.

All network calls go to a local HTTP server except the opt-in live check, which
runs only when ``ORCAROUTER_API_KEY`` is set and uses the provider code path.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from engines.api.providers import catalog as catalog_mod
from engines.api.providers.catalog import (
    CatalogError,
    fetch_catalog,
    filter_models,
    normalize_model,
    parse_catalog,
)
from engines.api.providers.factory import get_provider, provider_status
from engines.api.providers.none import NoneProvider
from engines.api.providers.openai_compat import OpenAICompatProvider
from engines.api.providers.orcarouter import (
    BASE_URL,
    DEFAULT_MODEL,
    OrcaRouterProvider,
    mask_secret,
    scrub,
)

FAKE_KEY = "sk-orca-fake000000000000000000000000"


def _model(model_id, endpoints=None, modalities=None, **extra):
    entry = {"id": model_id, "name": model_id}
    if endpoints is not None:
        entry["supported_endpoint_types"] = endpoints
    if modalities is not None:
        entry["architecture"] = {"input_modalities": modalities}
    entry.update(extra)
    return entry


CATALOG_FIXTURE = [
    _model("openai/gpt-5.5", ["openai", "openai-response"], ["text", "image"],
           supported_parameters=["reasoning", "temperature"]),
    _model("anthropic/claude-opus-4.8", ["anthropic", "openai"], ["text", "image"]),
    _model("google/gemini-3.5-flash", ["gemini", "openai"], ["text", "image", "audio", "video"]),
    _model("deepseek/deepseek-v4-pro", ["openai"], ["text"]),
    _model("orcarouter/auto", ["openai"], ["text"]),
    _model("orcarouter/fusion", ["openai"], ["text"]),
    _model("orcacyber-ultra-1.0", ["openai"], ["text"]),
    _model("meta/llama-text-nodecl", ["openai"]),
    _model("openai/gpt-image-1", ["image-generation"], ["text"]),
    _model("kuaishou/kling-video", ["openai-video"], ["text"]),
    _model("jina/jina-reranker-v3", ["jina-rerank"], ["text"]),
    _model("openai/text-embedding-4", ["embeddings"], ["text"]),
    _model("vendor/audio-tts", ["audio"], ["text"]),
    _model("vendor/system-only", ["systemone"], ["text", "image"]),
    _model("vendor/dict-endpoints", [{"type": "openai"}, {"type": "anthropic"}], ["text"]),
]


class _Handler(BaseHTTPRequestHandler):
    """Records requests; serves the fixture catalog and a fake completion."""

    payload: dict = {"data": CATALOG_FIXTURE}
    status: int = 200
    requests: list = []
    chat_response: dict = {
        "id": "chatcmpl-test",
        "choices": [{"message": {"content": "summary ok"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    chat_status: int = 200

    def log_message(self, *args):  # silence
        pass

    def _send(self, status, body):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        type(self).requests.append(("GET", self.path, dict(self.headers)))
        self._send(self.status, self.payload)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        type(self).requests.append(("POST", self.path, dict(self.headers), body))
        self._send(self.chat_status, self.chat_response)


@pytest.fixture()
def server():
    _Handler.requests = []
    _Handler.payload = {"data": CATALOG_FIXTURE}
    _Handler.status = 200
    _Handler.chat_status = 200
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/v1"
    finally:
        httpd.shutdown()
        httpd.server_close()


# --- registry ---------------------------------------------------------------


def test_factory_returns_named_orcarouter_provider():
    p = get_provider(mode="user_key", provider="orcarouter", api_key=FAKE_KEY)
    assert isinstance(p, OrcaRouterProvider)
    assert isinstance(p, OpenAICompatProvider)
    assert p.provider_name == "orcarouter"
    assert p.base_url == BASE_URL == "https://api.orcarouter.ai/v1"
    assert p.default_model == DEFAULT_MODEL == "orcarouter/auto"
    assert p.display_name == "OrcaRouter Cyber Inference"


def test_factory_orcarouter_defaults_without_model():
    p = get_provider(mode="user_key", provider="orca", api_key=FAKE_KEY)
    assert isinstance(p, OrcaRouterProvider)
    assert p.provider_name == "orcarouter"


def test_factory_orcarouter_without_key_is_unavailable():
    p = get_provider(
        mode="user_key", provider="orcarouter", api_key=None, base_url=None
    )
    assert isinstance(p, OrcaRouterProvider)
    assert p.available is False


def test_factory_explicit_base_url_override_wins():
    p = get_provider(
        mode="user_key",
        provider="orcarouter",
        api_key=FAKE_KEY,
        base_url="http://127.0.0.1:9/v1",
    )
    assert p.base_url == "http://127.0.0.1:9/v1"


def test_status_masks_credential(monkeypatch):
    p = get_provider(mode="user_key", provider="orcarouter", api_key=FAKE_KEY)
    status = provider_status(p)
    blob = json.dumps(status)
    assert FAKE_KEY not in blob
    assert status["provider"] == "orcarouter"
    assert status["display_name"] == "OrcaRouter Cyber Inference"
    assert status["credential"] == "configured"
    assert status["credential_hint"].startswith("sk-orca-")


def test_none_provider_status_unchanged():
    status = provider_status(NoneProvider())
    assert status["provider"] == "none"
    assert "display_name" not in status


def test_scrub_removes_keys_from_error_text():
    text = f"LLM provider HTTP 401: Invalid key {FAKE_KEY} (Bearer {FAKE_KEY})"
    out = scrub(text, FAKE_KEY)
    assert FAKE_KEY not in out
    assert "sk-orca-" in out
    assert FAKE_KEY not in scrub(f"leaked {FAKE_KEY}")  # no explicit secret arg


def test_mask_secret_short_values():
    assert mask_secret(None) == ""
    assert "sk-orca-x" not in mask_secret("sk-orca-x")
    assert mask_secret(FAKE_KEY).endswith("00")


# --- catalog parsing and capability filters --------------------------------


def test_parse_catalog_keeps_vendor_namespace_and_metadata():
    models = parse_catalog({"data": CATALOG_FIXTURE})
    ids = [m["id"] for m in models]
    assert "openai/gpt-5.5" in ids
    gpt = next(m for m in models if m["id"] == "openai/gpt-5.5")
    assert gpt["input_modalities"] == ["text", "image"]
    assert gpt["reasoning"] is True
    assert "supported_endpoint_types" in models[0]


def test_parse_catalog_rejects_garbage():
    with pytest.raises(CatalogError):
        parse_catalog({"data": "nope"})
    with pytest.raises(CatalogError):
        parse_catalog(42)


def test_normalize_tolerates_missing_metadata():
    m = normalize_model({"id": "x/y"})
    assert m["input_modalities"] == []
    assert m["supported_endpoint_types"] == []
    assert m["reasoning"] is False


def _ids(models):
    return {m["id"] for m in models}


def test_chat_filter_excludes_image_video_rerank_embedding_audio():
    models = parse_catalog({"data": CATALOG_FIXTURE})
    chat = _ids(filter_models(models, capability="chat"))
    assert "openai/gpt-5.5" in chat
    assert "anthropic/claude-opus-4.8" in chat
    assert "google/gemini-3.5-flash" in chat
    assert "deepseek/deepseek-v4-pro" in chat
    assert "orcarouter/auto" in chat
    assert "orcacyber-ultra-1.0" in chat
    # Missing endpoint metadata: allowed only if it is not a non-text generator
    assert "meta/llama-text-nodecl" in chat
    assert "openai/gpt-image-1" not in chat
    assert "kuaishou/kling-video" not in chat
    assert "jina/jina-reranker-v3" not in chat
    assert "openai/text-embedding-4" not in chat
    assert "vendor/audio-tts" not in chat
    # Unknown endpoint types are not chat; structured endpoint entries still are.
    assert "vendor/system-only" not in chat
    assert "vendor/dict-endpoints" in chat


def test_multimodal_filter_fails_closed_without_declared_modality():
    models = parse_catalog({"data": CATALOG_FIXTURE})
    image = _ids(filter_models(models, capability="chat", modality="image"))
    assert "openai/gpt-5.5" in image
    assert "anthropic/claude-opus-4.8" in image
    assert "google/gemini-3.5-flash" in image
    # text-only and undeclared-modality chat models are excluded
    assert "deepseek/deepseek-v4-pro" not in image
    assert "meta/llama-text-nodecl" not in image
    assert "vendor/system-only" not in image
    assert "orcarouter/auto" not in image

    audio = _ids(filter_models(models, capability="chat", modality="audio"))
    assert audio == {"google/gemini-3.5-flash"}
    video = _ids(filter_models(models, capability="chat", modality="video"))
    assert video == {"google/gemini-3.5-flash"}


def test_capability_specific_filters():
    models = parse_catalog({"data": CATALOG_FIXTURE})
    assert _ids(filter_models(models, capability="embedding")) == {"openai/text-embedding-4"}
    assert _ids(filter_models(models, capability="image")) == {"openai/gpt-image-1"}
    assert _ids(filter_models(models, capability="video")) == {"kuaishou/kling-video"}
    assert _ids(filter_models(models, capability="rerank")) == {"jina/jina-reranker-v3"}


def test_filter_rejects_unknown_capability_and_modality():
    models = parse_catalog({"data": CATALOG_FIXTURE})
    with pytest.raises(ValueError):
        filter_models(models, capability="omniscient")
    with pytest.raises(ValueError):
        filter_models(models, capability="chat", modality="smell")
    with pytest.raises(ValueError):
        filter_models(models, capability="embedding", modality="image")


# --- live-ish catalog via local server -------------------------------------


def test_list_models_uses_get_v1_models_with_bearer(server):
    p = OrcaRouterProvider(api_key=FAKE_KEY, base_url=server)
    models = p.list_models()
    assert len(models) == len(CATALOG_FIXTURE)
    method, path, headers = _Handler.requests[-1]
    assert method == "GET"
    assert path == "/v1/models"
    assert headers.get("Authorization") == f"Bearer {FAKE_KEY}"


def test_catalog_filters_live_result_and_never_mixes_seed(server):
    p = OrcaRouterProvider(api_key=FAKE_KEY, base_url=server)
    result = p.catalog(capability="chat", modality="image")
    assert result["catalog_source"] == "live"
    assert result["degraded"] is False
    ids = {m["id"] for m in result["models"]}
    assert ids == {"openai/gpt-5.5", "anthropic/claude-opus-4.8", "google/gemini-3.5-flash"}
    # seed-only models such as deepseek/... must never be merged into live output
    assert "deepseek/deepseek-v4-pro" not in ids


def test_catalog_auth_error_degrades_to_verified_seed(server):
    _Handler.status = 401
    p = OrcaRouterProvider(api_key=FAKE_KEY, base_url=server)
    result = p.catalog(capability="chat")
    assert result["degraded"] is True
    assert result["catalog_source"] == "seed"
    assert "401" in result["error"]
    assert FAKE_KEY not in json.dumps(result)
    ids = {m["id"] for m in result["models"]}
    assert {"orcarouter/auto", "orcarouter/fusion", "openai/gpt-5.5"} <= ids
    assert "openai/gpt-image-1" not in ids


def test_catalog_network_error_degrades(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(catalog_mod.urllib.request, "urlopen", boom)
    result = OrcaRouterProvider(api_key=FAKE_KEY).catalog(capability="chat", modality="image")
    assert result["degraded"] is True
    assert "unreachable" in result["error"]
    ids = {m["id"] for m in result["models"]}
    # verified seed: only models declaring image input survive
    assert "openai/gpt-5.5" in ids
    assert "deepseek/deepseek-v4-pro" not in ids


def test_catalog_empty_catalog_degraded_state(server):
    _Handler.payload = {"data": []}
    result = OrcaRouterProvider(api_key=FAKE_KEY, base_url=server).catalog(capability="chat")
    assert result["catalog_source"] == "live"
    assert result["model_count"] == 0
    assert result["models"] == []


def test_fetch_catalog_non_json(server):
    _Handler.payload = ["not-a-dict"]
    models = fetch_catalog(server, FAKE_KEY)
    assert models == []


def test_seed_is_small_and_verified_only():
    result = OrcaRouterProvider(api_key=FAKE_KEY).catalog(discovery=False)
    ids = [m["id"] for m in result["models"]]
    assert len(ids) <= 6
    for seed in result["models"]:
        assert seed["verified"] is True
        assert seed["supported_endpoint_types"]
    gpt = next(m for m in result["models"] if m["id"] == "openai/gpt-5.5")
    assert gpt["reasoning_effort"] == ["low", "medium", "high", "xhigh"]


# --- completion path --------------------------------------------------------

def test_complete_wraps_socket_errors_without_leaking(monkeypatch):
    def truncated(*a, **k):
        raise TimeoutError("The read operation timed out")

    monkeypatch.setattr(catalog_mod.urllib.request, "urlopen", truncated)
    p = OrcaRouterProvider(api_key=FAKE_KEY)
    with pytest.raises(RuntimeError) as ei:
        p.complete([{"role": "user", "content": "x"}])
    assert "TimeoutError" in str(ei.value)
    assert FAKE_KEY not in str(ei.value)
    assert p.timeout == 60.0



def test_complete_posts_chat_completions_with_default_model(server):
    p = OrcaRouterProvider(api_key=FAKE_KEY, base_url=server)
    out = p.complete([{"role": "user", "content": "hi"}])
    assert out["content"] == "summary ok"
    assert out["model"] == "orcarouter/auto"
    method, path, headers, body = _Handler.requests[-1]
    assert method == "POST"
    assert path == "/v1/chat/completions"
    assert headers.get("Authorization") == f"Bearer {FAKE_KEY}"
    assert json.loads(body)["model"] == "orcarouter/auto"


def test_complete_explicit_cyber_model(server):
    p = OrcaRouterProvider(api_key=FAKE_KEY, base_url=server)
    p.complete([{"role": "user", "content": "scan"}], model="orcacyber-ultra-1.0")
    _, _, _, body = _Handler.requests[-1]
    assert json.loads(body)["model"] == "orcacyber-ultra-1.0"


def test_complete_error_text_is_redacted(server):
    _Handler.chat_status = 401
    _Handler.chat_response = {"error": f"invalid key {FAKE_KEY}"}
    p = OrcaRouterProvider(api_key=FAKE_KEY, base_url=server)
    with pytest.raises(RuntimeError) as ei:
        p.complete([{"role": "user", "content": "x"}])
    assert "401" in str(ei.value)
    assert FAKE_KEY not in str(ei.value)


def test_complete_without_key_raises():
    p = OrcaRouterProvider(api_key=None)
    with pytest.raises(RuntimeError):
        p.complete([{"role": "user", "content": "x"}])


# --- real live check (opt-in) ----------------------------------------------


@pytest.mark.skipif(
    not (os.environ.get("ORCAROUTER_API_KEY") or "").startswith("sk-orca-"),
    reason="ORCAROUTER_API_KEY not set",
)
def test_live_orcarouter_catalog_and_completion():
    """Real request through the implemented provider against api.orcarouter.ai."""
    key = os.environ["ORCAROUTER_API_KEY"]
    p = get_provider(mode="user_key", provider="orcarouter", api_key=key)
    assert isinstance(p, OrcaRouterProvider)

    cat = p.catalog(capability="chat")
    assert cat["catalog_source"] == "live", cat.get("error")
    assert cat["model_count"] > 0
    ids = {m["id"] for m in cat["models"]}
    # Catalog entries carry directory metadata: chat-capable for the text
    # dropdown, image input declared for the image dropdown.
    for model in cat["models"]:
        assert set(model["supported_endpoint_types"]) & catalog_mod.CHAT_ENDPOINT_TYPES
    assert not (ids & {"jina/jina-reranker-v3", "openai/gpt-image-1", "kuaishou/kling-video"})
    image_cat = p.catalog(capability="chat", modality="image")
    assert image_cat["catalog_source"] == "live", image_cat.get("error")
    for model in image_cat["models"]:
        assert "image" in model["input_modalities"]
        assert set(model["supported_endpoint_types"]) & catalog_mod.CHAT_ENDPOINT_TYPES

    # Prefer cyber tier when the verification key is unlocked; otherwise use a
    # public model this key can actually call to prove the wiring.
    model = "deepseek/deepseek-v4-flash" if "deepseek/deepseek-v4-flash" in ids else next(iter(sorted(ids)))
    out = p.complete(
        [{"role": "user", "content": "Reply with the single word: ok"}],
        model=model,
        max_tokens=16,
        timeout=120.0,
    )
    assert out["provider"] == "orcarouter"
    assert isinstance(out["content"], str)
    assert key not in json.dumps(out)
