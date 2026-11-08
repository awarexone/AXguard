"""API + GitHub-config wiring tests for OrcaRouter Cyber Inference."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from engines.api.app import create_app
from engines.api.settings import load_settings
from engines.github.config import load_github_config, resolve_ai_credentials

FAKE_KEY = "sk-orca-testfake0000000000000000000000"

CHAT = {"id": "orcarouter/auto", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]}}
IMAGE_CHAT = {
    "id": "openai/gpt-5.5",
    "supported_endpoint_types": ["openai", "openai-response"],
    "architecture": {"input_modalities": ["text", "image"]},
}
RERANK = {"id": "jina/jina-reranker-v3", "supported_endpoint_types": ["jina-rerank"]}
IMAGE_GEN = {"id": "openai/gpt-image-1", "supported_endpoint_types": ["image-generation"]}


class _Handler(BaseHTTPRequestHandler):
    payload: dict = {"data": [CHAT, IMAGE_CHAT, RERANK, IMAGE_GEN]}
    requests: list = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).requests.append((self.path, dict(self.headers)))
        raw = json.dumps(self.payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture()
def fake_catalog():
    _Handler.requests = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/v1"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(tmp_path, monkeypatch, base_url, provider="orcarouter", key=FAKE_KEY):
    data_dir = tmp_path / "api-data"
    monkeypatch.setenv("AXGUARD_API_DATA_DIR", str(data_dir))
    monkeypatch.delenv("AXGUARD_API_REQUIRE_AUTH", raising=False)
    monkeypatch.setenv("AXGUARD_AI_MODE", "user_key")
    monkeypatch.setenv("AXGUARD_AI_PROVIDER", provider)
    monkeypatch.setenv("AXGUARD_AI_MODEL", "orcarouter/auto")
    monkeypatch.setenv("AXGUARD_AI_BASE_URL", base_url or "")
    if key:
        monkeypatch.setenv("AXGUARD_AI_API_KEY", key)
    else:
        monkeypatch.delenv("AXGUARD_AI_API_KEY", raising=False)
    return TestClient(create_app(load_settings(data_dir=data_dir)))


def test_models_route_returns_filtered_live_catalog(tmp_path, monkeypatch, fake_catalog):
    with _client(tmp_path, monkeypatch, fake_catalog) as client:
        resp = client.get("/v1/models", params={"capability": "chat"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "orcarouter"
        assert body["catalog_source"] == "live"
        assert body["degraded"] is False
        ids = [m["id"] for m in body["models"]]
        assert "orcarouter/auto" in ids
        assert "jina/jina-reranker-v3" not in ids
        assert "openai/gpt-image-1" not in ids
        assert FAKE_KEY not in resp.text

        img = client.get("/v1/models", params={"capability": "chat", "modality": "image"}).json()
        assert [m["id"] for m in img["models"]] == ["openai/gpt-5.5"]

        rerank = client.get("/v1/models", params={"capability": "rerank"}).json()
        assert [m["id"] for m in rerank["models"]] == ["jina/jina-reranker-v3"]

    path, headers = _Handler.requests[-1]
    assert path == "/v1/models"
    assert headers.get("Authorization") == f"Bearer {FAKE_KEY}"


def test_models_route_validates_capability(tmp_path, monkeypatch, fake_catalog):
    with _client(tmp_path, monkeypatch, fake_catalog) as client:
        resp = client.get("/v1/models", params={"capability": "omniscient"})
        assert resp.status_code == 422
        assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_models_route_404_for_generic_provider(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, None, provider="groq", key="gsk_fake") as client:
        resp = client.get("/v1/models")
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "CATALOG_UNAVAILABLE"
        assert "gsk_" not in resp.text


def test_health_reports_named_provider_without_key(tmp_path, monkeypatch, fake_catalog):
    with _client(tmp_path, monkeypatch, fake_catalog) as client:
        provider = client.get("/v1/health").json()["provider"]
        assert provider["provider"] == "orcarouter"
        assert provider["display_name"] == "OrcaRouter Cyber Inference"
        assert provider["base_url"] == fake_catalog
        assert FAKE_KEY not in json.dumps(provider)


def test_llm_enrichment_accepts_named_orcarouter_provider(tmp_path, monkeypatch, fake_catalog):
    with _client(tmp_path, monkeypatch, fake_catalog) as client:
        target = tmp_path / "proj"
        target.mkdir()
        (target / "x.py").write_text("x = 1\n", encoding="utf-8")
        pid = client.post("/v1/projects", json={"name": "p", "path": str(target)}).json()["id"]
        resp = client.post(f"/v1/projects/{pid}/scans", json={"mode": "lite", "enrichment": "llm"})
        # Accepted (202) — the provider is a real BYOK provider, not NoneProvider.
        assert resp.status_code == 202, resp.text


def test_github_config_orcarouter_defaults(tmp_path, monkeypatch):
    cfg_path = tmp_path / ".axguard.yml"
    cfg_path.write_text("ai:\n  provider: orcarouter\n  mode: user_key\n", encoding="utf-8")
    monkeypatch.setenv("AXGUARD_AI_API_KEY", FAKE_KEY)
    monkeypatch.delenv("AXGUARD_AI_BASE_URL", raising=False)
    ai = resolve_ai_credentials(load_github_config(cfg_path))
    assert ai["provider"] == "orcarouter"
    assert ai["mode"] == "user_key"
    assert ai["base_url"] == "https://api.orcarouter.ai/v1"
    assert ai["model"] == "orcarouter/auto"


def test_github_config_orcarouter_respects_explicit_overrides(tmp_path, monkeypatch):
    cfg_path = tmp_path / ".axguard.yml"
    cfg_path.write_text(
        "ai:\n  provider: orcarouter\n  mode: user_key\n  model: orcacyber-ultra-1.0\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AXGUARD_AI_API_KEY", FAKE_KEY)
    monkeypatch.setenv("AXGUARD_AI_BASE_URL", "https://proxy.internal/v1")
    ai = resolve_ai_credentials(load_github_config(cfg_path))
    assert ai["model"] == "orcacyber-ultra-1.0"
    assert ai["base_url"] == "https://proxy.internal/v1"


def test_github_config_never_reads_literal_key_from_repo(tmp_path, monkeypatch):
    cfg_path = tmp_path / ".axguard.yml"
    cfg_path.write_text(
        "ai:\n  provider: orcarouter\n  mode: user_key\n  api_key: sk-orca-should-not-be-read\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("AXGUARD_AI_API_KEY", raising=False)
    ai = resolve_ai_credentials(load_github_config(cfg_path))
    assert ai["api_key"] is None


def test_cli_models_command(tmp_path, monkeypatch, fake_catalog, capsys):
    monkeypatch.setenv("AXGUARD_API_DATA_DIR", str(tmp_path / "api-data"))
    monkeypatch.setenv("AXGUARD_AI_MODE", "user_key")
    monkeypatch.setenv("AXGUARD_AI_PROVIDER", "orcarouter")
    monkeypatch.setenv("AXGUARD_AI_BASE_URL", fake_catalog)
    monkeypatch.setenv("AXGUARD_AI_API_KEY", FAKE_KEY)
    rc = _run_api_cli(
        ["api", "models", "--capability", "chat", "--modality", "image", "--check"]
    )
    out = capsys.readouterr().out
    assert rc == 0
    payload = json.loads(out)
    assert payload["catalog_source"] == "live"
    assert [m["id"] for m in payload["models"]] == ["openai/gpt-5.5"]
    assert FAKE_KEY not in out


def test_cli_models_check_fails_on_degraded(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AXGUARD_API_DATA_DIR", str(tmp_path / "api-data"))
    monkeypatch.setenv("AXGUARD_AI_MODE", "user_key")
    monkeypatch.setenv("AXGUARD_AI_PROVIDER", "orcarouter")
    monkeypatch.setenv("AXGUARD_AI_BASE_URL", "http://127.0.0.1:9/v1")
    monkeypatch.setenv("AXGUARD_AI_API_KEY", FAKE_KEY)
    rc = _run_api_cli(["api", "models", "--check"])
    out = capsys.readouterr().out
    assert rc == 1
    payload = json.loads(out)
    assert payload["degraded"] is True
    assert payload["catalog_source"] == "seed"
    assert FAKE_KEY not in out


def test_api_parser_exposes_models_subcommand():
    import argparse

    from engines.api.cli import add_api_parser

    parser = argparse.ArgumentParser()
    add_api_parser(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args(["api", "models", "--capability", "image"])
    assert args.command == "api"
    assert args.api_command == "models"
    assert args.capability == "image"


def _run_api_cli(argv):
    """Run ``axguard api ...`` through argparse + run_api_command.

    ``cli.main`` (whose parser this subcommand is mounted on) is imported
    lazily so on interpreters where an unrelated module in the CLI import
    chain only parses under newer Python versions the models path is still
    exercised end-to-end.
    """
    import argparse

    from engines.api.cli import add_api_parser, run_api_command

    parser = argparse.ArgumentParser(prog="axguard")
    add_api_parser(parser.add_subparsers(dest="command", required=True))
    return run_api_command(parser.parse_args(argv))
