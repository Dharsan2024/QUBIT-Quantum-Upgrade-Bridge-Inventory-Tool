"""The LLM-provider API surface: config get/patch, and the one hard guarantee that matters more
than any other endpoint in this file -- the plaintext API key must never appear in a response.

`verify` genuinely reaches the network for the external-provider branch, so those tests
monkeypatch `urllib.request.urlopen` rather than depending on a real provider being reachable.
"""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings


def _make_client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        create_schema_on_startup=True,
    )
    return TestClient(
        create_app(settings),
        headers={"Authorization": f"Bearer {settings.api_token}"},
    )


def test_config_defaults_to_ollama_with_no_key_configured(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        resp = client.get("/api/v1/llm-provider/config")
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "ollama"
        assert body["api_key_configured"] is False
        assert body["api_key_last4"] is None


def test_patch_config_saves_provider_fields_and_never_echoes_the_key(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        resp = client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
                "model": "qwen/qwen3-32b",
                "api_key": "gsk-super-secret-value",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["provider"] == "openai-compatible"
        assert body["base_url"] == "https://api.groq.com/openai/v1"
        assert body["model"] == "qwen/qwen3-32b"
        assert body["api_key_configured"] is True
        assert body["api_key_last4"] == "alue"
        # The raw key must not appear ANYWHERE in the raw response body, not just be absent from
        # a named field -- guards against it leaking into some other field by accident.
        assert "gsk-super-secret-value" not in resp.text

        again = client.get("/api/v1/llm-provider/config").json()
        assert again["provider"] == "openai-compatible"
        assert again["api_key_configured"] is True
        assert "gsk-super-secret-value" not in json.dumps(again)


def test_patch_config_omitting_api_key_keeps_the_existing_one(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={"provider": "openai-compatible", "api_key": "sk-original-key"},
        )
        resp = client.patch("/api/v1/llm-provider/config", json={"model": "new-model-id"})
        body = resp.json()
        assert body["model"] == "new-model-id"
        assert body["api_key_configured"] is True
        assert body["api_key_last4"] == "-key"


def test_patch_config_empty_string_clears_the_key(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={"provider": "openai-compatible", "api_key": "sk-to-be-cleared"},
        )
        resp = client.patch("/api/v1/llm-provider/config", json={"api_key": ""})
        body = resp.json()
        assert body["api_key_configured"] is False
        assert body["api_key_last4"] is None


def test_switching_back_to_ollama_does_not_probe_the_external_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`base_url` is the EXTERNAL endpoint and is deliberately kept when a user switches back to
    Local, so their settings survive the round trip. Reading it on the Ollama path made QUBIT probe
    the external URL as an Ollama server -- measured live, provider=ollama with a leftover Groq
    base_url reported "Ollama not reachable at https://api.groq.com/openai/v1" while Ollama was
    running fine on localhost.
    """
    probed: list[str] = []

    def fake_installed_models(base_url: str) -> list[str]:
        probed.append(base_url)
        return ["qwen2.5-coder:7b-instruct-q4_K_M"]

    monkeypatch.setattr("qubit_api.routers.llm_provider.installed_models", fake_installed_models)
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
                "api_key": "gsk-test",
            },
        )
        client.patch("/api/v1/llm-provider/config", json={"provider": "ollama"})

        assert client.post("/api/v1/llm-provider/verify").json()["ok"] is True
        assert client.get("/api/v1/llm-provider/models").json()["models"] != []

    assert probed, "the ollama path must actually probe something"
    assert all("groq" not in url for url in probed), f"probed the external URL: {probed}"
    assert all("11434" in url for url in probed), f"expected the local Ollama port: {probed}"


def test_ollama_verify_checks_the_model_generation_will_actually_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`LlmProviderConfig.model` names the EXTERNAL model and survives a switch back to Local, so
    checking it made verify report "Ollama is reachable, but 'openai/gpt-oss-120b' is not pulled"
    for a healthy local setup -- naming a model Ollama was never going to be asked for. The local
    path must check `MigrateConfig.model`, which is what generation really uses.
    """
    from qubit_migrate.config import MigrateConfig

    local_model = MigrateConfig().model
    monkeypatch.setattr(
        "qubit_api.routers.llm_provider.installed_models", lambda _base: [local_model]
    )
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
                "model": "openai/gpt-oss-120b",
                "api_key": "gsk-test",
            },
        )
        client.patch("/api/v1/llm-provider/config", json={"provider": "ollama"})

        body = client.post("/api/v1/llm-provider/verify").json()

    assert body["ok"] is True, f"local Ollama with its own model pulled must verify: {body}"
    assert "gpt-oss-120b" not in body["detail"]


def test_verify_reports_a_valid_key_with_no_quota_distinctly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured on a real Cerebras key: `GET /models` answers 200 with a full catalogue, then
    `/chat/completions` answers 402 "Payment required to access this resource". An earlier version
    of verify only read the catalogue, so it reported OK and every migration then failed. Verify
    must exercise GENERATION, and must not report "key rejected" for a key that is perfectly valid.
    """

    def fake_urlopen(req, timeout: float):
        raise urllib.error.HTTPError(
            req.full_url,
            402,
            "Payment Required",
            None,
            io.BytesIO(b'{"message":"Payment required to access this resource."}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.cerebras.ai/v1",
                "model": "gpt-oss-120b",
                "api_key": "csk-test",
            },
        )
        body = client.post("/api/v1/llm-provider/verify").json()

    assert body["ok"] is False
    assert "quota" in body["detail"].lower()
    assert "rejected" not in body["detail"].lower(), "a valid key must not be called rejected"


def test_verify_reports_both_ends_of_the_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backup exists because the primary WILL refuse requests once its allowance is spent, so
    whether the backup is actually reachable is worth knowing before that happens, not after.
    """

    def fake_urlopen(req, timeout: float):
        if "cerebras" in req.full_url:
            raise urllib.error.HTTPError(
                req.full_url, 402, "Payment Required", None, io.BytesIO(b"")
            )

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def read(self):
                return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode("utf-8")

        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
                "model": "openai/gpt-oss-120b",
                "api_key": "gsk-test",
                "backup_base_url": "https://api.cerebras.ai/v1",
                "backup_model": "gpt-oss-120b",
                "backup_api_key": "csk-test",
            },
        )
        body = client.post("/api/v1/llm-provider/verify").json()

    # One working endpoint is a usable chain.
    assert body["ok"] is True
    assert "primary OK" in body["detail"]
    assert "backup FAILED" in body["detail"]


def test_backup_key_is_encrypted_and_never_echoed(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        resp = client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "backup_base_url": "https://api.cerebras.ai/v1",
                "backup_model": "gpt-oss-120b",
                "backup_api_key": "csk-backup-secret-value",
            },
        )
        assert "csk-backup-secret-value" not in resp.text
        body = resp.json()
        assert body["backup_api_key_configured"] is True
        assert body["backup_api_key_last4"] == "alue"


def test_verify_external_without_key_reports_not_ok_without_a_network_call(
    tmp_path: Path,
) -> None:
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={"provider": "openai-compatible", "base_url": "https://api.example.com/v1"},
        )
        resp = client.post("/api/v1/llm-provider/verify")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "key" in body["detail"].lower()


def test_verify_external_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(req, timeout: float):
        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def read(self):
                return json.dumps({"data": []}).encode("utf-8")

        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
                "model": "openai/gpt-oss-120b",
                "api_key": "gsk-test",
            },
        )
        resp = client.post("/api/v1/llm-provider/verify")
        body = resp.json()
        assert body["ok"] is True


def test_models_lists_what_the_external_provider_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_urlopen(req, timeout: float):
        assert req.full_url.endswith("/models")

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def read(self):
                return json.dumps(
                    {"data": [{"id": "qwen/qwen3-32b"}, {"id": "llama-3.1-8b-instant"}]}
                ).encode("utf-8")

        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
                "api_key": "gsk-test",
            },
        )
        body = client.get("/api/v1/llm-provider/models").json()
        assert body["error"] == ""
        assert body["models"] == ["llama-3.1-8b-instant", "qwen/qwen3-32b"]


def test_models_reports_why_it_could_not_read_the_list(tmp_path: Path) -> None:
    # No key saved yet -- must say so rather than returning a silently-empty dropdown.
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={"provider": "openai-compatible", "base_url": "https://api.example.com/v1"},
        )
        body = client.get("/api/v1/llm-provider/models").json()
        assert body["models"] == []
        assert body["error"] != ""


def test_verify_external_reports_rejected_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_urlopen(req, timeout: float):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None, io.BytesIO(b""))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with _make_client(tmp_path) as client:
        client.patch(
            "/api/v1/llm-provider/config",
            json={
                "provider": "openai-compatible",
                "base_url": "https://api.groq.com/openai/v1",
                "model": "openai/gpt-oss-120b",
                "api_key": "gsk-bad",
            },
        )
        resp = client.post("/api/v1/llm-provider/verify")
        body = resp.json()
        assert body["ok"] is False
        assert "rejected" in body["detail"].lower()
