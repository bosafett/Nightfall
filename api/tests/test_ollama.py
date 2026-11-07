"""Local AI provider (Ollama): config limits and response handling. No model is contacted."""

import json

import httpx
import pytest

from nightfall.agents.providers import (
    GenerationRequest,
    OllamaProvider,
    ProviderError,
    ProviderUnavailable,
    get_provider,
)
from nightfall.agents.registry import AnalystOutput
from nightfall.config import ConfigError, get_settings, load_settings


def _ollama_env(monkeypatch: pytest.MonkeyPatch, url: str | None = None) -> None:
    monkeypatch.setenv("NIGHTFALL_AI_PROVIDER", "ollama")
    monkeypatch.setenv("NIGHTFALL_AI_MODEL", "qwen3:14b")
    monkeypatch.setenv("NIGHTFALL_COLLECTOR_MODE", "live")
    if url is not None:
        monkeypatch.setenv("NIGHTFALL_OLLAMA_URL", url)


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1:11434", "http://10.0.0.5:11434/", "http://ollama:11434", "http://localhost"],
)
def test_local_endpoints_are_accepted(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    _ollama_env(monkeypatch, url)
    s = load_settings()
    assert s.ai_provider == "ollama" and s.ollama_url == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.com",
        "http://8.8.8.8:11434",
        "http://ollama.example.com",
        "ftp://127.0.0.1",
        "http://127.0.0.1:11434/v1",
    ],
)
def test_remote_or_odd_endpoints_are_refused(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    _ollama_env(monkeypatch, url)
    with pytest.raises(ConfigError, match="NIGHTFALL_OLLAMA_URL"):
        load_settings()


def test_ollama_needs_a_model_and_a_self_hosted_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    _ollama_env(monkeypatch)
    monkeypatch.delenv("NIGHTFALL_AI_MODEL")
    with pytest.raises(ConfigError, match="NIGHTFALL_AI_MODEL"):
        load_settings()
    _ollama_env(monkeypatch)
    monkeypatch.setenv("NIGHTFALL_ON_DEMAND_WORKER", "true")
    monkeypatch.setenv("NIGHTFALL_WORKER_DATABASE_URL", "postgresql://w@localhost/db")
    with pytest.raises(ConfigError, match="self-hosted"):
        load_settings()


def test_get_provider_builds_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    _ollama_env(monkeypatch)
    get_settings.cache_clear()
    try:
        p = get_provider()
        assert isinstance(p, OllamaProvider) and p.model == "qwen3:14b"
    finally:
        get_settings.cache_clear()


def _provider(handler) -> tuple[OllamaProvider, list[dict]]:  # type: ignore[no-untyped-def]
    sent: list[dict] = []

    def record(req: httpx.Request) -> httpx.Response:
        sent.append(json.loads(req.content))
        return handler(req)

    p = OllamaProvider(model="qwen3:14b", url="http://127.0.0.1:11434")
    p.client = httpx.Client(
        base_url="http://127.0.0.1:11434", transport=httpx.MockTransport(record)
    )
    return p, sent


REQ = GenerationRequest(system="sys", user="usr", output_model=AnalystOutput, max_tokens=500)


def test_valid_answer_is_parsed_and_the_schema_is_sent() -> None:
    answer = {"summary": "Early.", "key_risks": [], "next_steps": ["Review."]}
    p, sent = _provider(
        lambda r: httpx.Response(
            200,
            json={
                "model": "qwen3:14b",
                "message": {"role": "assistant", "content": json.dumps(answer)},
                "done_reason": "stop",
                "prompt_eval_count": 12,
                "eval_count": 34,
            },
        )
    )
    res = p.generate(REQ)
    assert res.parsed.summary == "Early." and res.provider == "ollama"
    assert (res.input_tokens, res.output_tokens) == (12, 34)
    body = sent[0]
    assert body["stream"] is False and body["format"] == AnalystOutput.model_json_schema()
    assert body["options"] == {"temperature": 0, "num_predict": 500}
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (httpx.Response(404, json={"error": "model not found"}), ProviderUnavailable, "model"),
        (httpx.Response(500), ProviderError, "500"),
        (httpx.Response(200, text="not json"), ProviderError, "unreadable"),
        (
            httpx.Response(200, json={"message": {"content": '{"summary": 1}'}}),
            ProviderError,
            "required format",
        ),
        (
            httpx.Response(200, json={"message": {"content": "{}"}, "done_reason": "length"}),
            ProviderError,
            "cut off",
        ),
    ],
)
def test_bad_answers_are_rejected(response, error, message) -> None:  # type: ignore[no-untyped-def]
    p, _ = _provider(lambda r: response)
    with pytest.raises(error, match=message):
        p.generate(REQ)


def test_unreachable_server_is_reported() -> None:
    def down(r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    p, _ = _provider(down)
    with pytest.raises(ProviderUnavailable, match="couldn't be reached"):
        p.generate(REQ)
