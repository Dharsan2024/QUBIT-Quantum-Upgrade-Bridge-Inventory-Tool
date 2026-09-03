"""The provider dispatcher (`_generate`) added for the pluggable external-LLM design.

`provider="ollama"` (the default) must remain byte-identical to calling `_ollama_generate`
directly -- every other test file in this suite mocks that name and must keep passing unmodified.
`provider="openai-compatible"` must call the external endpoint and, ONLY on a connection/auth
failure, fall back to Ollama -- never on a successful external response.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest
from qubit_migrate.transform import llm
from qubit_migrate.transform.llm import OllamaError, _generate, _openai_compatible_generate


def test_generate_default_provider_calls_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_ollama(prompt: str, **kwargs: object) -> str:
        calls.append("ollama")
        return "ok"

    def boom_external(*args: object, **kwargs: object) -> str:
        calls.append("external")
        raise AssertionError("external provider must not be called for provider='ollama'")

    monkeypatch.setattr(llm, "_ollama_generate", fake_ollama)
    monkeypatch.setattr(llm, "_openai_compatible_generate", boom_external)

    result = _generate("prompt", model="qwen2.5-coder:7b-instruct-q4_K_M")

    assert result == "ok"
    assert calls == ["ollama"]


def test_generate_external_provider_success_does_not_touch_ollama(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_external(prompt: str, **kwargs: object) -> str:
        calls.append("external")
        return "external answer"

    def boom_ollama(*args: object, **kwargs: object) -> str:
        calls.append("ollama")
        raise AssertionError("ollama must not be called when the external call succeeds")

    monkeypatch.setattr(llm, "_openai_compatible_generate", fake_external)
    monkeypatch.setattr(llm, "_ollama_generate", boom_ollama)

    result = _generate(
        "prompt",
        model="gpt-4o-mini",
        base_url="https://api.example.com/v1",
        provider="openai-compatible",
        api_key="sk-test",
    )

    assert result == "external answer"
    assert calls == ["external"]


def test_generate_falls_back_to_ollama_when_external_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom_external(*args: object, **kwargs: object) -> str:
        raise OllamaError("external LLM provider is not reachable")

    fallback_calls: dict[str, object] = {}

    def fake_ollama(prompt: str, *, model: str, base_url: str, timeout: float, source: str) -> str:
        fallback_calls.update(model=model, base_url=base_url)
        return "local answer"

    monkeypatch.setattr(llm, "_openai_compatible_generate", boom_external)
    monkeypatch.setattr(llm, "_ollama_generate", fake_ollama)

    fallback_fired: list[str] = []
    result = _generate(
        "prompt",
        model="gpt-4o-mini",
        base_url="https://api.example.com/v1",
        provider="openai-compatible",
        api_key="sk-test",
        fallback_ollama_model="qwen2.5-coder:7b-instruct-q4_K_M",
        on_fallback=fallback_fired.append,
    )

    assert result == "local answer"
    # The callback carries the engine that ACTUALLY ran, so the patch and the reliability record
    # are attributed to it rather than to the provider that was merely configured.
    assert fallback_fired == ["qwen2.5-coder:7b-instruct-q4_K_M"]
    # The fallback runs against the LOCAL model, not the external one's model/base_url.
    assert fallback_calls["model"] == "qwen2.5-coder:7b-instruct-q4_K_M"
    assert fallback_calls["base_url"] == llm.DEFAULT_BASE_URL


def test_generate_external_provider_requires_api_key() -> None:
    with pytest.raises(OllamaError, match="no API key"):
        _generate(
            "prompt",
            model="gpt-4o-mini",
            base_url="https://api.example.com/v1",
            provider="openai-compatible",
            api_key=None,
        )


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def test_openai_compatible_generate_posts_chat_completions_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(req, timeout: float):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data)
        return _FakeResponse({"choices": [{"message": {"content": "the rewritten file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = _openai_compatible_generate(
        "migrate this file",
        model="qwen/qwen3-32b",
        base_url="https://api.groq.com/openai/v1",
        api_key="gsk-test",
    )

    assert result == "the rewritten file"
    assert captured["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer gsk-test"
    assert captured["body"]["model"] == "qwen/qwen3-32b"
    assert captured["body"]["messages"] == [{"role": "user", "content": "migrate this file"}]


def test_openai_compatible_generate_reports_bad_key_distinctly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(req, timeout: float):
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", None, io.BytesIO(b'{"error": "invalid api key"}')
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(OllamaError, match="rejected the API key"):
        _openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="bad-key"
        )


def test_openai_compatible_generate_reports_rate_limit_distinctly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(req, timeout: float):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", None, io.BytesIO(b""))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(OllamaError, match="rate-limited"):
        _openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
        )


def test_openai_compatible_generate_sets_a_real_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Groq answers the stdlib default `Python-urllib/3.12` with 403 and `curl` with 200 on the
    SAME valid key -- so an unset User-Agent looks exactly like a rejected key. Measured, not
    precautionary; this pins the header so the regression cannot come back silently.
    """
    seen: dict[str, str] = {}

    def fake_urlopen(req, timeout: float):
        seen.update(dict(req.header_items()))
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    _openai_compatible_generate(
        "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
    )
    # urllib title-cases header names when it stores them.
    agent = seen.get("User-agent") or seen.get("User-Agent") or ""
    assert agent.startswith("qubit-migrate/")
    assert "urllib" not in agent


def test_reasoning_effort_is_dropped_and_retried_when_a_model_rejects_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measured against Groq's own catalogue on one account: gpt-oss-120b/20b and qwen3.8 accept
    `reasoning_effort: "low"`, while qwen3.6-27b answers 400 ("must be one of `none` or `default`")
    and groq/compound answers 400 ("not supported with this model"). Hardcoding the field made
    those models unusable; dropping it and retrying once makes every model in a provider's live
    list selectable, while keeping reasoning suppressed wherever it IS supported.
    """
    bodies: list[dict[str, object]] = []

    def fake_urlopen(req, timeout: float):
        body = json.loads(req.data)
        bodies.append(body)
        if "reasoning_effort" in body:
            raise urllib.error.HTTPError(
                req.full_url,
                400,
                "Bad Request",
                None,
                io.BytesIO(
                    b'{"error":{"message":"`reasoning_effort` is not supported with this model"}}'
                ),
            )
        return _FakeResponse({"choices": [{"message": {"content": "the rewritten file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = _openai_compatible_generate(
        "prompt", model="groq/compound", base_url="https://api.example.com/v1", api_key="k"
    )

    assert result == "the rewritten file"
    assert len(bodies) == 2, "should send once with the field, then retry once without it"
    assert "reasoning_effort" in bodies[0]
    assert "reasoning_effort" not in bodies[1]


def test_max_tokens_is_sent_and_scales_with_the_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured, not theoretical: with no `max_tokens`, gpt-oss-120b answered a 913-line file with
    44 non-blank lines and the repair loop burned all three attempts on a truncation the model was
    never given room to avoid. A provider's DEFAULT answer length is not its maximum.
    """
    seen: list[dict[str, object]] = []

    def fake_urlopen(req, timeout: float):
        seen.append(json.loads(req.data))
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    small = "x = 1\n"
    big = "".join(f"line_{i} = {i}\n" for i in range(4000))
    for src in (small, big):
        _openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="k", source=src
        )

    assert all("max_tokens" in b for b in seen), "max_tokens must always be sent"
    budgets = [int(b["max_tokens"]) for b in seen]  # type: ignore[call-overload]
    assert budgets[1] > budgets[0], "the budget must scale with the file"
    assert budgets[1] <= llm._MAX_EXTERNAL_TOKENS


def test_max_tokens_never_exceeds_the_providers_request_allowance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A model's CONTEXT WINDOW is not what one request may use. Measured against Groq's free tier:
    gpt-oss-120b advertises 131,072 tokens of context while the tier caps a single request at 8,000
    tokens/minute and answers HTTP 413 above it ("Limit 8000, Requested 38840"). Sizing `max_tokens`
    from the window meant the request was refused before any generation happened, and every such
    finding scored as a rejection.
    """
    seen: list[dict[str, object]] = []

    def fake_urlopen(req, timeout: float):
        seen.append(json.loads(req.data))
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    allowance = 8000
    source = "".join(f"line_{i} = {i}\n" for i in range(600))
    prompt = f"instructions\n```python\n{source}```"

    _openai_compatible_generate(
        prompt,
        model="m",
        base_url="https://api.example.com/v1",
        api_key="k",
        source=source,
        budget_tokens=allowance,
    )

    body = seen[-1]
    prompt_tokens = len(prompt) // 3
    total = prompt_tokens + int(body["max_tokens"])  # type: ignore[call-overload]
    assert total <= allowance, (
        f"prompt ({prompt_tokens}) + max_tokens ({body['max_tokens']}) = {total} "
        f"exceeds the provider's {allowance}-token allowance"
    )


def test_an_empty_answer_walks_the_reasoning_ladder(monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured on `gemini-3.6-flash`: `reasoning_effort: "low"` returns HTTP **200** with
    `content: None` and `completion_tokens: 0` -- the reasoning consumed the entire budget --
    while `"minimal"` on the identical request answers correctly, and `"none"` is rejected with
    400. No status code distinguishes the first case, so the empty body is the only signal there
    is, and a fixed value cannot serve both this and Groq's gpt-oss (which wants `"low"`).
    """
    efforts: list[object] = []

    def fake_urlopen(req, timeout: float):
        body = json.loads(req.data)
        efforts.append(body.get("reasoning_effort", "<absent>"))
        if body.get("reasoning_effort") == "low":
            return _FakeResponse(
                {"choices": [{"message": {"content": None}, "finish_reason": "length"}]}
            )
        return _FakeResponse({"choices": [{"message": {"content": "the rewritten file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = _openai_compatible_generate(
        "prompt", model="gemini-3.6-flash", base_url="https://api.example.com/v1", api_key="k"
    )

    assert result == "the rewritten file"
    assert efforts[0] == "low", "the first rung must still suit gpt-oss, which wants 'low'"
    assert efforts[1] == "minimal", "an empty answer must advance the ladder, not give up"


def test_the_reasoning_ladder_is_bounded_and_reports_honestly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If every rung returns nothing, say so — including the likely reason — rather than looping."""
    calls: list[object] = []

    def fake_urlopen(req, timeout: float):
        calls.append(json.loads(req.data).get("reasoning_effort", "<absent>"))
        return _FakeResponse({"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(OllamaError, match="empty response"):
        _openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
        )

    assert calls == ["low", "minimal", "<absent>"], f"ladder must be walked exactly once: {calls}"


def test_the_working_reasoning_rung_is_remembered_per_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Walking the ladder once per CALL multiplies requests against the scarcest resource there is.

    Generating one patch already costs up to seven model calls, doubled by the orchestrator's
    feedback retry — and requests, not tokens, are what free tiers ration: `gemini-3.6-flash`
    allows **20 per day** (`GenerateRequestsPerDayPerProjectPerModel-FreeTier`, quotaValue 20).
    Re-discovering the setting each time could exhaust a day's quota on one task.
    """
    llm._REASONING_CHOICE.clear()
    efforts: list[object] = []

    def fake_urlopen(req, timeout: float):
        body = json.loads(req.data)
        efforts.append(body.get("reasoning_effort", "<absent>"))
        if body.get("reasoning_effort") == "low":
            return _FakeResponse({"choices": [{"message": {"content": None}}]})
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    kwargs = {
        "model": "gemini-3.6-flash",
        "base_url": "https://api.example.com/v1",
        "api_key": "k",
    }
    _openai_compatible_generate("prompt", **kwargs)  # type: ignore[arg-type]
    _openai_compatible_generate("prompt", **kwargs)  # type: ignore[arg-type]
    _openai_compatible_generate("prompt", **kwargs)  # type: ignore[arg-type]

    # First call walks low -> minimal (2 requests); the next two start at minimal (1 each).
    assert efforts == ["low", "minimal", "minimal", "minimal"], efforts
    llm._REASONING_CHOICE.clear()


def test_a_prompt_that_eats_the_whole_allowance_fails_before_the_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse rather than send a request that cannot succeed. Otherwise the provider answers 413,
    or truncates the answer to a handful of tokens which the repair loop then spends its whole
    three-attempt budget arguing with — and the model was never at fault.
    """
    called: list[int] = []
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **k: called.append(1),  # type: ignore[misc]
    )

    huge_prompt = "x" * 40_000  # ~13,300 tokens against an 8,000 allowance

    with pytest.raises(OllamaError, match="per-request allowance"):
        _openai_compatible_generate(
            huge_prompt,
            model="m",
            base_url="https://api.example.com/v1",
            api_key="k",
            budget_tokens=8000,
        )
    assert not called, "no HTTP request should be made for a prompt that cannot fit"


def test_an_unsupported_max_tokens_is_dropped_and_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drop-and-retry is per-field, not hardcoded to `reasoning_effort`: a provider that
    rejects `max_tokens` must still be usable, just at its own default length.
    """
    bodies: list[dict[str, object]] = []

    def fake_urlopen(req, timeout: float):
        body = json.loads(req.data)
        bodies.append(body)
        if "max_tokens" in body:
            raise urllib.error.HTTPError(
                req.full_url,
                400,
                "Bad Request",
                None,
                io.BytesIO(b'{"error":{"message":"`max_tokens` is not supported"}}'),
            )
        return _FakeResponse({"choices": [{"message": {"content": "the file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert (
        _openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
        )
        == "the file"
    )
    assert "max_tokens" not in bodies[-1]
    # `reasoning_effort` was never the problem, so it must survive.
    assert "reasoning_effort" in bodies[-1]


def test_a_400_unrelated_to_reasoning_effort_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retry is narrow on purpose: a 400 about anything else is a real error, and silently
    re-sending it would turn one bad request into two and report the second one's message.
    """
    calls: list[int] = []

    def fake_urlopen(req, timeout: float):
        calls.append(1)
        raise urllib.error.HTTPError(
            req.full_url,
            400,
            "Bad Request",
            None,
            io.BytesIO(b'{"error":{"message":"model `nope` does not exist"}}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    with pytest.raises(OllamaError, match="HTTP 400"):
        _openai_compatible_generate(
            "prompt", model="nope", base_url="https://api.example.com/v1", api_key="k"
        )
    assert len(calls) == 1, "a 400 that is not about reasoning_effort must not be retried"


def test_a_dead_local_model_escalates_to_the_backup(monkeypatch: pytest.MonkeyPatch) -> None:
    """The chain runs BOTH ways.

    Routing sends a finding to the local model when it has proven it can do that work and costs
    nothing -- but "free" is not "always running". With Ollama stopped, every locally-routed
    finding failed even though a working external engine was configured and idle. Spending one
    request beats failing the finding.
    """

    def dead_ollama(*_a: object, **_k: object) -> str:
        raise OllamaError("Ollama is not reachable at http://127.0.0.1:11434")

    def external(prompt: str, **kwargs: object) -> str:
        return "external answer"

    monkeypatch.setattr(llm, "_ollama_generate", dead_ollama)
    monkeypatch.setattr(llm, "_openai_compatible_generate", external)

    ran: list[str] = []
    result = _generate(
        "prompt",
        model="qwen2.5-coder:7b-instruct-q4_K_M",
        provider="ollama",
        backup=llm.ExternalEndpoint(
            base_url="https://api.groq.com/openai/v1",
            model="openai/gpt-oss-120b",
            api_key="k",
            budget_tokens=8000,
        ),
        on_fallback=ran.append,
    )

    assert result == "external answer"
    assert ran == ["openai-compatible:openai/gpt-oss-120b"], (
        "the patch must be attributed to the engine that actually ran"
    )


def test_a_dead_local_model_with_no_backup_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """An install with no keys must behave exactly as it always has -- and every existing test
    that mocks `_ollama_generate` into raising depends on that.
    """

    def dead_ollama(*_a: object, **_k: object) -> str:
        raise OllamaError("Ollama is not reachable")

    monkeypatch.setattr(llm, "_ollama_generate", dead_ollama)

    with pytest.raises(OllamaError, match="not reachable"):
        _generate("prompt", model="qwen2.5-coder:7b-instruct-q4_K_M", provider="ollama")


# The exact bodies the real providers returned when sent `chat_template_kwargs`, so these tests
# fail if the matching ever stops covering what production actually says.
_GROQ_400 = (
    b"""{"error":{"message":"property 'chat_template_kwargs' is unsupported","""
    b""""type":"invalid_request_error"}}"""
)
_MISTRAL_422 = (
    b"""{"object":"error","message":{"detail":[{"type":"extra_forbidden","""
    b""""loc":["body","chat_template_kwargs"],"msg":"Extra inputs are not permitted","""
    b""""input":{"thinking":false,"enable_thinking":false}}]},"""
    b""""type":"invalid_request_error","param":null,"code":null,"raw_status_code":422}"""
)


def test_chat_template_kwargs_turns_thinking_off_in_both_spellings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`reasoning_effort` alone does not reach every model that reasons.

    It is an API-level field the PROVIDER interprets, while `chat_template_kwargs` is handed to the
    model's own chat template -- which is where NVIDIA- and vLLM-hosted models actually take the
    switch. Measured on NVIDIA's endpoint, with both models answering correctly either way:
    `nemotron-3-ultra-550b` fell from 660 completion tokens to 98, and `deepseek-v4-pro` from 81.3s
    to 43.3s. Both spellings are sent because the providers disagree on the name -- NVIDIA's own
    examples use `thinking`, vLLM's Qwen templates use `enable_thinking` -- and a template that
    knows only one of them ignores the other.
    """
    llm._TEMPLATE_KWARGS_REFUSED.clear()
    bodies: list[dict[str, object]] = []

    def fake_urlopen(req, timeout: float):
        bodies.append(json.loads(req.data))
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    _openai_compatible_generate(
        "prompt",
        model="nvidia/nemotron-3-ultra-550b-a55b",
        base_url="https://integrate.example.com/v1",
        api_key="k",
    )

    assert bodies[0]["chat_template_kwargs"] == {"thinking": False, "enable_thinking": False}
    llm._TEMPLATE_KWARGS_REFUSED.clear()


@pytest.mark.parametrize(
    ("status", "body"),
    [(400, _GROQ_400), (422, _MISTRAL_422)],
    ids=["groq-400", "mistral-422"],
)
def test_a_refused_chat_template_kwargs_is_dropped_and_retried(
    monkeypatch: pytest.MonkeyPatch, status: int, body: bytes
) -> None:
    """The field is a vLLM/NIM extension rather than part of the OpenAI schema, so strict providers
    refuse it -- and they do not agree on how. Groq answers **400** *"property
    'chat_template_kwargs' is unsupported"*; Mistral's `codestral-2508` answers **422** with a
    pydantic `extra_forbidden` body. Treating only 400 as droppable would have propagated that 422
    as a hard failure and taken the pool's fastest engine (1.0s median, measured) out of service
    over a field it never needed.
    """
    llm._TEMPLATE_KWARGS_REFUSED.clear()
    sent: list[dict[str, object]] = []

    def fake_urlopen(req, timeout: float):
        payload = json.loads(req.data)
        sent.append(payload)
        if "chat_template_kwargs" in payload:
            raise urllib.error.HTTPError(req.full_url, status, "rejected", None, io.BytesIO(body))
        return _FakeResponse({"choices": [{"message": {"content": "the rewritten file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = _openai_compatible_generate(
        "prompt", model="codestral-2508", base_url="https://api.example.com/v1", api_key="k"
    )

    assert result == "the rewritten file"
    assert len(sent) == 2, "once with the field, then once without"
    assert "chat_template_kwargs" in sent[0]
    assert "chat_template_kwargs" not in sent[1]
    llm._TEMPLATE_KWARGS_REFUSED.clear()


def test_a_refused_chat_template_kwargs_is_not_offered_to_that_engine_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejection is cheap in tokens and expensive in the thing that actually runs out.

    Groq rations 1,000 requests per DAY, and a 400 spends one of them without generating anything.
    Rediscovering the same refusal on every call -- up to seven per patch, doubled by the
    orchestrator's feedback retry -- would burn quota purely on re-asking a settled question.
    """
    llm._TEMPLATE_KWARGS_REFUSED.clear()
    offered: list[bool] = []

    def fake_urlopen(req, timeout: float):
        payload = json.loads(req.data)
        offered.append("chat_template_kwargs" in payload)
        if "chat_template_kwargs" in payload:
            raise urllib.error.HTTPError(
                req.full_url, 400, "Bad Request", None, io.BytesIO(_GROQ_400)
            )
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    kwargs = {
        "model": "openai/gpt-oss-120b",
        "base_url": "https://api.groq.example/v1",
        "api_key": "k",
    }
    for _ in range(3):
        _openai_compatible_generate("prompt", **kwargs)  # type: ignore[arg-type]

    # The first call learns the refusal (2 requests); the next two never offer it again.
    assert offered == [True, False, False, False], offered
    llm._TEMPLATE_KWARGS_REFUSED.clear()


def test_an_ambiguous_thinking_rejection_drops_the_non_standard_field_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two fields in the payload now suppress reasoning, and a 400 that says only "thinking" could
    mean either of them. One has to be picked, so `_TUNING_FIELDS` puts the non-standard one first:
    it is the likelier culprit, and a wrong guess costs a further round trip rather than the call.
    """
    llm._TEMPLATE_KWARGS_REFUSED.clear()
    sent: list[dict[str, object]] = []
    refusal = b"""{"error":{"message":"chat template kwarg 'thinking' is not permitted"}}"""

    def fake_urlopen(req, timeout: float):
        payload = json.loads(req.data)
        sent.append(payload)
        if "chat_template_kwargs" in payload:
            raise urllib.error.HTTPError(
                req.full_url, 400, "Bad Request", None, io.BytesIO(refusal)
            )
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    _openai_compatible_generate(
        "prompt", model="some/model", base_url="https://api.example.com/v1", api_key="k"
    )

    assert len(sent) == 2, "the ambiguous wording should resolve in one retry, not two"
    assert "reasoning_effort" in sent[1], "the API-level field should have survived"
    llm._TEMPLATE_KWARGS_REFUSED.clear()


def test_googles_thinking_level_wording_still_drops_reasoning_effort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regression guard for the alias lists.

    Google's `gemma-4-31b-it` rejects `reasoning_effort` with *"Thinking level is not supported for
    this model."* -- a 400 that never contains the field name. Adding a bare "thinking" alias to
    `chat_template_kwargs` would look harmless and would make this common case cost an extra
    request every time, so the new entry is kept to literal spellings.
    """
    llm._TEMPLATE_KWARGS_REFUSED.clear()
    sent: list[dict[str, object]] = []

    def fake_urlopen(req, timeout: float):
        payload = json.loads(req.data)
        sent.append(payload)
        if "reasoning_effort" in payload:
            raise urllib.error.HTTPError(
                req.full_url,
                400,
                "Bad Request",
                None,
                io.BytesIO(
                    b"""{"error":{"message":"Thinking level is not supported for this model."}}"""
                ),
            )
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    _openai_compatible_generate(
        "prompt", model="gemma-4-31b-it", base_url="https://api.example.com/v1", api_key="k"
    )

    assert len(sent) == 2, "the named field should be dropped on the first retry"
    assert "chat_template_kwargs" in sent[1], "only the field Google named should have gone"
    llm._TEMPLATE_KWARGS_REFUSED.clear()


def test_generation_walks_the_whole_ranked_pool_before_giving_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One spare was never the shape of the problem: hosted engines fail INDEPENDENTLY.

    Measured on NVIDIA's `poolside/laguna-xs-2.1` -- ~2s when it answers, and 503
    "ResourceExhausted: Worker local total request limit reached" on 3 of 4 attempts. An engine
    that fast and that flaky is only worth attaching if the next one picks the work up; with a
    single backup, two unlucky engines in a row still failed the finding.
    """
    from qubit_migrate.transform.llm import ExternalEndpoint, _generate

    tried: list[str] = []

    def fake_urlopen(req, timeout: float):
        body = json.loads(req.data)
        tried.append(body["model"])
        if body["model"] != "third":
            raise urllib.error.HTTPError(
                req.full_url,
                503,
                "Service Unavailable",
                None,
                io.BytesIO(b'{"error":{"message":"ResourceExhausted"}}'),
            )
        return _FakeResponse({"choices": [{"message": {"content": "the rewritten file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    ran: list[str] = []

    result = _generate(
        "prompt",
        model="first",
        base_url="https://one.example/v1",
        api_key="k1",
        provider="openai-compatible",
        backup=ExternalEndpoint(base_url="https://two.example/v1", model="second", api_key="k2"),
        backups=(
            ExternalEndpoint(base_url="https://three.example/v1", model="third", api_key="k3"),
        ),
        on_fallback=ran.append,
    )

    assert result == "the rewritten file"
    assert tried == ["first", "second", "third"], "the pool is walked in its ranked order"
    assert ran == ["openai-compatible:third"], "the patch is attributed to the engine that ran"


def test_the_same_endpoint_is_not_tried_twice_because_it_appears_twice_in_the_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two pool rows can carry the same model under different keys -- that is the point of pooling,
    since separate keys are separate quotas. But a duplicate of the endpoint ALREADY in the chain
    buys nothing and still spends a request against a tier that rations requests.
    """
    from qubit_migrate.transform.llm import ExternalEndpoint, _generate

    tried: list[str] = []

    def fake_urlopen(req, timeout: float):
        tried.append(req.full_url)
        raise urllib.error.HTTPError(
            req.full_url, 503, "Service Unavailable", None, io.BytesIO(b"{}")
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr(
        "qubit_migrate.transform.llm._ollama_generate",
        lambda *a, **k: "local answer",
    )

    result = _generate(
        "prompt",
        model="dup",
        base_url="https://one.example/v1",
        api_key="k1",
        provider="openai-compatible",
        backups=(
            ExternalEndpoint(base_url="https://one.example/v1", model="dup", api_key="other-key"),
            ExternalEndpoint(base_url="https://two.example/v1", model="real", api_key="k2"),
        ),
    )

    assert result == "local answer"
    assert tried == [
        "https://one.example/v1/chat/completions",
        "https://two.example/v1/chat/completions",
    ], "the duplicate endpoint must not cost a second request"


def test_a_transiently_failing_engine_is_skipped_for_a_while(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding out that a provider is overloaded is expensive, so it is only paid once.

    Measured on a certbot migration: NVIDIA took **three minutes** to answer
    `503 Service temporarily overloaded`, and every finding in the plan paid that toll again because
    nothing remembered the last one. Twenty minutes of the run went on re-establishing that the same
    endpoint was still busy, while the local model sat idle at 0% GPU.
    """
    llm._ENGINE_COOLDOWN.clear()
    tried: list[str] = []

    def fake_urlopen(req, timeout: float):
        body = json.loads(req.data)
        tried.append(body["model"])
        if body["model"] == "busy":
            raise urllib.error.HTTPError(
                req.full_url,
                503,
                "Service Unavailable",
                None,
                io.BytesIO(b'{"error":{"message":"Service temporarily overloaded"}}'),
            )
        return _FakeResponse({"choices": [{"message": {"content": "the rewritten file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    spare = llm.ExternalEndpoint(base_url="https://spare.example/v1", model="spare", api_key="k2")

    # First call learns the 503 the hard way and falls through to the spare.
    llm._generate(
        "prompt",
        model="busy",
        base_url="https://busy.example/v1",
        api_key="k1",
        provider="openai-compatible",
        backups=(spare,),
    )
    # Second call must not ask the busy engine again.
    llm._generate(
        "prompt",
        model="busy",
        base_url="https://busy.example/v1",
        api_key="k1",
        provider="openai-compatible",
        backups=(spare,),
    )

    assert tried == ["busy", "spare", "spare"], tried
    llm._ENGINE_COOLDOWN.clear()


def test_the_last_engine_is_tried_even_while_cooling(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cooldown must never turn into "no engine at all". If the only endpoint left is cooling,
    asking it and failing is strictly better than refusing the finding without trying -- the window
    is 90 seconds and the provider may well have recovered inside it."""
    llm._ENGINE_COOLDOWN.clear()
    llm._start_cooldown("https://only.example/v1", "only")
    tried: list[str] = []

    def fake_urlopen(req, timeout: float):
        tried.append(json.loads(req.data)["model"])
        return _FakeResponse({"choices": [{"message": {"content": "file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    llm._generate(
        "prompt",
        model="only",
        base_url="https://only.example/v1",
        api_key="k",
        provider="openai-compatible",
    )

    assert tried == ["only"], "the sole remaining engine must still be asked"
    llm._ENGINE_COOLDOWN.clear()


def test_an_engine_whose_key_is_rejected_is_not_asked_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dead key is a fact about the configuration, not a bad moment for the provider.

    Measured on the certbot run: the configured primary answered HTTP 403 (Cloudflare 1010 — the key
    had been revoked). Nothing remembered it, so all 297 findings opened by asking the same dead
    endpoint. Each 403 was fast, which is precisely why nobody noticed: no timeout, no rate limit,
    just a run that silently never used the engine it was configured to use.
    """
    llm._ENGINE_REFUSED.clear()
    llm._ENGINE_COOLDOWN.clear()
    tried: list[str] = []

    def fake_urlopen(req, timeout: float):
        model = json.loads(req.data)["model"]
        tried.append(model)
        if model == "revoked":
            raise urllib.error.HTTPError(
                req.full_url, 403, "Forbidden", None, io.BytesIO(b"error code: 1010")
            )
        return _FakeResponse({"choices": [{"message": {"content": "the rewritten file"}}]})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    spare = llm.ExternalEndpoint(base_url="https://spare.example/v1", model="spare", api_key="k2")

    for _ in range(3):
        llm._generate(
            "prompt",
            model="revoked",
            base_url="https://dead.example/v1",
            api_key="k1",
            provider="openai-compatible",
            backups=(spare,),
        )

    assert tried == ["revoked", "spare", "spare", "spare"], tried
    llm._ENGINE_REFUSED.clear()


def test_a_rejected_key_is_skipped_even_as_the_only_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unlike a cooldown, which spares the last engine because the provider may have recovered.

    A rejected key cannot recover on its own, so asking it again produces one more identical
    rejection instead of an answer. The finding falls through to the local model, which is the
    engine that can actually do the work when nothing external is usable.
    """
    llm._ENGINE_REFUSED.clear()
    llm._ENGINE_COOLDOWN.clear()
    tried: list[str] = []

    def fake_urlopen(req, timeout: float):
        if "11434" in req.full_url:
            tried.append("local")
            return _FakeResponse({"response": "local answer"})
        tried.append(json.loads(req.data)["model"])
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", None, io.BytesIO(b"bad key")
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    for _ in range(2):
        llm._generate(
            "prompt",
            model="only",
            base_url="https://only.example/v1",
            api_key="k",
            provider="openai-compatible",
            fallback_ollama_model="qwen2.5-coder:7b",
        )

    assert tried == ["only", "local", "local"], tried
    llm._ENGINE_REFUSED.clear()
