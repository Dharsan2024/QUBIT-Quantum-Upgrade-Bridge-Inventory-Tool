"""What is left on the attached provider's rate limit, and why QUBIT has to know.

A hosted free tier is rationed far more tightly in REQUESTS than in tokens. Measured against Groq
from this installation, on a real call: 1,000 requests/day and 8,000 tokens per MINUTE, with the
token window resetting in 31 seconds and the request window in 86. One patch can cost up to
fourteen requests, so the binding constraint is the request count -- and QUBIT could not see it.
Every response carries `x-ratelimit-remaining-requests`; the only header ever read was
`x-ratelimit-limit-tokens`, once, to size a single request.

The consequence was that exhaustion was discovered by being refused. There was no way to pace a
run, to spend a day's last requests on the findings that most deserve them, or to tell an operator
what a run would cost before starting it.

The distinction these tests protect is `None` versus `0`. Google's OpenAI-compatible endpoint sends
none of these headers, so "unknown" has to stay distinguishable from "exhausted" all the way to the
UI -- rendering an unknown budget as an empty bar would tell an operator their quota is gone when
nothing of the sort has been reported.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform import llm


@pytest.fixture(autouse=True)
def _clean_budgets():
    llm._BUDGETS.clear()
    yield
    llm._BUDGETS.clear()


GROQ_HEADERS = {
    # Exactly the shape observed on a live call.
    "x-ratelimit-limit-requests": "1000",
    "x-ratelimit-remaining-requests": "999",
    "x-ratelimit-limit-tokens": "8000",
    "x-ratelimit-remaining-tokens": "3826",
    "x-ratelimit-reset-requests": "1m26.4s",
    "x-ratelimit-reset-tokens": "31.305s",
}


def test_the_provider_s_own_figures_are_recorded() -> None:
    llm._record_budget("groq::gpt-oss-120b", GROQ_HEADERS)

    budget = llm.rate_budget("groq::gpt-oss-120b")
    assert budget["remaining_requests"] == 999
    assert budget["limit_requests"] == 1000
    assert budget["remaining_tokens"] == 3826
    assert budget["limit_tokens"] == 8000
    assert budget["reset_requests"] == "1m26.4s"
    assert budget["reported"] is True


def test_a_provider_that_says_nothing_is_unknown_not_empty() -> None:
    """Google's OpenAI-compatible endpoint sends no rate-limit headers at all.

    Recording that as zero remaining would tell an operator their quota is exhausted on the
    strength of a provider that simply never mentioned it.
    """
    llm._record_budget("google::gemma-4-31b-it", {"content-type": "application/json"})

    assert llm.rate_budget("google::gemma-4-31b-it") == {}
    assert llm.rate_budget() == {}


def test_zero_remaining_is_reported_and_is_not_the_same_as_unknown() -> None:
    llm._record_budget("groq::m", {**GROQ_HEADERS, "x-ratelimit-remaining-requests": "0"})

    budget = llm.rate_budget("groq::m")
    assert budget["remaining_requests"] == 0
    assert budget["reported"] is True, "a real zero must be reported, not treated as silence"


def test_malformed_headers_never_break_a_generation() -> None:
    """Measurement must not be able to fail the thing it is measuring."""
    llm._record_budget("groq::m", {"x-ratelimit-remaining-requests": "not-a-number"})
    llm._record_budget("groq::m2", None)  # a provider that returned no headers object at all

    assert llm.rate_budget("groq::m") == {}


def test_each_engine_is_tracked_separately() -> None:
    """A primary and a backup have separate quotas, and the backup's exhaustion says nothing about
    the primary's."""
    llm._record_budget("groq::a", GROQ_HEADERS)
    llm._record_budget("groq::b", {**GROQ_HEADERS, "x-ratelimit-remaining-requests": "12"})

    everything = llm.rate_budget()
    assert set(everything) == {"groq::a", "groq::b"}
    assert everything["groq::a"]["remaining_requests"] == 999
    assert everything["groq::b"]["remaining_requests"] == 12


def test_seconds_suffixes_are_parsed() -> None:
    """Groq reports resets as `31.305s`, not as an integer."""
    assert llm._as_int("31.305s") == 31
    assert llm._as_int("1000") == 1000
    assert llm._as_int(None) is None
    assert llm._as_int("") is None


def test_a_response_without_headers_does_not_break_the_generation(monkeypatch) -> None:
    """Measurement must never be able to fail the thing it measures.

    The budget was first read as `resp.headers` at the call site -- outside `_record_budget`'s own
    suppression -- so any response object lacking that attribute raised straight through the
    generation path. Nine existing tests went red at once, which is the good outcome; in production
    it would have been an provider whose client returns a different response shape.
    """
    import io as _io
    import json as _json

    class HeaderlessResponse(_io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()
            return False

    payload = _json.dumps(
        {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    ).encode()
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *a, **k: HeaderlessResponse(payload))

    out = llm._openai_compatible_generate(
        "p", model="m", base_url="https://example.invalid/v1", api_key="k", timeout=5
    )

    assert out == "ok"
    assert llm.rate_budget() == {}, "nothing to report, and nothing broken"
