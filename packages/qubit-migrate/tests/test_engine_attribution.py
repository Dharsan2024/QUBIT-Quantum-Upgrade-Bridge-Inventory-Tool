"""Which engine actually answered, and why recording the wrong one is self-reinforcing.

QUBIT routes free-first: an unmetered engine that is capable of the work keeps it, and a rationed
request is spent only on what the free engine cannot do. "Cannot" is decided from this
installation's own record via `learn.reliability`, which keys on the engine NAME written onto the
patch. So an escalation that is not recorded does not merely mislabel a row -- it feeds the local
model a success for work a hosted engine did, that pairing then looks proven, and routing keeps
sending it back to the engine that never completed it. The hosted engine's record stays empty at the
same time, so it never earns the work either.

Observed on this installation before the fix: two patches recorded against
`qwen2.5-coder:7b-instruct-q4_K_M` whose own ledgers show five calls, every one to Groq or Google
and none to the local model at all.

The cause was that `backups` was threaded to every layer that can escalate -- `plan_rewrite` and
`self_review` included -- while `on_fallback` was passed to only one of them, so a planning or
review call that fell through from a dead local model to a hosted one did it silently.
"""

from __future__ import annotations

import io
import json
import urllib.error
import uuid
from datetime import UTC, datetime

import pytest
from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.transform.llm import (
    ExternalEndpoint,
    OllamaError,
    plan_rewrite,
    self_review,
)
from qubit_migrate.transform.rules import MigrationRule

HOSTED = ExternalEndpoint(base_url="https://api.example.com/v1", model="gpt-oss-120b", api_key="k")


def _rule() -> MigrationRule:
    return MigrationRule(
        id="test-rule",
        language="python",
        title="test",
        matches={},
        target={"algorithm": "ML-KEM-768"},
        raw={},
    )


def _asset() -> CryptoAsset:
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm="RSA-2048",
        usage_context=UsageContext.kex,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="a.py", line=1),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        discovered_at=datetime.now(UTC),
    )


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()


@pytest.fixture
def dead_local(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stopped Ollama server -- the condition that makes a local route escalate."""

    def boom(*args: object, **kwargs: object) -> str:
        raise OllamaError("Ollama is not reachable at http://127.0.0.1:11434")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", boom)


@pytest.fixture
def hosted_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(req, timeout: float):
        return _FakeResponse(
            {
                "choices": [
                    {"message": {"content": "1. Replace RSA with ML-KEM-768.\n2. Keep imports."}}
                ]
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)


def test_a_planning_call_that_escalates_says_which_engine_answered(
    dead_local: None, hosted_answers: None
) -> None:
    """Planning is the first model call of a patch, so an unrecorded escalation here mislabels
    everything that follows it."""
    ran: list[str] = []

    plan_rewrite(
        "import hashlib",
        _rule(),
        _asset(),
        model="qwen2.5-coder:7b",
        provider="ollama",
        backup=HOSTED,
        on_fallback=ran.append,
    )

    assert ran == ["openai-compatible:gpt-oss-120b"]


def test_a_self_review_call_that_escalates_says_which_engine_answered(
    dead_local: None, hosted_answers: None
) -> None:
    """Self-review is the LAST call, and the one whose correction ships, so it is the worst place
    to lose attribution."""
    ran: list[str] = []

    self_review(
        "import hashlib",
        "import hashlib  # draft",
        _rule(),
        _asset(),
        model="qwen2.5-coder:7b",
        provider="ollama",
        backup=HOSTED,
        on_fallback=ran.append,
    )

    assert ran == ["openai-compatible:gpt-oss-120b"]


def test_no_escalation_reports_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other half: a local model that answers must not be reported as a fallback, or the
    hosted engine collects credit for work it never did -- the same corruption mirrored."""
    monkeypatch.setattr(
        "qubit_migrate.transform.llm._ollama_generate",
        lambda *a, **k: "1. Replace RSA with ML-KEM-768.",
    )
    ran: list[str] = []

    plan_rewrite(
        "import hashlib",
        _rule(),
        _asset(),
        model="qwen2.5-coder:7b",
        provider="ollama",
        backup=HOSTED,
        on_fallback=ran.append,
    )

    assert ran == []


def test_an_escalation_that_also_fails_does_not_invent_an_attribution(
    dead_local: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If nothing answered, nothing produced the patch. Recording an engine here would credit a
    success to one that refused the request.

    `plan_rewrite` returns "" rather than raising -- the plan is an aid, and a generation that
    cannot get one proceeds without it -- so the graceful degradation is asserted alongside the
    silence. A swallowed failure is exactly where a phantom attribution would go unnoticed.
    """

    def refuse(req, timeout: float):
        raise urllib.error.HTTPError(
            req.full_url, 503, "Service Unavailable", None, io.BytesIO(b"{}")
        )

    monkeypatch.setattr("urllib.request.urlopen", refuse)
    ran: list[str] = []

    plan = plan_rewrite(
        "import hashlib",
        _rule(),
        _asset(),
        model="qwen2.5-coder:7b",
        provider="ollama",
        backup=HOSTED,
        on_fallback=ran.append,
    )

    assert plan == "", "a failed planning pass degrades to no plan, it does not fail the patch"
    assert ran == [], "no engine answered, so none may be credited"
