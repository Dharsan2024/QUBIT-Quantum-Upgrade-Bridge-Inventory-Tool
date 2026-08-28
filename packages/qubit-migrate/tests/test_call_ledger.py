"""What QUBIT spends on the attached model, and why it has to be counted at all.

QUBIT's claim about an LLM is an efficiency claim: do the deterministic work without the model,
replay what has already been validated, send an excerpt instead of a whole file, refuse an engine
that has never succeeded at a pairing. Every part of that was unmeasurable, because nothing counted
the calls. Both engines report usage in their own responses -- `prompt_eval_count`/`eval_count` from
Ollama, `usage` from an OpenAI-compatible endpoint -- and QUBIT read the answer text and discarded
the rest.

It matters most where the budget is smallest. A free tier is rationed in REQUESTS PER DAY (measured
on this installation: 1,000/day on Groq) and one patch can cost up to fourteen of them. A tool that
cannot count its own requests cannot pace them, prioritise them, or explain why it ran out.

The regression these tests exist for is the thread one. `_ollama_generate` runs the request in a raw
daemon thread, and a `threading.Thread` starts with an EMPTY context -- so the ledger installed by
`generate_patch` was invisible inside the worker and every local-model call was recorded as costing
nothing. That is not a missing feature, it is the efficiency claim silently inverted: the engine
that costs the most wall-clock would have looked free.
"""

from __future__ import annotations

import io
import json

import pytest
from qubit_migrate.transform import llm


class _FakeResponse(io.BytesIO):
    """Just enough of an HTTP response for `json.load` and a `with` block."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _ollama_payload(prompt_tokens: int, completion_tokens: int, text: str = "ok") -> bytes:
    return json.dumps(
        {
            "response": text,
            "done_reason": "stop",
            "prompt_eval_count": prompt_tokens,
            "eval_count": completion_tokens,
        }
    ).encode()


def test_nothing_is_recorded_when_nobody_is_counting() -> None:
    """The ledger is opt-in. Outside one, `_record_call` must be a no-op and never raise."""
    llm._record_call(engine="e", prompt_tokens=1, completion_tokens=2, seconds=0.1)


def test_a_local_call_is_counted_even_though_it_runs_in_a_worker_thread(monkeypatch) -> None:
    """The regression that would have made the slowest engine look free.

    `_ollama_generate` hands the request to a raw daemon thread. Context variables do not cross a
    thread boundary on their own, so without `contextvars.copy_context()` the ledger is simply not
    there when the call completes, and the call is recorded nowhere.
    """
    monkeypatch.setattr(
        llm.urllib.request,
        "urlopen",
        lambda *a, **k: _FakeResponse(_ollama_payload(1200, 340)),
    )

    with llm.ledger() as spend:
        llm._ollama_generate("prompt", model="test-model", timeout=30)

    assert len(spend.calls) == 1, "the call happened in another thread and was not counted"
    call = spend.calls[0]
    assert call.engine == "test-model"
    assert call.prompt_tokens == 1200
    assert call.completion_tokens == 340
    assert call.seconds >= 0.0


def test_the_ledger_totals_across_several_calls(monkeypatch) -> None:
    monkeypatch.setattr(
        llm.urllib.request,
        "urlopen",
        lambda *a, **k: _FakeResponse(_ollama_payload(100, 50)),
    )

    with llm.ledger() as spend:
        for _ in range(3):
            llm._ollama_generate("p", model="m", timeout=30)

    summary = spend.summary()
    assert summary["calls"] == 3
    assert summary["prompt_tokens"] == 300
    assert summary["completion_tokens"] == 150
    assert summary["by_engine"] == {"m": 3}


def test_a_rejected_answer_still_counts_against_the_budget(monkeypatch) -> None:
    """The quota was spent whether or not the text turned out to be usable.

    Counting only the calls that produced an accepted patch is exactly how a tool comes to believe
    it is thriftier than it is -- and the rejected attempts are the expensive ones: measured on this
    corpus, one `code-tls-01` finding spent 851 seconds over three attempts and produced nothing.
    """
    truncated = json.dumps(
        {
            "response": "half a file",
            # Ollama reports this when it hit the output ceiling; `_ollama_generate_once` raises.
            "done_reason": "length",
            "prompt_eval_count": 900,
            "eval_count": 4096,
        }
    ).encode()
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *a, **k: _FakeResponse(truncated))

    with llm.ledger() as spend, pytest.raises(llm.OllamaError):
        llm._ollama_generate("p", model="m", timeout=30)

    assert len(spend.calls) == 1, "a call that produced an unusable answer still cost a request"
    assert spend.calls[0].prompt_tokens == 900


def test_start_ledger_replaces_the_previous_one() -> None:
    """`generate_patch` opens a fresh ledger per patch rather than a `with` block, because wrapping
    its body would re-indent several hundred lines to measure something none of them are about."""
    first = llm.start_ledger()
    llm._record_call(engine="a", prompt_tokens=1, completion_tokens=1, seconds=0.0)
    second = llm.start_ledger()
    llm._record_call(engine="b", prompt_tokens=2, completion_tokens=2, seconds=0.0)

    assert len(first.calls) == 1
    assert len(second.calls) == 1
    assert second.calls[0].engine == "b"


def test_a_patch_made_without_a_model_records_no_calls() -> None:
    """The majority case, and the one the efficiency claim rests on: a deterministic codemod or a
    replay from the learned-patch cache costs nothing, and must be visible as costing nothing."""
    spend = llm.start_ledger()

    assert spend.summary() == {
        "calls": 0,
        "failed_calls": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "seconds": 0,
        "by_engine": {},
    }


# ── the spend that used to vanish ─────────────────────────────────────────────────────────────


def _seeded_task(tmp_path):
    from qubit_core import (
        AssetType,
        CryptoAsset,
        Location,
        QuantumAttack,
        QuantumVulnerability,
        RiskAnnotation,
        SourceScanner,
        UsageContext,
        utcnow,
    )
    from qubit_core.db import Base
    from qubit_core.db.models import ProjectRow, ScanRow
    from qubit_core.mapping import asset_to_row
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    src = tmp_path / "seal.py"
    src.write_text(
        "from Crypto.Cipher import DES3\nc = DES3.new(k, DES3.MODE_CBC)\n", encoding="utf-8"
    )
    session.add(
        asset_to_row(
            CryptoAsset(
                algorithm="3DES",
                usage_context=UsageContext.encryption_at_rest,
                source_scanner=SourceScanner.code,
                asset_type=AssetType.algorithm_use,
                location=Location(file_path=str(src), line=2),
                quantum_vulnerable=QuantumVulnerability(
                    vulnerable=True, attack=QuantumAttack.grover
                ),
                discovered_at=utcnow(),
                risk=RiskAnnotation(
                    score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
                ),
            ),
            scan_id=scan.id,
            project_id=project.id,
        )
    )
    session.commit()
    orch = MigrationOrchestrator(session)
    return orch, orch.get_queue(orch.build_plan().id)[0]


def test_a_generation_that_produces_no_patch_still_records_what_it_spent(tmp_path, monkeypatch):
    """The gap this exists to close.

    Cost was written only onto a patch row, so a finding that exhausted its repair budget and
    produced nothing recorded nothing -- and those are the expensive ones. Measured on the corpus
    while building this: three findings spent ten requests and 44,502 tokens between them for zero
    accepted patches, and only two were recorded, because the third never reached a patch. Losing
    the failures biases the efficiency figure in the flattering direction.
    """
    orch, task = _seeded_task(tmp_path)

    def burns_budget_then_fails(*a, **kw):
        for _ in range(4):
            llm._record_call(
                engine="test-engine", prompt_tokens=1000, completion_tokens=250, seconds=3.0
            )
        raise llm.OllamaError("rejected after 3 attempt(s)")

    monkeypatch.setattr("qubit_migrate.orchestrator.generate_llm_source", burns_budget_then_fails)

    with pytest.raises(ValueError):
        orch.generate_patch(task.id, generator="llm")

    orch.session.refresh(task)
    spent = task.spend_json or {}
    assert spent.get("calls") == 4, f"the failed attempt's spend vanished: {spent}"
    assert spent.get("prompt_tokens") == 4000
    assert spent.get("completion_tokens") == 1000
    assert spent.get("by_engine") == {"test-engine": 4}
    assert spent.get("attempts") == 1


def test_spend_accumulates_across_retries(tmp_path, monkeypatch):
    """A finding retried twice cost both attempts, and that is the number the paper asks for."""
    orch, task = _seeded_task(tmp_path)

    def burn(*a, **kw):
        llm._record_call(engine="e", prompt_tokens=100, completion_tokens=10, seconds=1.0)
        raise llm.OllamaError("nope")

    monkeypatch.setattr("qubit_migrate.orchestrator.generate_llm_source", burn)
    for _ in range(2):
        with pytest.raises(ValueError):
            orch.generate_patch(task.id, generator="llm")

    orch.session.refresh(task)
    spent = task.spend_json or {}
    assert spent.get("calls") == 2, f"expected both attempts counted, got {spent}"
    assert spent.get("attempts") == 2
