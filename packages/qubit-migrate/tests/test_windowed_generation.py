"""Showing the model an EXCERPT of a file too large to send whole.

QUBIT's generation contract is whole-file: the model is handed a file and returns all of it. That
is what lets `check_rewrite` recognise a truncated answer, and it is also why this installation
refuses 27 findings before spending a single token — a 9,702-line file needs ~115,994 tokens
against this installation's real 28,800-token prompt budget, and the refusal says, accurately,
that "splitting the change by hand is what this needs".

`build_excerpt` does that splitting. The model sees the imports, a marker standing for the region
it is not shown, and the neighbourhood of the flagged line; `Excerpt.splice` puts the answer back
into the untouched original. Measured across those 27 findings: a median excerpt of 1,800 tokens
against a whole-file median of 35,279, worst case 2,527 against 115,994 — a 96.3% reduction, and
every one of them now fits where none of them fitted before.

The tests that matter most here are the splice ones. A splice that lands an edit one line off, or
quietly drops the region between the head and the window, would produce a patch that still passes
the rescan and corrupts the file — the exact failure mode that made replaying stored `hunk_before`
windows unsafe, and the reason this reconstructs from the original rather than from the model.
"""

from __future__ import annotations

import pytest
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
from qubit_migrate.orchestrator import GuidedRemediation, MigrationOrchestrator
from qubit_migrate.transform import llm
from qubit_migrate.transform.llm import ModelOutputError, build_excerpt
from qubit_migrate.transform.rules import load_rules
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

# Comfortably past the 45% of an 8,192-token window that `llm_max_prompt_fraction` allows, at the
# ~3 chars/token estimate used throughout.
_FILLER = 1200


def _big_python(flagged: str = "cipher = DES3.new(key, DES3.MODE_CBC)") -> tuple[str, int]:
    """A file too large to send whole, and the 1-based line the finding sits on."""
    lines = ["from Crypto.Cipher import DES3", ""]
    lines += [f"SETTING_{i} = {i}" for i in range(_FILLER // 2)]
    at = len(lines) + 1
    lines.append(flagged)
    lines += [f"TRAILING_{i} = {i}" for i in range(_FILLER // 2)]
    return "\n".join(lines) + "\n", at


def _asset(path: str, line: int) -> CryptoAsset:
    return CryptoAsset(
        algorithm="3DES",
        usage_context=UsageContext.encryption_at_rest,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
        ),
    )


def _rule():
    return next(r for r in load_rules() if r.id == "py-weakcipher-01")


# ── the excerpt itself ────────────────────────────────────────────────────────────────────────


def test_a_file_the_window_already_covers_needs_no_excerpt() -> None:
    """None means "send the whole file", which is strictly better where it fits: no marker to
    get wrong, no splice to get wrong."""
    assert build_excerpt("\n".join(f"line{i}" for i in range(20)), 10) is None


def test_a_finding_with_no_usable_line_cannot_be_windowed() -> None:
    """The window is centred on the flagged line. Without one there is nothing to centre on, and
    the caller must keep refusing the file rather than guess at a region."""
    source = "\n".join(f"line{i}" for i in range(500))
    assert build_excerpt(source, None) is None
    assert build_excerpt(source, 0) is None
    assert build_excerpt(source, 10_000) is None


def test_the_excerpt_carries_the_imports_and_the_flagged_neighbourhood() -> None:
    source, at = _big_python()
    excerpt = build_excerpt(source, at)
    assert excerpt is not None

    # The imports, because nearly every PQC migration adds one and a patch that uses a symbol it
    # never imported is rejected by the `symbols` stage.
    assert "from Crypto.Cipher import DES3" in excerpt.text
    # The flagged line, found where the prompt says it is.
    assert excerpt.text.splitlines()[excerpt.line - 1] == "cipher = DES3.new(key, DES3.MODE_CBC)"
    # And a marker for everything in between.
    assert excerpt.text.count(llm.EXCERPT_MARKER) == 1
    assert len(excerpt.text) < len(source) / 5, "the excerpt has to be much smaller to be worth it"


# ── the splice, which is where a mistake would corrupt a file silently ────────────────────────


def test_splicing_back_an_unchanged_excerpt_restores_the_file_exactly() -> None:
    source, at = _big_python()
    excerpt = build_excerpt(source, at)
    assert excerpt is not None
    assert excerpt.splice(excerpt.text).rstrip("\n") == source.rstrip("\n")


def test_an_edit_inside_the_window_lands_on_the_original_line() -> None:
    """Off-by-one here would put the migration on the wrong line and still pass the rescan."""
    source, at = _big_python()
    excerpt = build_excerpt(source, at)
    assert excerpt is not None
    edited = excerpt.text.replace("DES3.new(key, DES3.MODE_CBC)", "AESGCM(key)")

    spliced = excerpt.splice(edited).splitlines()

    assert spliced[at - 1] == "cipher = AESGCM(key)"
    assert len(spliced) == len(source.splitlines()), (
        "no line may be added or lost by a same-size edit"
    )
    # The region the model never saw is byte-identical, taken from the original and not from the
    # answer — this is the property that makes windowing safe at all.
    assert spliced[300] == source.splitlines()[300]
    assert spliced[-1] == source.splitlines()[-1]


def test_an_import_added_to_the_head_region_reaches_the_file() -> None:
    source, at = _big_python()
    excerpt = build_excerpt(source, at)
    assert excerpt is not None
    edited = excerpt.text.replace(
        "from Crypto.Cipher import DES3",
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
    )

    spliced = excerpt.splice(edited)

    assert "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" in spliced
    assert "from Crypto.Cipher import DES3" not in spliced
    # The marker is a prompt device and must never survive into the patched file.
    assert llm.EXCERPT_MARKER not in spliced


@pytest.mark.parametrize(
    ("mangle", "why"),
    [
        (lambda t: t.replace(llm.EXCERPT_MARKER + "\n", ""), "dropped"),
        (
            lambda t: t.replace(llm.EXCERPT_MARKER, llm.EXCERPT_MARKER + "\n" + llm.EXCERPT_MARKER),
            "duplicated",
        ),
    ],
)
def test_a_mangled_marker_is_rejected_rather_than_spliced(mangle, why: str) -> None:
    """Rejected as malformed OUTPUT, not as a failed task: `ModelOutputError` is what the repair
    loop already catches, so the model gets told what it did and tries again.

    Splicing regardless is the dangerous alternative — a dropped marker would silently overwrite
    the whole head of the file with the window.
    """
    source, at = _big_python()
    excerpt = build_excerpt(source, at)
    assert excerpt is not None

    with pytest.raises(ModelOutputError, match="exactly once"):
        excerpt.splice(mangle(excerpt.text))


# ── the prompt has to ask for what the splice expects ─────────────────────────────────────────


def test_the_excerpt_prompt_asks_for_an_excerpt_and_the_whole_file_prompt_does_not() -> None:
    """The two contracts must not leak into each other. A prompt that says "return the complete
    file" while handing over an excerpt gets a model trying to invent the 9,000 lines it cannot
    see."""
    source, at = _big_python()
    excerpt = build_excerpt(source, at)
    assert excerpt is not None
    rule, asset = _rule(), _asset("app/seal.py", at)

    windowed = llm._build_prompt(
        excerpt.text, rule, llm._excerpt_asset(asset, excerpt), excerpt=True
    )
    whole = llm._build_prompt(source, rule, asset)

    assert llm.EXCERPT_MARKER in windowed
    assert "complete rewritten file" not in windowed
    assert "EXCERPT" in windowed

    assert llm.EXCERPT_MARKER not in whole
    assert "complete rewritten file" in whole


def test_the_prompt_quotes_the_line_number_the_model_can_actually_count_to() -> None:
    """The prompt says `line=N` and the model counts lines to find it. Leaving the original number
    would point thousands of lines past the end of the excerpt."""
    source, at = _big_python()
    excerpt = build_excerpt(source, at)
    assert excerpt is not None
    renumbered = llm._excerpt_asset(_asset("app/seal.py", at), excerpt)

    assert renumbered.location is not None
    assert renumbered.location.line == excerpt.line
    assert renumbered.location.line < len(excerpt.text.splitlines())
    assert at > len(excerpt.text.splitlines()), "the original line is the one that would not fit"


# ── end to end through the real generation function ───────────────────────────────────────────


def test_generation_shows_an_excerpt_and_returns_the_whole_file(monkeypatch) -> None:
    """The property the whole feature rests on: the model is shown a fraction of the file, and
    what comes back out of `generate_llm_source` is nonetheless the COMPLETE file."""
    source, at = _big_python()
    seen: list[str] = []

    def fake(prompt: str, *, model, base_url="x", timeout=0, **_):
        seen.append(prompt)
        # A model doing exactly what it was asked: return the excerpt it was given, edited.
        body = prompt.rsplit("```python\n", 1)[1].rsplit("```", 1)[0]
        return (
            "```python\n"
            + body.replace("DES3.new(key, DES3.MODE_CBC)", "AESGCM(key)")
            + "```\nSECURITY NOTES:\n- Replaced 3DES with AES-256-GCM.\n"
        )

    monkeypatch.setattr(llm, "installed_models", lambda base_url: [])
    monkeypatch.setattr(llm, "_ollama_generate", fake)

    result = llm.generate_llm_source(
        source,
        _rule(),
        _asset("app/seal.py", at),
        model="m",
        windowed=True,
        plan_first=False,
        self_review_pass=False,
    )

    assert len(seen) == 1
    # What the model was actually shown, versus what it would have been shown before.
    assert len(seen[0]) < len(source) / 2
    # And what came back is the whole file, edited in the right place, with the untouched regions
    # restored from the original rather than from the model.
    lines = result.splitlines()
    assert lines[at - 1] == "cipher = AESGCM(key)"
    assert len(lines) == len(source.splitlines())
    assert lines[-1] == source.splitlines()[-1]
    assert llm.EXCERPT_MARKER not in result


# ── the orchestrator's decision to window ─────────────────────────────────────────────────────


def _seeded(tmp_path, source: str, line: int):
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
    src.write_text(source, encoding="utf-8")
    session.add(asset_to_row(_asset(str(src), line), scan_id=scan.id, project_id=project.id))
    session.commit()
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    return orch, orch.get_queue(plan.id)[0]


def test_an_oversize_file_is_windowed_instead_of_refused(tmp_path, monkeypatch) -> None:
    """The behaviour change: this exact file used to be failed with "too large" and routed to
    written advice. Now it reaches the model, with `windowed=True`."""
    source, at = _big_python()
    orch, task = _seeded(tmp_path, source, at)
    assert orch._oversize_reason(source) is not None, "baseline: this file does not fit"

    got: dict = {}

    def spy(*a, **kw):
        got.update(kw)
        raise llm.OllamaError("stop here — the call itself is what is under test")

    monkeypatch.setattr("qubit_migrate.orchestrator.generate_llm_source", spy)
    # The orchestrator wraps a generation failure; the call itself is what is under test.
    with pytest.raises(ValueError):
        orch.generate_patch(task.id, generator="auto")

    assert got.get("windowed") is True


def test_a_file_that_fits_is_never_windowed(tmp_path, monkeypatch) -> None:
    """Windowing narrows what the model sees, so it must not happen to a file the model could
    have read completely."""
    source = "from Crypto.Cipher import DES3\ncipher = DES3.new(key, DES3.MODE_CBC)\n"
    orch, task = _seeded(tmp_path, source, 2)
    assert orch._oversize_reason(source) is None

    got: dict = {}

    def spy(*a, **kw):
        got.update(kw)
        raise llm.OllamaError("stop here")

    monkeypatch.setattr("qubit_migrate.orchestrator.generate_llm_source", spy)
    # The orchestrator wraps a generation failure; the call itself is what is under test.
    with pytest.raises(ValueError):
        orch.generate_patch(task.id, generator="auto")

    assert got.get("windowed") is False


def test_only_the_size_refusal_is_overridden(tmp_path, monkeypatch) -> None:
    """An excerpt answers "the file will not fit". It answers nothing about a pairing this engine
    has never once completed, so that refusal has to survive — otherwise windowing would spend
    quota to reach a verdict already measured.
    """
    source, at = _big_python()
    orch, task = _seeded(tmp_path, source, at)
    monkeypatch.setattr(
        MigrationOrchestrator,
        "_llm_detour_reason",
        lambda self, rule, src, lang, tid=None: "the local model has not completed this",
    )
    monkeypatch.setattr(
        "qubit_migrate.orchestrator.generate_llm_source",
        lambda *a, **kw: pytest.fail("a non-size refusal must not be overridden by windowing"),
    )

    with pytest.raises(GuidedRemediation):
        orch.generate_patch(task.id, generator="auto")


def test_the_reviewer_is_told_when_the_model_only_saw_an_excerpt(monkeypatch) -> None:
    """Every other caveat is the MODEL admitting a limit. This one is QUBIT admitting one, and it
    is the more important of the two: a reviewer who assumed the model had weighed the whole file
    would credit the patch with a judgement it never made."""

    def fake(prompt: str, *, model, base_url="x", timeout=0, **_):
        body = prompt.rsplit("```python\n", 1)[1].rsplit("```", 1)[0]
        return "```python\n" + body.replace("DES3.new(key, DES3.MODE_CBC)", "AESGCM(key)") + "```\n"

    monkeypatch.setattr(llm, "installed_models", lambda base_url: [])
    monkeypatch.setattr(llm, "_ollama_generate", fake)

    source, at = _big_python()
    windowed: list[str] = []
    llm.generate_llm_source(
        source,
        _rule(),
        _asset("app/seal.py", at),
        model="m",
        windowed=True,
        plan_first=False,
        self_review_pass=False,
        on_caveats=windowed.extend,
    )
    assert any("excerpt of this file" in c for c in windowed), windowed

    # ...and a file the model read completely must carry no such warning.
    whole: list[str] = []
    llm.generate_llm_source(
        "from Crypto.Cipher import DES3\ncipher = DES3.new(key, DES3.MODE_CBC)\n",
        _rule(),
        _asset("app/seal.py", 2),
        model="m",
        plan_first=False,
        self_review_pass=False,
        on_caveats=whole.extend,
    )
    assert not any("excerpt" in c for c in whole), whole


def test_a_blank_line_at_the_window_edge_survives_the_round_trip() -> None:
    """`"\n".join` and `splitlines()` are not inverses -- `"a\n".splitlines()` is `["a"]`.

    Building the excerpt with `splitlines()` swallowed a blank line sitting on a window boundary
    and shifted every line after the splice up by one. Measured against 304 real large
    findings on this installation, that corrupted 29 of them, and every corrupted file still
    parsed and still passed the rescan -- so nothing downstream would have caught it.
    """
    lines = [f"F{i} = {i}" for i in range(500)]
    lines[0] = "import x"
    at = 200  # 1-based, so the window is lines[169:230]
    lines[39] = ""  # the head's last line
    lines[169] = ""  # the window's first line
    lines[229] = ""  # the window's last line -- the one that used to disappear
    source = "\n".join(lines) + "\n"

    excerpt = build_excerpt(source, at)

    assert excerpt is not None
    assert excerpt.splice(excerpt.text) == source


def test_a_windowed_file_is_routed_by_its_excerpt_not_by_the_whole_file(tmp_path) -> None:
    """Engine selection has to size what is actually SENT, not what the finding sits in.

    `_select_engine` walks engines cheapest-first, skipping any whose budget the source will not
    fit AND any that has repeatedly failed this exact (rule, language). Sized on the whole file it
    returns None for every oversize finding, and `generate_patch` then falls back to a hardcoded
    local engine -- which silently bypasses the reliability gate, handing the work to the one
    engine already measured as unable to do it. Sized on the excerpt, the gate applies again and
    the finding escalates to an engine with no such record.
    """
    from qubit_core.db import secrets_at_rest
    from qubit_core.db.models import LlmProviderConfig
    from qubit_migrate.transform import learn

    source, at = _big_python()
    orch, _ = _seeded(tmp_path, source, at)
    rule = _rule()

    # This installation has measured the local model failing this pairing, repeatedly.
    for i in range(orch.config.llm_skip_after_failures + 2):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="python",
            algorithm="3DES",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="DES3.new(key, DES3.MODE_CBC)",
            failure_reason="unchanged",
            model_name=orch.config.model,
        )
    orch.session.add(
        LlmProviderConfig(
            id=1,
            provider="openai-compatible",
            base_url="https://api.groq.com/openai/v1",
            model="openai/gpt-oss-120b",
            api_key_encrypted=secrets_at_rest.encrypt("test-key"),
            # Groq's measured per-request allowance, far below the model's 131,072 context.
            context_tokens=8000,
        )
    )
    orch.session.commit()

    excerpt = build_excerpt(source, at)
    assert excerpt is not None

    # Sized on the whole file, nothing can take it -- which is what forced the local fallback.
    assert orch._select_engine(rule, source, "python") is None

    # Sized on the excerpt, the gate is honoured: the local model is skipped on its own measured
    # record, and the work goes to the engine that has none.
    picked = orch._select_engine(rule, excerpt.text, "python")
    assert picked is not None
    assert picked.endpoint is not None, "a gated local engine must not be handed the work anyway"
    assert picked.name == "openai-compatible:openai/gpt-oss-120b"


def test_an_excerpt_that_still_does_not_fit_falls_back_to_guidance(tmp_path, monkeypatch) -> None:
    """Windowing must not be allowed to clear the size refusal on a promise it cannot keep.

    A file whose import block alone runs longer than the budget produces an excerpt that is still
    too large. Sending it anyway hands a truncated prompt to the model and throws away the honest
    guided answer the refusal would have produced -- worse than not windowing at all.
    """
    source, at = _big_python()
    orch, task = _seeded(tmp_path, source, at)

    # Nothing fits, excerpt included.
    monkeypatch.setattr(
        MigrationOrchestrator, "_oversize_reason", lambda self, src: "too large for anything"
    )
    monkeypatch.setattr(
        "qubit_migrate.orchestrator.generate_llm_source",
        lambda *a, **kw: pytest.fail("an excerpt that does not fit must not be sent"),
    )

    with pytest.raises(GuidedRemediation):
        orch.generate_patch(task.id, generator="auto")


def test_an_engine_that_cannot_keep_the_marker_is_not_asked_a_third_time(monkeypatch) -> None:
    """Dropping the marker is not a repairable mistake, so it does not get the full repair budget.

    Measured on `evp_pkey_provided_test.c` (2,316 lines): the local 7B dropped the marker on 4 of
    4 attempts and spent 302 seconds being told the same thing three times, while gpt-oss-120b
    kept it in 9.0s and gemma-4-31b in 110.4s on the identical prompt. That makes it a property of
    the engine rather than of the phrasing -- one repair attempt is worth making, a second only
    spends time and quota. Failing sooner also records the outcome sooner, which is what lets the
    reliability gate route the next windowed finding to an engine that can answer it.
    """
    source, at = _big_python()
    calls: list[str] = []

    def drops_the_marker(prompt: str, *, model, base_url="x", timeout=0, **_):
        calls.append(prompt)
        body = prompt.rsplit("```python\n", 1)[1].rsplit("```", 1)[0]
        return "```python\n" + body.replace(llm.EXCERPT_MARKER + "\n", "") + "```\n"

    monkeypatch.setattr(llm, "installed_models", lambda base_url: [])
    monkeypatch.setattr(llm, "_ollama_generate", drops_the_marker)

    with pytest.raises(llm.OllamaError, match="exactly once"):
        llm.generate_llm_source(
            source,
            _rule(),
            _asset("app/seal.py", at),
            model="m",
            windowed=True,
            plan_first=False,
            self_review_pass=False,
        )

    assert len(calls) == 2, f"one attempt plus one repair, not the full budget; got {len(calls)}"
    # The second attempt must still have been TOLD what was wrong -- failing fast is not the same
    # as not trying.
    assert llm.EXCERPT_MARKER in calls[1]
    assert "REJECTED" in calls[1] or "exactly once" in calls[1]


def test_a_whole_file_rejection_is_restated_for_the_excerpt(monkeypatch) -> None:
    """The repair attempt has to be spent on the actual fault.

    Every check from `check_rewrite` onwards runs on the SPLICED file and speaks its language.
    Measured live on `evp_pkey_provided_test.c`: gemma-4-31b kept the marker, left one unbalanced
    brace inside its own region, and was told to "return the COMPLETE file" — an instruction it
    cannot follow, about a file it was never shown, that never mentions the brace.
    """
    source, at = _big_python()
    prompts: list[str] = []

    def unbalanced(prompt: str, *, model, base_url="x", timeout=0, **_):
        prompts.append(prompt)
        body = prompt.rsplit("```python\n", 1)[1].rsplit("```", 1)[0]
        # Marker kept, contract honoured — but one brace left open inside the region.
        return (
            "```python\n"
            + body.replace("cipher = DES3.new(key, DES3.MODE_CBC)", "cipher = AESGCM({key)")
            + "```\n"
        )

    monkeypatch.setattr(llm, "installed_models", lambda base_url: [])
    monkeypatch.setattr(llm, "_ollama_generate", unbalanced)

    with pytest.raises(llm.OllamaError):
        llm.generate_llm_source(
            source,
            _rule(),
            _asset("app/seal.py", at),
            model="m",
            windowed=True,
            plan_first=False,
            self_review_pass=False,
        )

    assert len(prompts) > 1, "the repair loop must have run"
    repair = prompts[1]
    assert "still editing an EXCERPT" in repair
    assert "closed inside them" in repair
    # The bare whole-file instruction must not be the last word the model reads on the subject.
    assert "That verdict is about the WHOLE file" in repair


def test_a_task_that_succeeds_stops_showing_its_old_failure(tmp_path, monkeypatch) -> None:
    """`last_error` was written and never cleared, so a retry that WORKED still displayed the
    failure that preceded it.

    Observed live: `evp_pkey_provided_test.c` reached `proposed` while still carrying "LLM rewrite
    rejected after 3 attempt(s): the returned file has unbalanced '{}' brackets" from the previous
    run. The Migrations queue renders that field as the task's reason, so an accepted patch read
    as a failed one.

    Uses the md5 -> sha256 migration deliberately: it is the one this suite can drive to a real
    `proposed` through the actual validator, so the assertion below is never skipped.
    """
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    src = tmp_path / "app.py"
    src.write_text("import hashlib\ndigest = hashlib.md5(data)\n", encoding="utf-8")
    asset = CryptoAsset(
        algorithm="MD5",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=str(src), line=2),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
        ),
    )
    session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()
    orch = MigrationOrchestrator(session)
    task = orch.get_queue(orch.build_plan().id)[0]

    def boom(prompt, *, model, base_url="x", timeout=0, **_):
        raise llm.OllamaError("the returned file has unbalanced '{}' brackets")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", boom)
    with pytest.raises(ValueError):
        orch.generate_patch(task.id, generator="llm")
    session.refresh(task)
    assert task.last_error and "unbalanced" in task.last_error, "baseline: the failure is recorded"

    monkeypatch.setattr(
        "qubit_migrate.transform.llm._ollama_generate",
        lambda prompt, *, model, base_url="x", timeout=0, **_: (
            "```python\nimport hashlib\ndigest = hashlib.sha256(data)\n```"
        ),
    )
    patch = orch.generate_patch(task.id, generator="llm")

    assert patch.status == "proposed", patch.validation_json
    session.refresh(task)
    assert task.last_error is None, f"stale failure survived a success: {task.last_error!r}"
