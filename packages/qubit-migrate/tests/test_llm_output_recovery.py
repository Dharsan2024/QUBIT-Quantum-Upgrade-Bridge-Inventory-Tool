"""Answers that were thrown away for being badly wrapped rather than wrong.

Twelve LLM migrations failed on the polyglot corpus. Five of them were not the model being wrong
about cryptography:

    the returned file has only 9 non-blank lines vs the original's 47   (x3)
    Model output contained no fenced code block                          (x2)

The first three were `num_predict` fixed at 4096 regardless of file size, so a large file could not
fit its own rewrite in the output budget and came back cut in half. The reported symptom -- a short
file -- accused the model of deleting code it had actually been interrupted while writing, and the
repair loop then spent two more attempts arguing with it.

The other two were formatting: the model returned the file without fences.

Both are recoverable without a better model, which is the only kind of fix available on a machine
running a 7B local model. These tests pin the recovery, and pin the limits on it -- accepting an
apology as source code would be worse than failing.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform.llm import (
    _MAX_PREDICT,
    _MIN_PREDICT,
    ModelOutputError,
    OllamaError,
    _output_budget,
    extract_code_block,
)
from qubit_migrate.transform.rules import MigrationRule


def _rule() -> MigrationRule:
    """The smallest rule the prompt builder will accept."""
    return MigrationRule(
        id="test-rule",
        language="python",
        title="test",
        matches={},
        target={"algorithm": "ML-KEM-768"},
        raw={},
    )


def _asset():  # type: ignore[no-untyped-def]
    import uuid
    from datetime import UTC, datetime

    from qubit_core import CryptoAsset
    from qubit_core.schemas import (
        AssetType,
        Location,
        QuantumAttack,
        QuantumVulnerability,
        SourceScanner,
        UsageContext,
    )

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


class TestOutputBudget:
    def test_a_small_file_still_gets_the_floor(self) -> None:
        assert _output_budget("short prompt") == _MIN_PREDICT

    def test_a_large_file_gets_more_than_the_old_fixed_budget(self) -> None:
        """The bug: 4096 tokens regardless of input, so a big file could not fit its own rewrite."""
        big = "x" * 60_000
        assert _output_budget(big) > 4096

    def test_the_budget_grows_with_the_prompt(self) -> None:
        assert _output_budget("y" * 90_000) > _output_budget("y" * 30_000)

    def test_it_is_capped(self) -> None:
        """A local 7B model cannot produce an unbounded answer inside the timeout."""
        assert _output_budget("z" * 10_000_000) == _MAX_PREDICT


class TestCodeExtraction:
    def test_a_closed_fence_is_preferred(self) -> None:
        text = "Here is the file:\n```python\nimport oqs\n```\n"
        assert extract_code_block(text).strip() == "import oqs"

    def test_the_largest_block_wins_when_there_are_several(self) -> None:
        text = "```\nshort\n```\nand\n```python\nline one\nline two\nline three\n```"
        assert "line three" in extract_code_block(text)

    def test_an_unterminated_fence_is_recovered(self) -> None:
        """A truncated answer opens a fence and never closes it.

        The content is still the model's own marked code. Discarding it loses a rewrite that is
        merely incomplete -- and the caller's length check reports that accurately.
        """
        text = "```python\nimport oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')"
        recovered = extract_code_block(text)
        assert "ML-KEM-768" in recovered

    def test_bare_code_with_no_fence_is_accepted(self) -> None:
        text = "import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')\n"
        assert "ML-KEM-768" in extract_code_block(text)

    @pytest.mark.parametrize(
        "prose",
        [
            "I cannot rewrite this file because it uses a library I do not know.\nSorry.",
            "Sure! Here is what you would need to change.\nFirst, replace RSA.",
            "Unfortunately the file is too large to process.\nTry a smaller one.",
        ],
    )
    def test_prose_is_refused_rather_than_treated_as_source(self, prose: str) -> None:
        """The guard on the last-resort path. An apology accepted as a file would be worse than
        the failure it replaces: it would reach the validator as a patch that deletes the code."""
        with pytest.raises(OllamaError, match="no fenced code block"):
            extract_code_block(prose)

    def test_a_single_line_of_bare_text_is_refused(self) -> None:
        """One line is far more likely to be a refusal than a whole rewritten file."""
        with pytest.raises(OllamaError, match="no fenced code block"):
            extract_code_block("Done.")

    def test_empty_output_is_refused(self) -> None:
        with pytest.raises(OllamaError, match="no fenced code block"):
            extract_code_block("   \n  ")


class TestRetryableVersusFatal:
    """Which failures get another attempt, and which end immediately.

    These need opposite handling and used to share one exception. A truncated answer is the model
    getting it wrong, and the repair loop exists precisely to tell it so -- but generation sat
    OUTSIDE the loop's `try`, so a truncation ended the attempt on the spot. Measured on Crypto.kt
    and Ledger.scala: two ~400-character files the model looped on until it exhausted the output
    budget, given no second chance to be told to stop rambling.

    A server that is not running is the opposite case. Retrying it three times makes the user wait
    three times as long to read the same sentence.
    """

    def test_output_errors_are_a_subclass_so_old_handlers_still_catch_them(self) -> None:
        assert issubclass(ModelOutputError, OllamaError)

    def test_a_truncated_answer_is_retryable(self) -> None:
        from qubit_migrate.transform import llm

        calls: list[str] = []

        def fake_generate(prompt: str, **_: object) -> str:
            # The self-review pass is a second call to the same server. Counting it
            # here would count a different property: this test is about the DRAFT
            # being re-prompted after a truncation, which the review is not part of.
            if "You are reviewing a cryptographic migration patch" in prompt:
                return "VERDICT: OK"
            calls.append(prompt)
            if len(calls) == 1:
                raise ModelOutputError("hit its output limit before finishing the file")
            return "```python\nimport oqs\n```"

        original = llm._ollama_generate
        original_installed = llm.installed_models
        llm._ollama_generate = fake_generate  # type: ignore[assignment]
        llm.installed_models = lambda *a, **k: ["test"]  # type: ignore[assignment]
        try:
            out = llm.generate_llm_source(
                "import rsa\n",
                _rule(),
                _asset(),
                model="test",
                verify=None,
            )
        finally:
            llm._ollama_generate = original  # type: ignore[assignment]
            llm.installed_models = original_installed  # type: ignore[assignment]

        assert len(calls) == 2, "a truncated answer must be re-prompted, not abandoned"
        assert "import oqs" in out
        assert "output limit" in calls[1], "the second prompt must say what went wrong"

    def test_a_transport_failure_is_not_retried(self) -> None:
        from qubit_migrate.transform import llm

        calls: list[str] = []

        def fake_generate(prompt: str, **_: object) -> str:
            calls.append(prompt)
            raise OllamaError("Ollama is not reachable at http://127.0.0.1:11434")

        original = llm._ollama_generate
        original_installed = llm.installed_models
        llm._ollama_generate = fake_generate  # type: ignore[assignment]
        llm.installed_models = lambda *a, **k: ["test"]  # type: ignore[assignment]
        try:
            with pytest.raises(OllamaError, match="not reachable"):
                llm.generate_llm_source(
                    "import rsa\n", _rule(), _asset(), model="test", verify=None
                )
        finally:
            llm._ollama_generate = original  # type: ignore[assignment]
            llm.installed_models = original_installed  # type: ignore[assignment]

        assert len(calls) == 1, "a dead server must not be asked three times"


class TestTheAnswerBudgetFitsTheAnswer:
    """`num_predict` has to hold a whole REWRITTEN file, which is longer than the original.

    Measured across every before/after pair in the rule pack, a structural migration
    (kex/signature) expands the file by a mean of 3.15x and up to 5.3x: replacing public-key
    encryption with a KEM is a KEM+DEM construction with new imports, a derived key, a nonce and
    an AEAD call where there was one line. Even the "simple" swaps average 2.56x.

    Budgeting from the PROMPT instead of the file made this correct only for small files, and the
    reason is arithmetic: prompt = instructions + example + file, so `len(prompt)/3` covers a
    3.15x answer only while instructions + example exceed ~2.15x the file. True at 40 lines, false
    at 200. That is exactly what the run showed — three of five recorded Go rejections were
    `num_predict` truncation at the 4096 floor, reported as the model failing the task.
    """

    def test_a_mid_size_file_is_not_truncated(self) -> None:
        """The band that actually broke: fits the prompt gate, answer did not fit the budget."""
        from qubit_migrate.transform.llm import _output_budget

        source = "x" * (200 * 45)  # ~200 lines of Go at ~45 chars/line
        prompt = ("instructions and example " * 200) + source

        budget = _output_budget(prompt, source)
        needed = int(len(source) * 3.15) // 3  # the measured structural expansion

        assert budget >= needed, (
            f"a {len(source)}-char file needs ~{needed} output tokens for a structural rewrite "
            f"but only {budget} were allowed — the answer is cut off and a possibly-correct "
            f"rewrite is thrown away as 'truncated'"
        )

    def test_every_file_the_router_admits_can_have_its_answer_emitted(self) -> None:
        """The invariant that makes truncation unreachable rather than merely less likely.

        The router already refuses files whose PROMPT will not fit the context window. This pins
        the other half: the largest file it still admits must have an answer budget big enough for
        a 3.15x expansion, so no file can pass the input gate only to be truncated on output.
        """
        from qubit_migrate.config import MigrateConfig
        from qubit_migrate.transform.llm import _output_budget

        config = MigrateConfig()
        largest_admitted = int(config.llm_context_tokens * config.llm_max_prompt_fraction) * 3
        source = "x" * largest_admitted

        budget = _output_budget(source + ("scaffolding " * 400), source)
        needed = int(largest_admitted * 3.15) // 3

        assert budget >= needed, (
            f"the router admits files up to {largest_admitted} chars, but the answer budget tops "
            f"out at {budget} tokens against the ~{needed} such a file needs. Raise "
            f"_MAX_PREDICT or lower llm_max_prompt_fraction so the two gates agree."
        )

    def test_a_small_file_keeps_the_floor_and_is_not_penalised(self) -> None:
        """The fix may only ever RAISE a budget. A small file must still get the 4096 floor."""
        from qubit_migrate.transform.llm import _MIN_PREDICT, _output_budget

        tiny = "package main\nfunc f() {}\n"
        assert _output_budget(tiny, tiny) == _MIN_PREDICT

    def test_the_source_aware_budget_never_lowers_the_prompt_derived_one(self) -> None:
        """A caller with no source in hand must not come off worse than before the change."""
        from qubit_migrate.transform.llm import _output_budget

        prompt = "y" * 60_000
        assert _output_budget(prompt, "") == _output_budget(prompt)
        assert _output_budget(prompt, "x" * 100) >= _output_budget(prompt)
