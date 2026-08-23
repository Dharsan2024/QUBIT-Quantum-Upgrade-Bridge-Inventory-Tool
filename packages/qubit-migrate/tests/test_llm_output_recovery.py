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
