"""Spend model time only where the model can actually deliver.

The hybrid has four tiers -- deterministic codemod, the learned-patch cache, the local LLM, and a
written guided path -- but the choice between them was a fixed preference order that never looked
at whether the model could succeed. Two cases cost the full three attempts before the outcome was
even in doubt:

* **A file too large for the context window.** The window holds prompt AND answer, and a whole-file
  rewrite answers at roughly the length of its input. Measured on node-forge, `pkcs1.js` needs
  ~27,400 tokens and `rsa.js` ~20,900 against an 8,192-token window. Ollama truncates the prompt
  silently, so the model was shown a fragment and asked to return the whole file.

* **A (rule, language) pair that has never once succeeded here.** `learn.reliability` already
  recorded pass/fail per rule and language and was called by nothing. `code-kex-01` is the case:
  replacing RSA key transport with a KEM restructures the protocol, and the local 7B model
  completed 0 of them across two measured runs and eleven languages.

Neither is a refusal. Both route to the guided path -- a real remediation plan with steps, commands
and sources -- leave the task retryable, and are bypassed by an explicit `generator="llm"`.
"""

from __future__ import annotations

import uuid

import pytest
from qubit_core.db import Base
from qubit_migrate.config import MigrateConfig
from qubit_migrate.orchestrator import MigrationOrchestrator
from qubit_migrate.transform import learn
from qubit_migrate.transform.rules import load_rules
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

SMALL_GO = 'package main\n\nimport "crypto/rsa"\n\nfunc f(k *rsa.PublicKey) {}\n'


@pytest.fixture
def orch() -> MigrationOrchestrator:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return MigrationOrchestrator(Session(engine))


def _kex_rule():
    return next(r for r in load_rules() if r.id == "code-kex-01")


def test_a_normal_file_with_no_history_goes_to_the_model(orch: MigrationOrchestrator) -> None:
    """The default must stay "try the model" -- routing is an exception, not a gate."""
    assert orch._llm_detour_reason(_kex_rule(), SMALL_GO, "go") is None


def test_a_file_too_large_for_the_context_window_is_detoured(
    orch: MigrationOrchestrator,
) -> None:
    """The `pkcs1.js` case: 3.3x the window, so it could never have succeeded even once."""
    # Comfortably past 45% of the 8192-token default, at the ~3 chars/token estimate used
    # throughout (`llm._output_budget` uses the same figure).
    huge = SMALL_GO + ("// filler comment line to grow the file\n" * 1200)

    reason = orch._llm_detour_reason(_kex_rule(), huge, "go")

    assert reason is not None, "a file far past the context window must not be sent"
    assert "too large" in reason
    assert "context window" in reason, "the reason has to say what the limit actually was"


def test_one_engines_failures_do_not_block_a_different_engine(
    orch: MigrationOrchestrator,
) -> None:
    """A ceiling measured on one model is not a property of the task.

    The detour message has always promised that "re-running after a model or engine upgrade will
    try again automatically", but `reliability` pooled every engine's failures — so configuring a
    stronger model inherited the weaker one's record and was refused before its first attempt.
    Measured live on `py-signature-01`/python: enough local-7B failures to trip the gate, and a
    freshly configured 120B model was skipped on that evidence.
    """
    from qubit_core.db import secrets_at_rest
    from qubit_core.db.models import LlmProviderConfig

    rule = _kex_rule()
    for i in range(orch.config.llm_skip_after_failures + 2):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="go",
            algorithm="RSA-2048",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="rsa.EncryptOAEP(...)",
            failure_reason="unchanged",
            model_name=orch.config.model,
        )
    orch.session.commit()

    # The engine that accumulated those failures is still gated.
    assert orch._llm_detour_reason(rule, SMALL_GO, "go") is not None

    # A different engine has no record here and must get its own first attempt.
    orch.session.add(
        LlmProviderConfig(
            id=1,
            provider="openai-compatible",
            base_url="https://api.groq.com/openai/v1",
            model="openai/gpt-oss-120b",
            api_key_encrypted=secrets_at_rest.encrypt("test-key"),
            context_tokens=131072,
        )
    )
    orch.session.commit()

    assert orch._active_model_name() == "openai-compatible:openai/gpt-oss-120b"
    assert orch._llm_detour_reason(rule, SMALL_GO, "go") is None, (
        "a newly configured engine must not inherit another engine's failures"
    )


def _configure_two_externals(orch: MigrationOrchestrator) -> None:
    """A fast small-allowance endpoint plus a slow large-allowance one -- the real shape measured:
    Groq's `gpt-oss-120b` answers in ~3.6s within 8,000 tokens, while `gemma-4-31b-it` needs 64,000
    and took 899 seconds for one patch through the app.
    """
    from qubit_core.db import secrets_at_rest
    from qubit_core.db.models import LlmProviderConfig

    orch.session.add(
        LlmProviderConfig(
            id=1,
            provider="openai-compatible",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai",
            model="gemma-4-31b-it",
            api_key_encrypted=secrets_at_rest.encrypt("big-key"),
            context_tokens=64000,
            backup_base_url="https://api.groq.com/openai/v1",
            backup_model="openai/gpt-oss-120b",
            backup_api_key_encrypted=secrets_at_rest.encrypt("fast-key"),
            backup_context_tokens=8000,
        )
    )
    orch.session.commit()


def test_work_the_free_local_model_can_do_never_reaches_a_metered_engine(
    orch: MigrationOrchestrator,
) -> None:
    """Credits are only worth spending where they buy something.

    Measured on this installation, the local 7B has passed `code-signature-01`/go 518 times — so
    routing that to a metered endpoint would cost quota and change nothing.
    """
    _configure_two_externals(orch)

    chosen = orch._select_engine(_kex_rule(), SMALL_GO, "go")

    assert chosen is not None
    assert chosen.metered is False, "a small file with no failure history must stay local and free"
    assert chosen.name == orch.config.model


def test_work_the_local_model_has_proven_it_cannot_do_escalates_instead_of_going_to_advice(
    orch: MigrationOrchestrator,
) -> None:
    """The complaint this whole feature exists to fix.

    `code-kex-01` in c/go/ruby has failed on the local model every single time it has been tried,
    and those findings used to be answered with written guidance. With another engine configured
    they should ESCALATE — which is both faster (no three doomed local attempts at ~23s) and the
    only way to get an actual patch.
    """
    rule = _kex_rule()
    for i in range(orch.config.llm_skip_after_failures + 1):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="go",
            algorithm="RSA-2048",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="rsa.EncryptOAEP(...)",
            failure_reason="unchanged",
            model_name=orch.config.model,
        )
    orch.session.commit()

    # With nothing else configured this is genuinely the end of the road.
    assert orch._select_engine(rule, SMALL_GO, "go") is None
    assert orch._llm_detour_reason(rule, SMALL_GO, "go") is not None

    _configure_two_externals(orch)

    chosen = orch._select_engine(rule, SMALL_GO, "go")
    assert chosen is not None, "a ruled-out local pairing must escalate, not go to advice"
    assert chosen.metered is True
    # The FAST small-allowance endpoint, because the file fits it.
    assert chosen.name == "openai-compatible:openai/gpt-oss-120b"
    assert orch._llm_detour_reason(rule, SMALL_GO, "go") is None


def test_the_smallest_sufficient_engine_wins_and_the_big_one_is_reserved_for_big_files(
    orch: MigrationOrchestrator,
) -> None:
    """Smallest-that-fits is simultaneously the cheapest and the fastest choice, not a trade-off:
    the large-allowance engine measured 899s per patch against the small one's ~3.6s per call.
    """
    rule = _kex_rule()
    for i in range(orch.config.llm_skip_after_failures + 1):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="go",
            algorithm="RSA-2048",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="rsa.EncryptOAEP(...)",
            failure_reason="unchanged",
            model_name=orch.config.model,
        )
    orch.session.commit()
    _configure_two_externals(orch)

    # Fits the 8,000-token endpoint (3,600-token prompt budget).
    small = orch._select_engine(rule, SMALL_GO, "go")
    assert small is not None and small.name == "openai-compatible:openai/gpt-oss-120b"

    # Past 8,000 but inside 64,000 -> only the large endpoint can hold it.
    medium = SMALL_GO + ("// filler comment line to grow the file\n" * 400)
    picked = orch._select_engine(rule, medium, "go")
    assert picked is not None, f"{len(medium) // 3} tokens should still fit the 64k engine"
    assert picked.name == "openai-compatible:gemma-4-31b-it"

    # Past every allowance -> guidance is the honest answer.
    enormous = SMALL_GO + ("// filler comment line to grow the file\n" * 5000)
    assert orch._select_engine(rule, enormous, "go") is None


def test_unattributed_history_counts_toward_the_local_engine(
    orch: MigrationOrchestrator,
) -> None:
    """A row written before engine attribution existed came from the local model. Treating it as
    belonging to nobody would silently disable the gate on every pre-existing install.
    """
    rule = _kex_rule()
    for i in range(orch.config.llm_skip_after_failures + 2):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="go",
            algorithm="RSA-2048",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="rsa.EncryptOAEP(...)",
            failure_reason="unchanged",
            # No model_name: exactly what the older rows look like.
        )
    orch.session.commit()

    assert orch._llm_detour_reason(rule, SMALL_GO, "go") is not None


def test_the_window_follows_the_configured_engine_not_the_local_default(
    orch: MigrationOrchestrator,
) -> None:
    """A file too large for the LOCAL model must still be sent when a large-context external
    provider is the one actually configured.

    This is the guided-vs-patch decision, and gating it on the local model's window while an
    external engine is selected produces exactly the complaint this feature exists to fix:
    written advice for a file the configured model could have rewritten. Measured: the shipped 7B
    model reports an 8,192-token window, gpt-oss-120b reports 131,072 -- 16x.
    """
    from qubit_core.db import secrets_at_rest
    from qubit_core.db.models import LlmProviderConfig

    huge = SMALL_GO + ("// filler comment line to grow the file\n" * 1200)
    assert orch._llm_detour_reason(_kex_rule(), huge, "go") is not None, "baseline: local detours"

    orch.session.add(
        LlmProviderConfig(
            id=1,
            provider="openai-compatible",
            base_url="https://api.groq.com/openai/v1",
            model="openai/gpt-oss-120b",
            api_key_encrypted=secrets_at_rest.encrypt("test-key"),
            context_tokens=131072,
        )
    )
    orch.session.commit()

    assert orch._effective_context_tokens() == 131072
    assert orch._llm_detour_reason(_kex_rule(), huge, "go") is None, (
        "a file that fits the CONFIGURED model's window must get a real generation attempt"
    )


def test_the_window_falls_back_to_local_when_the_provider_reported_none(
    orch: MigrationOrchestrator,
) -> None:
    """NULL `context_tokens` means the provider never told us -- never a licence to assume a big
    window, because guessing high sends a file to a model that will silently truncate it.
    """
    from qubit_core.db import secrets_at_rest
    from qubit_core.db.models import LlmProviderConfig

    orch.session.add(
        LlmProviderConfig(
            id=1,
            provider="openai-compatible",
            base_url="https://example.com/v1",
            model="mystery",
            api_key_encrypted=secrets_at_rest.encrypt("test-key"),
            context_tokens=None,
        )
    )
    orch.session.commit()

    assert orch._effective_context_tokens() == orch.config.llm_context_tokens


def test_a_pair_the_model_has_never_completed_is_detoured(orch: MigrationOrchestrator) -> None:
    """Measured evidence from THIS installation, not a hardcoded blocklist."""
    rule = _kex_rule()
    for i in range(orch.config.llm_skip_after_failures):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="go",
            algorithm="RSA-2048",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="rsa.EncryptOAEP(...)",
            failure_reason="the model returned the file unchanged",
        )
    orch.session.commit()

    reason = orch._llm_detour_reason(rule, SMALL_GO, "go")

    assert reason is not None, "four straight failures and no success is enough evidence"
    assert "has completed" in reason
    assert "go" in reason, "the reason must name the language, since routing is per-language"


def test_one_success_keeps_the_pair_on_the_model(orch: MigrationOrchestrator) -> None:
    """Evidence of success outranks any amount of failure.

    A rule that works sometimes is worth attempting; the detour is only for a pair with NO
    successes at all. Otherwise a hard-but-solvable migration would be switched off by a bad run.
    """
    rule = _kex_rule()
    for i in range(orch.config.llm_skip_after_failures + 3):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="go",
            algorithm="RSA-2048",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="rsa.EncryptOAEP(...)",
            failure_reason="unchanged",
        )
    learn.record_outcome(
        orch.session,
        rule_id=rule.id,
        language="go",
        algorithm="RSA-2048",
        shape="shape-good",
        passed=True,
        hunk_before="rsa.EncryptOAEP(...)",
        hunk_after="ek.Encapsulate()",
    )
    orch.session.commit()

    assert orch._llm_detour_reason(rule, SMALL_GO, "go") is None


def test_failures_in_one_language_do_not_detour_another(orch: MigrationOrchestrator) -> None:
    """Routing is per (rule, language). Go's ceiling says nothing about Java's."""
    rule = _kex_rule()
    for i in range(orch.config.llm_skip_after_failures + 2):
        learn.record_outcome(
            orch.session,
            rule_id=rule.id,
            language="go",
            algorithm="RSA-2048",
            shape=f"shape-{i}",
            passed=False,
            hunk_before="rsa.EncryptOAEP(...)",
            failure_reason="unchanged",
        )
    orch.session.commit()

    assert orch._llm_detour_reason(rule, SMALL_GO, "go") is not None
    assert orch._llm_detour_reason(rule, SMALL_GO, "java") is None


def test_a_detoured_finding_stays_retryable_and_is_not_counted_as_outstanding(
    orch: MigrationOrchestrator,
) -> None:
    """A detour must park the task the same way a real failure does.

    `resume_task` and the bulk run's retry query both select ONLY `resolution == "unresolved"`,
    and the Migration Hub's progress split reads the same field to separate handled work from
    outstanding work. A first version of the router set `last_error` and left `resolution` NULL,
    which made a detoured finding the worst of both worlds: never picked up again when a better
    engine arrived, and counted as outstanding forever so its plan could never read complete.

    Caught on real data -- 31 ruby-jwt tasks sitting at `deferred` with a null resolution.
    """
    from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED
    from qubit_migrate.state import MigrationTask

    task = MigrationTask(
        plan_id=uuid.uuid4(),
        unit_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        state="ready",
        rule_id="code-kex-01",
        effort_points=3,
        priority=0.5,
        rank=1,
    )
    orch.session.add(task)
    orch.session.commit()

    orch._fail_task(task, "detoured: the local model has not completed this pairing")

    assert task.state == "deferred"
    assert task.resolution == RESOLUTION_UNRESOLVED, (
        "a detoured task must be parked exactly as a failed one is, or it is never retried "
        "and never counted as handled"
    )


def _signature_rule():
    return next(r for r in load_rules() if r.id == "code-signature-01")


class TestAnUnverifiableTargetIsNotSentToTheModel:
    """A rewrite the rescan could never confirm must not cost three model attempts.

    Stage 5 asserts `rescan_expect.present`, so a rule is only satisfiable in a language where the
    SCANNER can recognise the target algorithm. Where it cannot, the task is unwinnable by
    construction — a flawless migration still reports "expected ML-DSA, not found" — and the three
    attempts prove nothing that was not already decided.

    Found by measurement, not by reading: go-ethereum produced 0 successful migrations from 107
    signature findings, and the recorded failure reasons name the cause outright ("QUBIT ships no
    verified ML-DSA shape for go"). Go had `crypto/mlkem` detection and no ML-DSA rule at all,
    because ML-DSA is not in the Go standard library and the CIRCL package `code-signature-01`
    tells the model to use was never taught to the scanner.
    """

    def test_go_signatures_reach_the_model_now_that_ml_dsa_is_detectable(
        self, orch: MigrationOrchestrator
    ) -> None:
        """The regression that motivated the whole check: Go must NOT be detoured any more.

        Pins the scanner fix (GO-CIRCL-MLDSA) from the migrator's side — if Go ML-DSA detection is
        ever dropped, this fails here rather than silently costing another 107-finding run.
        """
        assert orch._llm_detour_reason(_signature_rule(), SMALL_GO, "go") is None

    @pytest.mark.parametrize("language", ["ruby", "php", "dart"])
    @pytest.mark.parametrize("rule_id", ["code-kex-01", "code-signature-01"])
    def test_a_language_with_no_verified_target_shape_is_detoured(
        self, orch: MigrationOrchestrator, language: str, rule_id: str
    ) -> None:
        """These three claim the rule but have no confirmable ML-KEM/ML-DSA shape.

        Deliberately routed rather than "fixed" by inventing an API: writing a PQC example for a
        language whose ecosystem has no settled one would be a fabrication, and the rescan would
        still have nothing to match. The honest answer is the guided path plus a reason that says
        the gap is QUBIT's, not the model's.
        """
        rule = next(r for r in load_rules() if r.id == rule_id)

        reason = orch._llm_detour_reason(rule, SMALL_GO, language)

        assert reason is not None, (
            f"{rule_id} in {language} has no verified target shape, so the rescan cannot pass — "
            f"sending it to the model spends three attempts to prove that"
        )
        assert "cannot yet confirm" in reason
        assert language in reason, "the reason must name the language whose detection is missing"

    def test_the_detour_reason_blames_qubit_not_the_model(
        self, orch: MigrationOrchestrator
    ) -> None:
        """Accuracy matters here: this is a coverage gap, not a model that failed.

        The reliability detour's wording ("the local model has not completed...") would be wrong
        for this case and would push a user toward swapping models, which fixes nothing.
        """
        reason = orch._llm_detour_reason(_signature_rule(), SMALL_GO, "ruby")

        assert reason is not None
        assert "scanner" in reason, "say which component is missing the capability"
        assert "local model has not completed" not in reason, "must not blame the model"


def test_a_file_the_model_cannot_write_back_is_windowed_not_attempted() -> None:
    """The prompt was checked for fit; the answer never was.

    A whole-file rewrite has to EMIT the whole file, so a file needing more tokens than
    `_MAX_PREDICT` cannot come back complete however well the model behaves: generation stops at
    the ceiling, the repair loop reads the unbalanced brackets as the model getting it wrong, and
    three attempts go on proving what arithmetic knew in advance.

    This bites only when the prompt allowance EXCEEDS the answer ceiling, which needs a context
    window past ~36k tokens -- at the 8k and 32k engines configured here the prompt check always
    fires first. It is a guard for the large-context models that are now ordinary (128k and up),
    where the output ceiling, not the context window, becomes the binding constraint.
    """
    from qubit_migrate.transform.llm import _MAX_PREDICT

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    orch = MigrationOrchestrator(Session(engine), MigrateConfig(llm_context_tokens=131_072))
    allowance = int(131_072 * orch.config.llm_max_prompt_fraction)
    assert allowance > _MAX_PREDICT, (
        "otherwise the prompt check fires first and this branch is unreachable"
    )

    # Reads comfortably; cannot be written back.
    source = "x" * ((_MAX_PREDICT + 2_000) * 3)
    reason = orch._oversize_reason(source)

    assert reason is not None, "a file the model cannot write back must not be sent whole"
    assert "cannot write it back" in reason
    assert f"{_MAX_PREDICT:,}" in reason


def test_a_file_that_fits_both_ways_is_still_sent_whole(orch: MigrationOrchestrator) -> None:
    """The answer check must not narrow what already worked: a file small enough to read AND to
    write back keeps the whole-file path, which is the one that produces the best patches."""
    assert orch._oversize_reason("x" * 2_000) is None
