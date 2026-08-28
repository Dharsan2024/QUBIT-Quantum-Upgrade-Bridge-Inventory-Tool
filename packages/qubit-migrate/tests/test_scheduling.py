"""The routing policy, tested without a model, a network or a database.

`scheduling.choose` is deliberately pure, so the decision QUBIT makes about *when to spend a
rationed request* can be examined directly. Every figure these tests are built on was measured on
this installation rather than assumed:

* Mistral `codestral-2508` answers a real migration in ~1.0s; Groq `gpt-oss-120b` in ~2.0s;
  NVIDIA `nemotron-3-ultra-550b` in ~68s even with reasoning disabled.
* Groq rations **1,000 requests per day** and 8,000 tokens per minute, and reports its token
  window refilling as a duration (`7.66s`, `2m59.56s`); its 429 says *"try again in 4.86s"*.
* NVIDIA's `poolside/laguna-xs-2.1` answers in ~2s but returned 503 "ResourceExhausted" on 3 of 4
  attempts -- fast and flaky, which is what the failover queue exists for.
* The local 7B has passed `code-signature-01`/go 518 times, and never satisfied the windowed
  structured-output contract in 4 attempts.

A note on the default prompt fraction, which several tests lean on: at 0.45 a local 8,192-token
window allows 3,686 tokens of prompt and a hosted 32,000-token one allows 14,400. So a 10,000-token
prompt is the standard way here of taking the free engine out of the running *legitimately* -- the
rules that follow are about which METERED engine then gets the work, and with a free engine still
viable the answer would always be "the free one".
"""

from __future__ import annotations

from qubit_migrate.scheduling import DEFAULT_RESERVE_REQUESTS, EngineOffer, choose

LOCAL = EngineOffer(name="local", metered=False, budget_tokens=8192)
HOSTED = EngineOffer(name="hosted", metered=True, budget_tokens=32000, remaining_requests=900)

#: Bigger than the local window allows, so only metered engines can take it.
TOO_BIG_FOR_LOCAL = 10000


def test_a_free_engine_that_can_do_the_work_keeps_it_however_slow_it_is() -> None:
    """The rule that makes the rest of the quota affordable.

    Ranking on expected time instead would hand every finding to a hosted tier from the very first
    call: an untried engine has no measured latency, so a metered default of 5s beats a local
    default of 600s every time, and a day's 1,000 requests would go on work that was already free.
    """
    decision = choose(
        [
            EngineOffer(
                name="local", metered=False, budget_tokens=8192, passed=518, seconds_per_call=840.0
            ),
            EngineOffer(
                name="hosted",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                seconds_per_call=1.0,
            ),
        ],
        prompt_tokens=1000,
    )

    assert decision.engine == "local", decision.reason
    assert "518" in decision.reason


def test_an_untried_free_engine_still_outranks_a_fast_hosted_one() -> None:
    """Escalation is driven by evidence, never by a preference for the better model.

    A free engine with no record has not been shown to be incapable, and the gates that DO move
    work off it -- a measured failure record, a file too large for its window, a structured-output
    contract it has never satisfied -- are each tested below. Until one fires, the rationed request
    is not worth spending.
    """
    decision = choose(
        [
            EngineOffer(name="local", metered=False, budget_tokens=8192, seconds_per_call=840.0),
            EngineOffer(
                name="hosted",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                seconds_per_call=1.0,
            ),
        ],
        prompt_tokens=1000,
    )

    assert decision.engine == "local", decision.reason


def test_a_mixed_record_does_not_push_a_free_engine_off_work_it_mostly_does() -> None:
    """Only a record of failures with NO successes gates an engine, so a single stale failure
    cannot push a 518-success pairing onto a rationed tier."""
    decision = choose(
        [
            EngineOffer(
                name="local",
                metered=False,
                budget_tokens=8192,
                passed=518,
                failed=1,
                seconds_per_call=840.0,
            ),
            HOSTED,
        ],
        prompt_tokens=1000,
    )

    assert decision.engine == "local", decision.reason


def test_an_engine_that_has_only_ever_failed_this_pairing_is_skipped() -> None:
    """The gate that lets free-first coexist with getting work done: an engine measured as unable
    to do this exact (rule, language) does not get it again, and the finding escalates."""
    decision = choose(
        [EngineOffer(name="local", metered=False, budget_tokens=8192, failed=4), HOSTED],
        prompt_tokens=1000,
    )

    assert decision.engine == "hosted"
    assert ("local", "4 failures and no success on this rule and language") in decision.rejected


def test_structured_output_work_avoids_an_engine_that_has_never_produced_one() -> None:
    """Measured: the local 7B dropped the required marker on 4 of 4 windowed attempts while both
    hosted engines kept it. Sending it there spends the whole repair budget to reach a foregone
    conclusion."""
    offers = [
        EngineOffer(
            name="local", metered=False, budget_tokens=8192, passed=518, follows_contracts=False
        ),
        HOSTED,
    ]

    assert choose(offers, prompt_tokens=1000).engine == "local"
    assert choose(offers, prompt_tokens=1000, needs_contract=True).engine == "hosted"


def test_a_file_too_big_for_the_local_window_goes_to_the_larger_engine() -> None:
    """The window has to hold the ANSWER as well as the prompt, so fit is checked before anything
    else -- an engine that cannot physically receive the file is not a candidate at any price."""
    decision = choose([LOCAL, HOSTED], prompt_tokens=TOO_BIG_FOR_LOCAL)

    assert decision.engine == "hosted", decision.reason
    assert ("local", "prompt 10,000 tokens exceeds its 3,686 budget") in decision.rejected


def test_a_file_too_big_for_every_engine_is_routed_nowhere() -> None:
    """Not an error: `generate_patch` answers an oversize finding with an excerpt or with written
    guidance, and either beats a request that cannot fit in any window."""
    decision = choose([LOCAL, HOSTED], prompt_tokens=20000)

    assert decision.engine is None
    assert len(decision.rejected) == 2
    assert all("exceeds" in why for _, why in decision.rejected)


def test_the_ranked_runners_up_are_returned_for_failover() -> None:
    """Routing picks the best engine available; it cannot know a provider will answer 503.

    NVIDIA's `poolside/laguna-xs-2.1` answers in ~2s and returned 503 on 3 of 4 attempts. An engine
    that good and that flaky is only usable if the next one picks the work up, so the decision
    carries the whole queue behind the choice rather than one arbitrary spare.
    """
    decision = choose(
        [
            EngineOffer(name="local", metered=False, budget_tokens=8192, seconds_per_call=840.0),
            EngineOffer(
                name="slow-hosted",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                seconds_per_call=68.0,
            ),
            EngineOffer(
                name="fast-hosted",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                seconds_per_call=2.0,
            ),
        ],
        prompt_tokens=1000,
    )

    assert decision.engine == "local"
    assert decision.alternatives == ("fast-hosted", "slow-hosted"), "best first"


def test_an_engine_rejected_outright_is_not_offered_as_a_fallback() -> None:
    """A fallback queue of engines that were already refused would just spend requests to
    rediscover the refusal."""
    decision = choose(
        [
            EngineOffer(name="healthy", metered=True, budget_tokens=32000, remaining_requests=900),
            EngineOffer(name="broke", metered=True, budget_tokens=32000, remaining_requests=0),
            EngineOffer(name="tiny", metered=True, budget_tokens=4000, remaining_requests=900),
        ],
        prompt_tokens=TOO_BIG_FOR_LOCAL,
    )

    assert decision.engine == "healthy"
    assert decision.alternatives == ()
    assert dict(decision.rejected)["broke"] == "daily request quota exhausted"


def test_the_last_requests_of_the_day_are_held_in_reserve() -> None:
    """A day's quota belongs to the operator, not to one run: a bulk migration that spends the
    final requests leaves nothing for the verification pass that would prove it worked."""
    decision = choose(
        [
            EngineOffer(name="nearly-out", metered=True, budget_tokens=32000, remaining_requests=5),
            EngineOffer(name="plenty", metered=True, budget_tokens=32000, remaining_requests=900),
        ],
        prompt_tokens=TOO_BIG_FOR_LOCAL,
    )

    assert decision.engine == "plenty"
    assert "held in reserve" in dict(decision.rejected)["nearly-out"]
    assert DEFAULT_RESERVE_REQUESTS >= 5


def test_a_provider_that_reports_nothing_is_not_treated_as_exhausted() -> None:
    """Google's OpenAI-compatible endpoint sends no rate-limit headers, and NVIDIA's sends none
    either. `None` means "this provider does not say" -- reading it as zero would silently disable
    every engine that happens to be quiet.
    """
    decision = choose(
        [
            EngineOffer(
                name="quiet",
                metered=True,
                budget_tokens=32000,
                remaining_requests=None,
                remaining_tokens=None,
                seconds_per_call=2.0,
            )
        ],
        prompt_tokens=TOO_BIG_FOR_LOCAL,
    )

    assert decision.engine == "quiet", decision.reason
    assert not decision.rejected


def test_a_refilling_token_window_is_waited_for_rather_than_abandoned() -> None:
    """A token window refills; a daily quota does not. Groq's own 429 says *"try again in 4.86s"*,
    and waiting that out beats abandoning a 2s engine for a 68s one."""
    decision = choose(
        [
            EngineOffer(
                name="refilling",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                remaining_tokens=10,
                reset_tokens_s=4.86,
                seconds_per_call=2.0,
            ),
            EngineOffer(
                name="slow-but-ready",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                seconds_per_call=68.0,
            ),
        ],
        prompt_tokens=TOO_BIG_FOR_LOCAL,
    )

    assert decision.engine == "refilling"
    assert decision.wait_seconds == 4.86
    assert "token window" in decision.reason


def test_a_window_that_takes_too_long_is_not_worth_waiting_for() -> None:
    """The other side of the same rule: past `MAX_WAIT_SECONDS` an engine that is ready now wins,
    even if it is far slower per call."""
    decision = choose(
        [
            EngineOffer(
                name="refilling-slowly",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                remaining_tokens=10,
                reset_tokens_s=600.0,
                seconds_per_call=2.0,
            ),
            EngineOffer(
                name="slow-but-ready",
                metered=True,
                budget_tokens=32000,
                remaining_requests=900,
                seconds_per_call=68.0,
            ),
        ],
        prompt_tokens=TOO_BIG_FOR_LOCAL,
    )

    assert decision.engine == "slow-but-ready"
    assert "too long to wait" in dict(decision.rejected)["refilling-slowly"]


def test_no_engine_at_all_is_an_answer_not_an_error() -> None:
    """Returning None routes the finding to written guidance. That is a verdict -- spending
    fourteen minutes to confirm what the history already says would not be."""
    decision = choose(
        [EngineOffer(name="local", metered=False, budget_tokens=8192, failed=9)],
        prompt_tokens=1000,
    )

    assert decision.engine is None
    assert not decision.routed
    assert decision.rejected
