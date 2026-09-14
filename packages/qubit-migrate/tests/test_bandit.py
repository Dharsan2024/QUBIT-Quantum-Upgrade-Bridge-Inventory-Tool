"""Thompson sampling over engines: explore the untried, fade the failing, revive the unlucky.

The behaviours below are the reason for sampling rather than ranking by success rate. Each is
asserted statistically over many draws with a seeded generator, because a single draw proves
nothing about a randomised policy and a test that asserts on one is a coin flip wearing a green
tick.
"""

from __future__ import annotations

import random
from collections import Counter

import pytest
from qubit_migrate.bandit import DECAY, Posterior, observe, reward_for, thompson_order
from qubit_migrate.scheduling import EngineOffer, choose


def _trained(reward: float, times: int) -> Posterior:
    p = Posterior()
    for _ in range(times):
        p = observe(p, reward)
    return p


def _first_choice_counts(posteriors: dict[str, Posterior], draws: int = 3000) -> Counter[str]:
    rng = random.Random(20260902)
    names = list(posteriors)
    return Counter(thompson_order(names, posteriors, rng=rng)[0] for _ in range(draws))


class TestTheRewardIsGraded:
    """`accepted / rejected` cannot tell an engine that reaches L2 from one that reaches L3."""

    @pytest.mark.parametrize(
        ("level", "expected"),
        [(None, 0.0), (-1, 0.0), (0, 0.2), (1, 0.4), (2, 0.6), (3, 0.8), (4, 1.0)],
    )
    def test_each_rung_scores_differently(self, level: int | None, expected: float) -> None:
        assert reward_for(level) == pytest.approx(expected)

    def test_no_evidence_scores_zero_rather_than_negative(self) -> None:
        """The ladder starts at -1. Dividing that directly gives a NEGATIVE reward, which a Beta
        posterior cannot represent and which would corrupt the counts silently."""
        assert reward_for(-1) == 0.0
        assert observe(Posterior(), reward_for(-1)).beta > Posterior().beta

    def test_a_missing_record_is_counted_as_a_failure_not_skipped(self) -> None:
        """Dropping it would make an engine that fails silently look untried rather than
        unsuccessful."""
        assert reward_for(None) == 0.0

    def test_an_out_of_range_level_is_clamped(self) -> None:
        assert reward_for(99) == 1.0
        assert reward_for(-99) == 0.0

    def test_a_partial_outcome_moves_both_parameters(self) -> None:
        """An L2 patch is genuinely partial evidence. Thresholding it to a win or a loss throws
        away the distinction the ladder exists to make."""
        after = observe(Posterior(), reward_for(2))
        assert after.alpha > Posterior().alpha * DECAY
        assert after.beta > Posterior().beta * DECAY


class TestExploreFadeRevive:
    """The three behaviours the build plan names, each measured over many draws."""

    def test_a_never_tried_engine_is_explored(self) -> None:
        """Ranking by success rate gives an untried engine no way in at all — its mean sits below
        any engine with a single success, forever."""
        counts = _first_choice_counts(
            {"proven": _trained(reward_for(3), 20), "untried": Posterior()}
        )
        assert counts["untried"] > 0, "an untried engine must sometimes be tried"

    def test_a_proven_engine_is_still_preferred(self) -> None:
        """Exploration that does not exploit is just a shuffle."""
        counts = _first_choice_counts(
            {"proven": _trained(reward_for(3), 20), "untried": Posterior()}
        )
        assert counts["proven"] > counts["untried"] * 2

    def test_a_repeatedly_failing_engine_fades(self) -> None:
        counts = _first_choice_counts(
            {
                "proven": _trained(reward_for(3), 20),
                "failing": _trained(reward_for(-1), 12),
            }
        )
        assert counts["failing"] < counts["proven"] / 20

    def test_the_engine_the_old_rule_would_ban_is_still_reachable(self) -> None:
        """The property that separates this from the skip-after-4-failures rule it sits above.

        Four failures and no success is exactly the threshold at which the existing gate skips an
        engine permanently, on four observations. Here it is merely unlikely — measured below at a
        few draws per thousand — so a provider that changes the model behind a name, or a quota
        that is raised, can still be discovered.

        Stated honestly: this is about the engine at the BAN THRESHOLD. An engine that has failed
        twelve times running is not practically reachable by a draw, and should not be; its route
        back is `test_an_engine_that_starts_succeeding_recovers` plus the ordering property below.
        """
        counts = _first_choice_counts(
            {
                "proven": _trained(reward_for(3), 20),
                "at-the-threshold": _trained(reward_for(-1), 4),
            },
            draws=8000,
        )
        assert counts["at-the-threshold"] > 0, "the engine the old rule bans must still be tried"

    def test_a_faded_engine_stays_in_the_ordering(self) -> None:
        """The real revival mechanism, and it does not depend on winning a draw.

        The caller tries the ordering in sequence and falls through on failure, so an engine that
        never wins first place is still reached when those ahead of it fail. Dropping it from the
        list is what "banned" would actually mean — and nothing here does that, however bad its
        record.
        """
        posteriors = {
            "proven": _trained(reward_for(3), 20),
            "hopeless": _trained(reward_for(-1), 50),
        }
        rng = random.Random(4)
        for _ in range(200):
            assert set(thompson_order(list(posteriors), posteriors, rng=rng)) == set(posteriors)

    def test_an_engine_that_starts_succeeding_recovers(self) -> None:
        """Revival is not merely possible in principle — evidence must actually move it back."""
        sunk = _trained(reward_for(-1), 12)
        revived = sunk
        for _ in range(25):
            revived = observe(revived, reward_for(4))
        assert revived.mean > sunk.mean * 3

    def test_decay_lets_old_evidence_expire(self) -> None:
        """Without it a month-old verdict outlives the machine it was true on."""
        undecayed = Posterior()
        decayed = Posterior()
        for _ in range(40):
            undecayed = observe(undecayed, reward_for(-1), decay=1.0)
            decayed = observe(decayed, reward_for(-1))
        assert decayed.observations < undecayed.observations


class TestItOnlyReorders:
    """The safety property. Exploration must never reach past a filter."""

    def test_the_result_is_a_permutation_of_the_input(self) -> None:
        """A scheduler whose exploration can re-admit a rejected engine is a random number
        generator with extra steps: it would send a prompt to an engine too small to hold it, or
        spend a quota already reserved."""
        rng = random.Random(1)
        candidates = ["a", "b", "c", "d"]
        for _ in range(500):
            got = thompson_order(candidates, {}, rng=rng)
            assert sorted(got) == sorted(candidates)

    def test_an_engine_absent_from_the_candidates_is_never_returned(self) -> None:
        """Even with an overwhelming posterior — the filters, not the evidence, decide who is
        eligible."""
        posteriors = {
            "filtered-out": _trained(reward_for(4), 100),
            "eligible": _trained(reward_for(-1), 20),
        }
        rng = random.Random(2)
        for _ in range(300):
            assert thompson_order(["eligible"], posteriors, rng=rng) == ["eligible"]

    def test_an_unknown_candidate_uses_the_uniform_prior(self) -> None:
        """An engine with no history must be rankable, not crash the router."""
        assert thompson_order(["brand-new"], {}, rng=random.Random(3)) == ["brand-new"]

    def test_ties_fall_back_to_the_callers_cost_order(self) -> None:
        """The caller has already sorted by expected cost. When two engines draw identically the
        cheaper one must still win, rather than the order becoming arbitrary.

        The names are deliberately in an order that ALPHABETICAL sorting would reverse, so a
        tie-break that quietly sorted by name — the obvious way to make a sort "deterministic" —
        is caught rather than passing by coincidence.
        """

        class _Fixed(random.Random):
            def betavariate(self, alpha: float, beta: float) -> float:
                return 0.5

        assert thompson_order(["z-cheap", "a-dear"], {}, rng=_Fixed()) == ["z-cheap", "a-dear"]

    def test_one_draw_per_engine_per_call(self) -> None:
        """Sampling inside the comparator makes it inconsistent, and the result then depends on
        the sort's access pattern rather than on the evidence."""
        calls = 0

        class _Counting(random.Random):
            def betavariate(self, alpha: float, beta: float) -> float:
                nonlocal calls
                calls += 1
                return super().betavariate(alpha, beta)

        thompson_order(["a", "b", "c", "d", "e"], {}, rng=_Counting())
        assert calls == 5


class TestReproducibility:
    def test_the_same_seed_gives_the_same_order(self) -> None:
        """The evaluation has to replay a routing decision exactly. `secrets` cannot be seeded,
        which is why this uses `random` — it orders engines, never key material."""
        posteriors = {"a": _trained(reward_for(2), 5), "b": _trained(reward_for(3), 5)}
        first = thompson_order(["a", "b"], posteriors, rng=random.Random(99))
        second = thompson_order(["a", "b"], posteriors, rng=random.Random(99))
        assert first == second


class TestItComposesWithTheFilters:
    """Through `choose()` itself. The bandit may reorder survivors and nothing else.

    Tested here rather than on `thompson_order` alone because the property that matters is about
    the whole scheduler: a filter that the bandit can reach past is not a filter.
    """

    @staticmethod
    def _offer(name: str, **kw: object) -> EngineOffer:
        base: dict[str, object] = {
            "name": name,
            "metered": False,
            "budget_tokens": 100_000,
            "seconds_per_call": 1.0,
        }
        return EngineOffer(**{**base, **kw})  # type: ignore[arg-type]

    #: An overwhelming posterior, to prove the filters win anyway.
    _IRRESISTIBLE = _trained(reward_for(4), 200)

    def test_no_posteriors_leaves_the_cost_ranking_untouched(self) -> None:
        """An installation that has recorded no evidence yet behaves exactly as before."""
        offers = [
            self._offer("slow", seconds_per_call=90.0),
            self._offer("fast", seconds_per_call=1.0),
        ]
        assert choose(offers, prompt_tokens=100).engine == "fast"

    def test_a_context_window_rejection_survives_any_posterior(self) -> None:
        """The prompt does not fit. No amount of past success makes it fit."""
        offers = [
            self._offer("too-small", budget_tokens=100),
            self._offer("big-enough", budget_tokens=100_000),
        ]
        decision = choose(
            offers,
            prompt_tokens=10_000,
            posteriors={"too-small": self._IRRESISTIBLE},
            rng=random.Random(11),
        )
        assert decision.engine == "big-enough"
        assert "too-small" not in (decision.alternatives or ())

    def test_a_quota_reserve_survives_any_posterior(self) -> None:
        """The reserve is held back deliberately. Exploration must not spend it."""
        offers = [
            self._offer("nearly-empty", metered=True, remaining_requests=1),
            self._offer("free", metered=False),
        ]
        decision = choose(
            offers,
            prompt_tokens=100,
            posteriors={"nearly-empty": self._IRRESISTIBLE},
            rng=random.Random(12),
        )
        assert decision.engine == "free"
        assert any(name == "nearly-empty" for name, _ in decision.rejected)

    def test_the_contract_filter_survives_any_posterior(self) -> None:
        offers = [
            self._offer("no-contract", follows_contracts=False),
            self._offer("keeps-contract", follows_contracts=True),
        ]
        decision = choose(
            offers,
            prompt_tokens=100,
            needs_contract=True,
            posteriors={"no-contract": self._IRRESISTIBLE},
            rng=random.Random(13),
        )
        assert decision.engine == "keeps-contract"

    def test_the_retirement_gate_survives_any_posterior(self) -> None:
        """Four failures and no success is a hard skip in `choose`. The bandit sits ABOVE it, so
        a retired pairing is still not offered — the exploration it enables is over engines the
        gate already admitted."""
        offers = [
            self._offer("retired", passed=0, failed=9),
            self._offer("ok", passed=3, failed=0),
        ]
        decision = choose(
            offers,
            prompt_tokens=100,
            posteriors={"retired": self._IRRESISTIBLE},
            rng=random.Random(14),
        )
        assert decision.engine == "ok"

    def test_it_does_change_the_order_among_survivors(self) -> None:
        """The control for all of the above: if the bandit changed nothing, every test in this
        class would pass with the wiring removed."""
        offers = [
            self._offer("cheap-but-useless", seconds_per_call=1.0),
            self._offer("dearer-but-good", seconds_per_call=30.0),
        ]
        posteriors = {
            "cheap-but-useless": _trained(reward_for(-1), 6),
            "dearer-but-good": _trained(reward_for(4), 30),
        }
        chosen = Counter(
            choose(offers, prompt_tokens=100, posteriors=posteriors, rng=random.Random(seed)).engine
            for seed in range(200)
        )
        assert chosen["dearer-but-good"] > chosen["cheap-but-useless"], chosen
        # And the cost ranking alone would have picked the cheap one every time.
        assert choose(offers, prompt_tokens=100).engine == "cheap-but-useless"
