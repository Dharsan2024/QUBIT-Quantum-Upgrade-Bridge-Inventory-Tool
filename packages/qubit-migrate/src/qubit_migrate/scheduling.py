"""Which engine should answer this finding, right now, given what is left.

QUBIT treats an attached LLM as swappable infrastructure: the API key is a setting, and any
OpenAI-compatible endpoint can go in it. What QUBIT contributes is not the model but the decision
of *when to spend one* -- and the two kinds of engine available are opposites:

===============  ==================  ==========================  =====================
engine           throughput          capability                  limit
===============  ==================  ==========================  =====================
local Ollama 7B  ~14 min / finding   0 of 4 on a structured      none: unlimited, free
                                     output contract
Groq 120b        0.52 s / call       4 of 4                      1,000 req/day,
                                                                 8,000 tokens/minute
Google 31b       ~110 s / call       4 of 4                      separate daily quota
===============  ==================  ==========================  =====================

Every figure above was measured on this installation, not assumed.

The local engine is **unlimited but slow**; a hosted free tier is **fast but rationed**. The policy
that was here before ranked engines cheapest-first and therefore sent essentially everything to the
local model -- three orders of magnitude slower, on work it measurably cannot do. Free is not the
same as cheap when the resource being spent is the operator's afternoon.

So the scarce resource is not money, it is *hosted requests per day*, and the policy below spends
them where they convert into validated patches:

1. **Never buy what is already free.** An unmetered engine that is capable of the work keeps it,
   however slow it is; a rationed request is spent only on what the free engine *cannot* do. The
   three gates below are what "cannot" means -- a measured record of failing this exact pairing, a
   file too large for its window, or a structured-output contract it has never satisfied -- so
   escalation is always evidence-driven rather than a preference for the better model.

   This is the rule that makes the others affordable, and it is why local experience turns into
   hosted headroom: on this installation the local 7B has passed `code-signature-01`/go 518 times,
   and every pairing it learns to handle is quota released for the pairings it cannot.

   Ranking on expected time instead would invert this. An untried engine has no measured latency,
   so a metered default of 5s beats a local default of 600s, and a day's 1,000 requests would go on
   work that was already free.
2. **Capability before cost.** An engine with a measured record of failing this exact (rule,
   language) does not get it again, and work needing a structured-output contract does not go to an
   engine that has never once produced one. Spending a free request on a certain failure still
   costs fourteen minutes.
3. **Reserve the tail of the quota.** Hosted requests are refused below a reserve, so a run cannot
   consume the day's last requests on low-value findings and leave nothing for a rescan.
4. **Wait rather than fail.** A token-per-minute window refills; being refused does not. When a
   hosted engine is momentarily out of tokens but has requests left, the answer is to wait the few
   seconds the provider itself reports, not to fall back to an engine that will take a thousand
   times longer.
5. **Fall back, never stall.** With the hosted lane exhausted, the local engine still takes
   anything it is capable of. Unlimited-and-slow beats nothing.

This module is deliberately pure: it takes what is known and returns a decision. That is what makes
the policy testable without a model, a network, or a database, and what lets the numbers in the
table above be re-measured and the policy re-tuned without touching the orchestrator.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .bandit import Posterior, thompson_order

#: Hosted requests held back from ordinary work. A day's quota is the operator's, not one run's:
#: a bulk migration that spends the last request leaves nothing for the verification pass that
#: proves it worked.
DEFAULT_RESERVE_REQUESTS = 25

#: Longest QUBIT will wait for a token window to refill rather than route elsewhere. Groq reports
#: its token window resetting in ~31s; anything much beyond a minute is better spent on the local
#: engine, which by then has made real progress.
MAX_WAIT_SECONDS = 75.0


@dataclass(frozen=True)
class EngineOffer:
    """One engine, and what it can do for one finding at this moment.

    Everything here is either configuration or *measured* -- `passed`/`failed` come from this
    installation's own outcome history, and the remaining budget from the provider's own response
    headers. Nothing is a guess about a model's quality.
    """

    name: str
    #: Does using it consume a rationed quota? A local model does not.
    metered: bool
    #: Largest prompt this engine will accept, in tokens.
    budget_tokens: int
    #: Outcomes recorded for THIS engine on THIS (rule, language). Never pooled across engines:
    #: one engine's ceiling is not a property of the task.
    passed: int = 0
    failed: int = 0
    #: From the provider's own rate-limit headers. `None` means the provider does not say, which is
    #: not the same as zero and must never be treated as exhaustion.
    remaining_requests: int | None = None
    remaining_tokens: int | None = None
    #: Seconds until the token window refills, as the provider reports it.
    reset_tokens_s: float = 0.0
    #: Measured seconds per call on this installation. Used only to break ties in favour of the
    #: engine that finishes, not to predict quality.
    seconds_per_call: float | None = None
    #: Has this engine ever satisfied a structured-output contract (the windowed excerpt format)?
    #: `None` means untried.
    follows_contracts: bool | None = None


@dataclass(frozen=True)
class Decision:
    """Which engine gets the work, or why nothing does."""

    engine: str | None
    reason: str
    #: Seconds to wait before the chosen engine will accept the request.
    wait_seconds: float = 0.0
    #: Engines considered and rejected, with why -- so a routing decision can be explained rather
    #: than merely observed.
    rejected: tuple[tuple[str, str], ...] = ()
    #: The other engines that COULD have taken it, best first, for when the chosen one fails at
    #: request time. Routing picks the best engine available; it cannot know that a provider will
    #: answer 503. Measured on NVIDIA's `poolside/laguna-xs-2.1`: ~2s when it answers, and 503
    #: "ResourceExhausted" on 3 of 4 attempts. Without a ranked queue behind the choice, an engine
    #: like that fails findings instead of merely being skipped.
    alternatives: tuple[str, ...] = ()

    @property
    def routed(self) -> bool:
        return self.engine is not None


def choose(
    offers: list[EngineOffer],
    *,
    prompt_tokens: int,
    max_prompt_fraction: float = 0.45,
    skip_after_failures: int = 4,
    needs_contract: bool = False,
    reserve_requests: int = DEFAULT_RESERVE_REQUESTS,
    max_wait_seconds: float = MAX_WAIT_SECONDS,
    posteriors: dict[str, Posterior] | None = None,
    rng: random.Random | None = None,
) -> Decision:
    """Pick the engine most likely to turn this finding into a validated patch soonest.

    Returns a `Decision` whose `engine` is None when nothing can take the work -- which is a real
    answer, not an error: the caller routes the finding to written guidance instead of spending
    fourteen minutes proving what the history already says.

    `posteriors` is optional and absent by default. Without it the ordering is exactly the cost
    ranking it has always been, so an installation that has recorded no evidence levels yet -- and
    every test written before the bandit existed -- behaves identically. `rng` exists so the
    evaluation can replay a routing decision.
    """
    rejected: list[tuple[str, str]] = []
    #: (tier, expected seconds, engine, wait) -- tier 0 is "free and already proven", so it sorts
    #: ahead of everything regardless of speed. See the ranking block below.
    viable: list[tuple[int, float, EngineOffer, float]] = []

    for offer in offers:
        # 1. Can it physically hold the prompt? The window holds the answer too.
        allowed = int(offer.budget_tokens * max_prompt_fraction)
        if prompt_tokens > allowed:
            rejected.append(
                (offer.name, f"prompt {prompt_tokens:,} tokens exceeds its {allowed:,} budget")
            )
            continue

        # 2. Has it already been shown not to do this? Measured per engine, never pooled.
        if offer.passed == 0 and offer.failed >= skip_after_failures:
            rejected.append(
                (offer.name, f"{offer.failed} failures and no success on this rule and language")
            )
            continue

        # 3. Structured-output work needs an engine that has produced one. Measured: the local 7B
        #    dropped the required marker on 4 of 4 attempts while both hosted engines kept it, so
        #    sending it there spends the repair budget to reach a foregone conclusion.
        if needs_contract and offer.follows_contracts is False:
            rejected.append((offer.name, "has never satisfied a structured-output contract"))
            continue

        wait = 0.0
        if offer.metered:
            # 4. Keep a reserve. `None` means the provider does not report, so it cannot be spent
            #    down to a number we never learn -- treat silence as "proceed", not as "empty".
            if offer.remaining_requests is not None:
                if offer.remaining_requests <= 0:
                    rejected.append((offer.name, "daily request quota exhausted"))
                    continue
                if offer.remaining_requests <= reserve_requests:
                    rejected.append(
                        (
                            offer.name,
                            f"only {offer.remaining_requests} requests left, held in reserve",
                        )
                    )
                    continue
            # 5. A token window refills; waiting for it beats an engine a thousand times slower.
            if offer.remaining_tokens is not None and offer.remaining_tokens < prompt_tokens:
                if offer.reset_tokens_s > max_wait_seconds:
                    rejected.append(
                        (
                            offer.name,
                            f"token window refills in {offer.reset_tokens_s:.0f}s, "
                            "too long to wait",
                        )
                    )
                    continue
                wait = offer.reset_tokens_s

        # Rank by expected time to an answer. A metered engine that is fast and capable should be
        # preferred over a free one that is not -- the quota exists to be spent on exactly this.
        cost = (offer.seconds_per_call or (5.0 if offer.metered else 600.0)) + wait
        if offer.passed == 0 and offer.failed:
            cost *= 1 + offer.failed  # a shaky record makes it expected-slower, not forbidden

        # Free before metered, always -- see rule 1. An engine that reached this point has already
        # passed every capability gate, so a free one here is not a worse choice, only a slower
        # one, and the quota it saves is spent on findings it could not have taken at all.
        viable.append((1 if offer.metered else 0, cost, offer, wait))

    if not viable:
        return Decision(
            engine=None,
            reason="no engine can take this finding",
            rejected=tuple(rejected),
        )

    viable.sort(key=lambda row: (row[0], row[1], row[2].metered))

    # THOMPSON SAMPLING, over the survivors only.
    #
    # Everything above this line is a safety filter -- context window, quota reserve, contract
    # capability -- and the bandit cannot reach past any of it: it is handed the names that already
    # passed and returns a permutation of them. An exploration policy that could re-admit a
    # rejected engine would send a prompt to one too small to hold it, or spend a reserve that was
    # deliberately held back.
    #
    # What it changes is the ORDER, and only where the cost ranking was guessing. The cost model
    # falls back to a constant for an engine nobody has timed, and the failure gate above bans a
    # pairing permanently on four observations; neither improves as evidence accumulates. Sampling
    # from a Beta posterior does: an untried engine draws from the uniform prior and gets explored,
    # a failing one fades, and one whose provider has since changed the model behind the name can
    # be discovered again. See `qubit_migrate.bandit`.
    #
    # Ties fall back to the cost order, so when the posteriors have nothing to say the cheaper
    # engine still wins -- the bandit adds information, it does not discard what was already known.
    if posteriors:
        by_name_viable = {row[2].name: row for row in viable}
        ordered = thompson_order([row[2].name for row in viable], posteriors, rng=rng)
        viable = [by_name_viable[name] for name in ordered]

    tier, cost, chosen, wait = viable[0]
    if tier == 0:
        why = "free engine able to take it; no rationed request needed"
        if chosen.passed:
            why += f" ({chosen.passed} prior successes on this rule and language)"
    else:
        why = f"fastest engine able to take it (~{cost:.0f}s expected)"
    if wait:
        why += f", after waiting {wait:.0f}s for its token window"
    elif chosen.remaining_requests is not None:
        why += f"; {chosen.remaining_requests:,} requests left today"
    return Decision(
        engine=chosen.name,
        reason=why,
        wait_seconds=wait,
        rejected=tuple(rejected),
        alternatives=tuple(offer.name for _, _, offer, _ in viable[1:]),
    )


__all__ = [
    "DEFAULT_RESERVE_REQUESTS",
    "MAX_WAIT_SECONDS",
    "Decision",
    "EngineOffer",
    "choose",
]
