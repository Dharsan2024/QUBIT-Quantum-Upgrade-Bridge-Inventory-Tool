"""Thompson sampling over (engine, shape): which engine gets tried, and why it changes.

QUBIT's engine choice is a filter followed by a rank. The filters are safety properties — can the
engine hold the prompt, does it have quota left, has it ever satisfied a structured-output
contract — and they are not negotiable. What sat on top was a fixed cost ordering, which has one
failure the measurement programme cannot live with: **it never revisits its own conclusion.**

An engine that failed its first four attempts on a pairing is skipped from then on, permanently,
on four observations. An engine that has never been tried is ordered by a guessed constant. Neither
is a claim the data supports, and neither improves as the data grows.

**Sampling, not averaging.** The obvious fix is to rank by observed success rate. That is the
exploit-only policy, and it is worse than what it replaces: an engine tried once and failed has a
mean of 0 and is never tried again, so its single unlucky draw becomes permanent. Drawing from the
posterior instead means Beta(1, 2) still beats Beta(9, 1) sometimes — rarely, and less often as
evidence accumulates, which is exactly the behaviour wanted. A never-tried engine draws from the
uniform prior and therefore gets explored; a failing one fades rather than being banned; a revived
one is retried.

**Graded reward, not binary.** `accepted / rejected` cannot distinguish an engine that reliably
produces L2 patches from one that reaches L3, and that difference is the whole point of the
evidence ladder. The reward is the rung reached, normalised — see `reward_for`.

**It only reorders.** The bandit is handed the engines that already passed every filter and
returns them in a different order. It cannot admit an engine the filters rejected, and a test
pins that: a scheduler where exploration can reach past a quota limit or a context-window check is
not a scheduler, it is a random number generator with extra steps.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

__all__ = [
    "DECAY",
    "Posterior",
    "observe",
    "reward_for",
    "thompson_order",
]

#: Weight retained by existing evidence when a new observation arrives.
#:
#: Without decay an engine that failed twenty times last month can never recover inside this
#: installation's lifetime, which contradicts the "revived retried" requirement: providers change
#: models behind a name, quotas change, and a 7B that could not hold a contract in March may hold
#: one in September. 0.98 gives a half-life around 34 observations — long enough that the order is
#: stable within a run, short enough that a stale verdict does not outlive its evidence.
DECAY = 0.98

#: The evidence ladder runs -1 (nothing established) to 4 (the project's own tests). Six rungs, so
#: the reward is `(level + 1) / 5`, which puts NO_EVIDENCE at 0.0 and L4 at 1.0.
#:
#: Written out rather than borrowed as "level / 5": the ladder in `transform/validate.py` starts at
#: -1, and dividing that directly yields a NEGATIVE reward, which a Beta posterior cannot represent
#: and which would corrupt the count silently.
_LADDER_SPAN = 5.0
_LADDER_FLOOR = -1


@dataclass(frozen=True)
class Posterior:
    """Beta(alpha, beta) over "this engine produces evidence for this shape".

    Starts uniform — Beta(1, 1) — which is the honest prior for an engine nobody has tried. A
    zero-weight prior would make the first observation total, so one bad first attempt would
    permanently sink an engine that is fine.
    """

    alpha: float = 1.0
    beta: float = 1.0

    @property
    def mean(self) -> float:
        """Reported, never used for ranking. Ranking by the mean is the exploit-only policy this
        module exists to avoid."""
        total = self.alpha + self.beta
        return self.alpha / total if total else 0.5

    @property
    def observations(self) -> float:
        """Effective evidence behind this posterior, discounting the Beta(1,1) prior."""
        return max(0.0, self.alpha + self.beta - 2.0)


def reward_for(evidence_level: int | None) -> float:
    """The rung reached, normalised to [0, 1].

    `None` — no validation record at all — scores 0.0 rather than being skipped. An attempt that
    produced nothing is evidence about the engine, and dropping it would make a engine that fails
    silently look untried rather than unsuccessful.
    """
    if evidence_level is None:
        return 0.0
    clamped = max(_LADDER_FLOOR, min(4, int(evidence_level)))
    return (clamped - _LADDER_FLOOR) / _LADDER_SPAN


def observe(posterior: Posterior, reward: float, *, decay: float = DECAY) -> Posterior:
    """Fold one graded outcome into the posterior.

    The reward is split across both parameters — `reward` to alpha, `1 - reward` to beta — rather
    than thresholded to a win or a loss. An L2 patch is genuinely partial evidence, and rounding it
    to either pole throws away the distinction the ladder was built to make.
    """
    r = max(0.0, min(1.0, reward))
    return Posterior(
        alpha=posterior.alpha * decay + r,
        beta=posterior.beta * decay + (1.0 - r),
    )


def thompson_order(
    candidates: Sequence[str],
    posteriors: dict[str, Posterior],
    *,
    rng: random.Random | None = None,
) -> list[str]:
    """Order `candidates` by one draw from each posterior, best first.

    `candidates` must already have passed every filter. Nothing here can add an engine, and the
    returned list is a permutation of the input — the caller's safety decisions survive intact.

    One draw per engine per call, not per comparison: sampling repeatedly inside a sort would make
    the comparator inconsistent and the result depends on the sort's access pattern rather than on
    the evidence.
    """
    # `random`, not `secrets`: this decides which engine to TRY first, never a key, a nonce
    # or anything an adversary sees. A seedable generator is a requirement rather than a
    # compromise — the evaluation has to replay a routing decision exactly, and `secrets`
    # cannot be seeded.
    source = rng or random.Random()  # noqa: S311 - routing order, never key material
    draws = {
        name: source.betavariate(
            max(1e-6, posteriors.get(name, Posterior()).alpha),
            max(1e-6, posteriors.get(name, Posterior()).beta),
        )
        for name in candidates
    }
    # Ties fall to the input order, which the caller has already sorted by cost — so when two
    # engines draw identically the cheaper one still wins.
    #
    # That comes free from `sorted` being stable; an explicit position in the key would be
    # redundant, and redundant code that looks like a safeguard is worse than none, because the
    # next reader believes the guarantee lives there rather than in the sort.
    return sorted(candidates, key=lambda n: -draws[n])
