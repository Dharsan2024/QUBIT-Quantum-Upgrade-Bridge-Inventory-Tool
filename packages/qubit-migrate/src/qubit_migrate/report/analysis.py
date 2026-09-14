"""The statistics, fixed before the data: denominator ladder, cluster bootstrap, exact McNemar.

Every choice here has a cheaper alternative that would give a narrower interval or a smaller
p-value, and each of those alternatives is wrong for a specific, nameable reason. They are written
down so the choice cannot be quietly revisited once the results are in.

**Clusters are files, not findings.** Five MD5 calls in one module are one problem, not five
independent observations. A Wilson interval over findings treats them as five, and reports a
precision it has not earned — the more concentrated the findings, the more it overstates. The
bootstrap resamples FILES with replacement, and a rule-clustered sensitivity analysis is run
alongside with the **wider** of the two reported.

**McNemar is exact, not chi-squared.** The chi-squared approximation needs the discordant count to
be reasonably large; with two model-path findings on a corpus it is not, and the approximation
produces a p-value with no relationship to the data. The exact binomial test is a few lines and is
correct at every count including zero.

**Every claim is about the PROCEDURE.** The arms are not exchangeable at the finding level:
`learn.reliability` makes a finding's treatment depend on earlier findings' outcomes within the
same run. So "arm B accepted more findings than arm A" is supportable and "the model is better on
this finding" is not, and no function here returns the second kind of quantity.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "BOOTSTRAP_DRAWS",
    "COMPARISONS",
    "DenominatorLadder",
    "Interval",
    "McNemarResult",
    "bootstrap_rate",
    "denominator_ladder",
    "exact_mcnemar",
    "holm",
    "verified_accept",
]

#: Pre-registered. Large enough that the interval is stable to the reported precision, and it is
#: fixed here rather than passed in so it cannot be tuned until an interval looks good.
BOOTSTRAP_DRAWS = 10_000

#: The three comparisons, named before any result was read. Holm corrects across exactly these.
#: A fourth added later would need its own pre-registration; `B1-fwd vs B1-rev` is deliberately
#: absent because it is an ordering CHECK, not a hypothesis.
COMPARISONS = (
    ("B1-fwd", "A1"),
    ("A2", "B1-fwd"),
    ("B2", "B1-fwd"),
)


def verified_accept(row: Any) -> bool:
    """The primary endpoint. **This number does not currently exist anywhere.**

    All four conditions, and each excludes a way the headline figure has been inflated before:

    * accepted at all;
    * the rescan expectation was **not vacuous** — a criterion the asset could not fail is not
      evidence, however green;
    * the project's own tests actually **ran** and passed, rather than being skipped;
    * the finding sits on a line the suite **executes**, because a finding on an uncovered line
      cannot be falsified by that suite and reporting it as verified is the same inflation with a
      better image behind it.
    """
    stages = getattr(row, "stage_outcomes", None) or {}
    return bool(
        getattr(row, "outcome", "") == "accepted"
        and not getattr(row, "vacuous", False)
        and stages.get("tests") == "pass"
        and getattr(row, "covered", False)
    )


@dataclass(frozen=True)
class DenominatorLadder:
    """Every finding, and where it left the pipeline. Ordered, never collapsed.

    Collapsing these is how the previous harness went wrong: `AlreadySatisfied` and
    `GuidedRemediation` were both recorded as `status="error"`, so two verdicts became failures and
    the denominator for "attempted" silently included findings nothing had attempted.
    """

    total: int = 0
    no_rule: int = 0
    vacuous: int = 0
    guided: int = 0
    attempted: int = 0
    accepted: int = 0
    verified: int = 0

    def as_rows(self) -> list[tuple[str, int, str]]:
        """`(stage, remaining, what left here)` — the table as it is published."""
        return [
            ("total findings", self.total, ""),
            ("minus no-rule", self.total - self.no_rule, f"{self.no_rule} had no rule"),
            (
                "minus vacuous",
                self.total - self.no_rule - self.vacuous,
                f"{self.vacuous} routed to a criterion their algorithm cannot fail",
            ),
            (
                "minus guided",
                self.total - self.no_rule - self.vacuous - self.guided,
                f"{self.guided} routed to a written procedure",
            ),
            ("attempted", self.attempted, ""),
            ("accepted", self.accepted, ""),
            ("verified", self.verified, "tests ran, on covered lines, non-vacuous"),
        ]


def denominator_ladder(rows: Sequence[Any]) -> DenominatorLadder:
    """Build the ladder from measurement rows."""
    return DenominatorLadder(
        total=len(rows),
        no_rule=sum(1 for r in rows if getattr(r, "path", "") == "no-rule"),
        vacuous=sum(1 for r in rows if getattr(r, "vacuous", False)),
        guided=sum(1 for r in rows if getattr(r, "path", "") == "guided"),
        attempted=sum(1 for r in rows if getattr(r, "path", "") in ("codemod", "model")),
        accepted=sum(1 for r in rows if getattr(r, "outcome", "") == "accepted"),
        verified=sum(1 for r in rows if verified_accept(r)),
    )


@dataclass(frozen=True)
class Interval:
    point: float
    low: float
    high: float
    #: What was resampled. Reported because the interval means different things for each, and a
    #: reader who is not told will assume the narrower one.
    cluster: str
    draws: int = BOOTSTRAP_DRAWS

    @property
    def width(self) -> float:
        return self.high - self.low

    def as_dict(self) -> dict[str, Any]:
        return {
            "point": round(self.point, 4),
            "ci_low": round(self.low, 4),
            "ci_high": round(self.high, 4),
            "cluster": self.cluster,
            "draws": self.draws,
        }


def bootstrap_rate(
    rows: Sequence[Any],
    numerator: Callable[[Any], bool],
    *,
    cluster_by: Callable[[Any], str],
    cluster_name: str,
    draws: int = BOOTSTRAP_DRAWS,
    seed: int = 20260902,
) -> Interval | None:
    """A rate and its cluster-bootstrap interval, resampling CLUSTERS with replacement.

    `None` when there are fewer than two clusters: an interval computed from one cluster is a
    statement about that cluster's internal variation, which is exactly the correlation being
    corrected for, and reporting it would be worse than reporting nothing.
    """
    clusters: dict[str, list[Any]] = {}
    for row in rows:
        clusters.setdefault(cluster_by(row), []).append(row)
    if len(clusters) < 2:
        return None

    keys = list(clusters)
    total = len(rows)
    point = sum(1 for r in rows if numerator(r)) / total if total else 0.0

    rng = random.Random(seed)  # noqa: S311 - resampling, never key material
    rates: list[float] = []
    for _ in range(draws):
        hits = seen = 0
        # Resample the same NUMBER of clusters, so a draw that happens to pick large files does
        # not also change the sample size and confound the two effects.
        for _ in range(len(keys)):
            for row in clusters[keys[rng.randrange(len(keys))]]:
                seen += 1
                hits += bool(numerator(row))
        rates.append(hits / seen if seen else 0.0)

    rates.sort()
    lo = rates[int(0.025 * (len(rates) - 1))]
    hi = rates[int(0.975 * (len(rates) - 1))]
    return Interval(point=point, low=lo, high=hi, cluster=cluster_name, draws=draws)


def widest(*intervals: Interval | None) -> Interval | None:
    """The widest of several clusterings.

    Pre-registered: file-clustered and rule-clustered intervals are both computed and the **wider**
    is reported. Choosing per result would be choosing the answer.
    """
    present = [i for i in intervals if i is not None]
    return max(present, key=lambda i: i.width) if present else None


@dataclass(frozen=True)
class McNemarResult:
    """Discordant pairs and an exact p-value."""

    #: `a` succeeded where `b` failed.
    a_only: int
    #: `b` succeeded where `a` failed.
    b_only: int
    p_value: float
    #: Risk difference, `a` minus `b`, over the paired findings.
    risk_difference: float
    n_pairs: int

    @property
    def discordant(self) -> int:
        return self.a_only + self.b_only

    def as_dict(self) -> dict[str, Any]:
        return {
            "a_only": self.a_only,
            "b_only": self.b_only,
            "discordant": self.discordant,
            "n_pairs": self.n_pairs,
            "p_value": round(self.p_value, 6),
            "risk_difference": round(self.risk_difference, 4),
        }


def exact_mcnemar(
    paired: Sequence[tuple[bool, bool]],
) -> McNemarResult:
    """Two-sided exact McNemar over `(a_success, b_success)` pairs.

    Exact rather than chi-squared. The approximation needs a reasonably large discordant count, and
    with two model-path findings on a corpus it is not — the approximation would still print a
    number, and that number would have no relationship to the data. Under the null the discordant
    pairs are Binomial(n, 1/2), which `math.comb` evaluates exactly at any n including zero.
    """
    a_only = sum(1 for a, b in paired if a and not b)
    b_only = sum(1 for a, b in paired if b and not a)
    n = a_only + b_only

    if n == 0:
        # No discordant pairs is not evidence of no difference; it is no evidence either way.
        p = 1.0
    else:
        k = min(a_only, b_only)
        tail = sum(math.comb(n, i) for i in range(k + 1)) / (2**n)
        p = min(1.0, 2 * tail)

    pairs = len(paired)
    rd = ((a_only - b_only) / pairs) if pairs else 0.0
    return McNemarResult(a_only=a_only, b_only=b_only, p_value=p, risk_difference=rd, n_pairs=pairs)


def holm(p_values: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni step-down correction.

    Holm rather than plain Bonferroni: it is uniformly more powerful and controls the same
    family-wise error rate, so there is no reason to take the weaker one. Adjusted values are made
    monotone, which stops a later comparison being reported as more significant than an earlier one
    it cannot beat.
    """
    if not p_values:
        return {}
    ordered = sorted(p_values.items(), key=lambda kv: kv[1])
    m = len(ordered)
    adjusted: dict[str, float] = {}
    running = 0.0
    for i, (name, p) in enumerate(ordered):
        running = max(running, min(1.0, (m - i) * p))
        adjusted[name] = running
    return adjusted
