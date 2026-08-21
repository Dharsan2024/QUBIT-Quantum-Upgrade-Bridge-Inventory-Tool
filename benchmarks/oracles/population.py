"""Estimating what *every* detector missed.

Every published crypto-inventory tool reports recall against a corpus it can see. None of them
estimate the cryptography that no tool in the comparison found at all — and that number, not the
pairwise agreement, is what a reader actually wants to know before trusting an inventory.

It is estimable. Capture-recapture has been used to size populations nobody can enumerate since
Petersen (1896) and Lincoln (1930) counted fish, and Eick et al. (1992) and Briand et al. brought it
into software engineering to estimate residual defects from overlapping code inspections. Detectors
are inspectors. If QUBIT finds n1 crypto sites, an independent detector finds n2, and m of them are
the same sites, then a large overlap means both were thorough and a small overlap means the
population extends well past either list:

    Chapman (bias-corrected Lincoln-Petersen):   N = (n1+1)(n2+1)/(m+1) - 1

The four assumptions, and their honest status here:

1. **Closed population.** A source tree pinned to a commit does not change between scans. Holds.
2. **Correct matching.** A "recapture" must be the same site seen twice. Matching is by
   `(file, algorithm family)` rather than by line, because two detectors legitimately report
   different lines for one multi-line call, and coarse families because they disagree about
   parameters. Holds as well as the vocabulary mapping in `base.py` does.
3. **Equal catchability.** VIOLATED. Some cryptography is easy for everyone (a literal `md5(`) and
   some is hard for everyone (an algorithm named through a variable). This is heterogeneity, and
   with three or more detectors it can be modelled rather than assumed away -- see
   `loglinear_estimate`.
4. **Independent capture.** VIOLATED, and in a direction we can name. Detectors are not independent
   observers: they are all written from public documentation of the same libraries, so they tend to
   find the same easy things and miss the same hard things. Positive correlation inflates `m`,
   which deflates `N`, which INFLATES the resulting recall.

Assumptions 3 and 4 are why this module is worth having rather than a liability. The estimate is
biased in a known direction, so the honest reading is not "QUBIT's recall is X" but:

    **X is an upper bound on QUBIT's recall. The true figure is worse, and so is every
    published figure computed without an estimator at all.**

**How much worse — measured, not asserted.** `test_population.py` simulates a population of 1000
sites split into an easy half (every detector likely to fire) and a hard half (every detector
unlikely), which is the real failure mode: everyone finds a literal `md5(`, nobody finds an
algorithm named through a variable. Against a known true N of 1000:

    2-source Chapman ............... 593
    3-source, independence model .... 630
    3-source, one interaction ....... 640
    3-source, two interactions ...... 653

Every estimator is badly low, and the interaction terms move in the right direction without
recovering the magnitude. So the claim this module supports is deliberately weak and deliberately
solid: **it establishes a floor on what was missed, not an estimate of it.** Reporting 653 as "the
answer" when the truth is 1000 would be the same overclaiming this benchmark exists to expose,
one level up. What survives is the comparative statement -- recall measured against the union of
detectors is optimistic, here is a lower bound on by how much -- and that is still more than the
field currently says.

Three detectors are the minimum for any of this: with two, the saturated model has exactly as many
parameters as observable cells and the correlation cannot be estimated at all, only assumed away.
That is why adding a third detector mattered more than adding a fifth corpus.

References
----------
* Chapman, D.G. (1951). *Some properties of the hypergeometric distribution with applications to
  zoological sample censuses.* Univ. California Publ. Statist. 1:131-160.
* Seber, G.A.F. (1982). *The Estimation of Animal Abundance*, 2nd ed. — variance of the Chapman
  estimator, §3.1.
* Eick, S.G., Loader, C.R., Long, M.D., Votta, L.G., Vander Wiel, S. (1992). *Estimating software
  fault content before coding.* ICSE-14.
* Fienberg, S.E. (1972). *The multiple recapture census for closed populations and incomplete 2^k
  contingency tables.* Biometrika 59(3):591-603 — the log-linear formulation used below.
* Wilson, E.B. (1927). *Probable inference, the law of succession, and statistical inference.*
  JASA 22:209-212.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Interval:
    """A point estimate and the range it is actually pinned down to."""

    point: float
    low: float
    high: float

    def __str__(self) -> str:
        return f"{self.point:.1f} [{self.low:.1f}, {self.high:.1f}]"


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> Interval:
    """Wilson score interval for a proportion.

    The normal approximation is wrong at the counts this benchmark produces -- it happily reports a
    lower bound below zero for 4 hits out of 4, which is how a recall of 100% ends up with a
    confidence interval that includes impossible values. Wilson does not do that, and it is barely
    more code.
    """
    if trials <= 0:
        return Interval(0.0, 0.0, 0.0)
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = (z / denominator) * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    return Interval(p, max(0.0, centre - margin), min(1.0, centre + margin))


@dataclass(frozen=True)
class PopulationEstimate:
    """What two or more detectors jointly imply about how much they both missed."""

    observed: int
    #: Estimated true population size, including sites no detector reported.
    total: Interval
    #: Estimated sites missed by every detector in the comparison.
    missed_by_all: float
    method: str
    #: Assumption violations that bias this estimate, and in which direction.
    caveats: list[str] = field(default_factory=list)

    def recall_of(self, found: int) -> Interval:
        """One detector's recall against the ESTIMATED population, not against the union.

        Read this as an upper bound. See the module docstring, assumption 4.
        """
        if self.total.point <= 0:
            return Interval(0.0, 0.0, 0.0)
        return Interval(
            min(1.0, found / self.total.point),
            min(1.0, found / self.total.high) if self.total.high > 0 else 0.0,
            min(1.0, found / self.total.low) if self.total.low > 0 else 1.0,
        )


def chapman_estimate(n1: int, n2: int, m: int, z: float = 1.96) -> PopulationEstimate:
    """Two-detector population estimate, Chapman-corrected.

    The plain Lincoln-Petersen estimator `n1*n2/m` is undefined when the detectors share nothing and
    badly biased when they share little, which is exactly the regime a hard corpus produces.
    Chapman's +1 correction is defined at m=0 and is near-unbiased whenever n1+n2 >= N.
    """
    if n1 < 0 or n2 < 0 or m < 0:
        raise ValueError("counts must be non-negative")
    if m > min(n1, n2):
        raise ValueError(f"overlap {m} exceeds the smaller detector's {min(n1, n2)} findings")

    total = (n1 + 1) * (n2 + 1) / (m + 1) - 1
    variance = ((n1 + 1) * (n2 + 1) * (n1 - m) * (n2 - m)) / ((m + 1) ** 2 * (m + 2))
    se = math.sqrt(variance) if variance > 0 else 0.0
    observed = n1 + n2 - m

    caveats = [
        "positive correlation between detectors inflates the overlap, so this total is an "
        "UNDER-estimate and any recall computed from it is an UPPER bound",
        "under realistic heterogeneity this estimator is badly low (simulation: 593 against a "
        "true 1000); treat it as a floor on the population, never as its size",
    ]
    if m == 0:
        caveats.append(
            "the detectors share no findings at all: the estimate is driven entirely by Chapman's "
            "correction and carries essentially no information"
        )
    elif m < 5:
        caveats.append(f"overlap is only {m} sites; the interval is wide and the point unstable")
    if observed > total:
        # Chapman can land below the union when the overlap is near-total. The union is a hard
        # floor -- those sites were observed -- so report it rather than a number we know is wrong.
        caveats.append(
            f"estimate ({total:.1f}) fell below the {observed} sites actually observed; "
            "clamped to the union, which is a hard lower bound"
        )
        total = float(observed)

    return PopulationEstimate(
        observed=observed,
        total=Interval(total, max(float(observed), total - z * se), total + z * se),
        missed_by_all=max(0.0, total - observed),
        method="Chapman (2-source)",
        caveats=caveats,
    )


def capture_histories(
    finding_sites: Mapping[str, set[tuple[str, str]]],
) -> dict[tuple[bool, ...], int]:
    """Fold per-detector site sets into the 2^k contingency table of capture patterns.

    The unobservable cell -- captured by nobody -- is absent by construction. Estimating it is the
    whole exercise.
    """
    names = sorted(finding_sites)
    universe: set[tuple[str, str]] = set()
    for sites in finding_sites.values():
        universe |= sites

    table: dict[tuple[bool, ...], int] = {}
    for site in universe:
        pattern = tuple(site in finding_sites[name] for name in names)
        table[pattern] = table.get(pattern, 0) + 1
    return table


def loglinear_estimate(
    table: Mapping[tuple[bool, ...], int],
    *,
    interactions: Sequence[tuple[int, int]] | None = None,
) -> PopulationEstimate:
    """Three-or-more-detector estimate that allows detectors to be correlated.

    Fienberg's formulation: treat the 2^k capture patterns as an incomplete contingency table and
    fit a Poisson log-linear model to the 2^k - 1 observable cells,

        log E[count] = a + sum_i b_i x_i + sum_(i,j in interactions) g_ij x_i x_j

    where x_i indicates capture by detector i. The fitted intercept `a` is the log-expected count of
    the cell where every x_i is zero -- the sites nobody found -- so `exp(a)` estimates them
    directly.

    Passing `interactions` is how assumption 4 stops being an assumption. With no interaction terms
    this reduces to the independence model and reproduces the Chapman-style optimism. Adding the
    pair (i, j) says detectors i and j tend to succeed and fail together, which is what actually
    happens between two detectors built from the same library documentation, and it moves the
    estimate of the unseen cell UP.

    Requires >= 3 detectors: with two, the saturated model has as many parameters as observable
    cells and the unseen cell is not identifiable without exactly the independence assumption we are
    trying to relax.
    """
    patterns = list(table)
    if not patterns:
        raise ValueError("empty capture table")
    k = len(patterns[0])
    if k < 3:
        raise ValueError(f"log-linear estimation needs >= 3 detectors, got {k}")

    interactions = list(interactions or [])
    rows: list[list[float]] = []
    counts: list[float] = []
    for pattern in itertools.product([False, True], repeat=k):
        if not any(pattern):
            continue  # the unobservable cell
        row = [1.0] + [1.0 if bit else 0.0 for bit in pattern]
        row += [1.0 if (pattern[i] and pattern[j]) else 0.0 for i, j in interactions]
        rows.append(row)
        counts.append(float(table.get(pattern, 0)))

    if len(rows) <= len(rows[0]):
        raise ValueError(
            f"model has {len(rows[0])} parameters for {len(rows)} observable cells; "
            "drop an interaction term or add a detector"
        )

    intercept, se = _fit_poisson_intercept(rows, counts)
    unseen = math.exp(intercept)
    observed = int(sum(counts))
    total = observed + unseen

    label = "independence" if not interactions else f"interactions {interactions}"
    caveats: list[str] = []
    if not interactions:
        caveats.append(
            "independence model: assumes detectors succeed and fail independently, which they do "
            "not -- this total is an UNDER-estimate"
        )
    if any(count == 0 for count in counts):
        caveats.append(
            "some capture patterns have zero observed sites; the fit is sparse and the unseen-cell "
            "estimate is correspondingly fragile"
        )

    # Delta method on exp(intercept).
    low = math.exp(intercept - 1.96 * se) if se else unseen
    high = math.exp(intercept + 1.96 * se) if se else unseen
    return PopulationEstimate(
        observed=observed,
        total=Interval(total, observed + low, observed + high),
        missed_by_all=unseen,
        method=f"log-linear {k}-source ({label})",
        caveats=caveats,
    )


def _fit_poisson_intercept(
    rows: Sequence[Sequence[float]], counts: Sequence[float]
) -> tuple[float, float]:
    """Poisson GLM with a log link, by IRLS. Returns (intercept, standard error).

    Hand-rolled rather than pulled from statsmodels so the benchmark has no runtime dependency
    beyond numpy, and so the one number the whole estimate rests on is visibly computed rather than
    produced by a call nobody checks.
    """
    import numpy as np

    design = np.asarray(rows, dtype=float)
    observed = np.asarray(counts, dtype=float)
    beta = np.zeros(design.shape[1])
    beta[0] = math.log(max(observed.mean(), 0.5))

    for _ in range(200):
        eta = design @ beta
        mu = np.exp(np.clip(eta, -30, 30))
        weights = np.diag(mu)
        # Working response for IRLS on a log link.
        z = eta + (observed - mu) / np.maximum(mu, 1e-9)
        try:
            information = design.T @ weights @ design
            step = np.linalg.solve(information, design.T @ weights @ z)
        except np.linalg.LinAlgError:
            information = design.T @ weights @ design + np.eye(design.shape[1]) * 1e-8
            step = np.linalg.solve(information, design.T @ weights @ z)
        if np.max(np.abs(step - beta)) < 1e-10:
            beta = step
            break
        beta = step

    eta = design @ beta
    mu = np.exp(np.clip(eta, -30, 30))
    information = design.T @ np.diag(mu) @ design
    try:
        covariance = np.linalg.inv(information)
        se = math.sqrt(max(covariance[0, 0], 0.0))
    except np.linalg.LinAlgError:
        se = 0.0
    return float(beta[0]), se


def agreement_matrix(
    finding_sites: Mapping[str, set[tuple[str, str]]],
) -> dict[tuple[str, str], float]:
    """Pairwise Jaccard agreement, as a sanity check before any estimator is trusted.

    Two detectors that agree on almost nothing are either measuring different things or one of them
    is broken, and either way a population estimate built on that overlap means nothing. Printing
    this beside the estimate is what makes it possible to notice.
    """
    names = sorted(finding_sites)
    out: dict[tuple[str, str], float] = {}
    for left, right in itertools.combinations(names, 2):
        a, b = finding_sites[left], finding_sites[right]
        union = len(a | b)
        out[(left, right)] = (len(a & b) / union) if union else 0.0
    return out


def stratified_proportion(
    strata: Iterable[tuple[int, int, int]],
) -> Interval:
    """Combine per-stratum adjudication results back into one population proportion.

    Each stratum contributes `(population_size, sampled, true_positives)`. Sampling was deliberately
    uneven -- the strata where precision and recall actually live get sampled hardest -- so a raw
    ratio over all labels would be dominated by whichever stratum was sampled most and would not
    describe the corpus at all. Each stratum is weighted back to its true size.
    """
    total_population = 0
    weighted = 0.0
    variance = 0.0
    for size, sampled, positives in strata:
        if size <= 0 or sampled <= 0:
            continue
        p = positives / sampled
        total_population += size
        weighted += size * p
        # Finite-population-corrected variance of the stratum mean.
        correction = max(0.0, (size - sampled) / size)
        variance += (size**2) * correction * p * (1 - p) / sampled

    if total_population == 0:
        return Interval(0.0, 0.0, 0.0)
    point = weighted / total_population
    se = math.sqrt(variance) / total_population if variance > 0 else 0.0
    return Interval(point, max(0.0, point - 1.96 * se), min(1.0, point + 1.96 * se))


__all__ = [
    "Interval",
    "PopulationEstimate",
    "agreement_matrix",
    "capture_histories",
    "chapman_estimate",
    "loglinear_estimate",
    "stratified_proportion",
    "wilson_interval",
]
