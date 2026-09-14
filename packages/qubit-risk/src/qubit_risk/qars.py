"""QARS — Quantum Asset Risk Score. **Adopted prior work, implemented and cited.**

    Kaušpadienė et al., *Towards a Unified Quantum Risk Assessment*,
    **Electronics 2025, 14, 3338** (MDPI, 22 August 2025).
    Layer-specific extension: **Electronics 2025, 15, 2546**.

    QARS occupies the risk-assessment stage of the EU **PAREK** framework
    (Post-quantum inventory, Risk assessment, road-mapping, Execution, Key governance).

This module is not a QUBIT contribution and must never be presented as one. The model is
published, has a prototype tool, and sits inside a named EU framework; claiming it as novel invites
the reviewer who wrote it. What QUBIT contributes is *empirical grounding*: two of the six inputs
move from assumed to measured.

| input | meaning | in QARS | in QUBIT |
|---|---|---|---|
| `X` | confidentiality shelf-life | organisational policy | same — a business input |
| **`Y`** | **time to migrate** | **expert estimate** | **MEASURED** — see `04-measurement` |
| `Z` | CRQC horizon | published forecasts | same — nobody measures this |
| `D` | sensitivity label | data classification | same |
| **`v`** | **crypto visibility** | **assumed known** | **COMPUTED by the scanner, before/after** |
| `q` | harvestability | analyst judgement | partial — probing evidences live endpoints |

`Y` is the one the literature is missing, and the authors say so themselves: their future work
names "the collection of real-world migration times" as the way past reliance on synthetic
scenarios. That is why the citation is load-bearing rather than a concession — "we measure `Y`" is
meaningless without `Y`'s definition, which belongs to Mosca and to the models that operationalised
him.

**Inherited limitation, stated rather than hidden:** in the layer-specific model `Z` must be
treated as an institutional planning constant, not an empirical estimate. QUBIT inherits that and
should say so wherever a QARS score is published.

**Deliberately not implemented:** Quantum Amplitude Estimation for tail risk. That belongs to a
quantum-finance credit-risk model which shares the acronym, not to this one.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

#: Eq. (5) — `g : D -> [0,1]`, the sensitivity map.
SENSITIVITY_GRADE: dict[str, float] = {
    "low": 0.25,
    "moderate": 0.50,
    "high": 0.75,
    "critical": 1.00,
}

#: Published sector weight profiles `(w_T, w_S, w_E)`, Table in §Calibration stage 3.
#:
#: `baseline` is the default and is deliberately NOT one of the sectors: silently picking a sector
#: would embed a policy judgement about the operator's business into a number they are meant to
#: read as neutral.
SECTOR_WEIGHTS: dict[str, tuple[float, float, float]] = {
    "baseline": (1 / 3, 1 / 3, 1 / 3),
    # Long-term protection and impact severity dominate.
    "finance": (0.4, 0.4, 0.2),
    # Constrained upgrade cycles, wide exposure.
    "iot": (0.5, 0.2, 0.3),
    # High harvesting exposure.
    "cloud": (0.3, 0.2, 0.5),
}

#: Eq. (4) — steepness of the logistic. The authors leave `alpha` free; 4.0 puts the transition
#: firmly around `r = 1` without saturating so fast that the score stops discriminating either side
#: of it, which is what makes the number useful for RANKING rather than only for triage.
DEFAULT_ALPHA = 4.0

#: Layer-specific Grover attenuation, Electronics 15(12):2546.
#:
#: Grover gives only a QUADRATIC speedup against symmetric cryptography, where Shor collapses
#: asymmetric schemes outright. Symmetric assets must therefore not compete for urgency on equal
#: terms — QUBIT already routes hash findings to guidance, which is the right REMEDIATION, but
#: without this an AES-256 asset inflates urgency it does not deserve and competes with RSA-2048
#: for the operator's attention.
#:
#: `alpha_t` ~ one sixth of the classical asymmetric coefficient: symmetric migration pressure is
#: dominated by long-tail effects such as key-derivation transitions, not by imminent CRQC
#: compromise.
GROVER_ALPHA_T = 1 / 6
#: `alpha_i` scales the impact factors, capturing irreducible residual risk — side channels, key
#: management failure, cross-layer compromise — that remains even when the symmetric mathematics is
#: sound. Attenuated, never zeroed: the residue is real.
GROVER_ALPHA_I = 0.5


@dataclass(frozen=True)
class QarsInputs:
    """The six inputs, named as the paper names them."""

    #: `X` — required confidentiality duration, years.
    shelf_life_years: float
    #: `Y` — time to complete the migration, years. **Measured**, not estimated; see
    #: `qubit_migrate.report.measurements`. Defaulting it silently would reintroduce the very
    #: expert judgement this project replaces, so callers pass it explicitly.
    migration_years: float
    #: `Z` — years until an adversary holds a CRQC able to break this primitive. A planning
    #: constant, not a measurement.
    crqc_years: float
    #: `D` — one of low / moderate / high / critical.
    sensitivity: str
    #: `q` — network / cloud / supply-chain harvestability, in [0, 1].
    harvestability: float
    #: `v` — 1 when RSA/ECC/DH is in use, 0 for PQC or a non-public-key primitive. Computed by the
    #: scanner per asset, before AND after, which is the part the original model cannot do.
    visibility: float = 1.0
    #: True for a Grover-tier (symmetric / hash) asset. Drives the layer-specific attenuation.
    symmetric: bool = False


@dataclass(frozen=True)
class QarsScore:
    """A score and everything needed to reproduce it.

    The components and weights travel with the number because **a score without its weights is not
    reproducible**: the same asset scores 0.55 under baseline weights and 0.71 under the finance
    profile, and a stored bare figure cannot be told apart from a mis-scored one later.
    """

    qars: float
    timeline: float
    sensitivity: float
    exposure: float
    weights: tuple[float, float, float]
    sector: str
    alpha: float
    #: Mosca's ratio `r = (X + Y) / Z`. Kept because `r > 1` is exactly Mosca's binary condition,
    #: and a reader who trusts that framing can check it directly.
    ratio: float
    #: True when Grover attenuation was applied.
    attenuated: bool = False
    regime: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def too_late(self) -> bool:
        """Mosca's condition `X + Y > Z`, which the logistic maps to the neutral midpoint 0.5."""
        return self.ratio > 1.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "qars": round(self.qars, 4),
            "components": {
                "timeline": round(self.timeline, 4),
                "sensitivity": round(self.sensitivity, 4),
                "exposure": round(self.exposure, 4),
            },
            "weights": {
                "w_T": round(self.weights[0], 4),
                "w_S": round(self.weights[1], 4),
                "w_E": round(self.weights[2], 4),
            },
            "sector": self.sector,
            "alpha": self.alpha,
            "ratio": round(self.ratio, 4),
            "too_late": self.too_late,
            "grover_attenuated": self.attenuated,
            "regime": self.regime,
            "model": "QARS (Electronics 2025, 14, 3338)",
            "notes": list(self.notes),
        }


def f_time(ratio: float, alpha: float = DEFAULT_ALPHA) -> float:
    """Eq. (4) — `T = 1 / (1 + e^(-alpha (r - 1)))`.

    `r = 1` maps to exactly 0.5, which is Mosca's binary condition sitting at the neutral midpoint
    of a continuous scale. That correspondence is the reason the logistic was chosen over the
    linear surrogate `min(1, r)`, which the paper offers for low-uncertainty settings but which
    saturates and stops ranking assets once they pass the threshold.
    """
    # Guard the exponent rather than the result: `math.exp` overflows near ±710, and a very large
    # ratio (a one-year CRQC horizon against a thirty-year shelf life) is realistic input.
    exponent = -alpha * (ratio - 1.0)
    if exponent > 700:
        return 0.0
    if exponent < -700:
        return 1.0
    return 1.0 / (1.0 + math.exp(exponent))


def f_sens(sensitivity: str) -> float:
    """Eq. (5) — `S = f_sens(g(D))`, with `f_sens` the identity.

    An unrecognised label returns the MODERATE grade rather than 0. Scoring an unknown
    classification as harmless is the failure that makes a risk register useless: the assets
    nobody has classified are exactly the ones nobody has looked at.
    """
    return SENSITIVITY_GRADE.get((sensitivity or "").strip().lower(), 0.50)


def f_expos(visibility: float, harvestability: float) -> float:
    """Eqs. (6)-(8) — `E = v * q`.

    The authors state the consequence explicitly: a PQC-protected asset has `v = 0`, so `E = 0`
    regardless of exposure. That is the model working as designed, not a rounding artefact — and
    it is what makes `E` fall observably after a successful migration, which is the one QARS input
    QUBIT can watch change over time.
    """
    return max(0.0, min(1.0, visibility)) * max(0.0, min(1.0, harvestability))


def weights_for(sector: str = "baseline") -> tuple[float, float, float]:
    """Published `(w_T, w_S, w_E)` for a sector, defaulting to baseline thirds."""
    return SECTOR_WEIGHTS.get((sector or "").strip().lower(), SECTOR_WEIGHTS["baseline"])


def score(
    inputs: QarsInputs,
    *,
    sector: str = "baseline",
    alpha: float = DEFAULT_ALPHA,
    regime: str | None = None,
) -> QarsScore:
    """Eq. (2) — `QARS = w_T·T + w_S·S + w_E·E`, in [0, 1].

    Grover attenuation is applied to a symmetric asset per Electronics 15(12):2546, and is recorded
    in the result rather than folded silently into the number.
    """
    notes: list[str] = []
    w_t, w_s, w_e = weights_for(sector)

    # `Z <= 0` would divide by zero, and it is a real input: an operator who believes a CRQC exists
    # today enters 0. Treated as "the horizon has passed", which is the only reading that is not a
    # crash and not a silent zero.
    if inputs.crqc_years <= 0:
        ratio = float("inf")
        notes.append("Z <= 0: the CRQC horizon is treated as already passed")
    else:
        ratio = (inputs.shelf_life_years + inputs.migration_years) / inputs.crqc_years

    timeline = f_time(ratio, alpha)
    sensitivity = f_sens(inputs.sensitivity)
    exposure = f_expos(inputs.visibility, inputs.harvestability)

    attenuated = False
    if inputs.symmetric:
        # Grover is a QUADRATIC speedup, not a break. Attenuating the timeline by ~1/6 and the
        # impact by 1/2 keeps symmetric assets on the register — the residual risk is real — while
        # stopping them from outranking an RSA key that Shor collapses outright.
        timeline *= GROVER_ALPHA_T
        sensitivity *= GROVER_ALPHA_I
        exposure *= GROVER_ALPHA_I
        attenuated = True
        notes.append(
            "Grover-tier asset: timeline scaled by 1/6 and impact by 1/2 "
            "(Electronics 15(12):2546). Quadratic speedup, not a break."
        )

    total = w_t * timeline + w_s * sensitivity + w_e * exposure
    return QarsScore(
        qars=max(0.0, min(1.0, total)),
        timeline=timeline,
        sensitivity=sensitivity,
        exposure=exposure,
        weights=(w_t, w_s, w_e),
        sector=(sector or "baseline").strip().lower(),
        alpha=alpha,
        ratio=ratio,
        attenuated=attenuated,
        regime=regime,
        notes=notes,
    )


__all__ = [
    "DEFAULT_ALPHA",
    "GROVER_ALPHA_I",
    "GROVER_ALPHA_T",
    "SECTOR_WEIGHTS",
    "SENSITIVITY_GRADE",
    "QarsInputs",
    "QarsScore",
    "f_expos",
    "f_sens",
    "f_time",
    "score",
    "weights_for",
]
