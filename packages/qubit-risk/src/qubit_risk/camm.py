"""CAMM crypto-agility assessment, computed from scan evidence instead of asked in a questionnaire.

The Crypto-Agility Maturity Model (Hohm, Wiesmaier et al., arXiv:2202.07645; LNCS 13877) defines
five levels and 25 requirements for how readily a system can change its cryptography. It is applied
by expert review: someone reads the architecture and answers whether each requirement holds.

QUBIT holds direct evidence for a handful of those requirements and for no others, and the useful
consequence is asymmetric:

    A scan can REFUTE a maturity level. It can never CONFIRM one.

If a codebase resolves 12% of its cryptographic findings to `UNKNOWN(...)`, requirement 2.1
("the algorithms used are uniquely identifiable") is contradicted by evidence, and the system is
below Level 2 whatever an assessor was told. If nothing contradicts 2.1, that is not evidence the
requirement holds — the scanner never looked at most of what CAMM asks about.

So this module reports three verdicts per requirement — ``refuted``, ``unrefuted`` and
``not_assessable`` — and a **ceiling**: the highest level not contradicted by evidence. It never
reports an achieved level, because it cannot know one. Anything reporting a CAMM level from a source
scan alone is overclaiming, and saying so is more useful than a number that reads well.

Four requirements are assessable, all from the inventory itself:

* **1.4 Cryptography Inventory** — "their current security level is known": the share of findings
  that resolve to a known algorithm rather than `UNKNOWN(...)`.
* **2.1 Algorithm IDs** — "uniquely identifiable": the same evidence against its own threshold, kept
  separate because they are separate requirements.
* **2.2 Algorithm Intersection** — "all subsystems share a common set of algorithms": whether, for
  each purpose in use, one primitive is common across most components.
* **2.4 Opportunistic Security** — "always uses the strongest available algorithm": contradicted
  wherever a component uses a weak primitive while already using a stronger one for the same job.

**2.0 Cryptographic Modularity** was tried and withdrawn: counting files containing cryptography
can hint that a codebase is not modular, but the check could never refute anything, and a verdict
that is always "unrefuted" reads like evidence while being none.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from qubit_core import CryptoAsset

#: `resolve()` could not identify the algorithm, so it was recorded verbatim as `UNKNOWN(...)`.
_UNKNOWN_PREFIX = "UNKNOWN("

#: Verdicts. Deliberately not "pass"/"fail": only refutation is evidenced.
REFUTED = "refuted"
UNREFUTED = "unrefuted"
NOT_ASSESSABLE = "not_assessable"


@dataclass(frozen=True)
class RequirementVerdict:
    """One CAMM requirement, and what the scan can say about it."""

    id: str
    level: int
    name: str
    text: str
    verdict: str  # refuted | unrefuted | not_assessable
    detail: str
    #: Locations that contradict the requirement, for a reader who wants to check the verdict.
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AgilityReport:
    #: Highest level NOT contradicted by evidence. Not a claim that the level is achieved.
    ceiling: int
    ceiling_name: str
    #: Why the ceiling is where it is, or that nothing contradicted the top level.
    ceiling_reason: str
    requirements: list[RequirementVerdict]
    assessable: int
    refuted: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "ceiling": self.ceiling,
            "ceiling_name": self.ceiling_name,
            "ceiling_reason": self.ceiling_reason,
            "assessable": self.assessable,
            "refuted": self.refuted,
            "requirements": [
                {
                    "id": r.id,
                    "level": r.level,
                    "name": r.name,
                    "text": r.text.strip(),
                    "verdict": r.verdict,
                    "detail": r.detail,
                    "evidence": r.evidence[:20],
                }
                for r in self.requirements
            ],
        }


def _catalogue() -> dict[str, Any]:
    path = Path(__file__).parent / "params" / "camm_requirements.yaml"
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


def _component_of(asset: CryptoAsset) -> str:
    """The 'subsystem' an asset belongs to, for requirement 2.2.

    CAMM says subsystem and defines no boundary, because the boundary is architectural. The nearest
    thing a source scan has is the directory a file sits in, which is how codebases are actually
    partitioned. Named explicitly so the choice is visible rather than buried.
    """
    location = asset.location
    if location is None or not location.file_path:
        return "?"
    parent = Path(location.file_path).parent.as_posix()
    return parent or "."


def _where(asset: CryptoAsset) -> str:
    location = asset.location
    if location is None or not location.file_path:
        return asset.algorithm
    line = f":{location.line}" if location.line else ""
    return f"{Path(location.file_path).name}{line} ({asset.algorithm})"


def _check_identifiable(assets: list[CryptoAsset], minimum: float) -> tuple[bool, str, list[str]]:
    """Share of findings that resolve to a named algorithm rather than `UNKNOWN(...)`."""
    if not assets:
        return False, "no cryptographic findings to assess", []
    unknown = [a for a in assets if a.algorithm.startswith(_UNKNOWN_PREFIX)]
    share = 1.0 - (len(unknown) / len(assets))
    detail = (
        f"{len(assets) - len(unknown)} of {len(assets)} findings resolve to a known algorithm "
        f"({share:.1%}; requirement threshold {minimum:.0%})"
    )
    return share >= minimum, detail, [_where(a) for a in unknown]


def _check_intersection(assets: list[CryptoAsset], min_share: float) -> tuple[bool, str, list[str]]:
    """2.2 — for each purpose in use, is one primitive common across most components?"""
    components: set[str] = {_component_of(a) for a in assets}
    if len(components) < 2:
        return True, "fewer than two components scanned; nothing to intersect", []

    by_purpose: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for asset in assets:
        by_purpose[asset.usage_context.value][asset.algorithm].add(_component_of(asset))

    contradicted: list[str] = []
    for purpose, algorithms in sorted(by_purpose.items()):
        using = {c for algo_components in algorithms.values() for c in algo_components}
        if len(using) < 2:
            continue
        best = max(algorithms.items(), key=lambda kv: len(kv[1]))
        share = len(best[1]) / len(using)
        if share < min_share:
            contradicted.append(
                f"{purpose}: no shared primitive — most common is {best[0]} in "
                f"{len(best[1])} of {len(using)} components ({share:.0%})"
            )
    if contradicted:
        return False, f"{len(contradicted)} purpose(s) have no common algorithm", contradicted
    return True, f"every purpose has a primitive shared by most of {len(components)} components", []


def _check_opportunistic(assets: list[CryptoAsset]) -> tuple[bool, str, list[str]]:
    """2.4 — a weak primitive used beside a stronger one of the SAME family, in one component.

    "Strongest available" only means anything between algorithms that are alternatives for each
    other. The first version of this check compared any vulnerable finding against any
    non-vulnerable one sharing a usage context, and on go-jose it produced:

        [unknown]: uses ECDSA-P256 while PII: email address is already in use here
        [token]:   uses ECDSA-P256 ... while ... JSON Web Token, PBKDF2 is already in use here

    Neither is a statement about anything. A PII finding is not an algorithm; ECDSA and HMAC are
    different key models, not weak and strong versions of one job; and a JOSE library implements
    every registered algorithm because that is what it is for.

    Restricting to one family makes each verdict a genuine upgrade path — SHA-1 beside SHA-256,
    AES-128 beside AES-256, RSA-1024 beside RSA-2048 — where the stronger option is demonstrably
    already available in that component because it is already being called there.
    """
    from qubit_core.algorithms import resolve

    grouped: dict[tuple[str, str, str], list[CryptoAsset]] = defaultdict(list)
    for asset in assets:
        # Secrets, keys and PII are findings, not algorithm choices; they have no stronger variant.
        if asset.asset_type.value != "algorithm-use":
            continue
        spec = resolve(asset.algorithm)
        if spec is None or not spec.family:
            continue
        grouped[(_component_of(asset), asset.usage_context.value, spec.family)].append(asset)

    contradicted: list[str] = []
    for (component, purpose, family_name), group in sorted(grouped.items()):
        weak = sorted({a.algorithm for a in group if a.quantum_vulnerable.vulnerable})
        strong = sorted({a.algorithm for a in group if not a.quantum_vulnerable.vulnerable})
        if weak and strong:
            contradicted.append(
                f"{component} [{purpose}, {family_name}]: uses {', '.join(weak)} while "
                f"{', '.join(strong)} from the same family is already in use here"
            )
    if contradicted:
        return (
            False,
            f"{len(contradicted)} component(s) use a weaker member of a family they already use",
            contradicted,
        )
    return (
        True,
        "no component uses a weak primitive alongside a stronger one of the same family",
        [],
    )


def _check_scan_coverage(assets: list[CryptoAsset]) -> tuple[bool, str, list[str]]:
    """1.0 — a scan that found nothing is not knowledge of the system."""
    if not assets:
        return False, "the scan produced no cryptographic findings at all", []
    return True, f"{len(assets)} cryptographic findings recorded", []


def assess_camm(assets: list[CryptoAsset]) -> AgilityReport:
    """Assess what a scan can say about CAMM, and be explicit about what it cannot.

    Returns a *ceiling*: the highest level no evidence contradicts. A level below the ceiling is
    not thereby achieved, and the ceiling itself is an upper bound.
    """
    catalogue = _catalogue()
    thresholds = catalogue["thresholds"]
    levels = catalogue["levels"]

    checks = {
        "scan_coverage": lambda: _check_scan_coverage(assets),
        "inventory_resolved": lambda: _check_identifiable(
            assets, float(thresholds["inventory_resolved_min"])
        ),
        "algorithm_identifiable": lambda: _check_identifiable(
            assets, float(thresholds["algorithm_identifiable_min"])
        ),
        "algorithm_intersection": lambda: _check_intersection(
            assets, float(thresholds["intersection_min_share"])
        ),
        "opportunistic_security": lambda: _check_opportunistic(assets),
    }

    verdicts: list[RequirementVerdict] = []
    for entry in catalogue["requirements"]:
        evidence_kind = str(entry.get("evidence") or "none")
        if evidence_kind == "none" or evidence_kind not in checks:
            verdicts.append(
                RequirementVerdict(
                    id=str(entry["id"]),
                    level=int(entry["level"]),
                    name=str(entry["name"]),
                    text=str(entry["text"]),
                    verdict=NOT_ASSESSABLE,
                    detail=(
                        "not observable from source code; requires architectural or process review"
                    ),
                )
            )
            continue
        holds, detail, evidence = checks[evidence_kind]()
        verdicts.append(
            RequirementVerdict(
                id=str(entry["id"]),
                level=int(entry["level"]),
                name=str(entry["name"]),
                text=str(entry["text"]),
                verdict=UNREFUTED if holds else REFUTED,
                detail=detail,
                evidence=evidence,
            )
        )

    refuted = [v for v in verdicts if v.verdict == REFUTED]
    assessable = [v for v in verdicts if v.verdict != NOT_ASSESSABLE]

    if refuted:
        # Levels are cumulative, so the first contradicted requirement caps everything above it.
        first = min(refuted, key=lambda v: (v.level, v.id))
        ceiling = first.level - 1
        reason = f"requirement {first.id} ({first.name}) is contradicted: {first.detail}"
    else:
        ceiling = max(int(k) for k in levels)
        reason = (
            "no evidence in this scan contradicts any level. This is NOT a claim that Level "
            f"{ceiling} is met — most CAMM requirements are not observable from source code."
        )

    return AgilityReport(
        ceiling=ceiling,
        ceiling_name=str(levels[ceiling]["name"]),
        ceiling_reason=reason,
        requirements=verdicts,
        assessable=len(assessable),
        refuted=len(refuted),
    )


__all__ = [
    "NOT_ASSESSABLE",
    "REFUTED",
    "UNREFUTED",
    "AgilityReport",
    "RequirementVerdict",
    "assess_camm",
]
