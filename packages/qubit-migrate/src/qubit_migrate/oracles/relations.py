"""Which metamorphic relations apply to a finding, and what each one asserts.

Selection is by the rule's ``usage_context`` and the plan's ``construction``, both
of which QUBIT already resolves before generation -- so no new inference is needed
to know that a signature finding wants sign/verify and a key-exchange finding
wants encapsulate/decapsulate.

The relations themselves live in ``params/relations.yaml`` rather than in code, so
the set can be extended for a new primitive family without touching the harness or
the validation stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml

#: A relation either asserts something must hold, or that something must NOT.
#:
#: The distinction is the whole reason this is an oracle rather than a smoke test.
#: A rewrite that quietly does nothing -- a `verify` that returns True whatever it
#: is given, a `decaps` that returns a constant -- satisfies every positive
#: relation. Only the negatives catch it, which is why a family with no negative
#: relation cannot award L3.
RelationKind = Literal["positive", "negative", "invariant"]

_PARAMS = Path(__file__).resolve().parent.parent / "params" / "relations.yaml"


@dataclass(frozen=True)
class Relation:
    """One assertion about the migrated primitive."""

    id: str
    kind: RelationKind
    #: The relation in the specification's own notation, e.g.
    #: ``verify(pk, m, sign(sk, m)) == True``. Carried through to the stored
    #: validation record so an L3 verdict can be audited rather than trusted.
    relation: str
    #: Why this relation exists — which silent failure it is there to catch.
    #: Surfaced to the operator when a relation fails, because "sig-wrong-key
    #: failed" means nothing on its own and "verification succeeded under the
    #: wrong key" means everything.
    rationale: str = ""
    #: Advisory relations are reported but never fail the stage. Sizes vary by
    #: encoding, so a signature-length check is evidence rather than a verdict.
    advisory: bool = False


@dataclass(frozen=True)
class RelationSet:
    """The relations that apply to one finding."""

    family: str
    relations: tuple[Relation, ...] = ()
    #: Stated limits of this family, carried into the report so the stage never
    #: implies more than it checked.
    limits: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.relations)

    @property
    def positives(self) -> tuple[Relation, ...]:
        return tuple(r for r in self.relations if r.kind == "positive")

    @property
    def negatives(self) -> tuple[Relation, ...]:
        return tuple(r for r in self.relations if r.kind == "negative")

    @property
    def can_award_evidence(self) -> bool:
        """A set with no negative relation cannot award L3, however many positives it has.

        Positives alone are satisfied by a rewrite that does nothing at all, so a
        family that has not yet had its negatives written is a family whose
        verdict would be worthless. Reported as `skipped`, never as `pass`.
        """
        return bool(self.positives) and bool(self.negatives)


@dataclass
class _Spec:
    version: str = ""
    families: dict[str, dict[str, Any]] = field(default_factory=dict)


@lru_cache(maxsize=1)
def _load(path: Path | None = None) -> _Spec:
    """Parse ``relations.yaml``. Cached — call ``_load.cache_clear()`` in tests."""
    target = path or _PARAMS
    if not target.exists():
        return _Spec()
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    return _Spec(version=str(raw.get("version", "")), families=raw.get("relations", {}) or {})


#: Relation kind -> the key it appears under in `relations.yaml`.
#:
#: Spelled out rather than assumed symmetric, because it is not: the spec reads
#: `positive:` and `negative:` but `invariants:`. Deriving the key from the kind
#: silently dropped every invariant — the loader looked for `invariant` and the
#: file said `invariants`, so the size-class checks were absent from every
#: relation set and nothing complained.
_SPEC_KEYS: dict[RelationKind, str] = {
    "positive": "positive",
    "negative": "negative",
    "invariant": "invariants",
}


def _build(family: str, spec: dict[str, Any]) -> RelationSet:
    relations: list[Relation] = []
    for kind, key in _SPEC_KEYS.items():
        for entry in spec.get(key) or []:
            relations.append(
                Relation(
                    id=str(entry.get("id", "")),
                    kind=kind,
                    relation=str(entry.get("relation", "")),
                    rationale=str(entry.get("rationale", "")).strip(),
                    # Invariants are evidence, not verdicts: a size class varies by
                    # encoding and would fail correct patches.
                    advisory=kind == "invariant" or bool(entry.get("advisory")),
                )
            )
    limits = tuple(str(x) for x in (spec.get("limits") or []))
    return RelationSet(family=family, relations=tuple(relations), limits=limits)


def relations_for(
    usage_context: str | None,
    construction: str = "pure",
    path: Path | None = None,
) -> RelationSet:
    """The relation set for this finding, or an empty set.

    An empty set is the honest answer for a usage context no family claims, and
    the caller must report `skipped` rather than inventing relations for it. A
    guessed oracle is worse than none: it produces a verdict nobody can defend.
    """
    spec = _load(path)
    if not usage_context:
        return RelationSet(family="")
    usage = usage_context.strip().lower()

    # A hybrid target is a different assertion, not the same one with an extra
    # step: the classical algorithm is deliberately RETAINED, and a composite
    # that ignores either half is the most dangerous possible outcome of a
    # migration -- it looks compliant and protects against nothing. So hybrid
    # constructions are matched first, and only fall back when no family claims
    # them.
    if construction == "hybrid":
        for family, entry in spec.families.items():
            allowed = {str(c).lower() for c in (entry.get("applies_to_construction") or [])}
            if not allowed or "hybrid" not in allowed:
                continue
            if usage in {str(u).lower() for u in (entry.get("applies_to_usage") or [])}:
                return _build(family, entry)

    for family, entry in spec.families.items():
        # A family that declares itself hybrid-only must not be selected for a
        # pure target — its negatives assert that BOTH components are checked,
        # which a pure migration would fail for the right reason.
        allowed = {str(c).lower() for c in (entry.get("applies_to_construction") or [])}
        if allowed and construction not in allowed:
            continue
        if usage in {str(u).lower() for u in (entry.get("applies_to_usage") or [])}:
            return _build(family, entry)

    return RelationSet(family="")


def relation_version(path: Path | None = None) -> str:
    """The spec version, recorded with every verdict so a result can be tied to the
    relation set that produced it. Changing a relation changes what L3 means."""
    return _load(path).version
