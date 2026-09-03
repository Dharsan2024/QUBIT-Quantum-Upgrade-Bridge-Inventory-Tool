"""Selecting the metamorphic relations for a finding.

The relation set is the oracle. Choosing the wrong one produces a verdict that
looks like evidence and is not, so the selection rules matter as much as the
relations themselves:

* A usage context nobody claims gets an EMPTY set, not a guessed one.
* A hybrid target gets the composite family, whose negatives assert that BOTH
  components are checked — a composite signature that ignores either half looks
  compliant and protects against nothing.
* A family with no negative relation cannot award evidence at all, because every
  positive relation is satisfied by a rewrite that does nothing.
"""

from __future__ import annotations

import pytest
from qubit_migrate.oracles import relations_for
from qubit_migrate.oracles.relations import relation_version


@pytest.mark.parametrize(
    ("usage", "expected_family"),
    [
        ("signature", "signature"),
        ("token", "signature"),
        ("firmware_signature", "signature"),
        ("kex", "kex"),
        ("key_agreement", "kex"),
        ("key_transport", "kex"),
        ("aead", "aead"),
        ("encryption", "aead"),
        ("data_at_rest", "aead"),
        ("hash", "hash"),
        ("integrity", "hash"),
        ("fingerprint", "hash"),
    ],
)
def test_each_usage_context_selects_its_family(usage: str, expected_family: str) -> None:
    """QUBIT already resolves `usage_context` before generation, so the oracle needs
    no new inference to know a signature finding wants sign/verify."""
    got = relations_for(usage)

    assert got.family == expected_family
    assert got.relations, f"{usage} selected {expected_family} but it carries no relations"


def test_an_unclaimed_usage_context_gets_no_relations() -> None:
    """The honest answer, and the caller must report `skipped` for it.

    A guessed oracle is worse than none: it produces a verdict nobody can defend,
    and it would award L3 to a finding whose behaviour was never checked.
    """
    got = relations_for("password_storage")

    assert not got
    assert got.family == ""
    assert got.relations == ()


def test_no_usage_context_gets_no_relations() -> None:
    """A finding with no usage context resolves to nothing rather than to a default.
    Defaulting here would silently apply signature relations to a hash."""
    assert not relations_for(None)
    assert not relations_for("")


def test_a_hybrid_target_selects_the_composite_family() -> None:
    """A hybrid migration is a different assertion, not the same one with an extra step.

    The classical algorithm is deliberately RETAINED, so the composite family's
    negatives check that neither half is decorative. Selecting the plain signature
    family for a hybrid target would pass a composite that ignores its PQC
    component entirely.
    """
    got = relations_for("signature", construction="hybrid")

    assert got.family == "composite_signature"
    ids = {r.id for r in got.negatives}
    # TWO negatives, covering both halves. They are named for what the harness measures — a byte
    # near the start of the signature and a byte near the end — rather than for "the classical
    # component" and "the PQC component", because `cryptography` 49.0.0 ships no composite
    # primitive: the patch defines the construction and owns the wire format, so the harness
    # cannot address either half by name. Naming a relation for something it does not measure is
    # the same defect as a criterion that cannot fail.
    assert ids == {"composite-prefix-corrupted", "composite-suffix-corrupted"}


def test_a_pure_target_never_selects_a_hybrid_only_family(tmp_path) -> None:
    """The composite family's negatives assert BOTH components are verified, which a
    correct PURE migration fails for the right reason — it has no classical component
    left to check. Selecting it for a pure target would reject correct patches.

    Written against a spec where the hybrid-only family is listed FIRST, because in
    the shipped spec `signature` precedes `composite_signature` and the dict order
    alone produces the right answer. A test that relied on that ordering would pass
    with the guard deleted, and would then break silently the day someone reorders
    the YAML.
    """
    from qubit_migrate.oracles.relations import _load

    spec = tmp_path / "relations.yaml"
    spec.write_text(
        "version: test\n"
        "relations:\n"
        "  hybrid_only:\n"
        "    applies_to_usage: [signature]\n"
        "    applies_to_construction: [hybrid]\n"
        "    positive:\n"
        "      - id: h1\n"
        "        relation: 'both components verify'\n"
        "        rationale: 'x'\n"
        "      - id: h2\n"
        "        relation: 'y'\n"
        "        rationale: 'y'\n"
        "  plain:\n"
        "    applies_to_usage: [signature]\n"
        "    positive:\n"
        "      - id: p1\n"
        "        relation: 'roundtrip'\n"
        "        rationale: 'x'\n"
        "    negative:\n"
        "      - id: n1\n"
        "        relation: 'wrong key fails'\n"
        "        rationale: 'x'\n",
        encoding="utf-8",
    )
    _load.cache_clear()
    try:
        assert relations_for("signature", construction="pure", path=spec).family == "plain"
        assert relations_for("signature", construction="hybrid", path=spec).family == "hybrid_only"
    finally:
        _load.cache_clear()


def test_a_hybrid_usage_with_no_hybrid_family_falls_back() -> None:
    """`kex` has no hybrid-specific family yet. Falling back to the pure relations is
    correct — encapsulate/decapsulate agreement holds for a hybrid KEM too — and is
    better than returning nothing for a finding the oracle can partly judge."""
    got = relations_for("kex", construction="hybrid")

    assert got.family == "kex"
    assert got.relations


@pytest.mark.parametrize("family_usage", ["signature", "kex", "aead", "hash"])
def test_every_family_carries_a_negative_relation(family_usage: str) -> None:
    """The property that makes this an oracle rather than a smoke test.

    Every positive relation is satisfied by a rewrite that does nothing at all —
    a `verify` returning True whatever it is given, a `decaps` returning a
    constant. Only the negatives catch that, so a family without one cannot award
    evidence.
    """
    got = relations_for(family_usage)

    assert got.negatives, f"{got.family} has no negative relation and cannot be an oracle"
    assert got.can_award_evidence


def test_a_family_without_negatives_cannot_award_evidence(tmp_path) -> None:
    """Asserted directly, because the guard is what stops a half-written family from
    silently producing L3 verdicts."""
    from qubit_migrate.oracles.relations import _load

    spec = tmp_path / "relations.yaml"
    spec.write_text(
        "version: test\n"
        "relations:\n"
        "  toothless:\n"
        "    applies_to_usage: [signature]\n"
        "    positive:\n"
        "      - id: p1\n"
        "        relation: 'always true'\n",
        encoding="utf-8",
    )
    _load.cache_clear()
    try:
        got = relations_for("signature", path=spec)
        assert got.positives
        assert not got.negatives
        assert not got.can_award_evidence, "positives alone must not award evidence"
    finally:
        _load.cache_clear()


def test_invariants_are_advisory_not_verdicts() -> None:
    """A signature-size class varies by encoding, so failing a patch on it would
    reject correct migrations. Invariants are reported as evidence and never as a
    verdict."""
    got = relations_for("signature")

    invariants = [r for r in got.relations if r.kind == "invariant"]
    assert invariants, "the signature family should carry a size-class invariant"
    assert all(r.advisory for r in invariants)


def test_every_relation_states_why_it_exists() -> None:
    """A failure report reading "sig-wrong-key failed" tells an operator nothing.
    "Verification succeeded under the wrong key" tells them everything, so the
    rationale travels with the relation rather than living in the spec document."""
    for usage in ("signature", "kex", "aead", "hash"):
        for relation in relations_for(usage).relations:
            assert relation.rationale, f"{relation.id} has no rationale"
            assert relation.relation, f"{relation.id} has no relation expression"


def test_the_spec_version_is_recorded() -> None:
    """Changing a relation changes what L3 means, so a verdict has to be tied to the
    relation set that produced it."""
    assert relation_version()


def test_families_carry_their_stated_limits() -> None:
    """The stage must never imply more than it checked. The relations test the
    primitive as the patched file uses it — not the application's whole protocol —
    and that limit is carried into the report rather than left in a document."""
    from qubit_migrate.oracles.relations import _load

    _load.cache_clear()
    spec = _load()
    assert spec.families, "the shipped relations.yaml should be loadable"
