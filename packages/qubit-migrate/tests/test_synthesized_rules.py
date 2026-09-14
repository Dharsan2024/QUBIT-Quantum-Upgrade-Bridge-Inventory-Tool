"""Findings the hand-written rule pack does not cover.

"No migration rule covers this finding" was the answer for anything the YAML pack had no entry for,
and it reads as a refusal. For a hash it is the right answer -- Grover is not Shor, and the fix is a
longer digest rather than a lattice scheme. For RSA in a key exchange it is not: QUBIT already knows
that becomes ML-KEM-768, because `kb.lookup_kb` holds the vetted mapping and
`/assets/{id}/recommendation` has always reported it. The only thing missing was using that to
generate the change.

What makes this safe is where the target comes from. The model is never asked what RSA should become
-- it is told, from QUBIT's own knowledge base -- and the patch it writes faces the same gates as
any other, the rescan included.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.transform.synthesized import provenance, synthesize_rule


def _asset(algorithm: str, usage: UsageContext, attack: QuantumAttack) -> CryptoAsset:
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm=algorithm,
        usage_context=usage,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="app.py", line=12),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=attack),
        discovered_at=datetime.now(UTC),
    )


@pytest.mark.parametrize(
    ("algorithm", "usage", "expected"),
    [
        ("RSA-2048", UsageContext.kex, "ML-KEM-768"),
        ("RSA", UsageContext.kex, "ML-KEM-768"),
        ("ECDSA-P256", UsageContext.signature, "ML-DSA-65"),
        ("DH", UsageContext.kex, "ML-KEM-768"),
        ("X25519", UsageContext.kex, "ML-KEM-768"),
    ],
)
def test_the_target_comes_from_qubits_knowledge_base(
    algorithm: str, usage: UsageContext, expected: str
) -> None:
    """The whole safety argument. If the target were the model's guess, a synthesised rule would be
    a rewrite with no authority behind it; because it is the KB's, the rule says the same thing the
    recommendation page has always said."""
    rule = synthesize_rule(_asset(algorithm, usage, QuantumAttack.shor), "python")

    assert rule is not None, f"{algorithm}/{usage.value} should be synthesisable"
    assert rule.target["algorithm"] == expected
    assert rule.target["pqc_target"] == expected


def test_a_hash_is_still_routed_to_guidance() -> None:
    """Grover is not Shor. A hash is not migrated to a lattice scheme, and pretending otherwise
    would be the "one-line md5 to sha256 as post-quantum" claim that makes the whole story
    unbelievable. Synthesis declines, and written guidance stays the honest answer."""
    assert synthesize_rule(_asset("MD5", UsageContext.hash, QuantumAttack.grover), "python") is None
    assert synthesize_rule(_asset("SHA-1", UsageContext.hash, QuantumAttack.grover), "py") is None


def test_a_synthesised_rule_carries_a_rescan_expectation() -> None:
    """The gate that turns a hypothesis into a verdict. Without `rescan_expect` the repair loop has
    no way to tell a real migration from a confident rewrite that changed nothing, and a
    synthesised rule is exactly where that matters most -- nobody hand-checked this transform."""
    rule = synthesize_rule(_asset("RSA-2048", UsageContext.kex, QuantumAttack.shor), "python")

    assert rule is not None
    assert rule.rescan_expect is not None
    # The shape the VALIDATOR reads, not a shape of this module's own choosing. The first version
    # of this test asserted a flat list and passed, while `_stage_rescan` crashed on every
    # synthesised patch with `'list' object has no attribute 'get'` -- a test that pinned the bug
    # instead of the contract.
    assert rule.rescan_expect["gone"]["algorithm_prefix"] == ["RSA"]
    assert rule.rescan_expect["present"]["algorithm_prefix"] == ["ML-KEM-768"]


def test_a_synthesised_rule_never_claims_a_codemod() -> None:
    """A codemod is a known-correct constant edit. There is no way to derive one for a transform
    nobody has written, and claiming one would send the finding to a deterministic path that does
    not exist."""
    rule = synthesize_rule(_asset("ECDSA-P256", UsageContext.signature, QuantumAttack.shor), "go")

    assert rule is not None
    assert rule.codemod is None
    assert rule.remediation == "auto", "it must reach the model, not the guided path"


def test_a_synthesised_rule_is_namespaced_and_declares_itself() -> None:
    """The reliability gate and the outcome history key on the rule id, so a derived rule must not
    be able to accumulate credit under a hand-written rule's name -- or the reverse."""
    rule = synthesize_rule(_asset("RSA-2048", UsageContext.kex, QuantumAttack.shor), "python")

    assert rule is not None
    assert rule.id.startswith("synth-")
    assert "python" in rule.id
    assert provenance(rule), "a derived rule has to say so in words the operator will read"


def test_prompt_constraints_demand_the_imports() -> None:
    """The measured failure mode for every engine tried, hosted and local: the algorithm is
    replaced and the import is not, so `symbols` rejects a patch that was otherwise correct. Three
    of three model-generated patches on the demo lab failed exactly this way."""
    rule = synthesize_rule(_asset("RSA-2048", UsageContext.kex, QuantumAttack.shor), "python")

    assert rule is not None
    joined = " ".join(rule.prompt_constraints).lower()
    assert "import" in joined


def _session():
    from qubit_core.db.models import Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_a_proven_rule_is_recalled_instead_of_re_derived() -> None:
    """The learning the operator asked for: a rule QUBIT worked out once is not worked out again.

    Recall is checked before derivation for consistency rather than speed. A stored rule is one
    whose patch passed the gates, so the second occurrence of a finding is answered by the
    derivation that WORKED, not by whatever the knowledge base resolves to at that moment.
    """
    from qubit_migrate.transform.synthesized import recall_rule, remember_rule

    session = _session()
    asset = _asset("RSA-2048", UsageContext.kex, QuantumAttack.shor)
    derived = synthesize_rule(asset, "python")
    assert derived is not None

    assert recall_rule(session, asset, "python") is None, "nothing proved yet"

    remember_rule(session, derived, asset, source_model="test-engine")
    recalled = recall_rule(session, asset, "python")

    assert recalled is not None
    assert recalled.id == derived.id
    assert recalled.target["algorithm"] == derived.target["algorithm"]
    assert recalled.rescan_expect == derived.rescan_expect


def test_recall_counts_how_often_a_learned_rule_is_used() -> None:
    """`hit_count` is the honest measure of whether self-derived rules earn their keep -- how many
    findings one has since handled. Without it the table is a claim rather than a result."""
    from qubit_core.db.models import LearnedRule
    from qubit_migrate.transform.synthesized import recall_rule, remember_rule
    from sqlalchemy import select

    session = _session()
    asset = _asset("ECDSA-P256", UsageContext.signature, QuantumAttack.shor)
    rule = synthesize_rule(asset, "python")
    assert rule is not None
    remember_rule(session, rule, asset)

    for _ in range(3):
        recall_rule(session, asset, "python")

    row = session.scalars(select(LearnedRule).where(LearnedRule.rule_id == rule.id)).one()
    assert row.hit_count == 3
    assert row.last_used_at is not None


def test_a_hand_written_rule_is_never_copied_into_the_learned_table() -> None:
    """The pack owns those. A second definition here would be one nobody updates, and the outcome
    history keys on the rule id -- two rows claiming `py-weakhash-01` would split its record."""
    from qubit_core.db.models import LearnedRule
    from qubit_migrate.transform.rules import load_rules
    from qubit_migrate.transform.synthesized import remember_rule
    from sqlalchemy import func, select

    session = _session()
    hand_written = next(r for r in load_rules() if not r.id.startswith("synth-"))
    remember_rule(session, hand_written, _asset("MD5", UsageContext.hash, QuantumAttack.grover))

    assert session.scalar(select(func.count()).select_from(LearnedRule)) == 0


def test_remembering_twice_does_not_duplicate() -> None:
    """A rule is derived per finding, so the same derivation arrives repeatedly in one run. The
    unique key is on (tenant, rule_id), and a second insert must be a no-op rather than an error
    that fails a patch which had already passed."""
    from qubit_core.db.models import LearnedRule
    from qubit_migrate.transform.synthesized import remember_rule
    from sqlalchemy import func, select

    session = _session()
    asset = _asset("DH", UsageContext.kex, QuantumAttack.shor)
    rule = synthesize_rule(asset, "python")
    assert rule is not None

    remember_rule(session, rule, asset)
    remember_rule(session, rule, asset)

    assert session.scalar(select(func.count()).select_from(LearnedRule)) == 1
