"""A finding the rule pack does not cover is migrated, not written off.

"No migration rule covers this finding" was the answer for anything with no YAML entry, and it read
as a refusal. QUBIT already knows what a family and usage should become -- `kb.lookup_kb` holds the
vetted mapping and `agility` resolves a policy target when the KB is silent, the same cascade
`/assets/{id}/recommendation` has always answered with. The only thing missing was using it to
generate the change.

What makes that safe is where the target comes from. The model is never asked what ElGamal should
become; it is told, from QUBIT's own knowledge, and the patch it writes faces every gate a
hand-written rule's patch faces, the rescan included.

**What this did NOT turn out to fix.** Measured on the certbot plan that prompted it: 87 findings
were routed to guidance, and 85 of them were CERTIFICATES matched by `cert-pqc-01`, whose rule says
guidance is the right answer -- a certificate is a signed object, and no edit to a file re-issues
one. Of the 26 findings with no rule at all, 16 were certificates, 8 were hardcoded secrets (not a
PQC migration in any form) and 2 were TLS suites in `.conf` files. Not one was a rule-less algorithm
in source code. So on that corpus this feature fires for nothing, and the guidance the operator was
looking at was correct. It is kept because the gap it closes is real -- `ElGamal` below is a genuine
example the pack has no entry for -- but it was not the cause of what they were seeing, and saying
otherwise would be inventing a result.

The limits matter as much as the capability: nothing is synthesised for a file in a language QUBIT
has no grammar for, because there is no rescan that could check such a rewrite even if it looked
plausible.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.orchestrator import GuidedRemediation, MigrationOrchestrator
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

#: ElGamal key agreement: Shor-broken, in Python, and genuinely absent from the rule pack. Confirmed
#: against `match_rule` rather than assumed -- RSA, DH, ECDH, X25519, DSA and Ed25519 all match a
#: hand-written rule, so a fixture built on any of those would be testing the pack, not this.
ELGAMAL_SOURCE = """\
from Crypto.PublicKey import ElGamal


def make_key():
    return ElGamal.generate(2048, get_random_bytes)
"""

MIGRATED = """\
from cryptography.hazmat.primitives.asymmetric import mlkem


def make_key():
    return mlkem.generate_private_key(mlkem.ML_KEM_768)
"""


def _seed(
    tmp_path: Path,
    name: str,
    source: str,
    algorithm: str,
    usage: UsageContext,
) -> tuple[Session, MigrationOrchestrator, uuid.UUID]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()

    src = tmp_path / name
    src.write_text(source, encoding="utf-8")
    asset = CryptoAsset(
        algorithm=algorithm,
        usage_context=usage,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=str(src), line=5),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        discovered_at=datetime.now(UTC),
        risk=RiskAnnotation(
            score=0.9, ci_low=0.8, ci_high=1.0, mosca_margin_years=-3.0, priority_rank=1
        ),
    )
    session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    task = orch.get_queue(plan.id)[0]
    assert task.rule_id is None, "the fixture must produce a finding the pack does not cover"
    return session, orch, task.id


def test_a_rule_less_code_finding_reaches_the_model(tmp_path, monkeypatch) -> None:
    """The behaviour change, at the point it is decided.

    This finding used to be refused before any engine was consulted. What is asserted is that the
    model is called AND told the right target -- a rewrite the model chose for itself would be a
    guess with no authority behind it, which is what would make the result unpublishable.
    """
    _, orch, task_id = _seed(tmp_path, "kex.py", ELGAMAL_SOURCE, "ElGamal", UsageContext.kex)

    seen: dict = {}

    def spy(source, rule, asset, **kw):
        seen["rule_id"] = rule.id
        seen["target"] = rule.target.get("algorithm")
        seen["constraints"] = " ".join(rule.prompt_constraints)
        return MIGRATED

    monkeypatch.setattr("qubit_migrate.orchestrator.generate_llm_source", spy)
    orch.generate_patch(task_id, generator="llm")

    assert seen.get("rule_id", "").startswith("synth-"), seen
    assert seen["target"] == "ML-KEM-768", "the target must be QUBIT's own, not the model's"
    assert "import" in seen["constraints"].lower()


def test_a_derived_rule_is_remembered_only_once_its_patch_passes(tmp_path, monkeypatch) -> None:
    """The learning the operator asked for, and the condition on it.

    A rule that produced an accepted patch is stored and reused. One whose patch the gates rejected
    is not: persisting a bad derivation would hand the same mistake to every later finding it
    matches, which is worse than deriving afresh each time.
    """
    from qubit_core.db.models import LearnedRule

    session, orch, task_id = _seed(tmp_path, "kex.py", ELGAMAL_SOURCE, "ElGamal", UsageContext.kex)
    monkeypatch.setattr("qubit_migrate.orchestrator.generate_llm_source", lambda *a, **k: MIGRATED)

    patch = orch.generate_patch(task_id, generator="llm")
    stored = session.scalar(select(func.count()).select_from(LearnedRule))

    if patch.status == "proposed":
        assert stored == 1, "an accepted patch's rule must be kept for the next finding"
        row = session.scalars(select(LearnedRule)).one()
        assert row.target_algorithm == "ML-KEM-768"
        assert row.rule_id.startswith("synth-")
    else:
        assert stored == 0, "a rejected patch's rule must NOT be kept"


def test_a_language_qubit_cannot_check_is_still_guidance(tmp_path, monkeypatch) -> None:
    """The guard that keeps this from becoming reckless.

    A synthesised rule tells the model to rewrite this file in this language. With no grammar for
    the suffix there is no language to name and no rescan that could check the result, so a plain
    text file mentioning a broken algorithm would be handed to a model as source code. The model
    must not be called at all.
    """
    _, orch, task_id = _seed(tmp_path, "notes.txt", "elgamal stuff\n", "ElGamal", UsageContext.kex)

    def never(*a, **kw):
        raise AssertionError("the model must not be asked to rewrite an unknown file type")

    monkeypatch.setattr("qubit_migrate.orchestrator.generate_llm_source", never)
    with pytest.raises(GuidedRemediation):
        orch.generate_patch(task_id, generator="llm")
