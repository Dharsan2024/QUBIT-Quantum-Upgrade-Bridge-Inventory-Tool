"""A criterion that cannot fail must not be read as "already migrated".

`_stage_rescan` narrows its `gone` prefixes to the ones describing THIS asset's algorithm and, when
none of them match, falls through to the full list -- which the asset then satisfies by construction.
The stage is honest about it: it sets `vacuous=True`, and `evidence_level` refuses to count a vacuous
pass as evidence.

The pre-flight probe in `_generate_patch` read only the pass/fail string from that stage and threw
the flag away, so a criterion that could not have failed was treated as proof the finding was already
done -- and no codemod and no model ever ran on it.

Measured on `inkwell-esign` through the desktop app: `encrypt_draft` and `decrypt_draft` are
AES-128-CBC, routed to `code-weakcipher-01`, whose `gone` list names DES, 3DES, RC4 and Blowfish.
None of those is anywhere in the file, so both findings were parked as finished work. Two of that
twin's five migratable findings were lost here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from qubit_core import CryptoAsset
from qubit_core.db import Base
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.orchestrator import MigrationOrchestrator
from qubit_migrate.transform.validate import StageResult
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@pytest.fixture
def orchestrator() -> MigrationOrchestrator:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return MigrationOrchestrator(Session(engine))


@pytest.fixture
def asset() -> CryptoAsset:
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm="AES-128",
        usage_context=UsageContext.encryption_at_rest,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="lib/inkwell/crypto/internal.rb", line=101),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=datetime.now(UTC),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.5, ci_high=0.5, mosca_margin_years=8.0, priority_rank=1
        ),
    )


#: A rule that declares a rescan expectation, which is all `_rescan_verifier` requires to build a
#: closure. The expectation's content is irrelevant here: the stage itself is replaced below.
RULE = SimpleNamespace(
    id="code-weakcipher-01",
    language="ruby",
    rescan_expect={"gone": {"algorithm_prefix": "DES,3DES,RC4,Blowfish"}},
)


def _install(monkeypatch, result: StageResult) -> None:
    """Make `_stage_rescan` return exactly `result`, so the test is about the flag, not the scanner."""
    import qubit_migrate.transform.validate as validate

    monkeypatch.setattr(validate, "_stage_rescan", lambda *a, **k: result)


class TestVacuousPasses:
    def test_a_vacuous_pass_is_flagged_on_the_closure(self, orchestrator, asset, monkeypatch):
        _install(
            monkeypatch,
            StageResult("pass", "rescan ok, but the 'gone' criterion does not name 'AES-128'",
                        0.0, vacuous=True),
        )
        verify = orchestrator._rescan_verifier(RULE, asset, "lib/inkwell/crypto/internal.rb")
        assert verify is not None

        # The repair loop's answer is unchanged -- there is nothing to correct.
        assert verify("anything") is None
        # ...but the probe can now tell that answer was unearned.
        assert verify.last_vacuous is True

    def test_a_real_pass_is_not_flagged(self, orchestrator, asset, monkeypatch):
        _install(monkeypatch, StageResult("pass", "rescan ok. algorithms: {'AES-256'}", 0.0))
        verify = orchestrator._rescan_verifier(RULE, asset, "lib/inkwell/crypto/internal.rb")

        assert verify("anything") is None
        assert verify.last_vacuous is False

    def test_the_probe_condition_rejects_a_vacuous_pass(self, orchestrator, asset, monkeypatch):
        """The composite the pre-flight actually evaluates.

        `already(orig) is None` alone is what parked the two AES findings; the second term is what
        stops it.
        """
        _install(monkeypatch, StageResult("pass", "vacuous", 0.0, vacuous=True))
        already = orchestrator._rescan_verifier(RULE, asset, "lib/inkwell/crypto/internal.rb")

        satisfied = already("src") is None and not getattr(already, "last_vacuous", False)
        assert satisfied is False, "a criterion that cannot fail was treated as already migrated"

    def test_the_probe_condition_still_accepts_a_real_pass(self, orchestrator, asset, monkeypatch):
        """The optimisation this probe exists for must survive the fix."""
        _install(monkeypatch, StageResult("pass", "rescan ok", 0.0))
        already = orchestrator._rescan_verifier(RULE, asset, "lib/inkwell/crypto/internal.rb")

        satisfied = already("src") is None and not getattr(already, "last_vacuous", False)
        assert satisfied is True

    def test_a_failing_rescan_is_never_satisfied(self, orchestrator, asset, monkeypatch):
        _install(
            monkeypatch,
            StageResult("fail", "Expected 'AES-128' gone, but still found", 0.0,
                        expectation="gone", expected="AES-128"),
        )
        already = orchestrator._rescan_verifier(RULE, asset, "lib/inkwell/crypto/internal.rb")

        assert already("src") is not None
        assert (already("src") is None and not already.last_vacuous) is False

    def test_last_vacuous_defaults_to_false_before_any_call(self, orchestrator, asset, monkeypatch):
        """A probe that throws must not leave the attribute unset and read as non-vacuous by luck."""
        _install(monkeypatch, StageResult("pass", "rescan ok", 0.0))
        verify = orchestrator._rescan_verifier(RULE, asset, "lib/inkwell/crypto/internal.rb")
        assert verify.last_vacuous is False
