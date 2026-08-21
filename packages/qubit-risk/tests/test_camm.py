"""CAMM assessment from scan evidence — and the limits of what that evidence can say.

The Crypto-Agility Maturity Model (arXiv:2202.07645, LNCS 13877) is normally applied by expert
review. A scanner holds direct evidence for a few of its 25 requirements and none of the rest, which
makes the result asymmetric: it can refute a level, never confirm one. These tests pin both halves
of that, because the failure mode of a maturity score is that it reads well and means nothing.

The 2.4 check is pinned hardest. Its first version compared any vulnerable finding against any
non-vulnerable one sharing a usage context, and on real code produced "uses ECDSA-P256 while PII:
email address is already in use here" — a sentence about nothing.
"""

from __future__ import annotations

import pytest
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_risk.camm import NOT_ASSESSABLE, REFUTED, UNREFUTED, assess_camm


def _asset(
    algorithm: str,
    path: str = "app/main.go",
    *,
    vulnerable: bool = False,
    usage: UsageContext = UsageContext.hash,
    asset_type: AssetType = AssetType.algorithm_use,
) -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=usage,
        source_scanner=SourceScanner.code,
        asset_type=asset_type,
        location=Location(file_path=path, line=1),
        quantum_vulnerable=QuantumVulnerability(
            vulnerable=vulnerable,
            attack=QuantumAttack.shor if vulnerable else QuantumAttack.none,
        ),
        evidence=Evidence(),
        discovered_at=utcnow(),
    )


def _verdict(report, requirement_id: str):  # type: ignore[no-untyped-def]
    match = next((r for r in report.requirements if r.id == requirement_id), None)
    assert match is not None, f"requirement {requirement_id} missing from the catalogue"
    return match


class TestTheModelIsReportedHonestly:
    def test_every_camm_requirement_is_present(self) -> None:
        report = assess_camm([_asset("SHA-256")])
        assert len(report.requirements) == 25, "CAMM defines 25 requirements across levels 1-4"

    def test_most_requirements_are_not_assessable_from_source(self) -> None:
        """The important negative result: a scan sees a small minority of what CAMM asks."""
        report = assess_camm([_asset("SHA-256")])
        not_assessable = [r for r in report.requirements if r.verdict == NOT_ASSESSABLE]
        assert len(not_assessable) > len(report.requirements) / 2
        assert report.assessable == len(report.requirements) - len(not_assessable)

    @pytest.mark.parametrize("requirement_id", ["1.1", "1.2", "1.3", "3.2", "4.0"])
    def test_organisational_requirements_are_never_claimed(self, requirement_id: str) -> None:
        report = assess_camm([_asset("SHA-256")])
        assert _verdict(report, requirement_id).verdict == NOT_ASSESSABLE

    def test_a_clean_scan_does_not_claim_the_top_level(self) -> None:
        report = assess_camm([_asset("SHA-256"), _asset("AES-256", "svc/a.go")])
        assert "NOT a claim" in report.ceiling_reason, (
            "an unrefuted ceiling must say it is not an achievement, or it will be read as one"
        )


class TestRefutation:
    def test_unresolved_algorithms_refute_algorithm_ids(self) -> None:
        """2.1 — `UNKNOWN(...)` is the algorithm failing to be uniquely identifiable."""
        assets = [_asset("UNKNOWN(Frobnicate)") for _ in range(3)] + [_asset("SHA-256")]
        report = assess_camm(assets)
        assert _verdict(report, "2.1").verdict == REFUTED
        # 1.4 ("their current security level is known") rests on the same evidence and is a Level 1
        # requirement, so an unidentifiable inventory refutes both and the ceiling falls to 0.
        assert _verdict(report, "1.4").verdict == REFUTED
        assert report.ceiling == 0

    def test_an_empty_scan_refutes_system_knowledge(self) -> None:
        report = assess_camm([])
        assert _verdict(report, "1.0").verdict == REFUTED
        assert report.ceiling == 0

    def test_the_ceiling_names_the_requirement_that_capped_it(self) -> None:
        report = assess_camm([_asset("UNKNOWN(x)")])
        assert "1.4" in report.ceiling_reason or "2.1" in report.ceiling_reason


class TestOpportunisticSecurity:
    def test_a_weaker_family_member_beside_a_stronger_one_is_refuted(self) -> None:
        report = assess_camm(
            [
                _asset("AES-128", "svc/crypt.go", vulnerable=True),
                _asset("AES-256", "svc/crypt.go"),
            ]
        )
        verdict = _verdict(report, "2.4")
        assert verdict.verdict == REFUTED
        assert "AES" in verdict.evidence[0]

    def test_different_families_are_not_compared(self) -> None:
        """RSA and AES are not weak and strong versions of one job.

        Comparing across families is what produced "uses ECDSA-P256 while PII: email address is
        already in use here" on real code.
        """
        report = assess_camm(
            [
                _asset("RSA-2048", "svc/keys.go", vulnerable=True, usage=UsageContext.kex),
                _asset("AES-256", "svc/keys.go", usage=UsageContext.kex),
            ]
        )
        assert _verdict(report, "2.4").verdict == UNREFUTED

    def test_non_algorithm_findings_are_excluded(self) -> None:
        """A secret or a PII hit is a finding, not an algorithm choice with a stronger variant."""
        report = assess_camm(
            [
                _asset("RSA-1024", "svc/keys.go", vulnerable=True, usage=UsageContext.kex),
                _asset(
                    "PII: email address",
                    "svc/keys.go",
                    usage=UsageContext.kex,
                    asset_type=AssetType.sensitive_data,
                ),
            ]
        )
        assert _verdict(report, "2.4").verdict == UNREFUTED

    def test_separate_components_are_judged_separately(self) -> None:
        """The stronger option must be available IN that component. That is what makes it
        evidence at all."""
        report = assess_camm(
            [
                _asset("AES-128", "svc/a.go", vulnerable=True),
                _asset("AES-256", "other/b.go"),
            ]
        )
        assert _verdict(report, "2.4").verdict == UNREFUTED
