from __future__ import annotations

from datetime import date

from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_risk import evaluate_cnsa2, load_config

CFG = load_config()


def _asset(
    algorithm: str,
    *,
    attack: QuantumAttack = QuantumAttack.shor,
    vulnerable: bool = True,
    usage: UsageContext = UsageContext.kex,
) -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm=algorithm,
        usage_context=usage,
        quantum_vulnerable=QuantumVulnerability(vulnerable=vulnerable, attack=attack),
        location=Location(file_path="a.py", line=1),
        evidence=Evidence(),
    )


def test_config_has_cnsa2_milestones() -> None:
    assert len(CFG.cnsa2_milestones["milestones"]) == 5


def test_empty_inventory_preparation_phase_non_compliant() -> None:
    report = evaluate_cnsa2([], CFG, as_of=date(2026, 8, 15))
    prep = next(m for m in report.milestones if m.name == "Preparation Phase")
    assert prep.is_due is True
    assert prep.status == "non-compliant"


def test_any_scan_satisfies_preparation_phase() -> None:
    report = evaluate_cnsa2([_asset("RSA-2048")], CFG, as_of=date(2026, 8, 15))
    prep = next(m for m in report.milestones if m.name == "Preparation Phase")
    assert prep.status == "compliant"


def test_future_milestones_score_100_regardless_of_evidence() -> None:
    # 2026-08-15: only "Preparation Phase" (2025-12-31) is due; the rest are not-yet-due.
    report = evaluate_cnsa2([_asset("RSA-2048")], CFG, as_of=date(2026, 8, 15))
    not_due = [m for m in report.milestones if not m.is_due]
    assert len(not_due) == 4
    assert all(m.score_contribution == 100.0 for m in not_due)


def test_fully_migrated_inventory_scores_high_past_all_deadlines() -> None:
    assets = [
        _asset(
            "X25519MLKEM768", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.kex
        ),
        _asset(
            "ML-DSA-65", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.signature
        ),
        _asset(
            "AES-256",
            attack=QuantumAttack.none,
            vulnerable=False,
            usage=UsageContext.encryption_at_rest,
        ),
        _asset("SHA-384", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.hash),
    ]
    report = evaluate_cnsa2(assets, CFG, as_of=date(2031, 1, 1))
    prep = next(m for m in report.milestones if m.name == "Preparation Phase")
    new_nss = next(m for m in report.milestones if m.name == "New NSS Systems")
    tls13 = next(m for m in report.milestones if m.name == "TLS 1.3 Required")
    legacy = next(m for m in report.milestones if m.name == "Legacy System Update")
    assert prep.status == "compliant"
    assert new_nss.status == "compliant"
    assert tls13.status == "compliant"
    assert legacy.status == "compliant"
    assert report.overall_score > 90.0


def test_shor_vulnerable_inventory_fails_legacy_milestone_past_2033() -> None:
    assets = [_asset("RSA-2048")]
    report = evaluate_cnsa2(assets, CFG, as_of=date(2034, 1, 1))
    legacy = next(m for m in report.milestones if m.name == "Legacy System Update")
    assert legacy.is_due is True
    assert legacy.status == "non-compliant"
    assert report.overall_score < 100.0


def test_hybrid_kex_confirmed_satisfies_tls13_milestone() -> None:
    assets = [
        _asset(
            "X25519MLKEM768", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.kex
        ),
    ]
    report = evaluate_cnsa2(assets, CFG, as_of=date(2030, 6, 1))
    tls13 = next(m for m in report.milestones if m.name == "TLS 1.3 Required")
    assert tls13.status == "compliant"


def test_partial_new_nss_reports_missing_categories() -> None:
    assets = [
        _asset(
            "ML-DSA-65", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.signature
        ),
    ]
    report = evaluate_cnsa2(assets, CFG, as_of=date(2027, 6, 1))
    new_nss = next(m for m in report.milestones if m.name == "New NSS Systems")
    assert new_nss.status == "partial"
    assert "PQC signature" in new_nss.evidence


def test_current_phase_is_first_not_yet_due_milestone() -> None:
    report = evaluate_cnsa2([], CFG, as_of=date(2026, 8, 15))
    assert report.current_phase == "New NSS Systems"


def test_next_deadline_and_days_are_consistent() -> None:
    report = evaluate_cnsa2([], CFG, as_of=date(2026, 8, 15))
    assert report.next_deadline == date(2027, 1, 1)
    assert report.days_to_next_deadline == (date(2027, 1, 1) - date(2026, 8, 15)).days


def test_all_compliant_reports_no_further_action() -> None:
    assets = [
        _asset(
            "X25519MLKEM768", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.kex
        ),
        _asset("ML-KEM-768", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.kex),
        _asset(
            "ML-DSA-65", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.signature
        ),
        _asset(
            "AES-256",
            attack=QuantumAttack.none,
            vulnerable=False,
            usage=UsageContext.encryption_at_rest,
        ),
        _asset("SHA-384", attack=QuantumAttack.none, vulnerable=False, usage=UsageContext.hash),
    ]
    report = evaluate_cnsa2(assets, CFG, as_of=date(2036, 1, 1))
    assert all(m.status == "compliant" for m in report.milestones)
    assert report.next_action == "all milestones compliant"
    assert report.overall_score == 100.0
