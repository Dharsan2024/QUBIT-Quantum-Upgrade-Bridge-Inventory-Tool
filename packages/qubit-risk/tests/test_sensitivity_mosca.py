from __future__ import annotations

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
from qubit_risk import CRQCTimelineSimulator, classify_sensitivity, load_config, mosca
from qubit_risk.mosca import migration_years

CFG = load_config()


def _asset(
    snippet: str = "",
    file_path: str = "a.py",
    usage: UsageContext = UsageContext.kex,
) -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        usage_context=usage,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(file_path=file_path, line=1),
        evidence=Evidence(snippet=snippet),
    )


def test_classify_credentials() -> None:
    r = classify_sensitivity(_asset(snippet="password = get_secret()"), CFG)
    assert r.sensitivity == "credentials"


def test_classify_financial() -> None:
    r = classify_sensitivity(_asset(snippet="card_number = form['cvv']"), CFG)
    assert r.sensitivity == "financial"


def test_classify_phi_beats_pii_on_tie_order() -> None:
    r = classify_sensitivity(_asset(snippet="patient email address"), CFG)
    assert r.sensitivity == "phi"  # phi (1.0) outranks pii (0.6)


def test_unknown_when_nothing_matches() -> None:
    r = classify_sensitivity(_asset(snippet="x = compute(y)"), CFG)
    assert r.sensitivity == "unknown"


def test_shelf_life_ordering() -> None:
    phi = classify_sensitivity(_asset(snippet="patient mrn"), CFG)
    fin = classify_sensitivity(_asset(snippet="invoice payroll"), CFG)
    eph = classify_sensitivity(_asset(snippet="session_token nonce"), CFG)
    assert phi.shelf_life_years > fin.shelf_life_years > eph.shelf_life_years
    assert phi.shelf_life_p90 > phi.shelf_life_years  # P90 above the mean


def test_mosca_margin_and_too_late() -> None:
    curve = CRQCTimelineSimulator(CFG).simulate("RSA-2048", n_trials=2000)
    assert curve is not None
    y = migration_years(CFG, "kex")
    # long shelf-life (30y) => data must stay secret well past
    # CRQC => negative margin, high p_too_late
    long = mosca(curve, shelf_p90=30.0, y_years=y, now_year=2026)
    short = mosca(curve, shelf_p90=0.1, y_years=y, now_year=2026)
    assert long.margin_years < short.margin_years
    assert 0.0 <= long.p_too_late <= 1.0
    assert long.p_too_late >= short.p_too_late
