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


def test_no_curve_margin_still_subtracts_shelf_life_and_effort() -> None:
    """Doc 02 F8 allows `Z = horizon - now` when no CRQC curve exists, but Z is the
    arrival-time INPUT: the margin is still Z - (X + Y). The pipeline used to assign Z straight
    to the margin, so every non-modelled asset reported the same horizon distance (+74.00y at
    horizon 2100) and the shelf-life it had just computed was discarded. Two Grover-tier assets
    with very different secrecy needs must NOT come out with the same margin.
    """
    from qubit_core.schemas import QuantumAttack, QuantumVulnerability
    from qubit_risk import RiskPipeline

    def grover_asset(snippet: str) -> CryptoAsset:
        a = _asset(snippet=snippet)
        a.algorithm = "MD5"
        a.quantum_vulnerable = QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover)
        return a

    long_lived = grover_asset("medical_record_phi = patient.diagnosis")
    ephemeral = grover_asset("tmp = ephemeral_cache_token")
    assessed = RiskPipeline(CFG).assess([long_lived, ephemeral])
    margins = {a.sensitivity.value: a.risk.mosca_margin_years for a in assessed}  # type: ignore[union-attr]

    horizon_distance = float(CFG.hardware_priors["horizon_year"]) - assessed[0].discovered_at.year
    # Never the bare horizon distance — X and Y must have been subtracted.
    assert all(m < horizon_distance for m in margins.values()), margins
    # And a longer secrecy requirement must leave a smaller margin.
    assert len(set(margins.values())) > 1, f"shelf-life had no effect on the margin: {margins}"
