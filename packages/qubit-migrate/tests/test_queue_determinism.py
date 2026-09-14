"""The migration queue must produce the same order for the same findings, every run.

Not tidiness. Ties are the COMMON case — three MD5 findings in one file have identical risk,
identical effort and therefore identical WSJF — and a random work order means two runs of one plan
credit `AlreadySatisfied` to different tasks, fill the learned-patch store in a different order,
and produce per-task timings that cannot be compared. For a project whose v2 programme is built on
reproducible measurement, that is a correctness property, not a preference.

Measured before the fix: three runs over three equal-priority findings, on a fresh database each
time, gave `[gamma, alpha, beta]`, `[alpha, gamma, beta]` and `[beta, gamma, alpha]`. The
tie-break was `str(asset.id)`, commented "for stability" — and `CryptoAsset.id` is a `uuid4`
generated afresh on every scan, so it stabilised the SORT while leaving the RESULT random.
"""

from __future__ import annotations

import uuid

from qubit_core import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    Sensitivity,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.queue import rank_ready_frontier


def _asset(path: str, line: int = 1, score: float = 0.5) -> CryptoAsset:
    """A finding with a FRESH random id, as a real scan produces."""
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm="MD5",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        sensitivity=Sensitivity.credentials,
        evidence=Evidence(),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=score, ci_low=score, ci_high=score, mosca_margin_years=1.0, priority_rank=1
        ),
    )


def _order(assets: list[CryptoAsset]) -> list[str]:
    return [t.asset.location.file_path for t in rank_ready_frontier(assets)]


class TestTiedFindingsOrderReproducibly:
    def test_the_same_findings_rank_the_same_way_every_time(self) -> None:
        """Fresh ids each round, exactly as a rescan produces."""
        orders = {
            tuple(_order([_asset(p) for p in ("gamma.py", "alpha.py", "beta.py")]))
            for _ in range(25)
        }
        assert len(orders) == 1, orders

    def test_input_order_does_not_change_the_result(self) -> None:
        """The scanner's traversal order must not reach the work queue."""
        forward = _order([_asset(p) for p in ("alpha.py", "beta.py", "gamma.py")])
        reverse = _order([_asset(p) for p in ("gamma.py", "beta.py", "alpha.py")])
        assert forward == reverse == ["alpha.py", "beta.py", "gamma.py"]

    def test_findings_in_one_file_order_by_line(self) -> None:
        """The realistic tie: several findings of the same algorithm in one file, all with
        identical risk and effort."""
        assets = [_asset("crypto.py", line=n) for n in (40, 12, 7)]
        assert [t.asset.location.line for t in rank_ready_frontier(assets)] == [7, 12, 40]

    def test_priority_still_dominates_the_tie_break(self) -> None:
        """The fix must not reorder findings that are NOT tied — a low-risk `alpha.py` must not
        overtake a high-risk `zeta.py` just because it sorts first alphabetically."""
        assets = [_asset("alpha.py", score=0.1), _asset("zeta.py", score=0.9)]
        assert _order(assets) == ["zeta.py", "alpha.py"]
