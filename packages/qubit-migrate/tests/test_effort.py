"""Unit tests for effort table (doc 03 §6.2)."""

from uuid import uuid4

from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.queue.effort import estimate_effort
from qubit_migrate.queue.priority import rank_ready_frontier


def test_estimate_effort():
    a = CryptoAsset(
        algorithm="MD5",
        key_size=None,
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
    )
    a.id = uuid4()

    # Base: config-only (1)
    e = estimate_effort(a, rule_kind="config-tls")
    assert e.points == 1

    # Base: KEM semantic change (3) + java (2) = 5
    e = estimate_effort(a, rule_kind="kem", language="java")
    assert e.points == 5

    # Base: sig swap (2) + no tests (2) = 4 -> snaps to 5
    e = estimate_effort(a, rule_kind="sig", has_tests=False)
    assert e.points == 5

    # Base: none (8) + fan_out (1) = 9 -> snaps to 13
    e = estimate_effort(a, fan_out=4)
    assert e.points == 13

def test_rank_ready_frontier():
    class _FakeRisk:
        def __init__(self, s, m):
            self.score = s
            self.mosca_margin_years = m

    a1 = CryptoAsset(algorithm="MD5", usage_context=UsageContext.hash, source_scanner=SourceScanner.code, asset_type=AssetType.algorithm_use, quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor))
    a1.id = uuid4()
    a1.risk = _FakeRisk(0.8, 1.0)

    a2 = CryptoAsset(algorithm="SHA-1", usage_context=UsageContext.hash, source_scanner=SourceScanner.code, asset_type=AssetType.algorithm_use, quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor))
    a2.id = uuid4()
    a2.risk = _FakeRisk(0.4, 5.0)

    # a1 priority = 0.8 / 1 (config) = 0.8
    # a2 priority = 0.4 / 1 (config) = 0.4
    q = rank_ready_frontier([a1, a2], effort_kwargs_map={
        a1.id: {"rule_kind": "config"},
        a2.id: {"rule_kind": "config"},
    })

    assert len(q) == 2
    assert q[0].asset.id == a1.id
    assert q[0].rank == 1
    assert q[1].asset.id == a2.id
    assert q[1].rank == 2
