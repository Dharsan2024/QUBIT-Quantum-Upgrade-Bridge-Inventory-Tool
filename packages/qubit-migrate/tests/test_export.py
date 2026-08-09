"""Tests for E3 dependency graph serialization (qubit_migrate.graph.export)."""

from __future__ import annotations

import networkx as nx
from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    Confidence,
    Evidence,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.graph import MigrationUnitInfo, serialize_graph


def test_serialize_graph_basic() -> None:
    # Setup mock assets
    import uuid

    a1 = CryptoAsset(
        id=uuid.uuid4(),
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        usage_context=UsageContext.kex,
        confidence=Confidence.high,
        quantum_vulnerable=QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none),
        evidence=Evidence(snippet="dummy"),
    )
    a2 = CryptoAsset(
        id=uuid.uuid4(),
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="AES-256",
        usage_context=UsageContext.encryption_at_rest,
        confidence=Confidence.high,
        quantum_vulnerable=QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none),
        evidence=Evidence(snippet="dummy"),
    )

    g = nx.DiGraph()
    g.add_node(a1.id, asset=a1)
    g.add_node(a2.id, asset=a2)
    g.add_edge(a1.id, a2.id, edge_type="same_module", confidence=1.0)

    units = [
        MigrationUnitInfo(order_index=0, member_ids=[a1.id], label="RSA-2048"),
        MigrationUnitInfo(order_index=1, member_ids=[a2.id], label="AES-256"),
    ]

    out = serialize_graph(g, units)

    assert "nodes" in out
    assert "edges" in out
    assert "units" in out

    assert len(out["nodes"]) == 2
    assert len(out["edges"]) == 1
    assert len(out["units"]) == 2

    edge = out["edges"][0]
    assert edge["source"] == str(a1.id)
    assert edge["target"] == str(a2.id)
    assert edge["kind"] == "same_module"
    assert edge["confidence"] == 1.0

    n1 = next(n for n in out["nodes"] if n["asset_id"] == str(a1.id))
    assert n1["algorithm"] == "RSA-2048"
    assert n1["order_index"] == 0
    assert n1["unit_id"] == 0

    u1 = out["units"][0]
    assert u1["unit_id"] == 0
    assert str(a1.id) in u1["members"]
    assert not u1["is_cycle"]
