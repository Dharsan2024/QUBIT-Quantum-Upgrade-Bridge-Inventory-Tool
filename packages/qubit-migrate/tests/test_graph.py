"""Unit tests for dependency-graph building (doc 03 §6.1)."""

from uuid import uuid4

from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    LibraryRef,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.graph.builder import build_dependency_graph
from qubit_migrate.graph.order import migration_order


def _asset(
    algo: str,
    asset_type: str | None = None,
    fingerprint: str | None = None,
    repo: str | None = None,
    library: str | None = None,
) -> CryptoAsset:
    a = CryptoAsset(
        algorithm=algo,
        key_size=None,
        usage_context=UsageContext.kex,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
    )
    if asset_type:
        a.asset_type = AssetType(asset_type)
    if fingerprint:
        a.fingerprint = fingerprint
    if repo:
        a.location = Location(file_path=f"{repo}/src/main.py", line=1)
    if library:
        a.library = LibraryRef(name=library, version="1.0")
    a.id = uuid4()
    return a


def test_cert_key_edges():
    """Edge type 2: cert -> key."""
    cert = _asset("RSA-2048", asset_type="certificate", fingerprint="fp123")
    key = _asset("RSA-2048", asset_type="key", fingerprint="fp123")
    other_key = _asset("RSA-2048", asset_type="key", fingerprint="fp456")

    g = build_dependency_graph([cert, key, other_key])

    assert g.number_of_nodes() == 3
    assert g.number_of_edges() == 1
    assert g.has_edge(cert.id, key.id)


def test_library_upgrade_edges():
    """Edge type 4: same repo, same library."""
    a1 = _asset("MD5", repo="repoA", library="hashlib")
    a2 = _asset("SHA-1", repo="repoA", library="hashlib")
    a3 = _asset("SHA-1", repo="repoB", library="hashlib")  # different repo

    g = build_dependency_graph([a1, a2, a3])

    # a1 and a2 should have an edge (any direction is fine, it forms an SCC)
    assert g.has_edge(a1.id, a2.id) or g.has_edge(a2.id, a1.id)
    assert not g.has_edge(a1.id, a3.id)


def test_migration_order():
    """SCC condensation and sorting."""
    # A -> B -> C -> A  (cycle, should be one unit)
    # D -> E (separate)
    a1 = _asset("MD5", repo="repoA", library="hashlib")
    a2 = _asset("SHA-1", repo="repoA", library="hashlib")

    # Add fake risk scores for sorting
    class _FakeRisk:
        score = 0.5

    class _FakeRiskHigh:
        score = 0.9

    a1.risk = _FakeRisk()
    a2.risk = _FakeRiskHigh()

    g = build_dependency_graph([a1, a2])
    # a1 <-> a2 due to library upgrade edge, forming an SCC
    # So they should be in the same MigrationUnit

    id_map = {a.id: a for a in [a1, a2]}
    units = migration_order(g, id_map)

    assert len(units) == 1
    assert len(units[0].member_ids) == 2
    assert set(units[0].member_ids) == {a1.id, a2.id}
    # Max risk should be 0.9
    assert units[0].max_risk(id_map) == 0.9
