"""Dependency-graph edge discovery from CryptoAsset rows (doc 03 §6.1).

M1 implements edge types 2, 4, 6 (schema-only, no symbols/imports contract yet).
Edge types 1, 3, 5, 7 are M2 additions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import networkx as nx
from qubit_core import CryptoAsset


@dataclass
class _Edge:
    src: UUID
    dst: UUID
    edge_type: str
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# M1 heuristics
# ---------------------------------------------------------------------------


def _cert_key_edges(assets: list[CryptoAsset]) -> list[_Edge]:
    """Edge type 2 — cert_key_binding.

    cert asset's SubjectPublicKeyInfo fingerprint == key asset fingerprint.
    Both are recorded by cert/key scanner in asset.fingerprint; at M1 we match
    by fingerprint equality among cert/key asset_types.
    """
    edges: list[_Edge] = []
    cert_assets = [
        a for a in assets if a.asset_type is not None and "cert" in a.asset_type.value.lower()
    ]
    key_assets = [
        a for a in assets if a.asset_type is not None and "key" in a.asset_type.value.lower()
    ]
    for cert in cert_assets:
        for key in key_assets:
            if cert.fingerprint and key.fingerprint and cert.fingerprint == key.fingerprint:
                # cert → key  (cert migrates first so the key pair is ready)
                edges.append(
                    _Edge(
                        src=cert.id,
                        dst=key.id,
                        edge_type="cert_key_binding",
                        confidence=1.0,
                        evidence={"cert_fingerprint": cert.fingerprint},
                    )
                )
    return edges


def _library_upgrade_edges(assets: list[CryptoAsset]) -> list[_Edge]:
    """Edge type 4 — library_upgrade.

    Creates a synthetic "library upgrade" prerequisite node for each
    (repo, library) pair where the library version is below the migration
    target minimum. At M1 we model this as edges between all assets in
    the same repo using the same library, forming a cluster that must
    move together after the library is upgraded.

    Because synthetic library nodes would require non-asset UUIDs (complex),
    we instead emit same-library intra-repo edges with confidence=1.0.
    The ordering effect is equivalent: all assets that need a library upgrade
    are in the same SCC → they migrate as one unit.
    """
    edges: list[_Edge] = []
    from collections import defaultdict

    # Group by (repo, library_name)
    groups: dict[tuple[str, str], list[CryptoAsset]] = defaultdict(list)
    for a in assets:
        if a.library and a.library.name and a.location and a.location.file_path:
            import os

            repo = os.path.split(a.location.file_path)[0]
            groups[(repo, a.library.name)].append(a)

    for group_assets in groups.values():
        if len(group_assets) < 2:
            continue
        # All assets in the group must migrate together (chain them)
        for i, src in enumerate(group_assets):
            for dst in group_assets[i + 1 :]:
                edges.append(
                    _Edge(
                        src=src.id,
                        dst=dst.id,
                        edge_type="library_upgrade",
                        confidence=1.0,
                        evidence={"library": src.library.name if src.library else ""},
                    )
                )
                edges.append(
                    _Edge(
                        src=dst.id,
                        dst=src.id,
                        edge_type="library_upgrade",
                        confidence=1.0,
                        evidence={"library": src.library.name if src.library else ""},
                    )
                )
    return edges


def _same_module_edges(assets: list[CryptoAsset]) -> list[_Edge]:
    """Edge type 6 — same_module (confidence=0.3, used for labeling only).

    Assets in the same file — weak co-migration hint. Normally excluded from
    ordering by min_confidence=0.5, but included in the graph for completeness.
    """
    edges: list[_Edge] = []
    from collections import defaultdict

    by_file: dict[str, list[CryptoAsset]] = defaultdict(list)
    for a in assets:
        if a.location and a.location.file_path:
            by_file[a.location.file_path].append(a)

    for file_assets in by_file.values():
        if len(file_assets) < 2:
            continue
        for i, src in enumerate(file_assets):
            for dst in file_assets[i + 1 :]:
                edges.append(
                    _Edge(
                        src=src.id,
                        dst=dst.id,
                        edge_type="same_module",
                        confidence=0.3,
                        evidence={"file": src.location.file_path if src.location else ""},
                    )
                )
    return edges


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_dependency_graph(
    assets: list[CryptoAsset],
    *,
    min_confidence: float = 0.5,
) -> nx.DiGraph:
    """Build directed dependency graph from CryptoAsset rows.

    Nodes are asset UUIDs. Edges point prerequisite → dependent.
    M1 edge types: 2 (cert_key), 4 (library_upgrade), 6 (same_module).
    """
    g: nx.DiGraph = nx.DiGraph()
    for a in assets:
        g.add_node(a.id, asset=a)

    heuristics = [_cert_key_edges, _library_upgrade_edges, _same_module_edges]
    for heuristic in heuristics:
        for e in heuristic(assets):
            if e.confidence >= min_confidence and e.src in g and e.dst in g:
                g.add_edge(
                    e.src,
                    e.dst,
                    edge_type=e.edge_type,
                    confidence=e.confidence,
                    evidence=e.evidence,
                )
    return g


__all__ = ["build_dependency_graph"]
