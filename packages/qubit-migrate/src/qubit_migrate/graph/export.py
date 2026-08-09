"""Dependency graph serialization for the API (E3)."""

from __future__ import annotations

import networkx as nx
from qubit_core import CryptoAsset

from .order import MigrationUnitInfo


def serialize_graph(g: nx.DiGraph, units: list[MigrationUnitInfo]) -> dict:
    """Serialize the dependency graph and units into a JSON-friendly format.

    Nodes carry asset details for rendering; edges carry confidence and kind.
    """
    nodes = []
    # Build mapping from node_id to its unit and order_index
    node_to_unit = {}
    for idx, u in enumerate(units):
        for mid in u.member_ids:
            node_to_unit[mid] = (idx, u.order_index)

    for node_id in g.nodes():
        asset: CryptoAsset = g.nodes[node_id]["asset"]
        unit_info = node_to_unit.get(node_id, (None, None))

        nodes.append(
            {
                "id": str(node_id),
                "asset_id": str(asset.id),
                "algorithm": asset.algorithm,
                "usage_context": (
                    asset.usage_context.value
                    if hasattr(asset.usage_context, "value")
                    else str(asset.usage_context)
                ),
                "risk_score": asset.risk.score if asset.risk else 0.0,
                "unit_id": unit_info[0],
                "order_index": unit_info[1],
            }
        )

    edges = []
    for u, v, data in g.edges(data=True):
        edges.append(
            {
                "source": str(u),
                "target": str(v),
                "kind": data.get("edge_type", "unknown"),
                "confidence": data.get("confidence", 0.0),
            }
        )

    out_units = []
    for idx, u in enumerate(units):
        out_units.append(
            {
                "unit_id": idx,
                "members": [str(m) for m in u.member_ids],
                "is_cycle": not u.is_atomic,
                "label": u.label,
            }
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "units": out_units,
    }
