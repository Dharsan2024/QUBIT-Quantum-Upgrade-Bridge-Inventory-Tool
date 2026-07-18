"""SCC condensation + topological ordering → MigrationUnit list (doc 03 §6.1)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import networkx as nx
from qubit_core import CryptoAsset


@dataclass
class MigrationUnitInfo:
    """In-memory representation of a MigrationUnit before DB persistence."""

    order_index: int
    member_ids: list[UUID]
    label: str = ""

    @property
    def is_atomic(self) -> bool:
        return len(self.member_ids) == 1

    def max_risk(self, id_to_asset: dict[UUID, CryptoAsset]) -> float:
        scores = [
            id_to_asset[mid].risk.score
            for mid in self.member_ids
            if mid in id_to_asset and id_to_asset[mid].risk
        ]
        return max(scores, default=0.0)


def migration_order(
    g: nx.DiGraph,
    id_to_asset: dict[UUID, CryptoAsset] | None = None,
) -> list[MigrationUnitInfo]:
    """Collapse SCCs and return a total topological order.

    Higher-risk units sort first within the topo order
    (lexicographical_topological_sort key = -max_risk).
    """
    if g.number_of_nodes() == 0:
        return []

    # SCCs → condensation DAG
    cond: nx.DiGraph = nx.condensation(g)
    id_map: dict[UUID, CryptoAsset] = id_to_asset or {}

    def _risk_key(node: int) -> float:
        members: list[UUID] = [g.nodes[n]["asset"].id for n in cond.nodes[node]["members"]]
        scores = [id_map[m].risk.score for m in members if m in id_map and id_map[m].risk]
        return -max(scores, default=0.0)

    try:
        order = list(nx.lexicographical_topological_sort(cond, key=_risk_key))
    except nx.NetworkXUnfeasible:
        # Fallback: unreachable if condensation is always a DAG, but be defensive
        order = list(cond.nodes())

    units: list[MigrationUnitInfo] = []
    for idx, node in enumerate(order):
        member_asset_ids: list[UUID] = [g.nodes[n]["asset"].id for n in cond.nodes[node]["members"]]
        algos = {id_map[m].algorithm for m in member_asset_ids if m in id_map}
        label = ", ".join(sorted(algos)) or f"unit-{idx}"
        if len(member_asset_ids) > 1:
            label = f"[atomic] {label} ({len(member_asset_ids)} assets)"
        units.append(
            MigrationUnitInfo(
                order_index=idx,
                member_ids=member_asset_ids,
                label=label,
            )
        )
    return units


__all__ = ["MigrationUnitInfo", "migration_order"]
