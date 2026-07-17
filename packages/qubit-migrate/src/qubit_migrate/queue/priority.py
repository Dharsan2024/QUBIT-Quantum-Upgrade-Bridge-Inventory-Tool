"""WSJF priority scoring + ready-frontier ranking (doc 03 §6.2)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from qubit_core import CryptoAsset

from .effort import EffortEstimate, estimate_effort


@dataclass
class PrioritizedTask:
    asset: CryptoAsset
    effort: EffortEstimate
    priority: float  # risk.score / effort.points (WSJF)
    rank: int  # 1-based, lower = migrate first


def rank_ready_frontier(
    assets: list[CryptoAsset],
    *,
    ready_ids: set[UUID] | None = None,
    effort_kwargs_map: dict[UUID, dict] | None = None,
) -> list[PrioritizedTask]:
    """Return tasks in priority order (highest WSJF first).

    ``ready_ids``: if provided, only assets whose id is in this set are ranked.
    ``effort_kwargs_map``: per-asset extra kwargs forwarded to ``estimate_effort``.
    """
    effort_map: dict[UUID, dict] = effort_kwargs_map or {}

    scored: list[tuple[float, float, CryptoAsset, EffortEstimate]] = []
    for a in assets:
        if ready_ids is not None and a.id not in ready_ids:
            continue
        score = (a.risk.score if a.risk else 0.0)
        mosca = (a.risk.mosca_margin_years if a.risk else 0.0)
        effort = estimate_effort(a, **(effort_map.get(a.id, {})))
        priority = score / effort.points if effort.points else 0.0
        # Sort key: (-priority, mosca_margin asc, str(id) for stability)
        scored.append((-priority, mosca, a, effort))

    scored.sort(key=lambda t: (t[0], t[1], str(t[2].id)))

    result: list[PrioritizedTask] = []
    for rank, (neg_priority, _, asset, effort) in enumerate(scored, start=1):
        result.append(
            PrioritizedTask(
                asset=asset,
                effort=effort,
                priority=-neg_priority,
                rank=rank,
            )
        )
    return result


__all__ = ["PrioritizedTask", "rank_ready_frontier"]
