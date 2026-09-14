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


def _tiebreak(asset: CryptoAsset) -> tuple[str, int, str]:
    """Stable ordering for assets of equal priority: file path, then line, then id.

    The tie-break used to be `str(asset.id)` alone, commented "for stability" — and it delivered
    stability of the SORT while leaving the RESULT random, because `CryptoAsset.id` is a `uuid4`
    generated afresh on every scan. Measured: three runs of one plan over three equal-priority
    findings produced three different orders — `[gamma, alpha, beta]`, `[alpha, gamma, beta]`,
    `[beta, gamma, alpha]` — on a fresh database each time.

    That matters beyond tidiness. Ties are the COMMON case, not the exotic one: three MD5 findings
    in one file have identical risk, identical effort and therefore identical WSJF. A random work
    order means two runs of the same plan credit `AlreadySatisfied` to different tasks, fill
    the learned-patch store in a different order, and produce per-task timings that cannot be
    compared — which is fatal for a measurement programme whose whole point is reproducibility.

    Path and line are intrinsic to the finding, so identical input now yields identical order. The
    id stays as the last resort, keeping the sort total when two findings genuinely share a
    location.
    """
    location = asset.location
    return (
        str(getattr(location, "file_path", "") or ""),
        int(getattr(location, "line", 0) or 0),
        str(asset.id),
    )


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
        score = a.risk.score if a.risk else 0.0
        mosca = a.risk.mosca_margin_years if a.risk else 0.0
        effort = estimate_effort(a, **(effort_map.get(a.id, {})))
        priority = score / effort.points if effort.points else 0.0
        scored.append((-priority, mosca, a, effort))

    scored.sort(key=lambda t: (t[0], t[1], *_tiebreak(t[2])))

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
