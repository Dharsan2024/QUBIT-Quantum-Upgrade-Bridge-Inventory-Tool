"""External validation for risk ranking (doc 02 §6.4.5, §8.3).

Computes a Bradley-Terry consensus ranking from pairwise human judgments and compares
model scores against that consensus using Spearman's rho.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit
from scipy.stats import spearmanr


@dataclass(frozen=True)
class PairwiseComparison:
    winner_id: str
    loser_id: str
    rater: str


@dataclass(frozen=True)
class ExternalValidationResult:
    n_assets: int
    n_comparisons: int
    consensus_scores: dict[str, float]
    spearman_by_model: dict[str, float]


def load_pairwise_csv(path: Path) -> list[PairwiseComparison]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or [])
        required = {"winner_id", "loser_id"}
        missing = required - fields
        if missing:
            msg = f"pairwise csv missing required columns: {sorted(missing)}"
            raise ValueError(msg)

        rows: list[PairwiseComparison] = []
        for i, row in enumerate(reader, start=2):
            winner = (row.get("winner_id") or "").strip()
            loser = (row.get("loser_id") or "").strip()
            if not winner or not loser:
                msg = f"pairwise row {i}: winner_id/loser_id must be non-empty"
                raise ValueError(msg)
            if winner == loser:
                msg = f"pairwise row {i}: winner_id and loser_id must differ"
                raise ValueError(msg)
            rater = (row.get("rater") or "unknown").strip() or "unknown"
            rows.append(PairwiseComparison(winner_id=winner, loser_id=loser, rater=rater))

    if not rows:
        raise ValueError("pairwise csv has no comparisons")
    return rows


def load_scores_csv(path: Path) -> tuple[dict[str, dict[str, float]], list[str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        if "asset_id" not in fieldnames:
            raise ValueError("scores csv missing required column: asset_id")

        model_cols = [c for c in fieldnames if c != "asset_id"]
        if not model_cols:
            raise ValueError("scores csv must include at least one model score column")

        scores: dict[str, dict[str, float]] = {}
        for i, row in enumerate(reader, start=2):
            asset_id = (row.get("asset_id") or "").strip()
            if not asset_id:
                raise ValueError(f"scores row {i}: asset_id must be non-empty")
            if asset_id in scores:
                raise ValueError(f"scores row {i}: duplicate asset_id {asset_id}")
            row_scores: dict[str, float] = {}
            for col in model_cols:
                raw = (row.get(col) or "").strip()
                if not raw:
                    raise ValueError(f"scores row {i}: column {col} must be non-empty")
                row_scores[col] = float(raw)
            scores[asset_id] = row_scores

    if not scores:
        raise ValueError("scores csv has no rows")
    return scores, model_cols


def _fit_bradley_terry(
    comparisons: list[PairwiseComparison], *, l2: float = 1e-3
) -> dict[str, float]:
    assets = sorted({c.winner_id for c in comparisons} | {c.loser_id for c in comparisons})
    if len(assets) < 2:
        raise ValueError("need at least 2 distinct assets for Bradley-Terry fit")

    idx = {asset_id: i for i, asset_id in enumerate(assets)}
    fixed = len(assets) - 1
    n_vars = len(assets) - 1

    def unpack(x: np.ndarray) -> np.ndarray:
        theta = np.zeros(len(assets), dtype=np.float64)
        theta[:fixed] = x
        return theta

    def objective(x: np.ndarray) -> tuple[float, np.ndarray]:
        theta = unpack(x)
        grad_full = np.zeros_like(theta)
        loss = 0.0
        for cmp in comparisons:
            iw = idx[cmp.winner_id]
            il = idx[cmp.loser_id]
            diff = theta[iw] - theta[il]
            p = float(expit(diff))
            loss -= np.log(p + 1e-12)
            g = -(1.0 - p)
            grad_full[iw] += g
            grad_full[il] -= g

        loss += 0.5 * l2 * float(np.sum(theta[:fixed] ** 2))
        grad_full[:fixed] += l2 * theta[:fixed]
        grad = grad_full[:fixed]
        return loss, grad

    x0 = np.zeros(n_vars, dtype=np.float64)

    def fn(x: np.ndarray) -> float:
        return objective(x)[0]

    def jac(x: np.ndarray) -> np.ndarray:
        return objective(x)[1]

    opt = minimize(fn, x0, jac=jac, method="L-BFGS-B")
    if not opt.success:
        raise ValueError(f"Bradley-Terry optimization failed: {opt.message}")

    theta = unpack(np.asarray(opt.x, dtype=np.float64))
    lo = float(np.min(theta))
    hi = float(np.max(theta))
    if hi - lo <= 1e-12:
        return {asset_id: 0.5 for asset_id in assets}
    return {asset_id: float((theta[idx[asset_id]] - lo) / (hi - lo)) for asset_id in assets}


def evaluate_external_validation(
    *, pairwise_csv: Path, scores_csv: Path
) -> ExternalValidationResult:
    comparisons = load_pairwise_csv(pairwise_csv)
    scores, model_cols = load_scores_csv(scores_csv)
    consensus = _fit_bradley_terry(comparisons)

    common_ids = sorted(set(consensus).intersection(scores))
    if len(common_ids) < 3:
        msg = "need at least 3 overlapping assets between pairwise and scores csv"
        raise ValueError(msg)

    y = np.array([consensus[a] for a in common_ids], dtype=np.float64)
    spearman_by_model: dict[str, float] = {}
    for model in model_cols:
        x = np.array([scores[a][model] for a in common_ids], dtype=np.float64)
        rho, _ = spearmanr(x, y)
        spearman_by_model[model] = float(0.0 if np.isnan(rho) else rho)

    return ExternalValidationResult(
        n_assets=len(common_ids),
        n_comparisons=len(comparisons),
        consensus_scores={a: consensus[a] for a in common_ids},
        spearman_by_model=spearman_by_model,
    )


__all__ = [
    "ExternalValidationResult",
    "PairwiseComparison",
    "evaluate_external_validation",
    "load_pairwise_csv",
    "load_scores_csv",
]
