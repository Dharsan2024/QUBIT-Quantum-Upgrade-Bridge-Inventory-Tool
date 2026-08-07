from __future__ import annotations

from pathlib import Path

import pytest
from qubit_risk.regressor.external_validation import evaluate_external_validation


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_external_validation_spearman_orders_models(tmp_path: Path) -> None:
    pairwise = _write(
        tmp_path / "pairwise.csv",
        "\n".join(
            [
                "winner_id,loser_id,rater",
                "a,b,r1",
                "a,c,r1",
                "a,d,r1",
                "b,c,r1",
                "b,d,r1",
                "c,d,r1",
                "a,b,r2",
                "a,c,r2",
                "b,c,r2",
                "b,d,r2",
                "c,d,r2",
            ]
        ),
    )
    scores = _write(
        tmp_path / "scores.csv",
        "\n".join(
            [
                "asset_id,xgb_score,bn_score,static_score",
                "a,0.95,0.80,0.20",
                "b,0.82,0.30,0.90",
                "c,0.40,0.35,0.70",
                "d,0.05,0.10,0.60",
            ]
        ),
    )

    out = evaluate_external_validation(pairwise_csv=pairwise, scores_csv=scores)
    assert out.n_assets == 4
    assert out.n_comparisons == 11
    assert out.spearman_by_model["xgb_score"] > out.spearman_by_model["bn_score"]
    assert out.spearman_by_model["xgb_score"] > out.spearman_by_model["static_score"]
    assert out.spearman_by_model["xgb_score"] >= 0.7


def test_external_validation_requires_overlap(tmp_path: Path) -> None:
    pairwise = _write(
        tmp_path / "pairwise.csv",
        "\n".join(
            [
                "winner_id,loser_id,rater",
                "a,b,r1",
                "a,c,r1",
                "b,c,r1",
            ]
        ),
    )
    scores = _write(
        tmp_path / "scores.csv",
        "\n".join(
            [
                "asset_id,xgb_score",
                "x,0.8",
                "y,0.5",
            ]
        ),
    )

    with pytest.raises(ValueError, match="overlapping assets"):
        evaluate_external_validation(pairwise_csv=pairwise, scores_csv=scores)
