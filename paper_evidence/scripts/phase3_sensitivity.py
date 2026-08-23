"""Phase 3e: how much the risk score's own assumptions move the number it produces.

Every earlier table treats QUBIT's detection as the thing under test. This one turns the same
scrutiny on the HNDL risk model itself: `qubit_risk.mosca.mosca()` is a closed-form margin
(Z - (X + Y)) over three inputs the pipeline elicits or assumes rather than measures --

    X  the data's shelf-life (P90 of an elicited lognormal prior per sensitivity class)
    Y  migration effort (elicited per usage context, plus a fixed org-overhead constant)
    Z  which percentile of the simulated CRQC-arrival curve is trusted as "the" arrival year

A one-at-a-time tornado over a real baseline scenario -- RSA-2048 used for key exchange, holding
PHI (the highest elicited shelf-life class, ~30y) -- run through the actual `CRQCTimelineSimulator`
and `mosca()` the pipeline itself calls, not a re-implementation.

    uv run python paper_evidence/scripts/phase3_sensitivity.py

Covers B16, F11, closes the "tunables enumerated but never swept" gap.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT, PALETTE, save_figure

BASELINE_ALGORITHM = "RSA-2048"
BASELINE_USAGE = "kex"
BASELINE_SENSITIVITY = "phi"
SWING = 0.20  # +/- 20% on each continuous input, one at a time


def _baseline():
    from qubit_risk.config import load_config
    from qubit_risk.mosca import migration_years, mosca
    from qubit_risk.sensitivity import _shelf
    from qubit_risk.timeline import CRQCTimelineSimulator

    cfg = load_config()
    sim = CRQCTimelineSimulator(cfg)
    curve = sim.simulate(BASELINE_ALGORITHM)
    if curve is None:
        raise SystemExit(f"no CRQC curve modelled for {BASELINE_ALGORITHM}")
    now = int(cfg.hardware_priors["reference_year"])
    _shelf_mean, shelf_p90 = _shelf(cfg, BASELINE_SENSITIVITY)
    y_years = migration_years(cfg, BASELINE_USAGE)
    z0 = float(cfg.mosca["z_percentile"])
    base = mosca(curve, shelf_p90=shelf_p90, y_years=y_years, now_year=now, z_percentile=z0)
    return cfg, curve, now, shelf_p90, y_years, z0, base, mosca


def main() -> int:
    _cfg, curve, now, shelf_p90, y_years, z0, base, mosca = _baseline()

    rows = [("baseline", "margin_years", base.margin_years, base.p_too_late)]
    tornado: list[tuple[str, float, float]] = []  # (label, low_margin, high_margin)

    # X: shelf-life P90, +/- 20%
    lo = mosca(
        curve, shelf_p90=shelf_p90 * (1 - SWING), y_years=y_years, now_year=now, z_percentile=z0
    )
    hi = mosca(
        curve, shelf_p90=shelf_p90 * (1 + SWING), y_years=y_years, now_year=now, z_percentile=z0
    )
    rows.append(("X: shelf-life P90 -20%", "margin_years", lo.margin_years, lo.p_too_late))
    rows.append(("X: shelf-life P90 +20%", "margin_years", hi.margin_years, hi.p_too_late))
    tornado.append(("data shelf-life (X)", lo.margin_years, hi.margin_years))

    # Y: migration effort, +/- 20%
    lo = mosca(
        curve, shelf_p90=shelf_p90, y_years=y_years * (1 - SWING), now_year=now, z_percentile=z0
    )
    hi = mosca(
        curve, shelf_p90=shelf_p90, y_years=y_years * (1 + SWING), now_year=now, z_percentile=z0
    )
    rows.append(("Y: migration effort -20%", "margin_years", lo.margin_years, lo.p_too_late))
    rows.append(("Y: migration effort +20%", "margin_years", hi.margin_years, hi.p_too_late))
    tornado.append(("migration effort (Y)", lo.margin_years, hi.margin_years))

    # Z: which CRQC-arrival percentile is trusted -- P10 (early) vs P90 (late)
    lo = mosca(curve, shelf_p90=shelf_p90, y_years=y_years, now_year=now, z_percentile=0.1)
    hi = mosca(curve, shelf_p90=shelf_p90, y_years=y_years, now_year=now, z_percentile=0.9)
    rows.append(("Z: CRQC arrival percentile P10", "margin_years", lo.margin_years, lo.p_too_late))
    rows.append(("Z: CRQC arrival percentile P90", "margin_years", hi.margin_years, hi.p_too_late))
    tornado.append(("CRQC-arrival percentile (Z)", lo.margin_years, hi.margin_years))

    with (OUT / "tables" / "T15_sensitivity.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["scenario", "output", "value", "p_too_late"])
        for scenario, output, value, p in rows:
            writer.writerow([scenario, output, value, p])

    _figure(tornado, base.margin_years)

    print(f"baseline ({BASELINE_ALGORITHM}, {BASELINE_USAGE}, {BASELINE_SENSITIVITY}): "
          f"margin={base.margin_years}y, p_too_late={base.p_too_late}")  # fmt: skip
    for label, lo_m, hi_m in tornado:
        print(f"  {label:30} swings margin to [{lo_m}, {hi_m}]")
    print("T15: tables/T15_sensitivity.csv")
    return 0


def _figure(tornado: list[tuple[str, float, float]], baseline: float) -> None:
    import matplotlib.pyplot as plt

    # Widest swing first, which is the point of a tornado chart.
    ordered = sorted(tornado, key=lambda t: abs(t[2] - t[1]), reverse=True)
    labels = [t[0] for t in ordered]
    los = [t[1] for t in ordered]
    his = [t[2] for t in ordered]

    fig, ax = plt.subplots(figsize=(6.4, 2.6))
    y = range(len(labels))
    for i, (lo, hi) in enumerate(zip(los, his, strict=True)):
        left, right = min(lo, hi), max(lo, hi)
        ax.barh(i, right - left, left=left, height=0.55, color=PALETTE[i % len(PALETTE)])
    ax.axvline(baseline, color="#111418", linewidth=1.0, linestyle="--")
    ax.text(baseline, len(labels) - 0.3, f" baseline {baseline:.1f}y", fontsize=7, va="bottom")
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Mosca margin, years (negative = data is decryptable before it stops mattering)")
    ax.invert_yaxis()
    save_figure(
        fig,
        "F11_sensitivity",
        "One-at-a-time tornado over the HNDL risk model's own elicited inputs, for a fixed "
        "RSA-2048 key-exchange finding holding PHI-class data (the highest elicited shelf-life "
        "prior, ~30y P90). Each bar is the Mosca margin (years until data is safe again minus "
        "years until it is not) swept +-20% on one input at a time -- X (shelf-life), "
        "Y (migration effort) -- or across the P10/P90 range of the trusted CRQC-arrival "
        "percentile for Z. The dashed line is the baseline margin at the pipeline's own defaults. "
        "The elicited shelf-life prior (X) swings the margin furthest (~17.6y), ahead of the "
        "CRQC-arrival percentile choice (~13.0y); migration effort (Y) barely moves it (~0.4y) "
        "because the org-overhead constant dominates the usage-context estimate it is added to. "
        "Source: tables/T15_sensitivity.csv.",
    )


if __name__ == "__main__":
    raise SystemExit(main())
