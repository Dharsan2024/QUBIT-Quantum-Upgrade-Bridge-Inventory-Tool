"""Shared figure style, so a diagram drawn in one script cannot look like a different document
from a chart drawn in another.

Every figure in the pack goes through `save_figure()`: vector SVG as the artifact of record, a PNG
beside it only because reportlab cannot embed SVG, and a caption file that states the finding rather
than the axes.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "paper_evidence"
FIG = OUT / "figures"

#: Okabe-Ito: distinguishable under the common forms of colour blindness and in greyscale.
PALETTE = ["#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#56B4E9"]

#: Diagram furniture. Kept separate from PALETTE because these are backgrounds and rules, not data
#: series, and they must never be read as encoding a value.
INK = "#111418"
MUTED = "#5b6470"
EDGE = "#8b949e"
FILL = "#f2f5f8"

plt.rcParams.update(
    {
        "font.size": 9,
        "axes.titlesize": 10,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "figure.dpi": 110,
        "savefig.bbox": "tight",
        "axes.spines.top": False,
        "axes.spines.right": False,
    }
)


def save_figure(fig, name: str, caption: str) -> None:
    """Write `<name>.svg`, `<name>.png` and `<name>_caption.txt` into `figures/`."""
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / f"{name}.svg", format="svg")
    fig.savefig(FIG / f"{name}.png", format="png", dpi=200)
    plt.close(fig)
    (FIG / f"{name}_caption.txt").write_text(caption.strip() + "\n", encoding="utf-8")
    print(f"{name}.svg")


def blank_axes(fig_width: float, fig_height: float):
    """A drawing surface with no axes furniture, for box-and-arrow diagrams."""
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    for spine in ax.spines.values():
        spine.set_visible(False)
    return fig, ax
