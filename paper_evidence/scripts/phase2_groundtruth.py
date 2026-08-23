"""Phase 2b: the ground-truth result, and the ablation that came out of it.

The one number in this pack that neither a language model nor this project's annotator produced.
CryptoAPI-Bench's labels were made by other people, published, peer-reviewed, and are the labels
CryptoGuard and CogniCrypt report against — so this is both independent of the project and
comparable to prior work.

Reads the two arms produced by `benchmarks/groundtruth/score_cryptoapi.py`:

    uv run python benchmarks/groundtruth/score_cryptoapi.py --no-fold \\
        --csv benchmarks/groundtruth/outcomes_nofold.csv \\
        --json benchmarks/groundtruth/result_nofold.json
    uv run python benchmarks/groundtruth/score_cryptoapi.py
    uv run python paper_evidence/scripts/phase2_groundtruth.py

Covers B12/T08 (ablation), B13/T09 (baseline comparison), F16, and closes Limitation L1.
"""

from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT, PALETTE, ROOT, save_figure

GT = ROOT / "benchmarks" / "groundtruth"
sys.path.insert(0, str(ROOT / "benchmarks" / "oracles"))

from population import wilson_interval  # noqa: E402

#: Short axis labels. The benchmark's own group names do not fit under a bar.
SHORT = {
    "Basis benchmark": "literal at\nthe call site",
    "Interprocedural (2 methods)": "via a local,\n2 methods",
    "pure Interprocedural cases": "via a local,\ninterprocedural",
    "Field sensitive": "via a\nfield",
    "Interprocedural + Field Sensitive": "via a field,\ninterprocedural",
    "Multiple java classes": "across\ntwo files",
    "Path sensitive cases": "path\nsensitive",
}

#: The order CryptoAPI-Bench's own paper uses, which is also the order of increasing analysis
#: difficulty: a literal at the call site, then a name, then a field, then another file.
DIMENSIONS = [
    "Basis benchmark",
    "Interprocedural (2 methods)",
    "pure Interprocedural cases",
    "Field sensitive",
    "Interprocedural + Field Sensitive",
    "Multiple java classes",
    "Path sensitive cases",
]


def _load(name: str) -> list[dict]:
    path = GT / name
    if not path.exists():
        raise SystemExit(f"missing {path}; run benchmarks/groundtruth/score_cryptoapi.py first")
    return list(csv.DictReader(path.open(encoding="utf-8")))


def _counts(rows: list[dict], group: str | None = None) -> Counter:
    subset = [r for r in rows if r["category"] == "A" and (group is None or r["group"] == group)]
    return Counter(r["outcome"] for r in subset)


def _rate(hit: int, total: int) -> str:
    if not total:
        return "n/a"
    band = wilson_interval(hit, total)
    return f"{hit / total:.1%} [{band.low:.1%}, {band.high:.1%}]"


def main() -> int:
    after = _load("cryptoapi_bench_outcomes.csv")
    before = _load("outcomes_nofold.csv")

    # T08 / B12 — the ablation, per analysis dimension.
    with (OUT / "tables" / "T08_ablation.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["dimension", "n", "recall_before", "recall_after", "tp_before", "tp_after",
             "fp_before", "fp_after"]
        )  # fmt: skip
        for dimension in DIMENSIONS:
            b, a = _counts(before, dimension), _counts(after, dimension)
            n = sum(b.values())
            if not n:
                continue
            writer.writerow(
                [dimension, n,
                 _rate(b["TP"], b["TP"] + b["FN"]), _rate(a["TP"], a["TP"] + a["FN"]),
                 b["TP"], a["TP"], b["FP"], a["FP"]]
            )  # fmt: skip
        b, a = _counts(before), _counts(after)
        writer.writerow(
            ["ALL (category A)", sum(b.values()),
             _rate(b["TP"], b["TP"] + b["FN"]), _rate(a["TP"], a["TP"] + a["FN"]),
             b["TP"], a["TP"], b["FP"], a["FP"]]
        )  # fmt: skip

    # T09 / B13 — the headline, against ground truth nobody here produced.
    with (OUT / "tables" / "T09_groundtruth.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["category", "n", "tp", "fp", "fn", "tn", "precision", "recall"])
        for label, key in (
            ("A — weak-algorithm identity", "A"),
            ("B — construct differs (RSA key size)", "B"),
            ("C — declared out of scope", "C"),
        ):
            subset = [r for r in after if r["category"] == key]
            counts = Counter(r["outcome"] for r in subset)
            tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
            writer.writerow(
                [label, len(subset), tp, fp, fn, tn,
                 _rate(tp, tp + fp), _rate(tp, tp + fn)]
            )  # fmt: skip

    _figure(before, after)

    b, a = _counts(before), _counts(after)
    print(f"T08: ablation over {len(DIMENSIONS)} analysis dimensions")
    print(f"T09: category A recall {_rate(b['TP'], b['TP'] + b['FN'])} -> "
          f"{_rate(a['TP'], a['TP'] + a['FN'])}")  # fmt: skip
    return 0


def _figure(before: list[dict], after: list[dict]) -> None:
    import matplotlib.pyplot as plt

    labels, before_recall, after_recall = [], [], []
    for dimension in DIMENSIONS:
        b, a = _counts(before, dimension), _counts(after, dimension)
        if not (b["TP"] + b["FN"]):
            continue  # a dimension with no positive cases has no recall to plot
        labels.append(SHORT[dimension])
        before_recall.append(100 * b["TP"] / (b["TP"] + b["FN"]))
        after_recall.append(100 * a["TP"] / (a["TP"] + a["FN"]))

    positions = range(len(labels))
    fig, ax = plt.subplots(figsize=(6.2, 3.1))
    width = 0.38
    ax.bar([p - width / 2 for p in positions], before_recall, width,
           label="AST match on literals only", color=PALETTE[1])  # fmt: skip
    ax.bar([p + width / 2 for p in positions], after_recall, width,
           label="+ intra-file constant folding", color=PALETTE[2])  # fmt: skip
    ax.set_xticks(list(positions))
    ax.set_xticklabels(labels, fontsize=7.0)
    ax.set_ylabel("recall (%)")
    ax.set_ylim(0, 108)
    ax.legend(frameon=False, loc="upper right", fontsize=7)
    save_figure(
        fig,
        "F16_ablation",
        "What folding a single intra-file constant assignment buys, per CryptoAPI-Bench analysis "
        "dimension. A purely syntactic AST match finds the misuse whenever the algorithm is a "
        "literal at the call site and finds none of it otherwise, which is the profile of every "
        'rule-pack crypto scanner. Resolving `String c = "DES/ECB/PKCS5Padding"` before the '
        "`Cipher.getInstance(c)` that uses it lifts the interprocedural cases from 0% to 100%; the "
        "field-sensitive and cross-file cases stay at 0% because they need real dataflow "
        "analysis, which is what CryptoGuard contributes and this does not attempt. "
        "Source: tables/T08_ablation.csv.",
    )


if __name__ == "__main__":
    raise SystemExit(main())
