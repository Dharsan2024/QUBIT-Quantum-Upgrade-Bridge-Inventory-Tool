"""Phase 3f: QUBIT's wall-clock cost against the same four baseline detectors the accuracy
comparison already uses -- pqaudit, semgrep, cryptoscan, sonar-cryptography.

The corpus sweep (`benchmarks/corpus/sweep.py`) never recorded a per-detector split, only one
`elapsed_s` for all five run together per repository, so this reuses the actual oracle wrapper
classes it calls (`benchmarks/oracles/run_multi.DETECTORS`) and times each one independently over a
handful of real corpus repositories spanning the size range already used in `phase3_performance.py`.
One repetition per detector per repository -- this is a comparative figure across five tools, not a
per-tool confidence interval, so it is reported as a single real run rather than padded with repeats
that would only multiply the runtime of the slowest detector (semgrep/cryptoscan, both AST-heavy).

    uv run python paper_evidence/scripts/phase3_overhead.py

Covers F17.
"""

from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks" / "oracles"))

from _style import OUT, PALETTE, ROOT, save_figure

#: Small to medium only -- sweep.py's own docstring notes semgrep/cryptoscan take minutes apiece
#: on the largest repos, and this figure needs relative order of magnitude, not the largest case.
TARGET_REPOS = [
    "lencx/ChatGPT",
    "valinet/ExplorerPatcher",
    "realm/SwiftLint",
    "JetBrains/compose-multiplatform",
]


def main() -> int:
    import json

    from run_multi import DETECTORS

    lock = json.loads(
        (ROOT / "benchmarks" / "corpus" / "corpus.lock.json").read_text(encoding="utf-8")
    )
    rows = []
    for name in TARGET_REPOS:
        target = ROOT / lock["repositories"][name]["path"]
        if not target.is_dir():
            print(f"skip {name}: not cloned")
            continue
        files = sum(1 for p in target.rglob("*") if p.is_file() and ".git" not in p.parts)
        print(f"{name} ({files} files)")
        for detector in DETECTORS:
            ok, reason = detector.available()
            if not ok:
                print(f"  {detector.name:20} unavailable: {reason}")
                continue
            t0 = time.monotonic()
            hits = detector.scan(target)
            elapsed = time.monotonic() - t0
            print(f"  {detector.name:20} {elapsed:7.2f}s  {len(hits)} findings")
            rows.append(
                {
                    "repository": name,
                    "files": files,
                    "detector": detector.name,
                    "seconds": round(elapsed, 2),
                    "findings": len(hits),
                }
            )

    if not rows:
        raise SystemExit("no timings collected -- no corpus repos on disk")

    (OUT / "data").mkdir(parents=True, exist_ok=True)
    target_csv = OUT / "data" / "detector_overhead.csv"
    with target_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    _figure(rows)
    print(f"\nwrote {target_csv}")
    return 0


def _figure(rows: list[dict]) -> None:
    import matplotlib.pyplot as plt

    detectors = sorted({r["detector"] for r in rows})
    repos = TARGET_REPOS

    fig, ax = plt.subplots(figsize=(6.0, 3.0))
    width = 0.8 / len(detectors)
    x = range(len(repos))
    for i, det in enumerate(detectors):
        ys = []
        for repo in repos:
            match = [r["seconds"] for r in rows if r["repository"] == repo and r["detector"] == det]
            ys.append(match[0] if match else 0.0)
        offsets = [xi + (i - (len(detectors) - 1) / 2) * width for xi in x]
        ax.bar(offsets, ys, width, label=det, color=PALETTE[i % len(PALETTE)])
    ax.set_xticks(list(x))
    ax.set_xticklabels([r.split("/")[-1] for r in repos], fontsize=8)
    ax.set_ylabel("wall-clock seconds (log)")
    ax.set_yscale("log")
    ax.legend(frameon=False, fontsize=7, ncol=3, loc="upper left")
    save_figure(
        fig,
        "F17_overhead",
        "QUBIT's wall-clock cost against the same four baseline detectors the accuracy comparison "
        "uses, one real run per detector per repository (log scale -- the spread is more than an "
        "order of magnitude, not a small effect). sonar-cryptography is absent from repositories "
        "outside its Java/Python/Go applicability gate. Source: data/detector_overhead.csv.",
    )


if __name__ == "__main__":
    raise SystemExit(main())
