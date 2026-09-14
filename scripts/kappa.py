"""Cohen's kappa over two raters' labels, plus every disagreement, verbatim.

Run once both rater files exist:

    uv run python scripts/kappa.py \
        --a unwanted/paper_evidence/labels_rater_a.csv \
        --b unwanted/paper_evidence/labels_rater_b.csv

Why kappa rather than raw agreement: with four verdicts and one of them dominant, two raters who
never look at the code would still agree most of the time. Kappa subtracts the agreement expected
from the marginals, so it measures whether the RUBRIC is reproducible rather than whether the
answer is usually the same.

Reported per stratum as well as overall, because the strata are not alike. `certificate` findings
are near-mechanical to judge; `library` findings turn entirely on how the rater reads the question
("is this algorithm used here?" versus "does this project depend on something offering it?"), and
that is where the two sets are most likely to part company. A single pooled kappa would hide it.

`unsure` is kept as a category rather than dropped. Two raters who are both unsure agree about
something real - that the packet does not contain enough to decide - and discarding those rows
would silently inflate agreement on the rest.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

VERDICTS = ("correct", "wrong-algorithm", "not-crypto", "unsure")


def _read(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    out: dict[str, dict[str, str]] = {}
    for r in rows:
        verdict = (r.get("verdict") or "").strip()
        if not verdict:
            continue
        if verdict not in VERDICTS:
            raise SystemExit(
                f"{path}: item {r.get('item')} has verdict {verdict!r}, not in {VERDICTS}"
            )
        out[r["token"]] = {"item": r.get("item", ""), "verdict": verdict, "note": r.get("note", "")}
    return out


def cohen_kappa(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """Cohen's kappa. Returns the components too, so a surprising value can be traced."""
    n = len(pairs)
    if n == 0:
        return {"n": 0, "kappa": None}
    observed = sum(1 for a, b in pairs if a == b) / n
    a_marg, b_marg = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    expected = sum((a_marg[v] / n) * (b_marg[v] / n) for v in VERDICTS)
    # Perfect agreement with a degenerate marginal (every row the same label) leaves kappa
    # undefined rather than 1.0 — reporting 1.0 there would claim reproducibility the data cannot
    # support.
    kappa = None if expected >= 1.0 else (observed - expected) / (1 - expected)
    return {
        "n": n,
        "observed_agreement": round(observed, 4),
        "expected_agreement": round(expected, 4),
        "kappa": None if kappa is None else round(kappa, 4),
        "rater_a_marginal": dict(a_marg),
        "rater_b_marginal": dict(b_marg),
    }


def _interpret(k: float | None) -> str:
    if k is None:
        return "undefined (a degenerate marginal)"
    for bound, label in (
        (0.0, "none"),
        (0.20, "slight"),
        (0.40, "fair"),
        (0.60, "moderate"),
        (0.80, "substantial"),
    ):
        if k <= bound:
            return label
    return "almost perfect"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--a", type=Path, default=Path("unwanted/paper_evidence/labels_rater_a.csv"))
    ap.add_argument("--b", type=Path, default=Path("unwanted/paper_evidence/labels_rater_b.csv"))
    ap.add_argument("--key", type=Path, default=Path("unwanted/paper_evidence/label_key.csv"))
    ap.add_argument("--packet", type=Path, default=Path("unwanted/paper_evidence/label_packet.csv"))
    ap.add_argument("--out", type=Path, default=Path("qubit-v2/05-detection"))
    args = ap.parse_args()

    if not args.b.is_file():
        raise SystemExit(
            f"rater B's labels are not at {args.b}.\n"
            "Fill the `verdict` column of label_packet.csv and save it there."
        )

    a, b = _read(args.a), _read(args.b)
    overlap = sorted(set(a) & set(b))
    print(f"rater A: {len(a)} labelled   rater B: {len(b)} labelled   overlap: {len(overlap)}")
    if not overlap:
        raise SystemExit("no overlapping tokens; the two files are not the same packet")

    key = {r["token"]: r for r in csv.DictReader(args.key.open(encoding="utf-8"))}
    packet = {r["token"]: r for r in csv.DictReader(args.packet.open(encoding="utf-8"))}

    by_type: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for tok in overlap:
        by_type[key[tok]["qubit_asset_type"]].append((a[tok]["verdict"], b[tok]["verdict"]))

    overall = cohen_kappa([(a[t]["verdict"], b[t]["verdict"]) for t in overlap])
    report: dict[str, Any] = {"overall": overall, "per_asset_type": {}}
    print(
        f"\n{'stratum':16s} {'n':>4} {'observed':>9} {'expected':>9} {'kappa':>7}  interpretation"
    )
    for t, pairs in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
        k = cohen_kappa(pairs)
        report["per_asset_type"][t] = k
        kv = k["kappa"]
        print(
            f"{t:16s} {k['n']:4d} {k['observed_agreement']:9.3f} {k['expected_agreement']:9.3f} "
            f"{'n/a' if kv is None else f'{kv:7.3f}'}  {_interpret(kv)}"
        )
    kv = overall["kappa"]
    print(
        f"{'ALL':16s} {overall['n']:4d} {overall['observed_agreement']:9.3f} "
        f"{overall['expected_agreement']:9.3f} {'n/a' if kv is None else f'{kv:7.3f}'}  "
        f"{_interpret(kv)}"
    )

    disagreements = [
        {
            "item": a[t]["item"],
            "token": t,
            "asset_type": key[t]["qubit_asset_type"],
            "claimed_algorithm": key[t]["qubit_algorithm"],
            "file": packet[t]["file"],
            "line": packet[t]["line"],
            "rater_a": a[t]["verdict"],
            "rater_a_note": a[t]["note"],
            "rater_b": b[t]["verdict"],
            "rater_b_note": b[t]["note"],
        }
        for t in overlap
        if a[t]["verdict"] != b[t]["verdict"]
    ]
    report["disagreements"] = disagreements
    print(f"\ndisagreements: {len(disagreements)} of {len(overlap)}")
    pattern = Counter((d["rater_a"], d["rater_b"]) for d in disagreements)
    for (ra, rb), n in pattern.most_common(8):
        print(f"   A={ra:16s} B={rb:16s} {n:4d}")

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "kappa.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    with (args.out / "disagreements.csv").open("w", encoding="utf-8", newline="") as fh:
        if disagreements:
            w = csv.DictWriter(fh, fieldnames=list(disagreements[0]), lineterminator="\n")
            w.writeheader()
            w.writerows(disagreements)
    print(f"\nwritten: {args.out / 'kappa.json'} and {args.out / 'disagreements.csv'}")


if __name__ == "__main__":
    main()
