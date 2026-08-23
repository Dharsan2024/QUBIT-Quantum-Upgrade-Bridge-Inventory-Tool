"""Roll the per-repository sweep results up into the tables the README quotes.

Written because the README's numbers were transcribed by hand the first time and went stale the
moment the classifier was fixed. Every figure it prints is regenerable from `results/`:

    uv run python benchmarks/corpus/aggregate.py

Two rules the totals follow, both of which change the answer.

**Detectors are summed only over repositories where they ran.** A detector that was unavailable for
one repository must not have a zero folded into its total; zero findings and zero capability look
identical in a column and mean opposite things.

**Nothing is averaged across repositories.** The corpus is 17 projects of wildly different size --
one contributes 317 exclusive findings and another 2 -- so a mean of per-repository rates would be
a statement about the small ones. Totals are pooled, and the spread is reported beside them rather
than smoothed away, because on this corpus the spread is the finding.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CLASSES = ("code", "mention", "comment", "absent", "not_applicable")


def load(results: Path) -> list[dict]:
    out = []
    for path in sorted(results.glob("*.json")):
        if path.name == "summary.json":
            continue
        out.append(json.loads(path.read_text(encoding="utf-8")))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=HERE / "results")
    args = parser.parse_args()

    records = load(args.results)
    if not records:
        raise SystemExit(f"no per-repository results in {args.results}")

    print(f"\n{len(records)} repositories included\n")

    # ---- per repository: who saw what, in the shared vocabulary -----------------------------
    print("SITES PER REPOSITORY (shared vocabulary; a detector that reported nothing shows 0)\n")
    detectors = ("qubit", "pqaudit", "semgrep", "cryptoscan")
    widths = {"qubit": 6, "pqaudit": 8, "semgrep": 8, "cryptoscan": 11}
    head = f"  {'repository':38} {'lang':11}"
    print(head + "".join(f"{n:>{widths[n]}}" for n in detectors))

    site_totals: dict[str, int] = defaultdict(int)
    for record in sorted(records, key=lambda r: r["repository"]):
        entries = record.get("comparison", {}).get("detectors", {})
        cells = ""
        for name in detectors:
            sites = entries.get(name, {}).get("sites")
            cells += f"{'-' if sites is None else sites:>{widths[name]}}"
            if sites:
                site_totals[name] += sites
        language = (
            record.get("primary_language") or record.get("stratum") or record.get("language", "")
        )
        print(f"  {record['repository'][:38]:38} {language[:11]:11}{cells}")
    print(
        f"\n  {'TOTAL':38} {'':11}" + "".join(f"{site_totals[n]:>{widths[n]}}" for n in detectors)
    )

    # ---- exclusive findings, classified ------------------------------------------------------
    print("\n\nEXCLUSIVE FINDINGS ACROSS THE CORPUS (reported by one detector and no other)\n")
    totals: dict[str, Counter[str]] = defaultdict(Counter)
    repos_seen: dict[str, set[str]] = defaultdict(set)
    per_repo_rate: dict[str, list[float]] = defaultdict(list)

    for record in records:
        for name, data in record.get("adjudication", {}).items():
            exclusive = data.get("exclusive", 0)
            if not exclusive:
                continue
            repos_seen[name].add(record["repository"])
            for cls in CLASSES:
                totals[name][cls] += data.get(cls, 0)
            totals[name]["exclusive"] += exclusive
            scored = sum(data.get(c, 0) for c in ("code", "mention", "comment", "absent"))
            if scored:
                per_repo_rate[name].append(data.get("code", 0) / scored)

    print(
        f"  {'detector':12} {'repos':>6} {'exclusive':>10} {'code':>7} {'mention':>8} "
        f"{'comment':>8} {'absent':>7} {'n/a':>5}   {'code share':>17}   per-repo spread"
    )
    for name in sorted(totals):
        row = totals[name]
        scored = row["code"] + row["mention"] + row["comment"] + row["absent"]
        share = f"{row['code'] / scored:6.1%}" if scored else "     —"
        rates = per_repo_rate[name]
        spread = (
            f"{min(rates):.0%} to {max(rates):.0%} (median {statistics.median(rates):.0%})"
            if len(rates) > 1
            else "one repository"
        )
        print(
            f"  {name:12} {len(repos_seen[name]):>6} {row['exclusive']:>10} {row['code']:>7} "
            f"{row['mention']:>8} {row['comment']:>8} {row['absent']:>7} "
            f"{row['not_applicable']:>5}   {share:>17}   {spread}"
        )

    print(
        "\n  'code'    the classifier's guess that the algorithm is used at that line\n"
        "  'absent'  the name is not on the line at all, only inside a longer word\n"
        "  'n/a'     a category (PII, SECRET, RUNTIME) it declines to judge by name\n"
        "\n  These are SCREENING classes, not verdicts. Their measured error rates against 601\n"
        "  hand labels are in benchmarks/adjudication/ — the classifier is right about `absent`\n"
        "  95.8% of the time and about `code` 76.6% of the time.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
