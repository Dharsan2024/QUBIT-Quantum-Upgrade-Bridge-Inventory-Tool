"""Re-run the HNDL scanner over exactly the lines that were hand-labelled, and report what moved.

This is the closing half of the loop the labels exist for. `score.py` says what the scanner got
wrong; this says whether fixing it worked, measured against the same 151 labels rather than against
a fresh set of invented test cases.

Both directions are printed, and the second is the one that matters. Dropping false positives is
easy -- a filter that rejects everything scores perfectly on that half and is worthless. The
question is whether the findings hand-labelled as **real** survived.

    uv run python benchmarks/adjudication/recheck.py

Note what this number is and is not. The filters in `qubit_scanner.secrets` were written *from*
these labels, so the figure it prints is **in-sample**: it is a measurement of whether the specific
defects found were actually repaired, not an estimate of precision on unseen code. A fresh sample
would be needed for that, and the sampler is `pool.py`.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "oracles"))
sys.path.insert(0, str(HERE))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from qubit_scanner.secrets import SecretScanner  # noqa: E402
from score import load, score  # noqa: E402

LOCK = REPO_ROOT / "benchmarks" / "corpus" / "corpus.lock.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worksheet", type=Path, default=HERE / "worksheet.json")
    parser.add_argument("--key", type=Path, default=HERE / "key.json")
    parser.add_argument("--labels", type=Path, default=HERE / "labels.jsonl")
    args = parser.parse_args()

    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    worksheet = load(args.worksheet)
    result = score(worksheet, load(args.key), load(args.labels))
    by_id = {item["id"]: item for item in worksheet}
    scanner = SecretScanner()

    scanned: dict[Path, set[tuple[int | None, str]]] = {}
    kept: collections.Counter[str] = collections.Counter()
    dropped: collections.Counter[str] = collections.Counter()
    missing = 0

    for row in result["rows"]:
        if not row["hndl"] or row["label"] not in {"USE", "MENTION", "ABSENT"}:
            continue
        item = by_id[row["id"]]
        meta = lock["repositories"].get(item["repository"])
        if meta is None:
            missing += 1
            continue
        path = REPO_ROOT / meta["path"] / item["path"]
        if not path.is_file():
            missing += 1
            continue
        if path not in scanned:
            scanned[path] = {(d.location.line, d.rule_id) for d in scanner.scan_file(path)}
        still = (item["line"], row["rule_id"]) in scanned[path]
        (kept if still else dropped)[row["label"]] += 1

    before = sum(kept.values()) + sum(dropped.values())
    after = sum(kept.values())
    print(f"\n{before} hand-labelled HNDL findings, re-scanned with the current scanner")
    if missing:
        print(f"  ({missing} skipped: repository not cloned)")
    print(f"\n  {'label':10} {'labelled':>9} {'still reported':>15} {'dropped':>9}")
    for label in ("USE", "MENTION", "ABSENT"):
        print(
            f"  {label:10} {kept[label] + dropped[label]:>9} {kept[label]:>15} {dropped[label]:>9}"
        )

    was = result["detectors_hndl"].get("qubit")
    print(
        f"\n  real findings kept: {kept['USE']}/{kept['USE'] + dropped['USE']}"
        f"    outright false positives dropped: {dropped['ABSENT']}/"
        f"{kept['ABSENT'] + dropped['ABSENT']}"
    )
    if after and was is not None:
        print(
            f"  precision on this sample: {kept['USE'] / after:.1%} ({kept['USE']}/{after}), "
            f"was {was['use_rate'].point:.1%} ({was['counts'].get('USE', 0)}/{before})"
        )
    print("\n  In-sample: these filters were written from these labels.")
    print("  See the module docstring for what that does and does not license.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
