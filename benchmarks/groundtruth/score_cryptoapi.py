"""Score QUBIT against CryptoAPI-Bench's published ground truth.

The first number in this project that no language model produced and that this project's authors
did not label. The construct mapping is fixed in `MAPPING.md`, written before this ran; the
categories it puts out of scope are excluded here by that document, not by whatever improved the
score.

    uv run python benchmarks/groundtruth/score_cryptoapi.py
    uv run python benchmarks/groundtruth/score_cryptoapi.py --json out.json

Source: https://github.com/CryptoAPI-Bench/CryptoAPI-Bench (MIT), Afrose et al., SecDev 2019.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
BENCH = REPO_ROOT / "git help" / "cryptoapi-bench"
TRUTH = HERE / "cryptoapi_bench_truth.csv"

sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "oracles"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from population import wilson_interval  # noqa: E402

#: Category A of MAPPING.md — weak-algorithm identity, what an inventory tool is for.
IN_SCOPE = {
    "md5 used", "sha1 used", "md4 used", "md2 used", "des used",
    "rc4 used", "blowfish used", "rc2 used", "idea used",
    "hmacmd5", "hmacsha1", "hmacsha256",
}  # fmt: skip

#: Category B — in scope, but QUBIT and the benchmark mean different things by "vulnerable".
CONSTRUCT_DIFFERS = {"rsa keysize 1024 bits"}

#: Category C — declared out of scope in MAPPING.md, with the reason recorded there.
OUT_OF_SCOPE = {
    "usage of ecb", "constant seed", "usage of random method from library",
    "pbe iteration < 1000", "http", "dummy certificate", "dummy verifier",
    "socket hostname w/o verification",
    "credential in string", "static/contant key", "static/constant key",
    "static/contant password", "static/constant password",
    "static/constant iv", "static/constant salt",
}  # fmt: skip


#: The two rules added, and the fold enabled, in response to what this benchmark showed. `--no-fold`
#: puts both back to how they were so the ablation is *reproduced* rather than remembered -- a
#: before/after number nobody can regenerate is not a measurement.
FOLD_RULES = frozenset({"JAVA-JCA-CIPHER", "JAVA-JCA-MESSAGEDIGEST"})


def disable_constant_folding() -> None:
    """Restore the pre-enhancement scanner: literal-only resolution, and without the two rules
    whose queries accept an identifier."""
    from qubit_scanner.catalog.loader import RuleCatalog
    from qubit_scanner.code import scanner as code_scanner

    def literal_only(node, root):
        return code_scanner.resolve.string_literal_value(node)

    code_scanner._string_value = literal_only

    original = RuleCatalog.for_language

    def without_new_rules(self, language):
        return [cr for cr in original(self, language) if cr.rule.id not in FOLD_RULES]

    RuleCatalog.for_language = without_new_rules  # type: ignore[method-assign]


def category(row: dict) -> str:
    """A/B/C per MAPPING.md. A secure `...Corrected` row inherits its family's category."""
    kind = (row["type"] or "").strip().lower()
    if kind in IN_SCOPE:
        return "A"
    if kind in CONSTRUCT_DIFFERS:
        return "B"
    if kind in OUT_OF_SCOPE:
        return "C"
    if kind in ("", "---"):
        # The secure counterparts carry no type. Their category comes from the file they correct:
        # `BrokenHashCorrected` is the secure twin of the MD5/SHA-1 cases, so it belongs in A.
        name = row["file"].lower()
        if any(k in name for k in ("brokenhash", "brokencrypto", "brokenmac")):
            return "A"
        if "insecureasymmetric" in name:
            return "B"
        return "C"
    return "C"


def qubit_verdict(paths: list[Path]) -> tuple[bool, list[str]]:
    """Does QUBIT report a vulnerable asset anywhere in these files?"""
    from qubit_core.algorithms import resolve
    from qubit_scanner.api import scan_paths

    result = scan_paths(paths, scanners={"code"})
    found = []
    vulnerable = False
    for asset in result.assets:
        record = resolve(asset.algorithm)
        flag = bool(record and record.vulnerable)
        found.append(f"{asset.algorithm}{'!' if flag else ''}")
        vulnerable = vulnerable or flag
    return vulnerable, found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=HERE / "cryptoapi_bench_result.json")
    parser.add_argument("--csv", type=Path, default=HERE / "cryptoapi_bench_outcomes.csv")
    parser.add_argument(
        "--no-fold",
        action="store_true",
        help="score the pre-enhancement scanner, for the ablation",
    )
    args = parser.parse_args()

    if args.no_fold:
        disable_constant_folding()
        print("ABLATION ARM: constant folding disabled, generic rules removed\n")

    if not TRUTH.exists():
        raise SystemExit(f"no {TRUTH.name}; run benchmarks/groundtruth/convert.py first")
    rows = list(csv.DictReader(TRUTH.open(encoding="utf-8")))

    outcomes = []
    skipped_unresolved = 0
    for row in rows:
        if not row["path"]:
            skipped_unresolved += 1
            continue
        paths = [BENCH / p for p in row["path"].split(";")]
        paths = [p for p in paths if p.exists()]
        if not paths:
            skipped_unresolved += 1
            continue
        if row["vulnerable"] == "unstated":
            continue

        expected = row["vulnerable"] == "true"
        got, algorithms = qubit_verdict(paths)
        outcomes.append(
            {
                "file": row["file"],
                "group": row["group"],
                "type": row["type"],
                "category": category(row),
                "expected_vulnerable": expected,
                "qubit_vulnerable": got,
                "outcome": ("TP" if got else "FN") if expected else ("FP" if got else "TN"),
                "algorithms": " ".join(sorted(set(algorithms)))[:120],
            }
        )
        print(
            f"  {outcomes[-1]['outcome']:3} [{outcomes[-1]['category']}] "
            f"{row['file'].split(';')[0][:44]:46} {outcomes[-1]['algorithms'][:44]}",
            flush=True,
        )

    with args.csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(outcomes[0]))
        writer.writeheader()
        writer.writerows(outcomes)

    report = {"skipped_unresolved": skipped_unresolved, "scored": len(outcomes)}
    print("\n" + "=" * 78)
    print(
        f"{len(outcomes)} cases scored, {skipped_unresolved} skipped (file not in the repository)"
    )

    for name, wanted in (
        ("A — weak-algorithm identity (the headline)", {"A"}),
        ("B — construct differs (RSA key size)", {"B"}),
        ("C — declared out of scope", {"C"}),
    ):
        subset = [o for o in outcomes if o["category"] in wanted]
        if not subset:
            continue
        counts = Counter(o["outcome"] for o in subset)
        tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
        print(f"\n{name}")
        print(f"  n {len(subset)}   TP {tp}  FP {fp}  FN {fn}  TN {tn}")
        if tp + fp:
            band = wilson_interval(tp, tp + fp)
            print(f"  precision {tp / (tp + fp):.1%} [{band.low:.1%}, {band.high:.1%}]")
        if tp + fn:
            band = wilson_interval(tp, tp + fn)
            print(f"  recall    {tp / (tp + fn):.1%} [{band.low:.1%}, {band.high:.1%}]")
        report[f"category_{sorted(wanted)[0]}"] = {
            "n": len(subset), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }  # fmt: skip

    misses = [o for o in outcomes if o["outcome"] == "FN" and o["category"] == "A"]
    if misses:
        print(f"\nMissed, in scope ({len(misses)}):")
        for miss in misses[:20]:
            print(f"    {miss['type'][:24]:26} {miss['file'].split(';')[0][:46]}")

    false_alarms = [o for o in outcomes if o["outcome"] == "FP" and o["category"] == "A"]
    if false_alarms:
        print(f"\nFalse alarms, in scope ({len(false_alarms)}):")
        for alarm in false_alarms[:20]:
            print(f"    {alarm['file'].split(';')[0][:46]:48} {alarm['algorithms'][:40]}")

    args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {args.csv.name} and {args.json.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
