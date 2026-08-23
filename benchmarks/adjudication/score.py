"""Score the hand labels: what the detectors' exclusive findings actually are, and how well the
screening classifier reproduces that.

Two questions, deliberately kept apart.

**1. Is the heuristic trustworthy?** `benchmarks/oracles/adjudicate.py` classifies every finding in
the 26-repository corpus without a human, and the corpus-level use/mention result rests entirely on
it. So it is scored against the labels rather than assumed correct: a confusion matrix, per-class
precision and recall with Wilson intervals, and Cohen's kappa. Where the two disagree, the hand
label wins -- the heuristic is the thing being measured.

**2. What are the exclusive findings?** For each detector, the fraction of its findings that no
other detector reported which are real cryptographic uses. This is precision on the stratum where
precision lives, and it is the number the corpus-level claim is made from.

Two things this deliberately does NOT do.

It does not pool the cryptographic findings with QUBIT's HNDL categories (`PII: EMAIL ADDRESS`,
`HARDCODED PASSWORD/SECRET`). They answer different questions about different subsystems and are
reported in separate tables. Averaging them would produce a number describing neither.

It does not bootstrap over findings. Findings inside one repository are not independent -- eleven of
them are the same `najeeb.thangal@orkes.io` in one checked-in fixture file, and 199 of the 601 are
the letters `DES` inside a SQL `ORDER BY`. Resampling findings would treat those as independent
evidence and produce an interval several times too narrow. The bootstrap is over **repositories**,
which is the unit that was actually sampled.

**Cohorts.** `--cohort` splits the labels by the `cohort` field written into `labels.jsonl`:

* `calibration` -- the original 601. The classifier's word-boundary defect and the HNDL scanner's
  filters were both found in these and repaired against them, so anything scored on them afterwards
  is IN-SAMPLE. It answers "were those specific defects fixed", which is worth knowing and is not
  the same question as "how well does it work".
* `holdout` -- drawn afterwards from findings nobody had looked at (`pool.py --exclude-labelled`),
  labelled under the same protocol, and scored without any further repair. This is the cohort a
  reviewer should read.

Labels written before cohorts existed carry no field and count as `calibration`, which is what they
are. Reporting the two together would let the repaired half carry the unrepaired half, so the
default prints the breakdown and refuses to average them silently.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "oracles"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from adjudicate import (  # noqa: E402
    CODE,
    COMMENT,
    NOT_APPLICABLE,
    STRING_LITERAL,
    SUBSTRING,
    classify,
)
from population import wilson_interval  # noqa: E402

USE = "USE"
MENTION = "MENTION"
ABSENT = "ABSENT"
AMBIGUOUS = "AMBIGUOUS"
LABELS = (USE, MENTION, ABSENT)

#: What each heuristic class is a prediction OF. Written in PROTOCOL.md before labelling.
HEURISTIC_TO_LABEL = {
    CODE: USE,
    STRING_LITERAL: MENTION,
    COMMENT: MENTION,
    SUBSTRING: ABSENT,
}

BOOTSTRAP_ROUNDS = 10_000
SEED = 20260821


def load(path: Path) -> list[dict]:
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return json.loads(path.read_text(encoding="utf-8"))


def cohens_kappa(pairs: list[tuple[str, str]]) -> float:
    """Agreement corrected for what two annotators would reach by chance alone.

    Raw agreement flatters any labelling whose classes are unbalanced, and these are: `ABSENT` is
    42% of the sample on its own, so a classifier that answered `ABSENT` every time would score 42%
    and know nothing.
    """
    n = len(pairs)
    if n == 0:
        return float("nan")
    observed = sum(1 for a, b in pairs if a == b) / n
    left = Counter(a for a, _ in pairs)
    right = Counter(b for _, b in pairs)
    expected = sum((left[k] / n) * (right[k] / n) for k in set(left) | set(right))
    if expected >= 1.0:
        return float("nan")
    return (observed - expected) / (1 - expected)


def score(worksheet: list[dict], key: list[dict], labels: list[dict]) -> dict:
    by_id = {item["id"]: item for item in worksheet}
    keyed = {row["id"]: row for row in key}
    labelled = {row["id"]: row for row in labels}

    rows = []
    for ident, label_row in labelled.items():
        item = by_id.get(ident)
        provenance = keyed.get(ident)
        if item is None or provenance is None:
            continue
        # Recomputed here rather than read from the sweep's saved output: the saved classes predate
        # the `not-applicable` class, and the number worth reporting is what the CURRENT classifier
        # would say about this line.
        heuristic = classify(item["source"], item["family"])
        rows.append(
            {
                "id": ident,
                "repository": item["repository"],
                "family": item["family"],
                "detector": provenance["detectors"][0],
                "rule_id": provenance.get("rule_id", ""),
                "label": label_row["label"],
                # Absent means "written before the split existed", which is the calibration set.
                "cohort": label_row.get("cohort", "calibration"),
                "heuristic": heuristic,
                # Which subsystem produced it, read off the rule id rather than guessed from the
                # family. Deciding by "the classifier declined to rule on it" put QUBIT's
                # `RUNTIME` family -- a crypto finding for an algorithm chosen at run time -- in
                # the HNDL table, where it is not a secret and cannot be scored as one.
                "hndl": provenance.get("rule_id", "").startswith(("SECRET-", "PII-")),
            }
        )

    crypto = [r for r in rows if not r["hndl"]]
    hndl = [r for r in rows if r["hndl"]]

    # --- the classifier, measured -------------------------------------------------------------
    # The classifier is scored only where it made a claim. A `not-applicable` verdict is a refusal
    # to rule, and scoring a refusal as a wrong answer would punish the one honest thing it does.
    comparable = [
        r for r in crypto if r["label"] in LABELS and r["heuristic"] in HEURISTIC_TO_LABEL
    ]
    declined = sum(1 for r in crypto if r["heuristic"] == NOT_APPLICABLE)
    pairs = [(HEURISTIC_TO_LABEL[r["heuristic"]], r["label"]) for r in comparable]
    matrix: dict[str, dict[str, int]] = {p: dict.fromkeys(LABELS, 0) for p in LABELS}
    for predicted, actual in pairs:
        matrix[predicted][actual] += 1

    per_class = {}
    for cls in LABELS:
        predicted = sum(matrix[cls].values())
        actual = sum(matrix[p][cls] for p in LABELS)
        hit = matrix[cls][cls]
        per_class[cls] = {
            "predicted": predicted,
            "actual": actual,
            "correct": hit,
            "precision": wilson_interval(hit, predicted) if predicted else None,
            "recall": wilson_interval(hit, actual) if actual else None,
        }

    # --- the detectors, measured --------------------------------------------------------------
    def detector_table(subset: list[dict]) -> dict:
        out: dict[str, dict] = {}
        for detector in sorted({r["detector"] for r in subset}):
            hits = [r for r in subset if r["detector"] == detector]
            counts = Counter(r["label"] for r in hits)
            out[detector] = {
                "labelled": len(hits),
                "counts": dict(counts),
                "use_rate": wilson_interval(counts[USE], len(hits)),
                "bootstrap": bootstrap_by_repository(hits),
            }
        return out

    return {
        "labelled": len(rows),
        "crypto": len(crypto),
        "hndl": len(hndl),
        "ambiguous": sum(1 for r in rows if r["label"] == AMBIGUOUS),
        "kappa": cohens_kappa(pairs),
        "raw_agreement": (
            sum(1 for a, b in pairs if a == b) / len(pairs) if pairs else float("nan")
        ),
        "declined": declined,
        "confusion": matrix,
        "per_class": per_class,
        "scored": len(comparable),
        "detectors_crypto": detector_table([r for r in crypto if r["label"] in LABELS]),
        "detectors_hndl": detector_table([r for r in hndl if r["label"] in LABELS]),
        "rows": rows,
    }


def bootstrap_by_repository(rows: list[dict], rounds: int = BOOTSTRAP_ROUNDS) -> dict | None:
    """Resample REPOSITORIES, not findings.

    A repository contributes a whole cluster of correlated findings at once -- eleven copies of one
    address in one fixture file, or two hundred SQL `ORDER BY` clauses. Treating those as
    independent draws is the mistake that would make every interval here look far tighter than the
    evidence supports.
    """
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_repo[row["repository"]].append(row)
    repositories = sorted(by_repo)
    if len(repositories) < 2:
        return None

    rng = random.Random(SEED)  # noqa: S311 — resampling, not cryptography
    draws = []
    for _ in range(rounds):
        picked = [rng.choice(repositories) for _ in repositories]
        total = sum(len(by_repo[name]) for name in picked)
        if not total:
            continue
        uses = sum(1 for name in picked for row in by_repo[name] if row["label"] == USE)
        draws.append(uses / total)
    draws.sort()
    if not draws:
        return None
    return {
        "repositories": len(repositories),
        "low": draws[int(0.025 * len(draws))],
        "high": draws[min(len(draws) - 1, int(0.975 * len(draws)))],
    }


def _pct(interval) -> str:  # type: ignore[no-untyped-def]
    if interval is None:
        return "     —"
    return f"{interval.point:5.1%} [{interval.low:4.1%}, {interval.high:4.1%}]"


def report(result: dict) -> None:
    print(f"\n{'=' * 78}\n{result['labelled']} hand-labelled findings")
    print(f"  {result['crypto']} cryptographic, {result['hndl']} HNDL categories, ", end="")
    print(f"{result['ambiguous']} unresolvable from the evidence shown\n")

    print("THE SCREENING CLASSIFIER, scored against the labels")
    print("-" * 78)
    print(
        f"  scored on      {result['scored']} findings "
        f"({result['declined']} more it declined to rule on)"
    )
    print(f"  raw agreement  {result['raw_agreement']:.1%}")
    print(f"  Cohen's kappa  {result['kappa']:.3f}")
    print("\n  rows = what adjudicate.py predicted, columns = the hand label\n")
    print(f"    {'':10} {'USE':>8} {'MENTION':>8} {'ABSENT':>8}")
    for predicted in LABELS:
        cells = "".join(f"{result['confusion'][predicted][a]:>9}" for a in LABELS)
        print(f"    {predicted:10}{cells}")

    print(f"\n    {'class':10} {'precision':>22} {'recall':>22}")
    for cls in LABELS:
        entry = result["per_class"][cls]
        print(f"    {cls:10} {_pct(entry['precision']):>22} {_pct(entry['recall']):>22}")

    for title, table, note in (
        (
            "EXCLUSIVE CRYPTOGRAPHIC FINDINGS: what fraction is a real use",
            result["detectors_crypto"],
            "findings this detector reported and no other did",
        ),
        (
            "QUBIT'S HNDL PASS: what fraction is a real secret or a real address",
            result["detectors_hndl"],
            "no other detector reports these categories at all",
        ),
    ):
        if not table:
            continue
        print(f"\n{title}")
        print("-" * 78)
        print(f"  ({note})\n")
        head = f"    {'detector':12} {'n':>5} {'use':>5} {'mention':>8} {'absent':>7}"
        print(f"{head} {'use rate (Wilson)':>24} {'bootstrap over repos':>24}")
        for detector, entry in table.items():
            counts = entry["counts"]
            boot = entry["bootstrap"]
            boot_text = (
                f"[{boot['low']:4.1%}, {boot['high']:4.1%}] n={boot['repositories']}"
                if boot
                else "one repository only"
            )
            print(
                f"    {detector:12} {entry['labelled']:>5} {counts.get(USE, 0):>5} "
                f"{counts.get(MENTION, 0):>8} {counts.get(ABSENT, 0):>7} "
                f"{_pct(entry['use_rate']):>24} {boot_text:>24}"
            )

    print(
        "\n  'use'     the algorithm is invoked, configured or selected at that line\n"
        "  'mention' the name is there but as data or prose: a ban list, a fixture, a comment\n"
        "  'absent'  the name is not there at all; the detector matched something else\n"
    )


def _resolve_cohort_files(args: argparse.Namespace) -> tuple[Path, Path]:
    """Where the worksheet and key for this cohort actually live.

    Every `pool.py` draw overwrites the top-level `worksheet.json` and `key.json`, so those name
    the most recent draw and not the cohort being scored. The per-cohort archives under
    `cohorts/<name>/` are the copies that pair with the labels, and they are the default.
    """
    archived = HERE / "cohorts" / args.cohort
    worksheet = args.worksheet or (
        archived / "worksheet.json" if archived.is_dir() else HERE / "worksheet.json"
    )
    key = args.key or (archived / "key.json" if archived.is_dir() else HERE / "key.json")
    for path in (worksheet, key):
        if not path.exists():
            raise SystemExit(f"missing {path}")
    return worksheet, key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # Default to None and resolve per cohort below. `worksheet.json` at the top level is whatever
    # the LAST draw wrote, so pointing a cohort at it silently scored zero findings -- the ids in
    # the file and the ids in the labels simply did not intersect, and nothing said so.
    parser.add_argument("--worksheet", type=Path, default=None)
    parser.add_argument("--key", type=Path, default=None)
    parser.add_argument("--labels", type=Path, default=HERE / "labels.jsonl")
    parser.add_argument("--json", type=Path, default=HERE / "scores.json")
    parser.add_argument(
        "--cohort",
        choices=["all", "calibration", "holdout"],
        default="all",
        help="which labels to score; 'holdout' is the out-of-sample one",
    )
    args = parser.parse_args()

    labels = load(args.labels)
    counts: dict[str, int] = {}
    for row in labels:
        cohort = row.get("cohort", "calibration")
        counts[cohort] = counts.get(cohort, 0) + 1
    if args.cohort != "all":
        labels = [r for r in labels if r.get("cohort", "calibration") == args.cohort]
        if not labels:
            raise SystemExit(f"no labels in cohort {args.cohort!r}; available: {counts or 'none'}")

    print(
        f"\ncohorts in {args.labels.name}: "
        + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    )
    print(f"scoring cohort: {args.cohort}")
    if args.cohort == "all" and len(counts) > 1:
        print(
            "  NOTE: this mixes the calibration set (repairs were made from it -- in-sample)\n"
            "  with the held-out set. Run --cohort holdout for the out-of-sample figure."
        )

    worksheet_path, key_path = _resolve_cohort_files(args)
    print(f"reading {worksheet_path.relative_to(HERE)} and {key_path.relative_to(HERE)}")

    result = score(load(worksheet_path), load(key_path), labels)
    if not result["labelled"]:
        raise SystemExit(
            f"no label id in {args.labels.name} matches an item in {worksheet_path}. "
            "The cohort archives under cohorts/<name>/ are the ones that pair with the labels."
        )
    report(result)

    if args.json:
        serialisable = {
            k: v
            for k, v in result.items()
            if k not in {"rows", "per_class", "detectors_crypto", "detectors_hndl"}
        }
        serialisable["per_class"] = {
            cls: {
                **{k: v for k, v in entry.items() if k not in {"precision", "recall"}},
                "precision": None
                if entry["precision"] is None
                else list(entry["precision"].as_tuple())
                if hasattr(entry["precision"], "as_tuple")
                else [entry["precision"].point, entry["precision"].low, entry["precision"].high],
                "recall": None
                if entry["recall"] is None
                else [entry["recall"].point, entry["recall"].low, entry["recall"].high],
            }
            for cls, entry in result["per_class"].items()
        }
        for name in ("detectors_crypto", "detectors_hndl"):
            serialisable[name] = {
                detector: {
                    "labelled": entry["labelled"],
                    "counts": entry["counts"],
                    "use_rate": [
                        entry["use_rate"].point,
                        entry["use_rate"].low,
                        entry["use_rate"].high,
                    ],
                    "bootstrap": entry["bootstrap"],
                }
                for detector, entry in result[name].items()
            }
        args.json.write_text(json.dumps(serialisable, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
