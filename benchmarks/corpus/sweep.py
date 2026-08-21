"""Run every detector over every pinned repository, and apply the inclusion criterion.

    uv run python benchmarks/corpus/sweep.py --out results/

One JSON per repository plus a summary. Repositories are processed independently and a failure in
one is recorded rather than aborting the run -- a sweep over 26 real projects that dies on the
seventh has measured seven projects and wasted the time spent on the other nineteen.

**The inclusion criterion is applied here, and it was fixed before any of this ran** (see
`build.py`): a repository enters the analysis only if at least TWO detectors report at least one
finding. A repository nobody fires on carries no information about relative recall; one only QUBIT
fires on cannot be adjudicated by agreement. Excluded repositories are listed in the summary with
their counts, so the criterion can be checked rather than trusted -- if it were ever relaxed after
seeing which way the results fell, the corpus would be selected on its own outcome.

Runtime is hours, not minutes. redis, go-ethereum and discourse are each large enough that
cryptoscan and semgrep take several minutes apiece.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "oracles"))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from adjudicate import CODE, COMMENT, STRING_LITERAL, adjudicate  # noqa: E402
from run_multi import collect, report  # noqa: E402

LOCK_FILE = HERE / "corpus.lock.json"

#: A repository must be seen by this many detectors to enter the analysis. Fixed in advance.
MIN_DETECTORS_WITH_FINDINGS = 2


def sweep(out_dir: Path, *, only: str | None = None) -> dict:
    if not LOCK_FILE.exists():
        raise SystemExit(f"no lockfile at {LOCK_FILE}; run `build.py clone` first")
    lock = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    out_dir.mkdir(parents=True, exist_ok=True)

    included: dict[str, dict] = {}
    excluded: dict[str, dict] = {}
    failed: dict[str, str] = {}

    repositories = sorted(lock["repositories"].items())
    for index, (full_name, meta) in enumerate(repositories, 1):
        if only and only not in full_name:
            continue
        target = REPO_ROOT / meta["path"]
        slug = full_name.replace("/", "__")
        print(f"\n[{index}/{len(repositories)}] {full_name} ({meta['language']})", flush=True)
        if not target.is_dir():
            failed[full_name] = "not cloned"
            print("  MISSING — not cloned", flush=True)
            continue

        started = time.time()
        try:
            findings, unavailable = collect(target)
        except Exception:  # one bad repository must not end the sweep
            failed[full_name] = traceback.format_exc(limit=3)
            print("  FAILED — see summary", flush=True)
            continue

        with_findings = sum(1 for hits in findings.values() if hits)
        record = {
            "repository": full_name,
            "language": meta["language"],
            "commit": meta["commit"],
            "license": meta["license"],
            "stars": meta["stars"],
            "detectors_with_findings": with_findings,
            "counts": {name: len(hits) for name, hits in findings.items()},
            "elapsed_s": round(time.time() - started, 1),
        }

        if with_findings < MIN_DETECTORS_WITH_FINDINGS:
            excluded[full_name] = record
            print(
                f"  EXCLUDED — only {with_findings} detector(s) found anything: {record['counts']}",
                flush=True,
            )
            continue

        try:
            comparison = report(full_name, findings, unavailable)
            record["comparison"] = comparison
            # The criterion again, on the population that is actually comparable. activeadmin
            # passed the raw check -- QUBIT 1 finding, pqaudit 7 -- and then produced an all-zero
            # row, because the two name entirely different families and the shared vocabulary was
            # empty. Two detectors that never name the same kind of thing have not agreed or
            # disagreed about anything, and averaging that in as 0% recall would be reporting a
            # vocabulary mismatch as a detection failure.
            comparable = sum(1 for entry in comparison["detectors"].values() if entry["sites"])
            if comparable < MIN_DETECTORS_WITH_FINDINGS:
                record["exclusion_reason"] = (
                    f"only {comparable} detector(s) reported sites in the shared vocabulary "
                    f"{comparison['shared_vocabulary']}"
                )
                excluded[full_name] = record
                print(f"  EXCLUDED — {record['exclusion_reason']}", flush=True)
                continue

            verdicts = adjudicate(target, findings, sample_size=25)
            record["adjudication"] = {
                name: {
                    "exclusive": data["exclusive_findings"],
                    "code": data["classes"].get(CODE, 0),
                    "mention": data["classes"].get(STRING_LITERAL, 0),
                    "comment": data["classes"].get(COMMENT, 0),
                    "sample": data["sample"],
                }
                for name, data in verdicts.items()
            }
        except Exception:
            failed[full_name] = traceback.format_exc(limit=3)
            print("  FAILED during analysis — see summary", flush=True)
            continue

        included[full_name] = record
        (out_dir / f"{slug}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")

    summary = {
        "included": len(included),
        "excluded": len(excluded),
        "failed": len(failed),
        "min_detectors_with_findings": MIN_DETECTORS_WITH_FINDINGS,
        "repositories": {
            name: {k: v for k, v in record.items() if k not in {"comparison", "adjudication"}}
            for name, record in included.items()
        },
        "excluded_detail": excluded,
        "failed_detail": failed,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE / "results")
    parser.add_argument("--only", default=None, help="substring filter, for re-running one repo")
    args = parser.parse_args()

    summary = sweep(args.out, only=args.only)
    print(
        f"\n\nincluded {summary['included']}, excluded {summary['excluded']}, "
        f"failed {summary['failed']} — wrote {args.out / 'summary.json'}"
    )
    for name, record in sorted(summary["excluded_detail"].items()):
        print(f"  excluded: {name:42} {record['counts']}")
    for name in sorted(summary["failed_detail"]):
        print(f"  failed:   {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
