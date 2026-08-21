"""Run every available detector over one corpus and report what they jointly imply.

    uv run python benchmarks/oracles/run_multi.py "git help/go-jose" --name go-jose
    uv run python benchmarks/oracles/run_multi.py "git help/vault" --name vault --json out.json

This differs from `benchmarks/recall/run.py` in one way that matters: there is no oracle and no tool
under test, only detectors. The recall harness asked "how much of pqaudit's output did QUBIT
reproduce", which is a fine question with a known ceiling — it cannot see anything pqaudit missed.
This one asks what all the detectors together imply about the cryptography NONE of them found, which
is the question a reader needs answered before trusting any inventory.

Output, in order of how much it should be trusted:

1. **Per-detector counts and the pairwise agreement matrix.** Raw, assumption-free. If two detectors
   share almost nothing, everything below is meaningless and this is where you see that.
2. **The capture table** — how many sites each combination of detectors found. This is the evidence
   the estimate is computed from, printed so it can be checked by hand.
3. **The population estimate**, with its caveats attached rather than in a footnote. Read it as a
   floor on what was missed. `population.py` explains, with a simulation, why it is not more.

Sites, not lines: the unit is `(file, algorithm family)`, because twelve QUBIT rules dedupe per file
by design and a line-level comparison against a regex that fires on every line measures that design
decision and nothing else. It scored 9.5% the first time this was tried.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# Windows consoles default to cp1252 and render every em-dash in this report as a replacement
# character. A benchmark report that cannot be read is not a report.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from base import Finding
from cryptoscan_oracle import CryptoscanDetector
from population import (
    agreement_matrix,
    capture_histories,
    chapman_estimate,
    loglinear_estimate,
)
from pqaudit_oracle import PqauditDetector
from qubit_detector import QubitDetector
from semgrep_oracle import SemgrepDetector

#: QUBIT first only so its counts read first. The comparison itself is order-independent.
DETECTORS = [QubitDetector(), PqauditDetector(), SemgrepDetector(), CryptoscanDetector()]


def _pct(interval) -> str:  # type: ignore[no-untyped-def]
    """Proportions read as percentages; `0.8 [0.7, 0.8]` hides the precision it has."""
    return f"{interval.point:.1%} [{interval.low:.1%}, {interval.high:.1%}]"


def _rule(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def collect(target: Path) -> tuple[dict[str, list[Finding]], dict[str, str]]:
    """Run every detector that can run here, and record why the others could not.

    A detector that is unavailable must never be silently recorded as finding nothing: zero findings
    and zero capability look identical in a table and mean opposite things.
    """
    findings: dict[str, list[Finding]] = {}
    unavailable: dict[str, str] = {}
    for detector in DETECTORS:
        ok, reason = detector.available()
        if not ok:
            unavailable[detector.name] = reason
            print(f"  {detector.name:12} SKIPPED — {reason}", file=sys.stderr)
            continue
        print(f"  {detector.name:12} running...", file=sys.stderr, flush=True)
        hits = detector.scan(target)
        findings[detector.name] = hits
        print(f"  {detector.name:12} {len(hits)} findings", file=sys.stderr)
    return findings, unavailable


def shared_vocabulary(findings: dict[str, list[Finding]], minimum: int = 2) -> set[str]:
    """Families that at least `minimum` detectors are capable of reporting at all.

    Without this the comparison quietly rewards QUBIT for having a bigger vocabulary rather than
    better detection. On go-jose, 109 of QUBIT's findings are the family `JSON WEB TOKEN`, which
    neither cryptoscan nor pqaudit has any name for -- so every one of them lands in "found by QUBIT
    alone", inflates the estimated population, and lowers everyone else's apparent recall. That is
    the same error as scoring QUBIT against cryptoscan's own sample files, pointing the other way,
    and it would be a much easier one to publish without noticing.

    Restricting to the shared vocabulary asks the only question the detectors can jointly answer:
    of the cryptography they all know how to name, who found it?
    """
    per_family: Counter[str] = Counter()
    for hits in findings.values():
        for fam in {f.family for f in hits}:
            per_family[fam] += 1
    return {fam for fam, detectors in per_family.items() if detectors >= minimum}


def report(
    name: str,
    findings: dict[str, list[Finding]],
    unavailable: dict[str, str],
    *,
    restrict_vocabulary: bool = True,
) -> dict:
    vocabulary = shared_vocabulary(findings)
    if restrict_vocabulary:
        findings = {
            detector: [f for f in hits if f.family in vocabulary]
            for detector, hits in findings.items()
        }
    sites = {detector: {f.site for f in hits} for detector, hits in findings.items()}

    _rule(f"{name}: what each detector found")
    if restrict_vocabulary:
        print(
            f"  restricted to the {len(vocabulary)} families >=2 detectors can name: "
            f"{', '.join(sorted(vocabulary))}"
        )
        print("  (a family only one detector has a word for cannot be a disagreement about it)\n")
    print(f"  {'detector':12} {'findings':>9} {'sites':>7}   top families")
    for detector, hits in sorted(findings.items()):
        families = Counter(f.family for f in hits).most_common(4)
        summary = ", ".join(f"{fam} x{n}" for fam, n in families) or "-"
        print(f"  {detector:12} {len(hits):>9} {len(sites[detector]):>7}   {summary}")
    for detector, reason in sorted(unavailable.items()):
        print(f"  {detector:12} {'unavailable':>9}           {reason}")

    _rule("pairwise agreement (Jaccard over sites)")
    agreement = agreement_matrix(sites)
    for (left, right), value in sorted(agreement.items()):
        note = "  <- share almost nothing; treat estimates below as noise" if value < 0.05 else ""
        print(f"  {left:12} vs {right:12} {value:6.1%}{note}")

    payload: dict = {
        "corpus": name,
        "shared_vocabulary": sorted(vocabulary),
        "vocabulary_restricted": restrict_vocabulary,
        "detectors": {
            detector: {"findings": len(hits), "sites": len(sites[detector])}
            for detector, hits in findings.items()
        },
        "unavailable": unavailable,
        "agreement": {f"{a}|{b}": v for (a, b), v in agreement.items()},
    }

    if len(sites) < 2:
        print("\n  fewer than two detectors ran; no population estimate is possible")
        return payload

    table = capture_histories(sites)
    order = sorted(sites)
    _rule("capture table (sites found by each combination)")
    for pattern, count in sorted(table.items(), key=lambda kv: (-kv[1], kv[0])):
        names = "+".join(n for n, bit in zip(order, pattern, strict=True) if bit)
        print(f"  {count:6}  {names}")
    print(f"  {'?':>6}  found by NO detector — estimated below")

    payload["capture_table"] = {
        "+".join(n for n, bit in zip(order, pattern, strict=True) if bit): count
        for pattern, count in table.items()
    }

    _rule("population estimate")
    estimates = []

    if "qubit" in sites:
        others = [d for d in order if d != "qubit"]
        for other in others:
            a, b = sites["qubit"], sites[other]
            estimate = chapman_estimate(len(a), len(b), len(a & b))
            print(f"\n  qubit vs {other} — {estimate.method}")
            print(f"    population    {estimate.total}")
            print(f"    missed by all {estimate.missed_by_all:.1f}")
            print(f"    qubit recall  {_pct(estimate.recall_of(len(a)))}   (UPPER bound)")
            for caveat in estimate.caveats:
                print(f"    ! {caveat}")
            estimates.append({"pair": f"qubit|{other}", **_as_dict(estimate, len(a))})

    if len(sites) >= 3:
        for interactions, label in [(None, "independence"), ([(0, 1)], "one interaction")]:
            try:
                estimate = loglinear_estimate(table, interactions=interactions)
            except ValueError as exc:
                print(f"\n  log-linear ({label}): not fitted — {exc}")
                continue
            print(f"\n  all detectors — {estimate.method}")
            print(f"    population    {estimate.total}")
            print(f"    missed by all {estimate.missed_by_all:.1f}")
            if "qubit" in sites:
                recall = estimate.recall_of(len(sites["qubit"]))
                print(f"    qubit recall  {_pct(recall)}   (UPPER bound)")
            for caveat in estimate.caveats:
                print(f"    ! {caveat}")
            estimates.append(
                {"model": label, **_as_dict(estimate, len(sites.get("qubit", set())))}
            )

    payload["estimates"] = estimates
    print(
        "\n  Every figure above is a FLOOR on the population and a CEILING on recall. "
        "See population.py."
    )
    return payload


def _as_dict(estimate, found: int) -> dict:  # type: ignore[no-untyped-def]
    recall = estimate.recall_of(found)
    return {
        "method": estimate.method,
        "observed": estimate.observed,
        "population": [estimate.total.point, estimate.total.low, estimate.total.high],
        "missed_by_all": estimate.missed_by_all,
        "qubit_recall_upper_bound": [recall.point, recall.low, recall.high],
        "caveats": estimate.caveats,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--name", default=None, help="label for the corpus in the report")
    parser.add_argument("--json", type=Path, default=None, help="also write the report as JSON")
    parser.add_argument(
        "--all-families",
        action="store_true",
        help="do NOT restrict to the shared vocabulary; credits every detector for families only "
        "it can name, which flatters whichever tool has the largest vocabulary",
    )
    args = parser.parse_args()

    target = args.target
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    name = args.name or target.name

    print(f"scanning {target} with {len(DETECTORS)} detectors", file=sys.stderr)
    findings, unavailable = collect(target)
    if not findings:
        print("no detector could run", file=sys.stderr)
        return 1

    payload = report(name, findings, unavailable, restrict_vocabulary=not args.all_families)
    if args.json:
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
