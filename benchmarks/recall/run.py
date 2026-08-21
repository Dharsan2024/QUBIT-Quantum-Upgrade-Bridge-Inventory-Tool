"""Measure QUBIT's detection against an independent detector on real, third-party source.

    uv run python benchmarks/recall/run.py "git help/go-jose" --name go-jose
    uv run python benchmarks/recall/run.py "git help/vault" --name vault --json out.json

What this reports, and what it deliberately does not:

* **Agreement** — both detectors found crypto of the same family on the same line. Neither tool is
  assumed correct; agreement between two independently written detectors is simply the strongest
  evidence available that something is really there.
* **Oracle-only** — the independent detector found something QUBIT did not. These are QUBIT's
  candidate false negatives, and the reason this harness exists. They are *candidates* because a
  regex over source text also fires on strings, identifiers and vendored fixtures, so they are
  printed in full for adjudication rather than counted as misses.
* **QUBIT-only** — QUBIT found something the regexes did not. Some of this is QUBIT's advantage: it
  parses, so it can resolve `HashAlgorithm.Create(algo)` or a digest named through a constant, which
  no line-level pattern can reach. Some of it will be QUBIT's own false positives. Same treatment:
  printed, not assumed.

Recall is reported over the adjudicable population — lines where the oracle fired — because that is
the only population where an independent opinion exists. It is a lower bound on QUBIT's true recall
against that oracle's vocabulary, not a measurement of every algorithm in the corpus, and it says
nothing about crypto neither tool knows to look for. Saying which is which is the point.

Provenance of the oracle and of every corpus repository is recorded in README.md.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from oracle import OracleFinding, load_rules, scan_tree

REPO_ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATTERNS = REPO_ROOT / "git help" / "pqaudit" / "rules" / "crypto-patterns.yaml"

#: Both tools name the same primitive differently — "3DES" vs "TripleDES", "ECDSA-P256" vs "ECDSA".
#: Comparison is by FAMILY, so a disagreement about parameters is not counted as a miss. The
#: families are deliberately coarse: the question is "did QUBIT see this cryptography at all".
_FAMILY_ALIASES: dict[str, str] = {
    "TRIPLEDES": "3DES",
    "DES3": "3DES",
    "ECDSA": "EC",
    "ECDH": "EC",
    "ECC": "EC",
    "ED25519": "EC",
    "X25519": "EC",
    "CURVE25519": "EC",
    "SHA1": "SHA-1",
    "SHA-1": "SHA-1",
    "MLKEM": "ML-KEM",
    "MLDSA": "ML-DSA",
    "SLHDSA": "SLH-DSA",
    "KYBER": "ML-KEM",
    "DILITHIUM": "ML-DSA",
}


def family(algorithm: str) -> str:
    """Coarse family label, so `RSA-2048` and `RSA` compare equal."""
    token = (algorithm or "").upper().strip()
    if not token:
        return "?"
    token = token.replace("_", "-")
    if token in _FAMILY_ALIASES:
        return _FAMILY_ALIASES[token]
    head = token.split("-")[0]
    return _FAMILY_ALIASES.get(head, head)


@dataclass(frozen=True)
class QubitFinding:
    path: str
    line: int
    algorithm: str
    rule_id: str


def run_qubit(target: Path) -> list[QubitFinding]:
    """Scan through the public CLI — the same entry point a user runs."""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "qubit_cli.main", "scan", str(target), "--json"],
        capture_output=True,
        timeout=3600,
        cwd=str(REPO_ROOT),
        check=False,
    )
    raw = result.stdout.decode("utf-8", errors="replace")
    start = raw.find("{")
    if start == -1:
        return []
    try:
        data = json.loads(raw[start:])
    except json.JSONDecodeError:
        return []
    findings: list[QubitFinding] = []
    for asset in data.get("assets", []):
        location = asset.get("location") or {}
        file_path = location.get("file_path")
        line = location.get("line")
        if not file_path or not line:
            continue
        try:
            rel = Path(file_path).resolve().relative_to(target.resolve()).as_posix()
        except ValueError:
            rel = Path(file_path).as_posix()
        findings.append(
            QubitFinding(
                path=rel,
                line=int(line),
                algorithm=str(asset.get("algorithm", "")),
                rule_id=str(asset.get("rule_id", "")),
            )
        )
    return findings


def compare(
    oracle_findings: list[OracleFinding], qubit_findings: list[QubitFinding], tolerance: int = 1
) -> dict[str, object]:
    """Align by file and line, allowing a small offset.

    An AST node's reported line and a regex's line can differ by one where a call spans lines, and
    counting that as a disagreement would manufacture both a miss and a false positive from a
    formatting detail.
    """
    by_file: dict[str, list[QubitFinding]] = defaultdict(list)
    for finding in qubit_findings:
        by_file[finding.path].append(finding)

    agreed: list[tuple[OracleFinding, QubitFinding]] = []
    oracle_only: list[OracleFinding] = []
    matched_qubit: set[tuple[str, int, str]] = set()

    for hit in oracle_findings:
        want = family(hit.algorithm)
        candidates = [
            q
            for q in by_file.get(hit.path, [])
            if abs(q.line - hit.line) <= tolerance and family(q.algorithm) == want
        ]
        if candidates:
            hit_line = hit.line
            best = min(candidates, key=lambda q: abs(q.line - hit_line))
            agreed.append((hit, best))
            matched_qubit.add((best.path, best.line, best.algorithm))
        else:
            oracle_only.append(hit)

    qubit_only = [q for q in qubit_findings if (q.path, q.line, q.algorithm) not in matched_qubit]

    # The primary measure. Twelve QUBIT rules carry `dedupe: per-file`, because an inventory that
    # lists the same `*ecdsa.PrivateKey` twenty times in one file is a worse inventory, not a more
    # complete one. Comparing line by line against a regex that fires on every line scores those
    # nineteen suppressed duplicates as misses, which is how the first run of this harness produced
    # 9.5% and meant nothing. What an inventory claims is per file: "this file uses ECDSA".
    oracle_pairs = {(f.path, family(f.algorithm)) for f in oracle_findings}
    qubit_pairs = {(q.path, family(q.algorithm)) for q in qubit_findings}
    covered = oracle_pairs & qubit_pairs
    missed_pairs = sorted(oracle_pairs - qubit_pairs)
    extra_pairs = sorted(qubit_pairs - oracle_pairs)

    total_oracle = len(oracle_findings)
    return {
        "oracle_total": total_oracle,
        "qubit_total": len(qubit_findings),
        "agreed": len(agreed),
        "oracle_only": oracle_only,
        "qubit_only": qubit_only,
        "line_recall": (len(agreed) / total_oracle) if total_oracle else None,
        "oracle_pairs": len(oracle_pairs),
        "qubit_pairs": len(qubit_pairs),
        "covered_pairs": len(covered),
        "missed_pairs": missed_pairs,
        "extra_pairs": extra_pairs,
        "recall": (len(covered) / len(oracle_pairs)) if oracle_pairs else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="corpus directory to scan")
    parser.add_argument("--name", default=None, help="label for this corpus in the output")
    parser.add_argument("--json", type=Path, default=None, help="write the full result as JSON")
    parser.add_argument("--show", type=int, default=25, help="disagreements to print per side")
    args = parser.parse_args()

    target: Path = args.target.resolve()
    if not target.is_dir():
        print(f"not a directory: {target}", file=sys.stderr)
        return 2
    if not ORACLE_PATTERNS.is_file():
        print(
            f"oracle patterns not found at {ORACLE_PATTERNS}.\n"
            "Clone https://github.com/PQCWorld/pqaudit into 'git help/pqaudit' (see README.md).",
            file=sys.stderr,
        )
        return 2

    name = args.name or target.name
    rules = load_rules(ORACLE_PATTERNS)
    print(f"corpus   : {name}  ({target})")
    print(f"oracle   : {len(rules)} rules from pqaudit/rules/crypto-patterns.yaml")

    oracle_findings = scan_tree(target, rules)
    qubit_findings = run_qubit(target)
    result = compare(oracle_findings, qubit_findings)

    oracle_only: list[OracleFinding] = result["oracle_only"]  # type: ignore[assignment]
    qubit_only: list[QubitFinding] = result["qubit_only"]  # type: ignore[assignment]
    missed_pairs: list[tuple[str, str]] = result["missed_pairs"]  # type: ignore[assignment]
    extra_pairs: list[tuple[str, str]] = result["extra_pairs"]  # type: ignore[assignment]
    recall = result["recall"]
    line_recall = result["line_recall"]

    print()
    print("PRIMARY — per (file, algorithm family), the claim an inventory makes")
    print(f"  independent detector : {result['oracle_pairs']}")
    print(f"  QUBIT                : {result['qubit_pairs']}")
    print(f"  both                 : {result['covered_pairs']}")
    print(f"  oracle only          : {len(missed_pairs)}   <- candidate QUBIT misses")
    print(f"  QUBIT only           : {len(extra_pairs)}")
    if recall is not None:
        print(f"  RECALL vs oracle     : {recall:.1%}")

    print()
    print("secondary — per line. Twelve QUBIT rules dedupe per file by design, so every")
    print("suppressed duplicate counts as a miss here. Reported for completeness, not as recall.")
    print(
        f"  oracle lines {result['oracle_total']} | QUBIT lines {result['qubit_total']} | "
        f"agreed {result['agreed']}" + (f" | {line_recall:.1%}" if line_recall is not None else "")
    )

    if missed_pairs:
        print("\n--- MISSED, by algorithm family (file-level)")
        for algorithm, count in Counter(a for _, a in missed_pairs).most_common():
            print(f"    {algorithm:<14} {count} file(s)")
        print(f"\n--- missed, first {args.show} (adjudicate these)")
        by_pair: dict[tuple[str, str], OracleFinding] = {}
        for finding in oracle_only:
            by_pair.setdefault((finding.path, family(finding.algorithm)), finding)
        for pair in missed_pairs[: args.show]:
            example = by_pair.get(pair)
            where = f"{example.path}:{example.line}" if example else pair[0]
            text = example.text if example else ""
            rule = f"[{example.rule_id}] " if example else ""
            print(f"    {pair[1]:<10} {where}  {rule}{text}")

    if extra_pairs:
        print(
            "\n--- QUBIT only, by algorithm family (its parser reaching past a regex, or its FPs)"
        )
        for algorithm, count in Counter(a for _, a in extra_pairs).most_common(20):
            print(f"    {algorithm:<14} {count} file(s)")

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "corpus": name,
                    "target": str(target),
                    "oracle_total": result["oracle_total"],
                    "qubit_total": result["qubit_total"],
                    "agreed": result["agreed"],
                    "recall": recall,
                    "line_recall": line_recall,
                    "oracle_pairs": result["oracle_pairs"],
                    "qubit_pairs": result["qubit_pairs"],
                    "covered_pairs": result["covered_pairs"],
                    "missed_pairs": missed_pairs,
                    "extra_pairs": extra_pairs,
                    "oracle_only": [f.__dict__ for f in oracle_only],
                    "qubit_only": [f.__dict__ for f in qubit_only],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
