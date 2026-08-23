"""Phase 1b: the reference tables a reader needs to check a claim rather than take it on trust.

Notation, the label taxonomy, what the corpus actually contains, which languages have which rules,
and how the compliance mapping is defined. All five are extraction, not measurement -- every row
comes from a file in the repository, so none of them can drift from what the code does.

Covers T01, T02, T04, T05, T14 of PAPER_EVIDENCE_SPEC.md.

    uv run python paper_evidence/scripts/phase1_reference.py
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT, ROOT

TABLES = OUT / "tables"

#: Every symbol the pack uses in a number, and what it means. Kept here rather than in prose so a
#: reader checking a figure does not have to reconstruct the convention from context.
NOTATION = [
    ("n", "count", "number of items in a sample, stated on every interval"),
    (
        "kappa",
        "Cohen's kappa",
        "chance-corrected agreement between two labellings of the same items",
    ),
    ("kappa_intra", "intra-rater kappa", "one annotator against themselves on hidden repeats"),
    ("P", "precision", "of the items given a label, the fraction that deserved it"),
    ("R", "recall", "of the items deserving a label, the fraction that got it"),
    ("F1", "harmonic mean", "2PR/(P+R)"),
    ("MCC", "Matthews correlation", "balanced even when the classes are not"),
    ("CI", "confidence interval", "95% throughout; Wilson for proportions"),
    ("[a, b]", "interval", "lower and upper bound, inclusive"),
    ("pp", "percentage points", "a difference between two percentages, never a ratio"),
    ("USE", "label", "the algorithm is invoked, configured or selected at this line"),
    ("MENTION", "label", "the name is present as data or prose, not as an operation"),
    ("ABSENT", "label", "the name is not there at all; the detector matched something else"),
    ("AMBIGUOUS", "label", "the line alone cannot settle it; never resolved by guessing"),
    ("HNDL", "harvest now, decrypt later", "the threat model the risk engine quantifies"),
    ("CRQC", "cryptographically relevant quantum computer", "the capability the timeline models"),
    ("CBOM", "cryptographic bill of materials", "CycloneDX 1.7, the exported inventory"),
]


def t01_notation() -> None:
    with (TABLES / "T01_notation.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["symbol", "name", "meaning"])
        writer.writerows(NOTATION)
    print(f"T01: {len(NOTATION)} symbols")


def t02_taxonomy() -> None:
    """The four labels, lifted from the protocol that defined them before any label was assigned."""
    protocol = ROOT / "benchmarks" / "adjudication" / "PROTOCOL.md"
    text = protocol.read_text(encoding="utf-8")
    # Only the table under "The four labels". PROTOCOL.md holds several other tables whose rows
    # also start with a backticked cell, and a bare prefix match swallowed all of them.
    section = text.split("## The four labels", 1)[1].split("\n## ", 1)[0]
    rows = [
        line.strip().strip("|").split("|")
        for line in section.splitlines()
        if line.strip().startswith("| `")
    ]
    with (TABLES / "T02_taxonomy.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["label", "means", "examples"])
        for row in rows:
            writer.writerow([cell.strip().replace("`", "") for cell in row[:3]])
    print(f"T02: {len(rows)} labels, from PROTOCOL.md")


def t04_dataset() -> None:
    """What the corpus is, including the part that is not what it looks like.

    `stratum` is the query a repository was drawn by; `primary_language` is what GitHub says it
    actually is. They differ for four repositories, because `language:C#` matches anything
    CONTAINING C#, so the C# and C++ strata drew C projects.
    """
    lock = json.loads(
        (ROOT / "benchmarks" / "corpus" / "corpus.lock.json").read_text(encoding="utf-8")
    )
    results = ROOT / "benchmarks" / "corpus" / "results"
    status: dict[str, str] = {}
    if results.is_dir():
        for path in sorted(results.glob("*.json")):
            if path.name == "summary.json":
                continue
            record = json.loads(path.read_text(encoding="utf-8"))
            status[record["repository"]] = (
                "included" if record.get("detectors_with_findings", 0) >= 2 else "excluded"
            )

    rows = []
    for name, meta in sorted(lock["repositories"].items()):
        rows.append(
            [
                name,
                meta.get("stratum", ""),
                meta.get("primary_language") or "UNKNOWN",
                meta.get("license") or "NOASSERTION",
                meta.get("stars", ""),
                (meta.get("commit") or "")[:12],
                status.get(name, "not yet swept"),
            ]
        )
    with (TABLES / "T04_dataset.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["repository", "stratum", "primary_language", "license", "stars", "commit", "status"]
        )
        writer.writerows(rows)

    mismatched = sum(1 for r in rows if r[1] != r[2])
    languages = len({r[2] for r in rows})
    print(
        f"T04: {len(rows)} repositories, {languages} real languages, {mismatched} not their stratum"
    )


def t05_coverage() -> None:
    """Which languages have rules, and how each one can name a post-quantum algorithm.

    Three states, not two. A pack can carry an explicit ML-KEM/ML-DSA rule (`literal`), or it can
    read the algorithm out of the call site so whatever the source names is what gets reported
    (`dynamic` -- this is how `Signature.getInstance("ML-DSA-65")` resolves under the generic JCA
    packs). Only a language with neither genuinely cannot report a migration target.
    """
    from _t05 import classify_rule
    from qubit_scanner.catalog.loader import RuleCatalog

    catalog = RuleCatalog.load()
    rows = []
    for language in sorted(catalog.languages()):
        compiled = catalog.for_language(language)
        kinds = [classify_rule(c.rule) for c in compiled]
        literal = kinds.count("literal")
        dynamic = kinds.count("dynamic")
        if literal:
            verdict = "yes, explicit rules"
        elif dynamic:
            verdict = "yes, resolved from source"
        else:
            verdict = "NO"
        rows.append([language, len(compiled), literal, dynamic, verdict])

    with (TABLES / "T05_coverage.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["language", "rules", "explicit_pqc_rules", "dynamic_rules", "can_report_a_pqc_target"]
        )
        writer.writerows(rows)
    without = [str(r[0]) for r in rows if r[4] == "NO"]
    explicit = sum(1 for r in rows if r[2])
    print(
        f"T05: {len(rows)} grammars, {explicit} with explicit PQC rules; "
        f"cannot report a PQC target at all: {', '.join(without) or 'none'}"
    )


def t14_compliance() -> None:
    """The CNSA 2.0 milestone table the risk engine evaluates against, with its weights."""
    import yaml

    params = ROOT / "packages" / "qubit-risk" / "src" / "qubit_risk" / "params"
    policy = yaml.safe_load((params / "cnsa2_milestones.yaml").read_text(encoding="utf-8"))

    with (TABLES / "T14_cnsa2.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["milestone", "deadline", "weight", "requirement"])
        for milestone in policy["milestones"]:
            writer.writerow(
                [
                    milestone["name"],
                    milestone["deadline"],
                    milestone["weight"],
                    " ".join(milestone["requirements"].split()),
                ]
            )

    kex = policy["approved_key_exchange"]
    lines = ["# T14 - CNSA 2.0 approved algorithms, as the engine classifies them", ""]
    for key, label in (
        ("approved_signatures", "Approved signatures"),
        ("approved_symmetric", "Approved symmetric"),
        ("approved_hash", "Approved hash"),
        ("transitional_until_2030", "Transitional, allowed only until the 2030 milestone"),
    ):
        lines.append(f"* **{label}:** " + ", ".join(policy[key]))
    lines.append("* **Approved key exchange, pure:** " + ", ".join(kex["pure"]))
    lines.append("* **Approved key exchange, hybrid:** " + ", ".join(kex["hybrid"]))
    total = sum(m["weight"] for m in policy["milestones"])
    lines += [
        "",
        f"Policy version `{policy['version']}`, weights summing to {total}. "
        "Source: `qubit_risk/params/cnsa2_milestones.yaml`.",
    ]
    (TABLES / "T14_cnsa2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"T14: {len(policy['milestones'])} milestones")


def main() -> int:
    TABLES.mkdir(parents=True, exist_ok=True)
    t01_notation()
    t02_taxonomy()
    t04_dataset()
    t05_coverage()
    t14_compliance()
    print("\nphase 1b complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
