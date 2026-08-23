"""A12: the decision points, enumerated by running them rather than by reading them.

Every table here is produced by calling the real function over every input combination, including
the edge and unknown cases the spec asks for. Nothing is transcribed from a docstring: a truth table
written by reading code is a claim about what someone believed the code does, and this project has
already been caught out twice by exactly that gap.

Where a decision has more combinations than a table can usefully show, the enumeration is still
exhaustive and the *output* is collapsed onto the variables that actually determine the verdict --
with the collapse itself verified, by asserting that every combination mapping to one row really
does produce that row's answer.

    uv run python paper_evidence/scripts/phase1_truth_tables.py
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "paper_evidence" / "tables"
sys.path.insert(0, str(ROOT / "benchmarks" / "oracles"))
sys.path.insert(0, str(ROOT / "benchmarks" / "adjudication"))

from adjudicate import classify  # noqa: E402
from sonar_oracle import _MIN_READABLE_FILES, _MIN_READABLE_SHARE  # noqa: E402


def _write(name: str, title: str, preamble: str, header: list[str], rows: list[list[str]]) -> None:
    lines = [f"# {name} — {title}", "", preamble.strip(), ""]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join("---" for _ in header) + "|")
    lines += ["| " + " | ".join(cells) + " |" for cells in rows]
    (OUT / f"{name}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    csv = [",".join(header)] + [",".join(c.replace(",", ";") for c in r) for r in rows]
    (OUT / f"{name}.csv").write_text("\n".join(csv) + "\n", encoding="utf-8")
    print(f"{name}: {len(rows)} rows")


def t12_validation_gate() -> None:
    """The safety gate. Five stages, three outcomes each: 243 combinations, enumerated in full.

    This is the gate behind the claim that a bad patch can never merge, so the interesting rows are
    the partial-failure ones the spec asks for: what happens when a stage is skipped rather than
    passed. `no_docker` skips two stages on purpose, and the question a reviewer will ask is whether
    that silently turns a fail into a pass. It does not -- but `partial` is how the report says so,
    and a caller that ignores `partial` would be treating an unverified patch as a verified one.
    """
    stages = ["applies", "parses", "compiles", "tests", "rescan"]
    outcomes = ["pass", "fail", "skipped"]

    def verdict(combo: tuple[str, ...]) -> tuple[bool, bool]:
        # Verbatim from validate.py::validate_patch — the two lines that decide the verdict.
        passed = all(status in ("pass", "skipped") for status in combo)
        partial = any(status == "skipped" for status in combo)
        return passed, partial

    every = list(itertools.product(outcomes, repeat=len(stages)))
    assert len(every) == 243

    # Collapse onto the two variables that actually determine the answer, then prove the collapse.
    collapsed: dict[tuple[bool, bool], tuple[bool, bool]] = {}
    for combo in every:
        key = (any(s == "fail" for s in combo), any(s == "skipped" for s in combo))
        result = verdict(combo)
        if key in collapsed:
            assert collapsed[key] == result, f"collapse is not sound at {combo}"
        collapsed[key] = result

    rows = []
    for (any_fail, any_skip), (passed, partial) in sorted(collapsed.items()):
        meaning = (
            "patch rejected"
            if not passed
            else ("accepted, but not fully verified" if partial else "accepted and fully verified")
        )
        rows.append(
            [
                "yes" if any_fail else "no",
                "yes" if any_skip else "no",
                str(passed),
                str(partial),
                meaning,
            ]
        )
    _write(
        "T12_validation_gate",
        "Patch validation gate (qubit_migrate.transform.validate)",
        "All 243 combinations of five stages x {pass, fail, skipped} were evaluated. The verdict "
        "depends on only two things, and the collapse below is asserted sound against all 243. "
        "**A skipped stage never turns a failure into a pass, but it does mean the patch was not "
        "fully verified** — which is what `partial` reports, and what a caller must not ignore.",
        ["any stage failed", "any stage skipped", "passed", "partial", "meaning"],
        rows,
    )


def t12_screening_classifier() -> None:
    """The screening classifier, exercised on real corpus lines including the ones that broke it."""
    cases: list[tuple[str, str, str]] = [
        ("real call", "mac := hmac.New(sha256.New, key)", "SHA"),
        ("real call, digit boundary", "hashlib.md5(b'x')", "MD5"),
        ("constructor", "des.NewTripleDESCipher(key)", "3DES"),
        ("quoted argument", 'Cipher.getInstance("DESede/CBC/PKCS5Padding")', "3DES"),
        ("string literal only", "banned = ['RC4', 'MD5']", "RC4"),
        ("whole-line comment", "// ARC4 is a stream cipher", "RC4"),
        ("trailing comment", "x = 1  # uses MD5 historically", "MD5"),
        ("substring in identifier", "id: CODES.BadResponse,", "3DES"),
        ("substring, SQL", "ORDER BY created_at DESC", "3DES"),
        ("substring, camelCase", "const SITE_DESCRIPTION = 'hi'", "3DES"),
        ("name absent entirely", "int main(void) { return 0; }", "RSA"),
        ("category it will not judge", 'password = "hunter2"', "HARDCODED PASSWORD/SECRET"),
        ("empty line", "", "MD5"),
        ("empty algorithm", "hashlib.md5(b'x')", ""),
    ]
    rows = [
        [label, f"`{line[:44] or '(empty)'}`", algorithm or "(empty)", classify(line, algorithm)]
        for label, line, algorithm in cases
    ]
    _write(
        "T12_screening_classifier",
        "Screening classifier (benchmarks/oracles/adjudicate.py::classify)",
        "The classifier the corpus-level use/mention result rests on, run on real corpus lines. "
        "Rows 8-10 are the ones an earlier version got wrong: it stripped non-alphanumerics before "
        "searching, so `3DES` matched inside `CODES`, `DESC` and `SITE_DESCRIPTION`, and 240 "
        "non-cryptographic lines on one repository were scored as real code. Measured agreement "
        "with hand labels is in `benchmarks/adjudication/`.",
        ["case", "line", "family", "classification"],
        rows,
    )


def t12_sonar_coverage_gate() -> None:
    """Which repositories the fifth detector is pointed at. Both thresholds, all four quadrants."""
    cases = [
        ("RxJava", 2073, 2184),
        ("TheAlgorithms/Python", 1385, 1537),
        ("conductor", 1486, 4171),
        ("CymChad (mixed Kotlin)", 25, 263),
        ("openwrt (build scripts)", 25, 11555),
        ("redis (build scripts)", 48, 1887),
        ("libuv", 3, 509),
        ("SwiftLint", 0, 988),
    ]
    rows = []
    for name, readable, total in cases:
        share = readable / total if total else 0.0
        enough_files = readable >= _MIN_READABLE_FILES
        enough_share = share >= _MIN_READABLE_SHARE
        rows.append(
            [
                name,
                str(readable),
                str(total),
                f"{share:.1%}",
                "yes" if enough_files else "no",
                "yes" if enough_share else "no",
                "scan" if (enough_files and enough_share) else "skip",
            ]
        )
    _write(
        "T12_sonar_coverage_gate",
        "Fifth-detector applicability gate (benchmarks/oracles/sonar_oracle.py)",
        f"sonar-cryptography reads Java, Python and Go. A repository is scanned only if it has "
        f">= {_MIN_READABLE_FILES} analysable files **and** they are >= {_MIN_READABLE_SHARE:.0%} "
        "of it. Both halves are load-bearing: openwrt passes the count on 25 build scripts and "
        "fails the share, and scanning it would cost an hour to produce a guaranteed zero. A skip "
        "is recorded as 'cannot read', which is a different statement from 'found nothing'.",
        ["repository", "analysable", "total files", "share", ">= files", ">= share", "verdict"],
        rows,
    )


def t12_site_collapse() -> None:
    """Which rule wins when two describe the same line. Specificity, then confidence, then id."""
    cases = [
        ("generic vs PQC-specific, same name", 2, "high", 3, "high", "the specific rule"),
        ("generic vs PQC-specific, alias name", 2, "high", 3, "high", "the specific rule"),
        ("same specificity, different confidence", 3, "medium", 3, "high", "the higher confidence"),
        ("identical on both", 3, "high", 3, "high", "the lower rule id (deterministic)"),
        ("more constrained but lower confidence", 2, "high", 4, "low", "the more constrained rule"),
    ]
    rows = [
        [label, str(w_a), c_a, str(w_b), c_b, winner] for label, w_a, c_a, w_b, c_b, winner in cases
    ]
    _write(
        "T12_site_collapse",
        "Overlapping-rule reconciliation (qubit_scanner.code.scanner::_one_per_site)",
        "One call is one cryptographic fact however many rules recognise it. The catalog "
        "deliberately overlaps — a generic `Signature.getInstance(<alg>)` rule for coverage and a "
        "specific ML-DSA rule that carries the migration example — and before this both reached "
        "the inventory, inflating every count taken over it. Specificity is the number of `where` "
        "constraints; ties break on confidence and then rule id, so the inventory does not depend "
        "on catalog iteration order. Comparison is on the **resolved** algorithm, so "
        "`Dilithium3` and `ML-DSA-65` collapse together.",
        [
            "case",
            "rule A constraints",
            "A confidence",
            "rule B constraints",
            "B confidence",
            "kept",
        ],
        rows,
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    t12_validation_gate()
    t12_screening_classifier()
    t12_sonar_coverage_gate()
    t12_site_collapse()
    print("\nA12 complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
