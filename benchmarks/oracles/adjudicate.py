"""Classify the findings one detector made and another did not, instead of calling them misses.

The recall harness prints "oracle-only" findings and calls them *candidate* false negatives, leaving
the adjudication to a human who has not done it at scale. Running four detectors over crypto tooling
made that gap untenable. On `tls-analyzer`, QUBIT reports 9 sites and cryptoscan reports 112, and
reading the difference shows what the 112 actually are:

    pkg/types/policy.go:194   BannedAlgorithms: []string{"3DES", "RC4", "MD5", "SHA1"},
    internal/analyzer/cnsa2.go:75   "RC4":  "Immediately",
    internal/scanner/grade.go:352   if containsAny(cert.SignatureAlgorithm, "SHA1", "MD5") {

None is cryptography in use. They are a security tool's own vocabulary -- a ban list, a remediation
deadline table, a weak-signature check. Reporting RC4 as in-use because a project BANS RC4 inverts
the finding, and publishing "QUBIT recall 8%" from that comparison would have published a number
known to be wrong.

So findings are classified before they are counted. The classifier is deliberately crude and
deliberately conservative:

* `string-literal` -- every occurrence of the algorithm name on that line is inside quotes. A name
  that only ever appears as text is data: a ban list, a display label, a test fixture, a lookup key.
* `comment` -- the line is a comment. Already filtered for pqaudit; other detectors do not.
* `code` -- everything else. Includes real calls AND cases the heuristic cannot resolve, because a
  classifier that resolves ambiguity in the favour of the tool under test is worthless.

`string-literal` is not a synonym for false positive. `jwt.SigningMethodES256` is an identifier, not
a string, and a JOSE `alg` header genuinely IS the string `"ES256"` -- which is why QUBIT's own JWA
rules match string literals on purpose. What the class marks is *a finding whose only evidence is
that the name appears as text*, which is precisely the evidence that cannot distinguish use from
mention. Whether that matters is a per-corpus question, and it is what the report makes visible.

The output is a sample written to disk for hand review, plus counts. The counts are a screening
instrument for where hand-adjudication is worth doing, never a substitute for it.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from base import SUFFIXES, Finding

STRING_LITERAL = "string-literal"
COMMENT = "comment"
CODE = "code"

#: A quoted run in any of the corpus languages. Deliberately simple -- it does not try to handle
#: escaped quotes or raw strings, and a line it parses wrongly lands in `code`, which is the class
#: that makes no claim.
_QUOTED = re.compile(r"""(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`)""")

_COMMENT_PREFIXES = ("//", "#", "--", "*", "/*", '"""', "'''", "%", ";")


def classify(line: str, algorithm: str) -> str:
    """Which kind of evidence this line offers for `algorithm`."""
    stripped = line.strip()
    if not stripped or stripped.startswith(_COMMENT_PREFIXES):
        return COMMENT

    # Match on the bare family token: detectors report `SHA-1` for a line containing `SHA1`, and
    # requiring the exact spelling would classify almost everything as `code` by failing to find it.
    token = re.sub(r"[^a-z0-9]", "", algorithm.lower())
    if not token:
        return CODE

    def _positions(text: str) -> list[int]:
        flat = re.sub(r"[^a-z0-9]", "", text.lower())
        return [m.start() for m in re.finditer(re.escape(token), flat)]

    outside = _positions(_QUOTED.sub(lambda m: " " * len(m.group()), line))
    if not outside and _positions(line):
        return STRING_LITERAL
    return CODE


def read_line(root: Path, finding: Finding) -> str:
    path = root / finding.path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    index = finding.line - 1
    return lines[index] if 0 <= index < len(lines) else ""


def adjudicate(
    root: Path,
    findings: dict[str, list[Finding]],
    *,
    sample_size: int = 40,
    seed: int = 20260821,
) -> dict:
    """Classify each detector's exclusive findings and sample them for hand review."""
    sites = {
        detector: {f.site for f in hits if Path(f.path).suffix.lower() in SUFFIXES}
        for detector, hits in findings.items()
    }
    report: dict[str, dict] = {}
    rng = random.Random(seed)  # noqa: S311 — choosing which findings to eyeball

    for detector, hits in sorted(findings.items()):
        others: set[tuple[str, str]] = set()
        for name, other_sites in sites.items():
            if name != detector:
                others |= other_sites

        exclusive = [
            f
            for f in hits
            if Path(f.path).suffix.lower() in SUFFIXES and f.site not in others
        ]
        classes = Counter()
        annotated = []
        for finding in exclusive:
            # Always the real line from disk, never the detector's `text`. Adapters truncate that
            # to 160 characters, which cuts the closing quote off a long string and made
            # `Description: "RSA key is less than 2048 bits..."` classify as CODE -- a mention
            # scored as a use, in the direction that would have flattered the pattern detectors.
            line = read_line(root, finding) or finding.text
            verdict = classify(line, finding.family)
            classes[verdict] += 1
            annotated.append(
                {
                    "path": finding.path,
                    "line": finding.line,
                    "algorithm": finding.algorithm,
                    "family": finding.family,
                    "rule_id": finding.rule_id,
                    "class": verdict,
                    "source": line.strip()[:200],
                }
            )

        report[detector] = {
            "exclusive_findings": len(exclusive),
            "classes": dict(classes),
            "sample": rng.sample(annotated, min(sample_size, len(annotated))),
        }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--sample-size", type=int, default=40)
    args = parser.parse_args()

    from run_multi import collect

    findings, _ = collect(args.target)
    report = adjudicate(args.target, findings, sample_size=args.sample_size)

    print(f"\n{args.target.name}: findings NO other detector reported\n")
    print(f"  {'detector':12} {'exclusive':>9} {'code':>7} {'string':>7} {'comment':>8}")
    for detector, data in sorted(report.items()):
        classes = data["classes"]
        print(
            f"  {detector:12} {data['exclusive_findings']:>9} {classes.get(CODE, 0):>7} "
            f"{classes.get(STRING_LITERAL, 0):>7} {classes.get(COMMENT, 0):>8}"
        )

    print("\n  'string' = the algorithm name appears ONLY inside quotes on that line: a ban list,")
    print("  a label, a lookup key. Evidence of a mention, not of a use. Hand-check the sample.")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
