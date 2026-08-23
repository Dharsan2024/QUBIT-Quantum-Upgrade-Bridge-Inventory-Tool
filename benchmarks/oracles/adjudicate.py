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
* `substring` -- the name appears only INSIDE a longer word. `DES` in `CODES`, `DESC`,
  `codesandbox`, `NUM_NODES`. Not a mention of the algorithm at all; the letters happen to line up.
* `comment` -- the line is a comment, whole-line or trailing. Already filtered for pqaudit; other
  detectors do not.
* `not-applicable` -- the classifier has nothing to say: a category rather than a name (see
  `_CATEGORY_MARKERS`), a blank line, or no algorithm to look for. An absent answer, stated.
* `code` -- everything else. Includes real calls AND cases the heuristic cannot resolve, because a
  classifier that resolves ambiguity in the favour of the tool under test is worthless.

The `substring` class was added after the 26-repository sweep, and it changed the conclusion rather
than refining it. On gatsbyjs/gatsby, QUBIT reported 0 sites and pqaudit reported 117; the first
version of this classifier scored 240 of pqaudit's exclusive findings as real `code`, because it
stripped punctuation before searching and destroyed every word boundary. Reading them showed
`CODES.BadResponse` and `date: DESC`. Without this class the corpus said QUBIT was missing almost
everything, and the truth was the opposite.

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
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).parent))

from base import SKIP_DIRS, SUFFIXES, Finding

STRING_LITERAL = "string-literal"
COMMENT = "comment"
CODE = "code"
SUBSTRING = "substring"
NOT_APPLICABLE = "not-applicable"

#: Punctuation that marks a family as a CATEGORY rather than a name a source file could contain.
#: QUBIT's HNDL pass reports `PII: EMAIL ADDRESS`, `HARDCODED PASSWORD/SECRET`, `GITHUB TOKEN`,
#: `PRIVATE KEY MATERIAL`. No token in any source file looks like those, so a classifier that
#: searches for the family name finds nothing and scores every one of them `substring` -- real
#: findings dismissed as coincidences of letters.
#:
#: The first version of this check tested only for `":"`, which caught the `PII:` families and
#: missed the other four. Hand adjudication found 35 more findings mislabelled that way, so the
#: rule is now "a name with a space, a colon or a slash in it is not a token".
#:
#: The honest answer is that this classifier has nothing to say about any of them. It says so.
_CATEGORY_MARKERS = (":", "/", " ")

#: Families that are markers rather than names, with no punctuation to give them away. `RUNTIME` is
#: QUBIT's label for an algorithm chosen at run time (`MessageDigest.getInstance(algorithm)`) --
#: there is no name on the line by construction.
_CATEGORY_FAMILIES = frozenset({"RUNTIME", "UNKNOWN", "?"})

#: `UNKNOWN(CHACHAPOLY)` is a real family label: the detector saw a primitive it has no canonical
#: name for and wrapped what it did see. The inner token is the thing to search for.
_WRAPPED = re.compile(r"^[A-Z]+\((?P<inner>[^)]+)\)$")

#: A quoted run in any of the corpus languages. Deliberately simple -- it does not try to handle
#: escaped quotes or raw strings, and a line it parses wrongly lands in `code`, which is the class
#: that makes no claim.
_QUOTED = re.compile(r"""(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`)""")

_COMMENT_PREFIXES = ("//", "#", "--", "*", "/*", '"""', "'''", "%", ";")

#: Markers that start a comment part-way along a line. Deliberately a much smaller set than
#: `_COMMENT_PREFIXES`: at the start of a line `*`, `%`, `;` and `--` are comment markers in some
#: language, but in the MIDDLE of a line they are multiplication, modulo, a statement terminator and
#: a decrement. Requiring whitespace before the marker also keeps `https://example.com` out of it.
#:
#: This exists because the classifier used to see whole-line comments only, so
#: `x = 1  # uses MD5 historically` scored as real usage. That biases the use/mention split towards
#: USE -- the same direction as the human/model disagreement measured in the agreement pass, so the
#: two compounded rather than cancelled.
_TRAILING_COMMENT = re.compile(r"(?:^|\s)(?://|#|/\*)")


#: How each family is actually SPELLED IN CODE, which is often not its family name. `3DES` is a
#: label no source file contains -- Go writes `des.NewTripleDESCipher`, Java writes `DESede`,
#: Crypto++ writes `DES_EDE3`. Without these, real usage is scored as substring noise, which is the
#: dangerous direction: it would dismiss genuine findings as false positives and make QUBIT look
#: better than it is. Caught by `des.NewTripleDESCipher(key)` classifying as `substring`.
_CODE_SPELLINGS: dict[str, tuple[str, ...]] = {
    "3DES": ("3DES", "TripleDES", "DESede", "DES3", "DES_EDE3", "DESEDE3"),
    "EC": ("EC", "ECDSA", "ECDH", "ECDHE", "Ed25519", "EdDSA", "X25519", "secp", "prime256"),
    "SHA-1": ("SHA-1", "SHA1"),
    "SHA-224": ("SHA-224", "SHA224"),
    "ML-KEM": ("ML-KEM", "MLKEM", "Kyber"),
    "ML-DSA": ("ML-DSA", "MLDSA", "Dilithium"),
    "SLH-DSA": ("SLH-DSA", "SLHDSA", "SPHINCS"),
    "FN-DSA": ("FN-DSA", "FNDSA", "Falcon"),
    "PBKDF2": ("PBKDF2", "Rfc2898", "PBEWith"),
    "RC4": ("RC4", "ARC4", "ARCFOUR"),
    # `strcasecmp(token, "tlsv1.3")` is how a C server reads its own protocol config, and the bare
    # spelling `TLS` cannot reach it: the `v` is a lower-case letter continuing the word.
    "TLS": ("TLS", "SSL", "TLSv", "SSLv"),
    # openssl's subcommands are the vocabulary key material is generated in. `genrsa` and `dhparam`
    # are single lower-case words, so nothing but an explicit spelling will find them.
    "RSA": ("RSA", "genrsa", "rsautl"),
    "DH": ("DH", "DHE", "DiffieHellman", "Diffie-Hellman", "dhparam"),
    # Argon2's variants carry a lower-case suffix: `$argon2i$`, `argon2id`.
    "ARGON2": ("ARGON2", "argon2i", "argon2d", "argon2id"),
    "ARGON2ID": ("ARGON2ID", "argon2id", "ARGON2"),
    # `XChaCha20Poly1305` starts with a capital X, which the camelCase rule reads as mid-acronym.
    "CHACHA20": ("CHACHA20", "XChaCha20", "ChaCha20"),
    "XCHACHA20": ("XCHACHA20", "XChaCha20"),
    "POLY1305": ("POLY1305", "ChaChaPoly"),
}


def is_category(algorithm: str) -> bool:
    """Is this family a CATEGORY of finding rather than the name of an algorithm?

    A category cannot be looked for in source text, so this classifier declines to rule on it
    instead of guessing. Getting this wrong is not neutral: every category it fails to recognise is
    scored `substring`, which reads as "the detector matched nothing real".
    """
    token = (algorithm or "").strip()
    if not token:
        return False
    return token.upper() in _CATEGORY_FAMILIES or any(m in token for m in _CATEGORY_MARKERS)


def _spellings(algorithm: str) -> list[str]:
    """The ways one family name is written, so `SHA-1` still matches a line containing `SHA1`.

    Only real variants, never a character-by-character loosening: `EC` must not be allowed to match
    `e-c`, or every hyphenated identifier in the corpus becomes elliptic-curve cryptography.
    """
    base = algorithm.strip()
    wrapped = _WRAPPED.match(base.upper())
    if wrapped:
        base = wrapped.group("inner")
    variants = {base, base.replace("-", ""), base.replace("-", "_")}
    variants.update(_CODE_SPELLINGS.get(base.upper(), ()))
    variants.update(_CODE_SPELLINGS.get(base, ()))
    return sorted({v for v in variants if v}, key=len, reverse=True)


def _bounded(text: str, start: int, end: int, spelling: str) -> bool:
    """Is `text[start:end]` a word of its own rather than a syllable inside a longer one?

    Two kinds of boundary count. The plain one is "not a letter or digit" -- `des.` and `(AES,`.
    The second is a camelCase hump, because `NewTripleDESCipher` really does contain the word
    `TripleDES`, while `CODES` does not contain the word `DES` in any sense that matters.

    The asymmetry is deliberate. A hump before the match requires the PRECEDING character to be
    lower-case or a digit (`New|TripleDES`), because an upper-case neighbour means the match is
    mid-acronym (`CO|DES`). A hump after only requires the NEXT character to be upper-case
    (`TripleDES|Cipher`).
    """
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""

    left_ok = (
        not before
        or not before.isalnum()
        or ((before.islower() or before.isdigit()) and spelling[:1].isupper())
    )
    # A DIGIT after the match is a boundary too, and leaving it out was this module's largest
    # single error. `SHA` could not match `sha256`, `ARGON2` could not match `argon2i`, `CHACHA20`
    # could not match `chacha20poly1305` -- so `hmac.New(sha256.New, key)` was scored as a
    # coincidence of letters. 107 of the 601 hand-labelled findings were wrong for this one reason.
    # It is safe because the LEFT boundary still guards the case this rule exists for: `CODES` is
    # rejected on its `O`, not on what follows the `S`.
    right_ok = not after or not after.isalnum() or after.isupper() or after.isdigit()
    return left_ok and right_ok


def classify(line: str, algorithm: str) -> str:
    """Which kind of evidence this line offers for `algorithm`.

    Four answers, and the fourth is the one that changed the corpus results. `_positions` used to
    strip every non-alphanumeric character from the line before searching, which destroyed word
    boundaries -- so the family `3DES` matched inside `CODES`, `DESC` and `codesandbox`. On
    gatsbyjs/gatsby that produced 240 pqaudit findings classified as real code, none of which were
    cryptography:

        id: CODES.BadResponse,
        allMarkdownRemark(sort: {frontmatter: {date: DESC}})
        codesandbox = { ...OPTION_DEFAULT_CODESANDBOX }

    That single defect is most of the gap between QUBIT and the regex detectors on this corpus, and
    without separating it the honest conclusion would have been the opposite of the true one.
    """
    if is_category(algorithm):
        # A category, not a name that appears in source. See `_CATEGORY_MARKERS`.
        return NOT_APPLICABLE

    stripped = line.strip()
    if not stripped:
        # An empty line is not a comment. It carries no evidence either way, which is what
        # `not-applicable` means; calling it a comment put a judgement where there was none.
        return NOT_APPLICABLE
    if stripped.startswith(_COMMENT_PREFIXES):
        return COMMENT
    if not algorithm.strip():
        # No name to look for. The classifier previously answered `code` here -- confidently, about
        # nothing.
        return NOT_APPLICABLE

    # `\b` alone is not enough: it treats `_` as a word character but not `-`, so `AES_KEY` would
    # count as a standalone `AES` while `sha-1-hash` would not. The boundary is explicitly "not a
    # letter or digit", which is what distinguishes a token from a syllable.
    #
    # Plus camelCase, because Go and Java bury the algorithm inside the identifier:
    # `des.NewTripleDESCipher`, `MessageDigest.getInstance`. A plain boundary scored that as
    # substring noise -- dismissing real 3DES usage as a false positive, which is the dangerous
    # direction of error. A camelCase hump IS a word break, so `TripleDES` inside
    # `NewTripleDESCipher` counts while `DES` inside `CODES` still does not.
    spellings = _spellings(algorithm)

    def _hits(text: str) -> bool:
        for spelling in spellings:
            for match in re.finditer(re.escape(spelling), text, re.IGNORECASE):
                # The MATCHED text, not the spelling: IGNORECASE means they can differ in
                # case, and the camelCase test reads the case of what is actually written.
                if _bounded(text, match.start(), match.end(), match.group()):
                    return True
        return False

    if not _hits(line):
        # The name appears only inside a longer word, or not at all. Either way this line is not
        # evidence that the algorithm is used here.
        return SUBSTRING

    unquoted = _QUOTED.sub(lambda m: " " * len(m.group()), line)

    # A trailing comment is a comment. Quotes are blanked first so a marker inside a string
    # literal -- a URL, a format template -- does not truncate the line.
    marker = _TRAILING_COMMENT.search(unquoted)
    if marker and not _hits(line[: marker.start()]):
        return COMMENT

    if not _hits(unquoted):
        return STRING_LITERAL
    return CODE


def is_repository_source(path: str) -> bool:
    """The same file population `run_multi.restrict_to_source` compares detectors over.

    Kept in step deliberately. When the two disagreed, the adjudication and the comparison were
    reporting on different sets of files and their numbers could not be put in one table.
    """
    parts = PurePosixPath(path).parts
    return Path(path).suffix.lower() in SUFFIXES and not (SKIP_DIRS & set(parts))


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
        detector: {f.site for f in hits if is_repository_source(f.path)}
        for detector, hits in findings.items()
    }
    report: dict[str, dict] = {}
    rng = random.Random(seed)  # noqa: S311 — choosing which findings to eyeball

    for detector, hits in sorted(findings.items()):
        others: set[tuple[str, str]] = set()
        for name, other_sites in sites.items():
            if name != detector:
                others |= other_sites

        exclusive = [f for f in hits if is_repository_source(f.path) and f.site not in others]
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
    head = f"  {'detector':12} {'exclusive':>9} {'code':>7} {'string':>7} {'comment':>8}"
    print(f"{head} {'absent':>7} {'n/a':>5}")
    for detector, data in sorted(report.items()):
        classes = data["classes"]
        print(
            f"  {detector:12} {data['exclusive_findings']:>9} {classes.get(CODE, 0):>7} "
            f"{classes.get(STRING_LITERAL, 0):>7} {classes.get(COMMENT, 0):>8} "
            f"{classes.get(SUBSTRING, 0):>7} {classes.get(NOT_APPLICABLE, 0):>5}"
        )

    print("\n  'string' = the algorithm name appears ONLY inside quotes on that line: a ban list,")
    print("  a label, a lookup key. Evidence of a mention, not of a use.")
    print("  'absent' = the name is not on that line at all, only inside a longer word.")
    print("  'n/a'    = a category (PII, SECRET) this classifier cannot judge by name.")
    print("  Every column is a screening heuristic, never a verdict. Hand-check the sample.")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
