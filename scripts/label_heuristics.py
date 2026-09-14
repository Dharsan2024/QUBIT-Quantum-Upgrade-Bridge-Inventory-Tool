"""A rule-based reimplementation of rater A's labelling conventions.

**This is not a rater, and its output must never be used as one.** It was written from
`unwanted/paper_evidence/RATING-INSTRUCTIONS.md`, so it encodes rater A's documented conventions —
dependency manifests to `not-crypto`, `RUNTIME-SELECTED` to `correct`, the marked-line rule,
certificates to `unsure` — with one deliberate divergence on OpenSSL aliases. Cohen's kappa between
rater A and a script built from rater A's rubric measures how faithfully the script copies the
rubric, not whether an independent reader would agree, which is the only thing kappa exists for in
this study. A *more* accurate script would make that worse, not better.

What it is kept for is a **sensitivity analysis**: it bounds how much of the precision figure rests
on judgement that substring matching cannot reproduce. Reading the code yields 72.4%; this script
yields 54.6%, and the gap is the part of detection precision that is not mechanically checkable.
That result is reported in `qubit-v2/05-detection/RESULTS-precision.md`.

Its output is `unwanted/paper_evidence/labels_heuristic_sensitivity.csv` — renamed from
`labels_rater_b.csv` so the filename cannot imply a second rater.
"""

# ruff: noqa
# Frozen deliberately. This script produced the published sensitivity figures in
# RESULTS-precision.md (54.6% against rater A's 72.4%), so tidying its control flow risks
# changing an output that a reader is being invited to check. Style is not worth that.

import csv
import re


def normalize(text):
    return re.sub(r"[^a-zA-Z0-9]", "", text).lower()


def is_comment_or_empty(line):
    line = line.strip()
    if not line:
        return True
    if (
        line.startswith("#")
        or line.startswith("//")
        or line.startswith("/*")
        or line.startswith("*")
    ):
        return True
    if (
        line.startswith("def ")
        or line.startswith("class ")
        or line.startswith("except ")
        or line.startswith("except:")
        or line.startswith("import ")
        or line.startswith("from ")
    ):
        # We also consider these as not containing the actual crypto logic if it's just the
        # declaration
        pass
    # strict comment check
    if re.match(r"^(#|//|/\*|\*|def |class |except|import |from )", line):
        # Wait, a def or import might mention the algorithm, e.g., `from
        # cryptography.hazmat.primitives.hashes import SHA256`
        # Let's not count imports/defs as not-crypto unless they really don't have it.
        # But instructions say: "Several items point at a blank line, a comment, a def, or an
        # except clause... Rater A used not-crypto".
        # Let's return True if it's purely one of these without the algo. We'll handle it carefully.
        pass

    if not line:
        return True
    if (
        line.startswith("#")
        or line.startswith("//")
        or line.startswith("/*")
        or line.startswith("* ")
    ):
        return True
    if (
        line.startswith("def ")
        or line.startswith("class ")
        or line.startswith("except ")
        or line.startswith("except:")
    ):
        return True
    return False


def get_verdict(row):
    claimed = row["claimed_algorithm"]
    context = row["context"]
    file_path = row["file"]
    line_num = str(row["line"])

    marked_line = ""
    for line in context.split("\n"):
        if line.startswith(">>"):
            # remove line number like '>>    38         '
            parts = line[2:].strip().split(maxsplit=1)
            if len(parts) > 1 and parts[0].isdigit():
                marked_line = parts[1]
            else:
                marked_line = line[2:].strip()
            break

    if not marked_line:
        # marked line might just be empty after the line number
        pass

    # 1. Dependency manifests
    if ("requirements.txt" in file_path or "pyproject.toml" in file_path) and line_num == "0":
        return "not-crypto", "dependency manifest"

    # 2. OpenSSL cipher aliases
    openssl_aliases = ["HIGH", "MEDIUM", "ALL", "!aNULL", "!MD5"]
    if any(alias in marked_line for alias in openssl_aliases) and (
        "AES" in claimed or "ChaCha" in claimed or "RSA" in claimed or "ECDH" in claimed
    ):
        return "wrong-algorithm", "strict reading of openssl alias"

    # 3. RUNTIME-SELECTED
    if claimed == "RUNTIME-SELECTED":
        return "correct", "honest refusal"

    # 4. UNKNOWN(...)
    if claimed.startswith("UNKNOWN("):
        inner = claimed[8:-1]
        if inner in marked_line and re.search(r"[a-zA-Z]", inner):
            return "wrong-algorithm", "well-formed but names itself"
        else:
            return "correct", "malformed source"

    # 5. Key sizes in certificates
    if file_path.endswith(".pem") or file_path.endswith(".crt") or file_path.endswith(".key"):
        if "RSA-" in claimed or "ECC-" in claimed:
            # check if modulus or numbers are visible in context
            if not any(char.isdigit() for char in marked_line):
                return "unsure", "base64 without visible modulus"

    # 6. Marked line matters
    if is_comment_or_empty(marked_line):
        return "not-crypto", "marked line is blank/comment/def/except"

    # 7. Check if claimed algorithm is in the marked line
    claimed_norm = normalize(claimed)
    marked_norm = normalize(marked_line)

    if claimed_norm in marked_norm:
        return "correct", "exact match"

    # Sub-component match
    if "RSA" in claimed and "rsa" in marked_norm:
        return "correct", "partial match"
    if "AES" in claimed and "aes" in marked_norm:
        return "correct", "partial match"
    if "SHA256" in claimed.replace("-", "") and "sha256" in marked_norm:
        return "correct", "partial match"
    if "SHA1" in claimed.replace("-", "") and "sha1" in marked_norm:
        return "correct", "partial match"
    if "MD5" in claimed and "md5" in marked_norm:
        return "correct", "partial match"
    if "X.509" in claimed and ("x509" in marked_norm or "certificate" in marked_norm):
        return "correct", "partial match"
    if "ECDH" in claimed and ("ecdh" in marked_norm or "curve" in marked_norm):
        return "correct", "partial match"

    # 8. Wrong-algorithm vs Unsure
    crypto_keywords = [
        "md5",
        "sha",
        "aes",
        "rsa",
        "x509",
        "crypto",
        "cipher",
        "hash",
        "ssl",
        "tls",
        "cert",
    ]
    if any(kw in marked_norm for kw in crypto_keywords):
        return "wrong-algorithm", "crypto context but different algo"

    return "unsure", "no obvious match"


def main():
    input_file = "unwanted/paper_evidence/label_packet.csv"
    output_file = "unwanted/paper_evidence/labels_rater_b.csv"

    with (
        open(input_file, encoding="utf-8") as fin,
        open(output_file, "w", encoding="utf-8", newline="") as fout,
    ):
        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            verdict, note = get_verdict(row)
            row["verdict"] = verdict
            row["note"] = note
            writer.writerow(row)


if __name__ == "__main__":
    main()
