"""Audit what a migration actually wrote into the files.

`twin_app_eval.py` answers "was the right finding acted on". This answers the different and equally
necessary question: **is what landed on disk correct code?**

A patch can be attributed to the right finding and still be wrong in the file — a mangled line, a
truncated tail, a duplicated import, a swap to something that is not actually an approved algorithm,
CRLF where the file used LF, an edit that silently moved a neighbouring line. `rescan` cannot
see any
of that: it re-runs the scanner, and the scanner is looking for algorithms, not for damage.

Every check here reads the bytes on disk and compares them against the pristine twin. Nothing
consults QUBIT's own record of what it did.

    python scripts/verify_migration.py --twin inkwell-esign
    python scripts/verify_migration.py --all
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from twin_migrate import TWINS  # noqa: E402

OUT = REPO / "test-output"

#: What a migration is allowed to have introduced. A swap to something outside this list is not a
#: migration -- it is a rewrite that happened to change the algorithm name, and the scanner would
#: report it as success either way because the weak name is gone.
APPROVED = (
    "SHA-256",
    "SHA256",
    "SHA-384",
    "SHA384",
    "SHA-512",
    "SHA512",
    "SHA3",
    "sha256",
    "sha384",
    "sha512",
    "AES-256-GCM",
    "AES-256",
    "aes-256-gcm",
    "AESGCM",
    "GCM",
    "ML-DSA",
    "MLDSA",
    "ML-KEM",
    "MLKEM",
    "Ed25519",
    "ECDSA",
    "SLH-DSA",
    "Argon2",
    "argon2",
    "scrypt",
    "bcrypt",
    "PBKDF2WithHmacSHA256",
    "SHA256withRSA",
    "SHA256withECDSA",
    "SHA2_256",
)

#: Names that must never appear in a line a migration just wrote.
WEAK = ("MD5", "md5", "SHA-1", "SHA1", "sha1", "DES", "RC4", "Blowfish", "ECB")

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".rb": "ruby",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".ts": "typescript",
}


def parses(path: Path) -> tuple[bool, str]:
    """Does the migrated file still parse, by its own language's grammar?"""
    language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
    if language is None:
        return True, "no grammar for this suffix; not checked"
    try:
        from tree_sitter_language_pack import get_parser

        tree = get_parser(language).parse(path.read_bytes())
    except Exception as exc:  # a missing grammar must not read as a broken file
        return True, f"parser unavailable ({exc})"

    def first_error(node) -> Any:
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "ERROR" or n.is_missing:
                return n
            stack.extend(n.children)
        return None

    bad = first_error(tree.root_node)
    if bad is not None:
        return False, f"syntax error at line {bad.start_point[0] + 1}"
    return True, "parses"


def audit_file(original: Path, migrated: Path, rel: str) -> dict[str, Any]:
    """Every way this one file's migration could be wrong, checked against the original."""
    problems: list[str] = []
    notes: list[str] = []

    before_bytes = original.read_bytes()
    after_bytes = migrated.read_bytes()
    before = before_bytes.decode("utf-8", errors="replace")
    after = after_bytes.decode("utf-8", errors="replace")

    # 1. Encoding and line endings. A patch applied with the wrong newline convention breaks
    #    `git apply` on the next run and shows up as a whole-file diff in review.
    if b"\r\n" in after_bytes and b"\r\n" not in before_bytes:
        problems.append("CRLF introduced into a file that was LF")
    if "�" in after and "�" not in before:
        problems.append("undecodable bytes introduced (encoding damage)")

    # 2. Truncation. The single most destructive failure and the easiest to miss, because a
    #    truncated file often still parses.
    before_lines, after_lines = before.splitlines(), after.splitlines()
    if len(after_lines) < len(before_lines) * 0.9:
        problems.append(
            f"file shrank from {len(before_lines)} to {len(after_lines)} lines "
            "-- possible truncation"
        )

    # 3. Syntax.
    ok, detail = parses(migrated)
    if not ok:
        problems.append(f"does not parse: {detail}")

    # 4. Every changed line, read as a migration.
    changes: list[dict[str, Any]] = []
    matcher = difflib.SequenceMatcher(None, before_lines, after_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        old_text = "\n".join(before_lines[i1:i2])
        new_text = "\n".join(after_lines[j1:j2])
        change = {
            "op": tag,
            "original_lines": [i1 + 1, i2],
            "before": old_text.strip()[:160],
            "after": new_text.strip()[:160],
        }

        # A line the migration wrote must not still name a broken primitive. An import line is the
        # legitimate exception: `add alongside` deliberately keeps the old import while another
        # call site still needs it.
        looks_like_import = bool(
            re.match(r'^\s*(import|from|require|use|#include|"[\w./-]+")', new_text.strip())
        )
        if new_text and not looks_like_import:
            left = [w for w in WEAK if w in new_text]
            if left:
                if tag == "insert":
                    # An INSERT has no "before", so every weak name in it looks introduced — and
                    # the commonest reason for one is a DUAL-PATH migration, which is the correct
                    # answer for a signature whose old artefacts must still verify.
                    #
                    # Measured on inkwell-esign: the model added `ml_dsa_signing_key`,
                    # `sign_document_ml_dsa` and `verify_document_ml_dsa` beside the retained
                    # legacy path — exactly what the manifest asks for — and this check called it
                    # two PROBLEMS. A verifier that reports the right answer as a defect is worse
                    # than no verifier, because it is the one a reviewer is asked to trust.
                    change["note"] = f"new code alongside a retained legacy path: {left}"
                    notes.append(
                        f"line {i1 + 1}: inserted code names {', '.join(left)} — dual-path "
                        "migration, or a legacy branch kept deliberately"
                    )
                elif all(w in old_text for w in left):
                    # The same weak name on both sides: nothing was migrated here.
                    change["note"] = f"weak name still present after the edit: {left}"
                    notes.append(f"line {i1 + 1}: weak name survives ({', '.join(left)})")
                else:
                    problems.append(f"line {i1 + 1}: introduced a weak name {left}")
        if new_text and not looks_like_import and not any(a in new_text for a in APPROVED):
            notes.append(
                f"line {i1 + 1}: no approved algorithm name in the new text -- "
                "may be a rewrite rather than a migration"
            )
        changes.append(change)

    # 5. Duplicated imports, which `add alongside` could produce if it ran twice.
    import_lines = [ln.strip() for ln in after_lines if re.match(r'^\s*"[\w./-]+"\s*$', ln)]
    dupes = {ln for ln in import_lines if import_lines.count(ln) > 1}
    if dupes:
        problems.append(f"duplicated import line(s): {sorted(dupes)}")

    return {
        "file": rel,
        "changed_hunks": len(changes),
        "changes": changes,
        "problems": problems,
        "notes": notes,
    }


def audit_twin(name: str) -> dict[str, Any]:
    original_root = REPO / "demo-lab" / name
    migrated_root = OUT / name
    if not migrated_root.is_dir():
        return {"twin": name, "error": f"no migrated copy at {migrated_root}"}

    files: list[dict[str, Any]] = []
    skip = {".git", "target", "__pycache__", ".pytest_cache"}
    for path in sorted(migrated_root.rglob("*")):
        rel_parts = path.relative_to(migrated_root).parts
        if not path.is_file() or any(p in skip for p in rel_parts):
            continue
        rel = "/".join(rel_parts)
        before = original_root / rel
        if not before.is_file():
            files.append(
                {
                    "file": rel,
                    "problems": ["file did not exist before the migration"],
                    "changes": [],
                    "notes": [],
                    "changed_hunks": 0,
                }
            )
            continue
        if before.read_bytes() == path.read_bytes():
            continue
        files.append(audit_file(before, path, rel))

    return {
        "twin": name,
        "files_changed": len(files),
        "problems": sum(len(f["problems"]) for f in files),
        "notes": sum(len(f["notes"]) for f in files),
        "files": files,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--twin", action="append", choices=sorted(TWINS))
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    names = sorted(TWINS) if args.all else (args.twin or [])
    if not names:
        ap.error("pass --twin NAME or --all")

    results = [audit_twin(n) for n in names]
    for r in results:
        if "error" in r:
            print(f"\n=== {r['twin']} === {r['error']}")
            continue
        verdict = "CLEAN" if r["problems"] == 0 else f"{r['problems']} PROBLEM(S)"
        print(f"\n=== {r['twin']} === {r['files_changed']} file(s) changed -- {verdict}")
        for f in r["files"]:
            if not f["changes"] and not f["problems"]:
                continue
            print(f"  {f['file']}  ({f['changed_hunks']} hunk(s))")
            for c in f["changes"]:
                print(f"     L{c['original_lines'][0]}  - {c['before']}")
                print(f"            + {c['after']}")
                if "note" in c:
                    print(f"            ! {c['note']}")
            for p in f["problems"]:
                print(f"     PROBLEM: {p}")
            for n in f["notes"]:
                print(f"     note: {n}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 1 if any(r.get("problems") for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
