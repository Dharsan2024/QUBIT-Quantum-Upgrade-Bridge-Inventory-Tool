"""Patch diffing and application (doc 03 §6.3.1).

Converts old_code/new_code pairs → unified diff via difflib.
Never trusts LLM line numbers — locates old_code by exact match then
whitespace-normalized match.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import subprocess
from pathlib import Path


class EditApplyError(Exception):
    """Raised when old_code cannot be located uniquely in the file."""


def _normalize_whitespace(s: str) -> str:
    """Collapse runs of spaces/tabs and strip trailing whitespace per line."""
    return "\n".join(re.sub(r"[ \t]+", " ", line).rstrip() for line in s.splitlines())


def apply_edits(
    original_source: str,
    new_source: str,
) -> str:
    """For codemod-generated patches, ``new_source`` is already the full replacement.

    This function is a thin passthrough that validates the sources are different.
    Raises ``EditApplyError`` if they are identical.
    """
    if original_source == new_source:
        raise EditApplyError("Codemod produced no change (original == new)")
    return new_source


def detect_line_ending(file_path: Path | str) -> str:
    """The line ending the file's OWN on-disk bytes use — `"\\r\\n"` if any appear, else `"\\n"`.

    Every reader in this codebase uses `Path.read_text()`, whose universal newline translation
    silently strips `\\r`, so `original_source`/`new_source` are always LF-only in memory even when
    the real file is CRLF. Sampling is enough — a file's line-ending convention is essentially
    always consistent throughout, and the first 64KB is plenty to see one.
    """
    try:
        raw = Path(file_path).read_bytes()[:65536]
    except OSError:
        return "\n"
    return "\r\n" if b"\r\n" in raw else "\n"


def old_new_to_diff(
    file_path: Path | str,
    original_source: str,
    new_source: str,
    *,
    line_ending: str = "\n",
) -> str:
    """Produce a unified diff from original_source → new_source for file_path.

    `line_ending="\\r\\n"` re-injects the file's real convention before diffing. Without it, a
    diff built from the LF-normalized strings this module always receives cannot `git apply`
    against a file whose stored bytes are CRLF — every context line differs by a trailing `\\r`
    that git won't ignore. Found on OpenSSL's `apps/passwd.c`: CRLF as OpenSSL itself committed
    it (confirmed via `git show HEAD:apps/passwd.c`, independent of any local checkout config),
    so this is not a Windows/autocrlf artifact — any platform hits it applying to this file.
    """
    if line_ending == "\r\n":
        original_source = original_source.replace("\n", "\r\n")
        new_source = new_source.replace("\n", "\r\n")
    original_lines = original_source.splitlines(keepends=True)
    new_lines = new_source.splitlines(keepends=True)
    fname = str(file_path)
    diff_lines = list(
        difflib.unified_diff(
            original_lines,
            new_lines,
            fromfile=f"a/{fname}",
            tofile=f"b/{fname}",
        )
    )
    return "".join(diff_lines)


_BLANK_LINE = re.compile(r"^[ \t]*$")


def _is_blank(line: str) -> bool:
    """A line with nothing on it. Indentation left behind by an editor counts — those are exactly
    the blank lines a reformatting model is most likely to tidy away."""
    return _BLANK_LINE.match(line.strip("\r\n")) is not None


def _split_blank_edges(lines: list[str]) -> tuple[list[str], list[str], list[str]]:
    """`(leading blanks, content, trailing blanks)`. An all-blank run is returned as leading."""
    lead = 0
    while lead < len(lines) and _is_blank(lines[lead]):
        lead += 1
    if lead == len(lines):
        return lines, [], []
    trail = len(lines)
    while trail > lead and _is_blank(lines[trail - 1]):
        trail -= 1
    return lines[:lead], lines[lead:trail], lines[trail:]


def restore_incidental_blank_lines(original_source: str, new_source: str) -> str:
    """Put back blank lines the rewrite dropped, and change nothing else.

    A model asked to migrate a file is given the whole file and returns the whole file, so what
    comes back carries its formatting habits along with the fix. Measured on certbot's
    `certbot-ci/.../misc.py`: a correct ML-DSA rewrite -- the right import, the right key type, the
    right CSR branch -- also collapsed PEP 8's two-blank-line separators to one, throughout
    functions the finding never touched.

    Nothing in the validation gate objects, and nothing should: blank lines change no parse, no
    symbol, no compilation and no rescan result. So the patch passes every stage and still arrives
    as a diff a maintainer would refuse, six lines of migration buried in forty lines of
    reformatting nobody asked for. On the tool's own terms that is a success; on the only terms
    that decide whether the migration is real -- would this be merged -- it is not.

    Only deletions of entirely blank lines are undone. A deleted run containing any real line is
    the model removing code, which is its job and is left alone; so is every insertion and every
    change to a line's content. The restoration cannot alter behaviour, because a blank line has
    none.
    """
    original_lines = original_source.splitlines(keepends=True)
    new_lines = new_source.splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(a=original_lines, b=new_lines, autojunk=False)

    restored: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        dropped, added = original_lines[i1:i2], new_lines[j1:j2]
        if tag == "delete":
            # A run that is entirely blank is spacing the model dropped, and comes back. A run
            # containing any real line is the model REMOVING CODE, which is its job — restoring
            # the blank lines that surrounded it would leave a gap where the code used to be.
            if all(_is_blank(line) for line in dropped):
                restored.extend(dropped)
            continue
        if tag != "replace":
            restored.extend(added)
            continue
        # `difflib` folds a dropped blank line into whatever edit sits next to it, so the certbot
        # case — one line changed, the two blank lines after it swallowed — arrives here as a
        # single `replace` rather than as an edit plus a deletion. Only the blank lines at the
        # BOUNDARIES are considered: the changed content itself is whatever the model wrote.
        dropped_lead, _, dropped_trail = _split_blank_edges(dropped)
        added_lead, added_core, added_trail = _split_blank_edges(added)
        # Whichever side has more. Restoring never removes: spacing the model ADDED is its own
        # choice inside an edit it was making, and second-guessing that would mean rewriting
        # output that is not wrong.
        restored.extend(dropped_lead if len(dropped_lead) > len(added_lead) else added_lead)
        restored.extend(added_core)
        restored.extend(dropped_trail if len(dropped_trail) > len(added_trail) else added_trail)
    return "".join(restored)


def sha256_of(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()


def git_apply_check(diff_text: str, repo_root: Path) -> tuple[bool, str]:
    """Run ``git apply --check`` against the diff in ``repo_root``.

    Returns (passed, stderr_output).
    """
    try:
        result = subprocess.run(
            ["git", "apply", "--check", "-"],
            input=diff_text.encode("utf-8"),
            capture_output=True,
            cwd=str(repo_root),
            timeout=30,
        )
        return result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)


__all__ = [
    "EditApplyError",
    "apply_edits",
    "detect_line_ending",
    "git_apply_check",
    "old_new_to_diff",
    "restore_incidental_blank_lines",
    "sha256_of",
]
