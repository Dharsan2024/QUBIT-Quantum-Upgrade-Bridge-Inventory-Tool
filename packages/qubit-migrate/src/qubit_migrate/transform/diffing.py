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
    "sha256_of",
]
