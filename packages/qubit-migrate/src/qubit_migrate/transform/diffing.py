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


def old_new_to_diff(
    file_path: Path | str,
    original_source: str,
    new_source: str,
) -> str:
    """Produce a unified diff from original_source → new_source for file_path."""
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
    "git_apply_check",
    "old_new_to_diff",
    "sha256_of",
]
