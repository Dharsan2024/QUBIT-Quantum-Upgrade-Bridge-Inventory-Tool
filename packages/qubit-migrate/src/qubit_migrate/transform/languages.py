"""One map from file suffix to language, for everything in qubit-migrate that needs it.

There used to be two — one in ``codemods.py`` deciding which token-swap table runs, one in
``validate.py`` deciding which tree-sitter grammar the patched file is parsed against — and they
drifted. ``.tsx`` and ``.cjs`` were present in the validator's copy and absent from the codemod's,
so a React component matched a rule listing ``.tsx``, produced no edit, and reported success. A
suffix that appears in a rule's ``file_suffix`` but in neither map is worse: the rule matches, the
codemod does nothing, and the validator skips the parse stage, so a patch that changes nothing
passes every check.

``test_transform_coverage.py`` asserts that every suffix named by any rule pack appears here, so a
new language cannot be half-wired again.

Deliberately a literal table rather than an import from ``qubit_scanner``: doc 03 §2 forbids
qubit-migrate from importing scanner internals. The two are kept in step by a test that compares
them, not by a dependency.
"""

from __future__ import annotations

from pathlib import Path

#: Suffix -> the language name used by the codemod tables and the validator's grammar lookup.
#: Every entry has a tree-sitter grammar in `tree_sitter_language_pack`, which is what makes the
#: validator's `parses` stage meaningful for it.
SUFFIX_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".mts": "typescript",
    ".cts": "typescript",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".sc": "scala",
    ".swift": "swift",
    ".dart": "dart",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".ksh": "bash",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".sql": "sql",
    ".ddl": "sql",
    ".dml": "sql",
    ".psql": "sql",
}

#: Language -> tree-sitter grammar name. Identical for most; `tsx` and `typescript` are separate
#: grammars in the pack, and a `.tsx` file does not parse cleanly under the plain TypeScript one.
TS_GRAMMAR: dict[str, str] = {
    "python": "python",
    "java": "java",
    "go": "go",
    "javascript": "javascript",
    "typescript": "typescript",
    "tsx": "tsx",
    "c": "c",
    "cpp": "cpp",
    "csharp": "csharp",
    "php": "php",
    "ruby": "ruby",
    "rust": "rust",
    "kotlin": "kotlin",
    "scala": "scala",
    "swift": "swift",
    "dart": "dart",
    "bash": "bash",
    "powershell": "powershell",
    "sql": "sql",
}


#: Language -> the file extension the scanner dispatches on for it. Used by the validator's rescan
#: stage, which has to write the patched source to a temp file the scanner will read with the RIGHT
#: grammar. This was a fourth hand-maintained 7-entry map living in `validate.py`; a language
#: missing from it skipped the rescan silently, which is the one stage that checks the patch
#: actually removed the weak algorithm. Derived here so it cannot fall behind SUFFIX_TO_LANGUAGE.
LANGUAGE_TO_EXT: dict[str, str] = {
    "python": ".py",
    "go": ".go",
    "java": ".java",
    "javascript": ".js",
    "typescript": ".ts",
    "tsx": ".tsx",
    "c": ".c",
    "cpp": ".cpp",
    "csharp": ".cs",
    "php": ".php",
    "ruby": ".rb",
    "rust": ".rs",
    "kotlin": ".kt",
    "scala": ".scala",
    "swift": ".swift",
    "dart": ".dart",
    "bash": ".sh",
    "powershell": ".ps1",
    "sql": ".sql",
}


def language_for_suffix(path: str | Path | None) -> str | None:
    """The language of ``path``, or None when its suffix is not a source file we know."""
    if not path:
        return None
    return SUFFIX_TO_LANGUAGE.get(Path(path).suffix.lower())


__all__ = ["LANGUAGE_TO_EXT", "SUFFIX_TO_LANGUAGE", "TS_GRAMMAR", "language_for_suffix"]
