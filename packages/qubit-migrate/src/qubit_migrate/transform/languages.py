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
from typing import Any

#: The names a rule may address a language by, when it writes per-language guidance as
#: "Go: use crypto/mlkem ...". Only the language whose name matches is shown that line, so a
#: `.rs` file is no longer handed Go's API as its only concrete instruction (measured: the model
#: transliterated `mlkem.GenerateKey768()` into Rust, where no such crate exists). A language not
#: listed here answers only to its own name.
LANGUAGE_ALIASES: dict[str, frozenset[str]] = {
    "javascript": frozenset({"javascript", "js", "node", "nodejs", "ecmascript"}),
    "typescript": frozenset({"typescript", "ts"}),
    # .tsx is TypeScript with JSX syntax; the crypto APIs a rule names are identical, so guidance
    # addressed to TypeScript applies to it. Its tree-sitter grammar differs, which is why it is a
    # separate language everywhere else.
    "tsx": frozenset({"tsx", "typescript", "ts", "react"}),
    "csharp": frozenset({"csharp", "c#", "dotnet", ".net"}),
    "cpp": frozenset({"cpp", "c++"}),
    "go": frozenset({"go", "golang"}),
    "bash": frozenset({"bash", "sh", "shell", "posix shell"}),
    "powershell": frozenset({"powershell", "pwsh"}),
    "python": frozenset({"python", "py"}),
    # Kotlin and Scala call the Java Cryptography Architecture directly — `Cipher.getInstance`,
    # `KeyPairGenerator.getInstance` — so a rule's "Java: ..." guidance is literally their API too.
    # Scoping it away from them cost three Kotlin tasks that had been passing, because the file was
    # left with no concrete API named at all.
    "kotlin": frozenset({"kotlin", "kt", "java"}),
    "scala": frozenset({"scala", "java"}),
}


def language_aliases(language: str | None) -> frozenset[str]:
    """Every name ``language`` answers to, lowercased. Its own name is always one of them."""
    lang = (language or "").strip().lower()
    if not lang:
        return frozenset()
    return LANGUAGE_ALIASES.get(lang, frozenset({lang}))


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


def parse_error(source: str, language: str | None) -> str | None:
    """Return a description of the first syntax problem in ``source``, or None if it parses.

    One implementation, two callers — the validator's `parses` stage and the LLM rewrite guard —
    because a check that exists twice is a check that will disagree with itself.

    Uses tree-sitter's ``has_error``, which reports an ERROR or MISSING node ANYWHERE in the tree.
    Both callers previously inspected only ``root_node.children``, so a syntax error nested inside a
    function body passed both. Measured: Go source handed to the Ruby grammar produces zero
    top-level ERROR children and ``has_error == True`` — which is exactly the shape the local model
    returned when it answered a Ruby file with a Go rewrite, and exactly what both checks missed.

    Returns None (rather than an error) when the language has no grammar: not every patched file is
    source code, and a config file has nothing to parse against.
    """
    lang = (language or "").lower()
    grammar = TS_GRAMMAR.get(lang)
    if grammar is None:
        return None
    try:
        from tree_sitter_language_pack import get_parser  # type: ignore[import-untyped]

        tree = get_parser(grammar).parse(source.encode("utf-8", errors="replace"))
    except Exception as exc:
        return f"could not parse as {lang}: {exc}"
    if not tree.root_node.has_error:
        return None
    node = _first_error(tree.root_node)
    where = f" at line {node.start_point[0] + 1}" if node is not None else ""
    return f"does not parse as {lang}{where}"


def _first_error(node: object) -> Any:
    """Depth-first search for the first ERROR/MISSING node, for a useful line number."""
    children = getattr(node, "children", None) or []
    for child in children:
        if getattr(child, "type", "") == "ERROR" or getattr(child, "is_missing", False):
            return child
        found = _first_error(child)
        if found is not None:
            return found
    return None


__all__ = [
    "LANGUAGE_TO_EXT",
    "SUFFIX_TO_LANGUAGE",
    "TS_GRAMMAR",
    "language_aliases",
    "language_for_suffix",
    "parse_error",
]
