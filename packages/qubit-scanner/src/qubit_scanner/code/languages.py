"""File → tree-sitter grammar resolution.

Extending to a new language is an entry here plus a YAML rule pack (doc 01 north star: rules are
data). The grammar set is deliberately chosen against measured market usage rather than taste —
see ``docs/design/01-discovery-inventory.md`` §4.5 for the sourcing. Every grammar named here is
provided by ``tree-sitter-language-pack``; adding one costs no new dependency.

Two failure modes this module has actually caused, both silent, both now covered:

* An extension absent from the map means the file is **never parsed** and contributes nothing.
  ``.tsx`` was missing, so every React/Next.js component — where a browser-side crypto call
  most often lives — was skipped while the ``.ts`` files beside it were scanned. A repo can look
  clean because its crypto lives in a file type the scanner declined to open.
* An extension mapped to a grammar for which no rule pack exists parses and matches nothing.
  ``.cpp`` mapped to ``cpp`` for a long time with zero C++ rules, which reads identically to
  "no crypto in this C++ service". Guarded now by ``test_language_coverage.py``, which asserts
  every mapped grammar actually has rules behind it.
"""

from __future__ import annotations

from pathlib import Path

# Extension → grammar. Lower-cased suffixes; see ``language_for``.
EXT_TO_LANGUAGE: dict[str, str] = {
    # ── Python ──
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    # ── JVM ──
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",  # Gradle Kotlin DSL — build scripts configure TLS and signing too
    ".scala": "scala",
    ".sc": "scala",
    # ── Go ──
    ".go": "go",
    # ── C / C++ ──
    ".c": "c",
    ".h": "c",  # C headers; C++-only headers use .hpp/.hh below
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".c++": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".h++": "cpp",
    ".ipp": "cpp",
    ".tpp": "cpp",
    # ── JavaScript / TypeScript ──
    # The javascript grammar parses JSX natively, so .jsx needs no separate grammar. TSX does
    # need one: tree-sitter ships typescript and tsx as distinct languages.
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    # ── .NET ──
    ".cs": "csharp",
    ".csx": "csharp",
    # ── Web / scripting ──
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".php7": "php",
    ".php8": "php",
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    ".ru": "ruby",  # config.ru — Rack entry point, where TLS options get set
    # ── Systems / mobile ──
    ".rs": "rust",
    ".swift": "swift",
    ".dart": "dart",
    # ── Shell / ops ──
    ".sh": "bash",
    ".bash": "bash",
    ".ksh": "bash",
    ".zsh": "bash",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    # ── Data ──
    ".sql": "sql",
    ".ddl": "sql",
    ".dml": "sql",
    ".psql": "sql",
}

# Extensionless files whose name alone identifies the language. Real repositories are full of
# these and a suffix-only lookup skips every one.
NAME_TO_LANGUAGE: dict[str, str] = {
    "rakefile": "ruby",
    "gemfile": "ruby",
    "guardfile": "ruby",
    "vagrantfile": "ruby",
    "brewfile": "ruby",
    "podfile": "ruby",
    "fastfile": "ruby",
}

# Shebang interpreter → grammar, for extensionless executables. A deployment script named
# `deploy` that calls `openssl enc -des3` is exactly the artifact this catches; it has no suffix
# and no recognisable name, so nothing else in this module would look at it.
_SHEBANG_INTERPRETERS: dict[str, str] = {
    "sh": "bash",
    "bash": "bash",
    "zsh": "bash",
    "ksh": "bash",
    "dash": "bash",
    "python": "python",
    "python3": "python",
    "ruby": "ruby",
    "pwsh": "powershell",
    "powershell": "powershell",
    "node": "javascript",
}

# Read at most this much of a file to look for a shebang. A shebang is by definition the first
# line, so this is generous; it exists only to bound the read on a huge extensionless blob.
_SHEBANG_PROBE_BYTES = 128


def language_for(path: Path) -> str | None:
    """Grammar for ``path`` based on its suffix, or its whole name when it has no suffix."""
    ext = path.suffix.lower()
    if ext:
        return EXT_TO_LANGUAGE.get(ext)
    return NAME_TO_LANGUAGE.get(path.name.lower())


def language_from_shebang(first_bytes: bytes) -> str | None:
    """Grammar named by a ``#!`` line, or None.

    Handles both direct interpreters (``#!/bin/bash``) and ``env`` indirection
    (``#!/usr/bin/env python3``), which is the more common spelling in portable scripts.
    """
    if not first_bytes.startswith(b"#!"):
        return None
    line = first_bytes.split(b"\n", 1)[0].decode("utf-8", "replace")
    tokens = line[2:].replace("\t", " ").split()
    for token in tokens:
        name = token.rsplit("/", 1)[-1].lower()
        if name in ("env", "-s") or name.startswith("-"):
            continue  # `env` and its flags are not the interpreter
        # Strip a version suffix only when the bare name is unknown (python3 -> python3 is a key).
        if name in _SHEBANG_INTERPRETERS:
            return _SHEBANG_INTERPRETERS[name]
        return None
    return None


def language_for_content(path: Path, first_bytes: bytes) -> str | None:
    """``language_for``, with a shebang fallback for a file that has neither suffix nor name."""
    return language_for(path) or language_from_shebang(first_bytes)


__all__ = [
    "EXT_TO_LANGUAGE",
    "NAME_TO_LANGUAGE",
    "language_for",
    "language_for_content",
    "language_from_shebang",
]
