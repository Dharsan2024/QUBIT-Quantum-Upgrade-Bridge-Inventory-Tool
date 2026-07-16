"""File-extension → tree-sitter grammar name. Extending to a new language is a one-line addition
here plus a YAML rule pack (doc 01 north star: rules are data)."""

from __future__ import annotations

from pathlib import Path

EXT_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
}


def language_for(path: Path) -> str | None:
    return EXT_TO_LANGUAGE.get(path.suffix.lower())


__all__ = ["EXT_TO_LANGUAGE", "language_for"]
