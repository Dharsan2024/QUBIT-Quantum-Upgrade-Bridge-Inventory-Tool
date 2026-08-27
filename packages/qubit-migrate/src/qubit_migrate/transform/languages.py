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

import re
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


#: Tree-sitter node types that name an imported/required module, per grammar. Only the node TYPE
#: is named here, never a library or algorithm — the symbols themselves are read out of the file.
_IMPORT_NODES: dict[str, tuple[str, ...]] = {
    "go": ("import_spec",),
    "python": ("import_statement", "import_from_statement"),
    "java": ("import_declaration",),
    "javascript": ("import_statement", "call_expression"),
    "typescript": ("import_statement", "call_expression"),
    "rust": ("use_declaration",),
    "csharp": ("using_directive",),
    "kotlin": ("import_header",),
    "scala": ("import_declaration",),
    "swift": ("import_declaration",),
    "ruby": ("call",),
    "php": ("namespace_use_declaration",),
    "dart": ("import_or_export",),
    "c": ("preproc_include",),
    "cpp": ("preproc_include",),
}

#: Qualified reference: `pkg.Symbol`, `pkg::Symbol`, `pkg->Symbol`. Captures the qualifier only.
_QUALIFIER = re.compile(r"\b([a-z][A-Za-z0-9_]*)\s*(?:\.|::)\s*[A-Za-z_]\w*")


#: Keywords that open an import statement in some language. Stripped before the path is read, so
#: `from argon2 import PasswordHasher` does not yield a package helpfully named "from".
_IMPORT_KEYWORDS = re.compile(
    r"^\s*(?:from|import|use|using|require|include|package|pub)\b\s*", re.I
)


def _bindings_from_import(text: str) -> set[str]:
    """The name(s) an import statement makes available, from its SHAPE rather than its language.

    Three shapes cover every language QUBIT parses, and a language may use more than one:

    * quoted path — `import "crypto/ecdsa"`, `import x from "node:crypto"` (Go, JS, TS)
    * dotted/scoped path — `import java.security.MessageDigest;`, `use rand::rngs::OsRng;`
      (Java, Kotlin, Scala, Rust, C#, PHP)
    * from-import — `from argon2 import PasswordHasher` (Python), where the bound name is what
      follows `import`, NOT the module it came from

    An explicit alias always wins, because that is the name the code will actually use.

    Shape-driven rather than a per-language table on purpose: an earlier version read only quoted
    paths, so for Python it fell through to the raw statement text and extracted the leading
    keyword as the package name — which made every Python import look like a package called
    `from` or `import`, and then flagged the file's real usages as unresolved. It failed the M2
    acceptance test on a correct argon2 migration.
    """
    names: set[str] = set()
    stripped = text.strip().rstrip(";")

    # An alias is definitive wherever it appears: `import x as y`, `foo "bar/baz"`, `use a as b`.
    aliases = set(re.findall(r"\bas\s+(\w+)", stripped))
    names |= aliases

    quoted = re.findall(r'["\']([^"\']+)["\']', stripped)
    if quoted:
        for raw in quoted:
            # `:` splits too, so `node:crypto` yields `crypto` rather than the `node` scheme.
            path_parts = [s for s in re.split(r"[\\/:]", raw.strip()) if s]
            cleaned = re.sub(r"[^A-Za-z0-9_].*$", "", path_parts[-1]) if path_parts else ""
            if cleaned:
                names.add(cleaned)
        # `import crypto from "node:crypto"` — the JS/TS default import binds the name BEFORE
        # `from`, which is the one the code actually calls.
        default_import = re.match(r"^\s*import\s+(\w+)\s+from\b", stripped)
        if default_import:
            names.add(default_import.group(1))
        # A Go named import puts the alias before the quoted path with no keyword between them;
        # `from` must not be mistaken for such an alias, which is why keywords are excluded.
        for alias in re.findall(r"(\w+)\s+[\"']", stripped):
            if not _IMPORT_KEYWORDS.match(alias + " "):
                names.add(alias)
        # `import { ml_dsa65 } from "@noble/post-quantum/ml-dsa"` — a JS/TS named import binds the
        # braced members, and those are what the code calls. Checked inside the quoted branch
        # because the module path is quoted too, so the brace group would otherwise never be read.
        for group in re.findall(r"[{]([^}]*)[}]", stripped):
            for part in group.split(","):
                member = re.split(r"\s+as\s+", part.strip())[-1].strip()
                if member and member != "*":
                    names.add(member)
        return names

    # from X import a, b  ->  a and b are the bindings, X is not.
    from_import = re.match(r"^\s*from\s+[\w.]+\s+import\s+(.+)$", stripped, re.S)
    if from_import:
        for part in from_import.group(1).split(","):
            part = part.strip().strip("()").strip()
            if not part or part == "*":
                continue
            names.add(re.split(r"\s+as\s+", part)[-1].strip())
        return names

    body = _IMPORT_KEYWORDS.sub("", stripped)
    # Brace groups: `use a::{b, c}`, `import {x, y} from ...` — every member is a binding.
    braced = re.search(r"[{]([^}]*)[}]", body)
    if braced:
        for part in braced.group(1).split(","):
            member = re.split(r"\s+as\s+", part.strip())[-1].strip()
            if member and member != "*":
                names.add(member)
        return names

    # Plain dotted or scoped path: the binding is its last segment. `import a.b.c` in Python binds
    # `a`, but `a` is also then only ever used as `a.`, so the last segment is a safe superset for
    # the purpose this serves (is a qualifier resolvable) as long as both are recorded.
    segments = [s for s in re.split(r"[.:/\\]+", body) if s]
    if segments:
        first = re.sub(r"[^A-Za-z0-9_].*$", "", segments[0])
        last = re.sub(r"[^A-Za-z0-9_].*$", "", segments[-1])
        names |= {n for n in (first, last) if n}
    return names


def _import_names(source: str, language: str) -> set[str]:
    """Every module/package name this file imports, read from the parse tree."""
    lang = (language or "").lower()
    grammar = TS_GRAMMAR.get(lang)
    names: set[str] = set()
    if grammar is None:
        return names
    try:
        from tree_sitter_language_pack import get_parser  # type: ignore[import-untyped]

        tree = get_parser(grammar).parse(source.encode("utf-8", errors="replace"))
    except Exception:
        return names

    wanted = _IMPORT_NODES.get(lang, ())

    def walk(node: Any) -> None:
        if node.type in wanted:
            text = node.text.decode("utf-8", errors="replace") if node.text else ""
            names.update(_bindings_from_import(text))
        for child in getattr(node, "children", None) or []:
            walk(child)

    walk(tree.root_node)
    return names


#: String and comment content, removed before looking for qualified references. An import PATH is
#: a string (`"github.com/cloudflare/circl/sign/mldsa/mldsa65"`), and left in place it reads as a
#: reference to a package called `github` — which is how a first version of this reported
#: `github` as an undefined package in every Go file that imports anything from a URL host.
_STRINGS_AND_COMMENTS = re.compile(
    r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    r"|//[^\n]*|#[^\n]*|/\*[\s\S]*?\*/",
)


def unresolved_qualifiers(source: str, language: str) -> set[str]:
    """Qualifiers used as `pkg.Symbol` in ``source`` that no import in the file provides.

    Deliberately returns a SET to be differenced against the same call on the original file, so
    only what a patch newly broke is ever reported. Local variables produce false positives on
    their own (`t.Run`, `err.Error`), which is exactly why the caller must diff rather than
    treat this as an absolute answer.
    """
    imported = _import_names(source, language)
    used = set(_QUALIFIER.findall(_STRINGS_AND_COMMENTS.sub(" ", source)))
    return used - imported


def _body_without_imports(source: str, language: str) -> str:
    """``source`` with its import statements removed, so an import cannot look like its own use."""
    lang = (language or "").lower()
    grammar = TS_GRAMMAR.get(lang)
    if grammar is None:
        return source
    try:
        from tree_sitter_language_pack import get_parser  # type: ignore[import-untyped]

        tree = get_parser(grammar).parse(source.encode("utf-8", errors="replace"))
    except Exception:
        return source

    wanted = _IMPORT_NODES.get(lang, ())
    spans: list[tuple[int, int]] = []

    def walk(node: Any) -> None:
        if node.type in wanted:
            spans.append((node.start_byte, node.end_byte))
            return
        for child in getattr(node, "children", None) or []:
            walk(child)

    walk(tree.root_node)
    raw = source.encode("utf-8", errors="replace")
    for start, end in sorted(spans, reverse=True):
        raw = raw[:start] + b" " * (end - start) + raw[end:]
    return raw.decode("utf-8", errors="replace")


def unused_imports(source: str, language: str) -> set[str]:
    """Imports the file declares and never mentions again anywhere outside the import block.

    In Go this is a compile ERROR rather than a warning, which is why it is worth a stage of its
    own; elsewhere it is at worst a lint failure and the caller can weigh it accordingly.

    Looks for the bare identifier, NOT for `name.`. A `from argon2 import PasswordHasher` binding
    is used as `PasswordHasher()` — a constructor call with no member access — so requiring a dot
    reported every such import as unused and failed the M2 acceptance test on a correct argon2
    migration. Go's `rand.Reader` still matches, since the bare-name search subsumes it.
    """
    imported = _import_names(source, language)
    body = _body_without_imports(source, language)
    return {n for n in imported if n != "_" and not re.search(rf"\b{re.escape(n)}\b", body)}
