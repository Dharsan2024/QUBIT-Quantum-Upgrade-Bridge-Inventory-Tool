"""Semantic-gap resolution (doc 01 §6.2), scoped for a real but tractable implementation:

- import table extraction (for rule shortlisting)
- string-literal reading and single-assignment string-constant folding
  (handles the ``algo = "RSA"; Cipher.getInstance(algo)`` case)
- integer-literal reading (for key sizes)

Everything is best-effort: unresolved values yield ``None`` and the caller emits a low-confidence
finding rather than dropping it.
"""

from __future__ import annotations

from tree_sitter import Node, Query, QueryCursor
from tree_sitter_language_pack import get_language

# Per-language queries that capture imported top-level module names.
_IMPORT_QUERIES: dict[str, str] = {
    "python": """
        (import_statement name: (dotted_name (identifier) @mod))
        (import_statement name: (aliased_import name: (dotted_name (identifier) @mod)))
        (import_from_statement module_name: (dotted_name (identifier) @mod))
    """,
    "java": """
        (import_declaration (scoped_identifier) @mod)
        (import_declaration (identifier) @mod)
    """,
    "go": """
        (import_spec path: (interpreted_string_literal) @mod)
    """,
    "csharp": """
        (using_directive (qualified_name) @mod)
        (using_directive (identifier) @mod)
    """,
    "kotlin": """
        (import_header (identifier) @mod)
    """,
    "scala": """
        (import_declaration (identifier) @mod)
        (import_declaration (stable_identifier) @mod)
    """,
    "swift": """
        (import_declaration (identifier) @mod)
    """,
    "rust": """
        (use_declaration argument: (scoped_identifier) @mod)
        (use_declaration argument: (identifier) @mod)
        (use_declaration argument: (scoped_use_list path: (identifier) @mod))
        (use_declaration argument: (use_wildcard (scoped_identifier) @mod))
        (use_declaration argument: (use_as_clause path: (scoped_identifier) @mod))
    """,
    "php": """
        (namespace_use_declaration (namespace_use_clause (qualified_name) @mod))
        (namespace_use_declaration (namespace_use_clause (name) @mod))
    """,
    "dart": """
        (import_specification (configurable_uri (uri) @mod))
    """,
    "ruby": """
        (call method: (identifier) @_kw arguments: (argument_list (string (string_content) @mod)))
        (call
          method: (identifier) @_kw
          arguments: (argument_list (call receiver: (constant) @mod)))
    """,
}

# Guard captures, because py-tree-sitter's `matches()` does NOT apply a query's `#eq?` text
# predicates — measured, not assumed: a `(#eq? @_kw "require")` predicate on the Ruby query above
# left every `foo("bar")` call in the result set. Ruby spells its imports as ordinary method calls,
# so without this the "imports" of a file would include the string argument of every call in it.
# Over-capturing is not a correctness bug for the import GATE (a superset only costs shortlisting),
# but it does pollute `evidence.context.imports`, which is an M2 signal a human reads.
_IMPORT_GUARDS: dict[str, tuple[str, frozenset[str]]] = {
    "ruby": ("_kw", frozenset({"require", "require_relative", "load", "autoload"})),
}

# Namespace separators to normalize before taking the leading component: Rust `::`, PHP `\`,
# Go/Dart `/`, and the dotted form everything else uses. Missing one leaves the whole path as the
# "module" name, so a `detect_imports: [md5]` gate would never fire on `use md5::Md5;`.
_IMPORT_SEPARATORS = ("::", "\\", "/", ".")

# Prefixes a language attaches to its own import URIs, stripped so the package name is the module.
_IMPORT_URI_PREFIXES = ("package:", "dart:")

_import_query_cache: dict[str, Query] = {}


def _import_query(language: str) -> Query | None:
    if language in _import_query_cache:
        return _import_query_cache[language]
    src = _IMPORT_QUERIES.get(language)
    if src is None:
        return None
    q = Query(get_language(language), src)  # type: ignore[arg-type]
    _import_query_cache[language] = q
    return q


def node_text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", "replace")


def extract_imports(root: Node, language: str) -> set[str]:
    """Return the set of top-level imported module names (leading path component)."""
    q = _import_query(language)
    if q is None:
        return set()
    guard = _IMPORT_GUARDS.get(language)
    mods: set[str] = set()
    for _, caps in QueryCursor(q).matches(root):
        if guard is not None:
            capture, allowed = guard
            keywords = caps.get(capture, [])
            if not keywords or node_text(keywords[0]) not in allowed:
                continue
        for node in caps.get("mod", []):
            top = _leading_module_component(node_text(node))
            if top:
                mods.add(top)
    return mods


def _leading_module_component(text: str) -> str:
    r"""`md5::Md5` -> `md5`; `package:crypto/crypto.dart` -> `crypto`; `A\B` -> `A`."""
    value = text.strip().strip('"').strip("'").strip("`")
    for prefix in _IMPORT_URI_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix) :]
    normalized = value
    for sep in _IMPORT_SEPARATORS:
        normalized = normalized.replace(sep, ".")
    return normalized.split(".")[0].strip()


# Every grammar's spelling of "a quoted string". A node type missing here makes a rule's
# `string-literal`/`string-constant` extractor return None, which the caller turns into an
# UNRESOLVED finding — the algorithm is lost even though the rule matched. Asserted per grammar by
# `test_language_coverage.py`.
_STRING_NODE_TYPES = frozenset(
    {
        "string",  # python, ruby, scala, bash, js/ts
        "string_literal",  # java, c/c++, rust, kotlin, dart, csharp, powershell
        "interpreted_string_literal",  # go
        "raw_string_literal",  # go, rust
        "encapsed_string",  # php double-quoted
        "line_string_literal",  # swift
        "verbatim_string_literal",  # csharp @"..."
        "expandable_string_literal",  # powershell "..."
        "literal",  # sql — one node type serves both strings and numbers
    }
)

# Bare-word tokens that carry a value without quotes. Shell and PowerShell command arguments are
# why this exists: `openssl dgst -md5 f` and `Get-FileHash -Algorithm MD5` contain no string node
# anywhere, and the algorithm IS the token.
_BARE_WORD_NODE_TYPES = frozenset({"word", "generic_token", "command_parameter"})

# Grammar-specific child nodes that already hold the unquoted body.
_STRING_CONTENT_NODE_TYPES = frozenset({"string_content", "string_literal_content"})


def string_literal_value(node: Node) -> str | None:
    """If ``node`` is (or contains) a string literal, return its inner text; else None."""
    if node.type in _STRING_NODE_TYPES:
        raw = node_text(node)
        # strip common prefixes (b, r, f, csharp @) then surrounding quotes
        i = 0
        while i < len(raw) and raw[i] not in ("'", '"', "`"):
            i += 1
        body = raw[i:]
        if len(body) >= 2 and body[0] in ("'", '"', "`"):
            return body.strip(body[0])
        return body
    if node.type in _STRING_CONTENT_NODE_TYPES:  # python / php / csharp child node
        return node_text(node)
    if node.type in _BARE_WORD_NODE_TYPES:
        # A shell or PowerShell bare word IS its value. A leading dash is part of the flag
        # spelling (`-md5`) and the rules capturing these want the flag text, so it is kept.
        return node_text(node)
    return None


def resolve_string_constant(name: str, root: Node) -> str | None:
    """Fold a single local ``name = "literal"`` assignment anywhere in the file.

    Deliberately simple (intra-file, single assignment). If there are zero or many assignments,
    return None — the caller keeps the finding as UNRESOLVED rather than guessing.
    """
    matches: list[str] = []
    _collect_string_assignments(root, name, matches)
    return matches[0] if len(matches) == 1 else None


# Node types that bind a name to a value, per grammar. `algo = "DES"` followed by
# `Cipher.getInstance(algo)` is the most common way real code hides its algorithm from an AST
# match, and every language spells the binding differently. Only Python's `assignment` was
# handled, so the fold worked in Python and silently gave up everywhere else — every such call in
# Java, Go, C#, Kotlin or PHP became an UNRESOLVED finding carrying no algorithm name at all.
_ASSIGNMENT_NODE_TYPES = frozenset(
    {
        "assignment",  # python, ruby
        "assignment_expression",  # java, c, c++, php, js/ts, csharp, powershell
        "variable_declarator",  # java, csharp
        "init_declarator",  # c, c++
        "short_var_declaration",  # go
        "var_spec",  # go
        "const_spec",  # go
        "let_declaration",  # rust
        "property_declaration",  # kotlin, swift
        "val_definition",  # scala
        "var_definition",  # scala
        "variable_declaration",  # dart, csharp
        "initialized_variable_definition",  # dart
        "variable_assignment",  # bash
    }
)


def _collect_string_assignments(node: Node, name: str, out: list[str]) -> None:
    if node.type in _ASSIGNMENT_NODE_TYPES:
        val = _assigned_string(node, name)
        if val is not None:
            out.append(val)
    for child in node.children:
        _collect_string_assignments(child, name, out)


# Single-child wrappers that stand between a binding and its value. Go wraps both sides of
# `algo := "DES"` in an `expression_list`, so the value node is never the string itself and the
# fold returned None for every Go file. C wraps the target in a `pointer_declarator`
# (`const char *algo = "DES"`), which is how almost all C string constants are written.
_VALUE_WRAPPER_TYPES = frozenset(
    {
        "expression_list",  # go
        "parenthesized_expression",
        "argument",  # php, dart
        "value_argument",  # kotlin, swift
    }
)
_TARGET_WRAPPER_TYPES = frozenset(
    {
        "expression_list",  # go
        "pointer_declarator",  # c, c++
        "array_declarator",  # c, c++
        "variable_declaration",  # dart, csharp, kotlin
        "pattern",  # swift
        "value_binding_pattern",  # swift
        "init_declarator",  # c, c++
    }
)


def _unwrap(node: Node, wrappers: frozenset[str], depth: int = 4) -> Node:
    """Descend through single-named-child wrapper nodes to the value they contain."""
    current = node
    for _ in range(depth):
        if current.type not in wrappers:
            return current
        named = [c for c in current.children if c.is_named]
        declarator = current.child_by_field_name("declarator")
        if declarator is not None:
            current = declarator
        elif len(named) == 1:
            current = named[0]
        else:
            return current
    return current


def _assigned_string(node: Node, name: str) -> str | None:
    """The string assigned to ``name`` by this binding node, or None.

    Field names differ per grammar (``left``/``right``, ``name``/``value``, ``pattern``), and
    several grammars give the binding no fields at all — Dart's
    ``initialized_variable_definition`` and Kotlin's ``property_declaration`` are flat child
    lists. So this tries the fields first and falls back to positional structure: the bound name
    must appear before the value.
    """
    field_pairs = (
        ("left", "right"),  # python, java, php, js/ts, csharp, go (:=)
        ("name", "value"),  # go var_spec, kotlin, swift
        ("pattern", "value"),  # rust
        ("declarator", "value"),  # c, c++
    )
    for name_field, value_field in field_pairs:
        target = node.child_by_field_name(name_field)
        value = node.child_by_field_name(value_field)
        if target is None:
            continue
        if _binding_name(_unwrap(target, _TARGET_WRAPPER_TYPES)) != name:
            continue
        if value is not None:
            found = string_literal_value(_unwrap(value, _VALUE_WRAPPER_TYPES))
            if found is not None:
                return found
        break  # right target, no readable value — fall through to the positional scan

    # Positional fallback: find the binding target matching `name`, then the first string after it.
    named = [c for c in node.children if c.is_named]
    index = next((i for i, c in enumerate(named) if _binding_name(c) == name), None)
    if index is None:
        return None
    for candidate in named[index + 1 :]:
        val = string_literal_value(_unwrap(candidate, _VALUE_WRAPPER_TYPES))
        if val is not None:
            return val
    return None


def _binding_name(node: Node) -> str:
    """Text of a binding target, unwrapping the single-child wrappers grammars use for one.

    Kotlin wraps it as ``variable_declaration > simple_identifier``, Swift as
    ``pattern > simple_identifier``; Ruby and Bash use a bare identifier.
    """
    if node.type in ("identifier", "simple_identifier", "variable_name", "field_identifier"):
        return node_text(node).strip()
    if node.type in _TARGET_WRAPPER_TYPES:
        declarator = node.child_by_field_name("declarator")
        if declarator is not None:
            return _binding_name(declarator)
        named = [c for c in node.children if c.is_named]
        if len(named) == 1:
            return _binding_name(named[0])
    return ""


# Every grammar's spelling of "an integer". Missing a name here fails SILENTLY — the rule still
# matches but `key_size` comes back None, so a 1024-bit RSA key is reported as bare "RSA" and
# loses the size that made it urgent. That is the difference between RSA-1024, already within
# reach classically, and RSA-3072, which is a CRQC problem rather than a today problem.
_INT_NODE_TYPES = frozenset(
    {
        "integer",  # python, php, ruby
        "int_literal",  # go
        "decimal_integer_literal",  # java, dart, powershell
        "number_literal",  # c, c++
        "number",  # js/ts, bash
        "integer_literal",  # rust, kotlin, swift, scala, csharp, powershell
        "literal",  # sql
        "word",  # bash — `-b 1024` lexes the size as a bare word
        "generic_token",  # powershell bare argument
    }
)


def int_literal_value(node: Node) -> int | None:
    if node.type in _INT_NODE_TYPES:
        text = node_text(node)
        try:
            return int(text)
        except ValueError:
            # C/C++ allow suffixes and separators (2048u, 0x800, 2_048 in some grammars).
            cleaned = text.rstrip("uUlL").replace("_", "")
            try:
                return int(cleaned, 0)
            except ValueError:
                return None
    return None


__all__ = [
    "extract_imports",
    "int_literal_value",
    "node_text",
    "resolve_string_constant",
    "string_literal_value",
]
