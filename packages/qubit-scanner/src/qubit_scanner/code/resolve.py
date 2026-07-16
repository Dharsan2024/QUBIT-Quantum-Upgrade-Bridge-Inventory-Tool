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
}

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
    """Return the set of top-level imported module names (first dotted component)."""
    q = _import_query(language)
    if q is None:
        return set()
    mods: set[str] = set()
    for _, caps in QueryCursor(q).matches(root):
        for node in caps.get("mod", []):
            text = node_text(node).strip('"').strip("'")
            top = text.replace("/", ".").split(".")[0]
            if top:
                mods.add(top)
    return mods


def string_literal_value(node: Node) -> str | None:
    """If ``node`` is (or contains) a string literal, return its inner text; else None."""
    if node.type in ("string", "interpreted_string_literal", "string_literal"):
        raw = node_text(node)
        # strip common prefixes (b, r, f) then surrounding quotes
        i = 0
        while i < len(raw) and raw[i] not in ("'", '"', "`"):
            i += 1
        body = raw[i:]
        if len(body) >= 2 and body[0] in ("'", '"', "`"):
            return body.strip(body[0])
        return body
    if node.type == "string_content":  # python child node
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


def _collect_string_assignments(node: Node, name: str, out: list[str]) -> None:
    # Python: (assignment left: (identifier) right: (string ...))
    if node.type == "assignment":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None and node_text(left) == name:
            val = string_literal_value(right)
            if val is not None:
                out.append(val)
    for child in node.children:
        _collect_string_assignments(child, name, out)


def int_literal_value(node: Node) -> int | None:
    if node.type in ("integer", "int_literal", "decimal_integer_literal"):
        try:
            return int(node_text(node))
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
