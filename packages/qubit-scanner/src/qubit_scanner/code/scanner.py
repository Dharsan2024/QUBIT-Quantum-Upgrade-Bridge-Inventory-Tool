"""``CodeScanner`` — parse a source file, run the shortlisted rules over its AST, and emit raw
``Detection`` values. Pure discovery; normalization into ``CryptoAsset`` happens in ``normalize``.
"""

from __future__ import annotations

import re
from pathlib import Path

from qubit_core import Location
from tree_sitter import Node, QueryCursor
from tree_sitter_language_pack import get_parser

from ..catalog import CompiledRule, RuleCatalog
from ..catalog.schema import Extractor, WhereFilter
from ..models import Detection
from . import resolve
from .languages import language_for

# tree-sitter reports ERROR nodes for unparseable regions; above this fraction we skip the file.
_MAX_ERROR_RATIO = 0.20


class CodeScanner:
    """Runs a rule catalog against source files of the languages it knows."""

    def __init__(self, catalog: RuleCatalog) -> None:
        self._catalog = catalog

    def scan_file(self, path: Path, *, repo: str | None = None) -> list[Detection]:
        language = language_for(path)
        if language is None or not self._catalog.for_language(language):
            return []
        try:
            source = path.read_bytes()
        except OSError:
            return []
        return self.scan_source(source, language, file_path=str(path), repo=repo)

    def scan_source(
        self,
        source: bytes,
        language: str,
        *,
        file_path: str = "<memory>",
        repo: str | None = None,
    ) -> list[Detection]:
        rules = self._catalog.for_language(language)
        if not rules:
            return []
        parser = get_parser(language)  # type: ignore[arg-type]
        tree = parser.parse(source)
        root = tree.root_node
        if _error_ratio(root) > _MAX_ERROR_RATIO:
            return []

        imports = resolve.extract_imports(root, language)
        shortlist = [r for r in rules if _import_gate(r, imports)]

        detections: list[Detection] = []
        for cr in shortlist:
            for _, caps in QueryCursor(cr.query).matches(root):
                det = self._match_to_detection(cr, caps, source, root, language, file_path, repo)
                if det is not None:
                    detections.append(det)
        return detections

    def _match_to_detection(
        self,
        cr: CompiledRule,
        caps: dict[str, list[Node]],
        source: bytes,
        root: Node,
        language: str,
        file_path: str,
        repo: str | None,
    ) -> Detection | None:
        rule = cr.rule
        if not all(_where_ok(w, caps) for w in rule.match.where):
            return None

        raw_algo = _extract(rule.extract["algorithm"], caps, root)
        if raw_algo is None:
            raw_algo = "UNRESOLVED"
        key_size = None
        if "key_size" in rule.extract:
            ks = _extract(rule.extract["key_size"], caps, root)
            key_size = int(ks) if ks and str(ks).isdigit() else None

        anchor = _anchor_node(caps)
        line = (anchor.start_point.row + 1) if anchor is not None else None
        snippet = _snippet(source, anchor)
        confidence = "low" if raw_algo in ("UNRESOLVED",) else rule.confidence

        return Detection(
            scanner="code",
            rule_id=rule.id,
            raw_algorithm=str(raw_algo),
            key_size=key_size,
            usage_context=rule.asset.usage_context,
            asset_type=rule.asset.asset_type,
            location=Location(repo=repo, file_path=file_path, line=line),
            library_name=cr.library_name,
            evidence_snippet=snippet,
            confidence=confidence,
        )


def _import_gate(cr: CompiledRule, imports: set[str]) -> bool:
    if not cr.detect_imports:
        return True
    return any(mod in imports for mod in cr.detect_imports)


def _where_ok(w: WhereFilter, caps: dict[str, list[Node]]) -> bool:
    nodes = caps.get(w.capture)
    if not nodes:
        return False
    text = resolve.node_text(nodes[0])
    if w.equals is not None and text != w.equals:
        return False
    if w.in_ is not None and text not in w.in_:
        return False
    return w.regex is None or re.search(w.regex, text) is not None


def _extract(ex: Extractor, caps: dict[str, list[Node]], root: Node) -> str | None:
    if ex.literal is not None:
        return ex.literal
    if ex.from_ is None:
        return None
    nodes = caps.get(ex.from_)
    if not nodes:
        return None
    node = nodes[0]
    match ex.resolve:
        case "capture-text":
            return resolve.node_text(node)
        case "string-literal":
            return resolve.string_literal_value(node)
        case "string-constant":
            val = resolve.string_literal_value(node)
            if val is not None:
                return val
            if node.type == "identifier":
                return resolve.resolve_string_constant(resolve.node_text(node), root)
            return None
        case "int-literal":
            iv = resolve.int_literal_value(node)
            return str(iv) if iv is not None else None
        case _:
            return resolve.node_text(node)


def _anchor_node(caps: dict[str, list[Node]]) -> Node | None:
    # prefer an explicit @call/@anchor capture; else the earliest captured node
    for key in ("call", "anchor"):
        if caps.get(key):
            return caps[key][0]
    all_nodes = [n for nodes in caps.values() for n in nodes]
    return min(all_nodes, key=lambda n: n.start_byte) if all_nodes else None


def _snippet(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    text = source.decode("utf-8", "replace")
    lines = text.splitlines()
    row = node.start_point.row
    lo, hi = max(0, row - 2), min(len(lines), row + 3)  # ±2 lines around the finding
    return "\n".join(lines[lo:hi])


def _error_ratio(root: Node) -> float:
    total = 0
    errors = 0
    stack = [root]
    while stack:
        n = stack.pop()
        total += 1
        if n.is_error or n.type == "ERROR":
            errors += 1
        stack.extend(n.children)
    return errors / total if total else 0.0


__all__ = ["CodeScanner"]
