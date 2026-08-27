"""Load YAML rule packs and compile each rule's tree-sitter query against its grammar.

A bad rule (invalid YAML, invalid query for the grammar) fails LOUDLY at load — never silently at
scan time (doc 01 NFR-7).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml
from tree_sitter import Query
from tree_sitter_language_pack import get_language

from .schema import Rule, RuleFile

# Directory of the built-in rule packs shipped with the package.
BUILTIN_RULES_DIR = Path(__file__).parent / "rules"


class RuleLoadError(Exception):
    """Raised when a rule file is malformed or a query fails to compile."""


def _required_literal_groups(rule: Rule) -> tuple[tuple[bytes, ...], ...]:
    """Literals the source MUST contain for this rule to produce any detection.

    Each returned group is a set of alternatives: for the rule to match, EVERY group must have at
    least one of its members present somewhere in the file. That follows directly from how the
    filters are applied -- `_where_ok` is called under `all(...)`, so a single unsatisfiable
    `where` clause makes the whole rule unsatisfiable, and it compares `resolve.node_text(node)`,
    which is by construction a verbatim slice of the source.

    So `{capture: meth, equals: createHash}` means a file that never contains the bytes
    `createHash` cannot yield a single detection from this rule -- yet the rule's tree-sitter query
    (a generic `call_expression` pattern) would still be run over the whole tree, match every call
    in the file, and have each match rejected one at a time.

    Measured on node-forge, warm: 3,179 query executions across 115 files produced 79,066 candidate
    matches and 3 findings, with 73% of scan time inside `QueryCursor.matches`. A substring test is
    orders of magnitude cheaper than walking a parse tree, and it is exact rather than heuristic --
    see `matchable_against` for why this can only ever skip work that was provably wasted.

    `regex` clauses contribute nothing (a pattern's literal core is not safely extractable), and a
    rule with no usable clause returns an empty tuple, meaning "always run me".
    """
    groups: list[tuple[bytes, ...]] = []
    for where in rule.match.where:
        if where.equals is not None:
            groups.append((where.equals.encode("utf-8"),))
        elif where.in_:
            groups.append(tuple(value.encode("utf-8") for value in where.in_))
    return tuple(groups)


@dataclass(frozen=True)
class CompiledRule:
    rule: Rule
    query: Query
    language: str
    library_name: str
    detect_imports: tuple[str, ...]
    source_file: Path
    #: Precomputed once per rule, not per file — see `_required_literal_groups`.
    required_literals: tuple[tuple[bytes, ...], ...] = ()

    def matchable_against(self, source: bytes) -> bool:
        """Could this rule match `source` at all? A conservative, exact pre-filter.

        Only ever returns False when the rule is PROVABLY unable to produce a detection, so
        skipping is not an approximation and scan results are byte-for-byte identical with it on
        or off (`test_scan_prefilter.py` asserts exactly that over the real rule catalog).
        """
        return all(any(literal in source for literal in group) for group in self.required_literals)


@lru_cache(maxsize=8)
def _load_catalog_cached(dirs: tuple[Path, ...]) -> tuple[CompiledRule, ...]:
    """Read, validate and compile every rule pack under ``dirs`` — once per directory set.

    This was uncached, and it is the most expensive repeated operation in the scanner: 29 YAML
    files parsed and ~152 tree-sitter queries compiled on EVERY ``RuleCatalog.load()``. Profiling
    a real scan put it at **0.8s of 2.17s (37%)**, and it is paid far more often than once per
    run — ``scan_paths()`` loads it whenever no catalog is passed in, ``qubit run`` scans twice
    (before and after), and the validator's rescan stage pays it again in a fresh subprocess per
    patch.

    The rule pack is static per install, so the work is pure waste. Keyed on the directory tuple
    so a test loading a temporary pack gets its own entry; an immutable tuple is returned so no
    caller can mutate the shared value. Tests that rewrite a rule directory in place must call
    ``RuleCatalog.load.cache_clear()``. Mirrors
    ``qubit_migrate.transform.rules._load_rules_cached``, which already solved this for the
    migration rule pack.
    """
    compiled: list[CompiledRule] = []
    for root in dirs:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.yaml")):
            compiled.extend(RuleCatalog._load_file(path))
    return tuple(compiled)


class RuleCatalog:
    """A loaded, compiled set of detection rules, indexed by language."""

    def __init__(self, compiled: list[CompiledRule]) -> None:
        self._compiled = compiled
        self._by_language: dict[str, list[CompiledRule]] = {}
        for c in compiled:
            self._by_language.setdefault(c.language, []).append(c)

    def __len__(self) -> int:
        return len(self._compiled)

    def languages(self) -> list[str]:
        return sorted(self._by_language)

    def for_language(self, language: str) -> list[CompiledRule]:
        return self._by_language.get(language, [])

    def all_rules(self) -> list[CompiledRule]:
        return list(self._compiled)

    @classmethod
    def load(cls, dirs: list[Path] | None = None) -> RuleCatalog:
        """Load and compile all ``*.yaml`` rule packs under the given dirs (default: built-ins).

        Cached per directory set — see :func:`_load_catalog_cached` for why that matters.
        """
        search = tuple(dirs) if dirs is not None else (BUILTIN_RULES_DIR,)
        return cls(list(_load_catalog_cached(search)))

    @staticmethod
    def _load_file(path: Path) -> list[CompiledRule]:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise RuleLoadError(f"{path}: invalid YAML: {e}") from e
        try:
            rf = RuleFile.model_validate(raw)
        except Exception as e:  # pydantic ValidationError
            raise RuleLoadError(f"{path}: does not match qubit-rule/v1: {e}") from e

        grammars: list[tuple[str, object]] = []
        for name in rf.languages():
            try:
                grammars.append((name, get_language(name)))  # type: ignore[arg-type]
            except Exception as e:
                raise RuleLoadError(f"{path}: unknown grammar '{name}': {e}") from e

        out: list[CompiledRule] = []
        for rule in rf.rules:
            if "algorithm" not in rule.extract:
                raise RuleLoadError(f"{path}:{rule.id}: extract must define 'algorithm'")
            # One CompiledRule per (rule, grammar): a tree-sitter Query is bound to the Language
            # it was compiled against and cannot be run over a tree from another grammar, so a
            # pack covering TypeScript and TSX genuinely needs two compiled queries.
            for name, language in grammars:
                try:
                    query = Query(language, rule.match.query)  # type: ignore[arg-type]
                except Exception as e:
                    raise RuleLoadError(
                        f"{path}:{rule.id}: query does not compile for grammar '{name}': {e}"
                    ) from e
                out.append(
                    CompiledRule(
                        rule=rule,
                        query=query,
                        language=name,
                        library_name=rf.library.name,
                        detect_imports=tuple(rf.library.detect_imports),
                        source_file=path,
                        required_literals=_required_literal_groups(rule),
                    )
                )
        return out


__all__ = ["BUILTIN_RULES_DIR", "CompiledRule", "RuleCatalog", "RuleLoadError"]


# Expose cache_clear() on the public entry point, matching qubit-migrate's load_rules contract.
RuleCatalog.load.__func__.cache_clear = _load_catalog_cached.cache_clear  # type: ignore[attr-defined]
