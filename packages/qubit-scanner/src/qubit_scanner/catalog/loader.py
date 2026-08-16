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


@dataclass(frozen=True)
class CompiledRule:
    rule: Rule
    query: Query
    language: str
    library_name: str
    detect_imports: tuple[str, ...]
    source_file: Path


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

        try:
            language = get_language(rf.language)  # type: ignore[arg-type]
        except Exception as e:
            raise RuleLoadError(f"{path}: unknown grammar '{rf.language}': {e}") from e

        out: list[CompiledRule] = []
        for rule in rf.rules:
            if "algorithm" not in rule.extract:
                raise RuleLoadError(f"{path}:{rule.id}: extract must define 'algorithm'")
            try:
                query = Query(language, rule.match.query)
            except Exception as e:
                raise RuleLoadError(f"{path}:{rule.id}: query does not compile: {e}") from e
            out.append(
                CompiledRule(
                    rule=rule,
                    query=query,
                    language=rf.language,
                    library_name=rf.library.name,
                    detect_imports=tuple(rf.library.detect_imports),
                    source_file=path,
                )
            )
        return out


__all__ = ["BUILTIN_RULES_DIR", "CompiledRule", "RuleCatalog", "RuleLoadError"]


# Expose cache_clear() on the public entry point, matching qubit-migrate's load_rules contract.
RuleCatalog.load.__func__.cache_clear = _load_catalog_cached.cache_clear  # type: ignore[attr-defined]
