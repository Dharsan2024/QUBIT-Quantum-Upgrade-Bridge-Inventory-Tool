"""Load YAML rule packs and compile each rule's tree-sitter query against its grammar.

A bad rule (invalid YAML, invalid query for the grammar) fails LOUDLY at load — never silently at
scan time (doc 01 NFR-7).
"""

from __future__ import annotations

from dataclasses import dataclass
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
        """Load and compile all ``*.yaml`` rule packs under the given dirs (default: built-ins)."""
        search = dirs if dirs is not None else [BUILTIN_RULES_DIR]
        compiled: list[CompiledRule] = []
        for root in search:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*.yaml")):
                compiled.extend(cls._load_file(path))
        return cls(compiled)

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
