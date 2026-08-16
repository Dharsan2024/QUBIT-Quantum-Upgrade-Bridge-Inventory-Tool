"""MigrationRule YAML loader + matcher (doc 03 §4.5)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator, model_validator
from qubit_core import CryptoAsset

RULES_DIR = Path(__file__).parent / "rules"


class MigrationRule(BaseModel):
    """One entry in the YAML rule pack."""

    id: str
    language: str
    title: str
    matches: dict[str, Any]
    target: dict[str, Any]
    data_compat: str = "in_place"
    semantic_note: str = ""
    codemod: str | None = None
    prompt_constraints: list[str] = []
    example: dict[str, str] | None = None
    # Additional worked examples for rules with more than one replacement path, keyed by the YAML
    # field name (`example_generic_digest`, ...). Collected so the LLM prompt can few-shot ALL the
    # branches a rule offers — demonstrating only one of them biases the model toward it, which is
    # exactly how py-weakhash-01 ended up emitting argon2 for generic digests.
    extra_examples: dict[str, dict[str, str]] = {}
    rescan_expect: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def _collect_extra_examples(cls, data: Any) -> Any:
        if isinstance(data, dict):
            extras = {
                key: value
                for key, value in data.items()
                if key.startswith("example_") and isinstance(value, dict)
            }
            if extras:
                data = {k: v for k, v in data.items() if k not in extras}
                data["extra_examples"] = extras
        return data

    @field_validator("data_compat")
    @classmethod
    def _valid_compat(cls, v: str) -> str:
        valid = {"in_place", "dual_read", "reencrypt_required"}
        if v not in valid:
            raise ValueError(f"data_compat must be one of {valid}")
        return v


@lru_cache(maxsize=8)
def _load_rules_cached(base: Path) -> tuple[MigrationRule, ...]:
    """Parse + validate every *.yaml rule under ``base`` once (cached per directory).

    The rule pack is static per install, so re-reading/parsing it on every call (e.g. one
    `GET /assets/{id}/recommendation` per asset) is wasted disk I/O + YAML parsing. Returns an
    immutable tuple so the cache can't be mutated by a caller. Tests that write a temporary rule
    dir should call ``load_rules.cache_clear()``.
    """
    rules: list[MigrationRule] = []
    for path in sorted(base.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(MigrationRule.model_validate(data))
    return tuple(rules)


def load_rules(rules_dir: Path | None = None) -> list[MigrationRule]:
    """Load all *.yaml rule files from the rules directory (cached; see ``_load_rules_cached``)."""
    return list(_load_rules_cached(rules_dir or RULES_DIR))


# Expose cache_clear() on the public name, matching the KB/agility loaders' test contract.
load_rules.cache_clear = _load_rules_cached.cache_clear  # type: ignore[attr-defined]


def match_rule(
    asset: CryptoAsset,
    rules: list[MigrationRule] | None = None,
) -> MigrationRule | None:
    """Return the best matching rule for ``asset``, or ``None``."""
    all_rules = rules if rules is not None else load_rules()

    for rule in all_rules:
        m = rule.matches
        # algorithm match
        alg_list = m.get("algorithm")
        if alg_list and asset.algorithm not in alg_list:
            continue
        # usage_context match
        uc_list = m.get("usage_context")
        if uc_list and asset.usage_context.value not in uc_list:
            continue
        # library match (null in list means "any or none")
        lib_list = m.get("library_name")
        if lib_list is not None:
            asset_lib = asset.library.name if asset.library else None
            if None not in lib_list and asset_lib not in lib_list:
                continue
        return rule
    return None


__all__ = ["MigrationRule", "load_rules", "match_rule"]
