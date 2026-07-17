"""MigrationRule YAML loader + matcher (doc 03 §4.5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator
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
    rescan_expect: dict[str, Any] | None = None

    @field_validator("data_compat")
    @classmethod
    def _valid_compat(cls, v: str) -> str:
        valid = {"in_place", "dual_read", "reencrypt_required"}
        if v not in valid:
            raise ValueError(f"data_compat must be one of {valid}")
        return v


def load_rules(rules_dir: Path | None = None) -> list[MigrationRule]:
    """Load all *.yaml rule files from the rules directory."""
    base = rules_dir or RULES_DIR
    rules: list[MigrationRule] = []
    for path in sorted(base.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(MigrationRule.model_validate(data))
    return rules


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
