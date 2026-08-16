"""MigrationRule YAML loader + matcher (doc 03 §4.5)."""

from __future__ import annotations

from fnmatch import fnmatch
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
    # True when the codemod is the AUTHORITY for this transform and an LLM must never replace it,
    # even under an explicit `--generator llm`.
    #
    # This is not a stylistic preference. Config and manifest hardening is a fixed, known-correct
    # edit: `ssl_ecdh_curve X25519MLKEM768`, `KexAlgorithms sntrup761x25519-sha512@openssh.com`, a
    # version floor. The codemod writes exactly that and is idempotent. Handing the same file to a
    # 7B model produced a config that looked modern — TLS 1.2+1.3, AEAD ciphers — but silently
    # omitted the hybrid group, which is the ONE line that makes the deployment quantum-safe. It
    # then left every sibling asset in that file unfixable, because the model saw an
    # already-modern-looking config and returned it unchanged.
    #
    # LLM rewrites earn their place where the transform needs semantic judgement about surrounding
    # code (key lengths, nonce handling, call-site changes). They have no place where the correct
    # output is a constant.
    codemod_authoritative: bool = False
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
        # source_scanner match. WITHOUT this, a config-hardening rule listing common algorithm
        # names (a weak TLS suite legitimately contains RSA / AES-128 / 3DES) would also claim
        # Python or Go CODE assets with the same algorithm, and the config codemod would then be
        # pointed at a source file it cannot edit. Provenance has to be part of matching.
        src_list = m.get("source_scanner")
        if src_list and asset.source_scanner.value not in src_list:
            continue
        # file_suffix match. Needed to separate rules that differ only by LANGUAGE: the Python
        # weak-hash rule uses a precise libcst codemod, while the cross-language one does a
        # line-scoped token swap. Both match MD5/SHA-1 in code, so without this the generic
        # rule (earlier alphabetically) would claim .py files and apply the blunter transform.
        suffix_list = m.get("file_suffix")
        if suffix_list:
            path = asset.location.file_path if asset.location else None
            suffix = Path(path).suffix.lower() if path else ""
            if suffix not in suffix_list:
                continue
        # file_name match (basename globs). A suffix cannot separate the config rules:
        # `sshd_config` has none at all, and nginx/Apache both use `.conf`. Without this, cfg-ssh-01
        # and cfg-tls-01 matched ANY config-scanner asset carrying one of their algorithm names — so
        # an ECDSA-P256 finding in `requirements.txt` (the dependency scanner also reports
        # `source_scanner=config`) was claimed by the SSH rule, which then pointed the sshd
        # hardening codemod at a pip manifest instead of letting dep-pqc-01 bump the pin.
        name_list = m.get("file_name")
        if name_list:
            path = asset.location.file_path if asset.location else None
            name = Path(path).name.lower() if path else ""
            if not any(fnmatch(name, pattern.lower()) for pattern in name_list):
                continue
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
