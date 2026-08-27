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
    #: Which language the unlabelled `example:` block is written in.
    #:
    #: A cross-language rule declares `language: multi`, so nothing said what its primary example
    #: was written in — and the prompt builder attached that example to files in EVERY language it
    #: had no specific example for. Measured against the real 7B model, that made the model return
    #: the example's language: a Ruby file came back as Go. Stated here so an example is only ever
    #: shown to a file it actually demonstrates.
    example_language: str | None = None
    rescan_expect: dict[str, Any] | None = None
    #: How this finding gets fixed. "auto" lets the orchestrator choose (codemod when the rule has
    #: one, otherwise the model). "guided" says no edit QUBIT can make is the right answer, and the
    #: task should resolve to a concrete guided path instead of burning three model attempts on
    #: something structurally impossible.
    #:
    #: `guided` is a RESULT, not a failure. A certificate cannot be rewritten - editing the bytes
    #: invalidates the CA signature - and an ecosystem with no trustworthy provider cannot have one
    #: installed on the user's behalf. Both are answers; "manual change" was not.
    remediation: str = "auto"

    @field_validator("remediation")
    @classmethod
    def _valid_remediation(cls, v: str) -> str:
        valid = {"auto", "guided"}
        if v not in valid:
            raise ValueError(f"remediation must be one of {valid}")
        return v

    @model_validator(mode="after")
    def _known_weaknesses(self) -> MigrationRule:
        """A `matches.weakness` naming an id the catalogue cannot produce is a rule that can never
        fire. Caught at load time, where it is a typo, rather than at scan time, where it is a
        silent coverage hole."""
        from qubit_core.weaknesses import KNOWN_WEAKNESS_IDS

        declared = self.matches.get("weakness") or []
        unknown = [w for w in declared if w not in KNOWN_WEAKNESS_IDS]
        if unknown:
            raise ValueError(
                f"rule {self.id} matches unknown weakness id(s) {unknown}; "
                f"known ids are {sorted(KNOWN_WEAKNESS_IDS)}"
            )
        return self

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
        # weakness match. The only clause that reads a property of the CALL rather than of the
        # algorithm: `AES-256` is a sound cipher and `AES-256` in ECB mode is not, and the two are
        # the same asset by every other field. A rule listing a weakness fires ONLY on findings
        # carrying it, which is what lets an ECB rule exist without claiming every AES finding.
        weakness_list = m.get("weakness")
        if weakness_list and not _has_weakness(asset, weakness_list):
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
            if None not in lib_list and not _library_matches(asset_lib, lib_list):
                continue
        return rule
    return None


def _has_weakness(asset: CryptoAsset, wanted: list[Any]) -> bool:
    """True when the scanner recorded one of ``wanted`` on this finding.

    Weaknesses live in `evidence.context.extra["weaknesses"]` as dicts carrying the id, the CWE,
    the authority and the remedy — see `qubit_core.weaknesses`. Read defensively because an asset
    hydrated from an older scan has no such key at all.
    """
    evidence = getattr(asset, "evidence", None)
    context = getattr(evidence, "context", None)
    raw = (getattr(context, "extra", None) or {}).get("weaknesses")
    if not isinstance(raw, list):
        return False
    present = {w.get("id") for w in raw if isinstance(w, dict)}
    return any(w in present for w in wanted)


def _library_key(name: str) -> str:
    """A package name reduced to the form rules are written in.

    Ecosystems qualify a package differently and the scanner reports what the manifest says, so an
    exact string comparison silently fails on whole ecosystems. Maven names a dependency
    `org.bouncycastle:bcprov-jdk18on` (groupId:artifactId) while the rule — and the version floor
    table in `codemods._MIN_PQC_VERSIONS` — is keyed on `bcprov-jdk18on`. That mismatch made
    `dep-pqc-01` unreachable for every Maven project: measured on the 21-app demo corpus, 4
    BouncyCastle findings in `pom.xml` reported "no migration rule" even though a verified PQC
    floor for that exact artifact was already on file.

    Reduced to the last colon-delimited segment, lowercased, with `_` normalised to `-` (pip treats
    the two as equivalent). npm scopes are deliberately NOT stripped: `@noble/post-quantum` and a
    hypothetical unscoped `post-quantum` are different packages, and `/` is not a separator here.
    """
    return name.rsplit(":", 1)[-1].strip().lower().replace("_", "-")


def _library_matches(asset_lib: str | None, lib_list: list[Any]) -> bool:
    """True when the asset's library is one the rule names, comparing on `_library_key`."""
    if asset_lib is None:
        return False
    key = _library_key(asset_lib)
    return any(isinstance(x, str) and _library_key(x) == key for x in lib_list)


__all__ = ["MigrationRule", "load_rules", "match_rule"]
