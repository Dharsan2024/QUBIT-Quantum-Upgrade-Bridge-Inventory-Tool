"""Crypto Agility Policy — load + resolve (E2, doc 08 §2).

Versioned params file: ``params/agility_policy.yaml``.
``resolve_target()`` is the single authority for the PQC target when a migration
rule does not pin one explicitly.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from qubit_core import CryptoAsset

_PARAMS_DIR = Path(__file__).parent / "params"
_POLICY_PATH = _PARAMS_DIR / "agility_policy.yaml"

# Bucket: map CryptoAsset usage_context values to policy-default keys.
_UC_BUCKET: dict[str, str] = {
    "kex": "kex",
    "encryption-at-rest": "encryption_at_rest",
    "signature": "signature",
    "hash": "hash",
    "tls": "kex",  # TLS key exchange is a kex concern
    "token": "signature",  # token signing → signature bucket (before override applied)
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AgilityTarget(BaseModel):
    """Policy-resolved target specification."""

    mode: str  # "pure" | "hybrid"
    target: str  # canonical algorithm, e.g. ML-KEM-768
    parameter_set: str | None = None
    hybrid_group: str | None = None
    category: int | None = None
    fips: str | None = None
    rationale: str = ""


class AgilityOverrideMatch(BaseModel):
    usage_context: str | None = None
    sensitivity: str | None = None


class AgilityOverride(BaseModel):
    match: AgilityOverrideMatch
    set: AgilityTarget


class AgilityPolicy(BaseModel):
    """Full agility policy (versioned)."""

    version: str
    defaults: dict[str, AgilityTarget] = Field(default_factory=dict)
    overrides: list[AgilityOverride] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def load_agility_policy(path: Path | None = None) -> AgilityPolicy:
    """Load and validate the agility policy YAML.

    Cached after first load — call ``load_agility_policy.cache_clear()`` in tests.
    """
    p = path or _POLICY_PATH
    raw: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8"))
    return AgilityPolicy.model_validate(raw)


def policy_file_hash(path: Path | None = None) -> str:
    """SHA-256 hex digest of the policy file — for engine-version records."""
    p = path or _POLICY_PATH
    return hashlib.sha256(p.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


def resolve_target(
    asset: CryptoAsset,
    policy: AgilityPolicy | None = None,
) -> AgilityTarget | None:
    """Return the policy-resolved PQC target for ``asset``, or ``None``.

    Resolution order:
    1. Check ``policy.overrides`` in order; first match on usage_context and/or
       sensitivity wins.
    2. Look up ``policy.defaults[bucket]`` where ``bucket`` is derived from
       ``asset.usage_context`` via ``_UC_BUCKET``.
    3. Return ``None`` if no bucket maps (e.g. non-vulnerable / unknown context).
    """
    p = policy or load_agility_policy()

    uc = (
        asset.usage_context.value
        if hasattr(asset.usage_context, "value")
        else str(asset.usage_context)
    )
    sensitivity = (
        asset.sensitivity.value
        if asset.sensitivity and hasattr(asset.sensitivity, "value")
        else (str(asset.sensitivity) if asset.sensitivity else None)
    )

    # 1. Overrides
    for override in p.overrides:
        m = override.match
        if m.usage_context and m.usage_context != uc:
            continue
        if m.sensitivity and m.sensitivity != sensitivity:
            continue
        return override.set

    # 2. Default bucket
    bucket = _UC_BUCKET.get(uc)
    if bucket and bucket in p.defaults:
        return p.defaults[bucket]

    return None


__all__ = [
    "AgilityOverride",
    "AgilityOverrideMatch",
    "AgilityPolicy",
    "AgilityTarget",
    "load_agility_policy",
    "policy_file_hash",
    "resolve_target",
]
