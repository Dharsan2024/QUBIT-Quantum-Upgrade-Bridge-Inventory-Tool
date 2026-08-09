"""Tests for E2 Crypto Agility Policy (qubit_migrate.agility)."""

from __future__ import annotations

from unittest.mock import MagicMock

from qubit_migrate.agility import (
    AgilityPolicy,
    load_agility_policy,
    policy_file_hash,
    resolve_target,
)


def _make_asset(usage_context: str, algorithm: str = "RSA-2048", sensitivity: str = "unknown"):
    """Build a minimal mock CryptoAsset for testing resolve_target()."""
    asset = MagicMock()
    asset.usage_context.value = usage_context
    asset.sensitivity.value = sensitivity
    asset.sensitivity.__bool__ = lambda _: True
    asset.algorithm = algorithm
    return asset


def test_load_agility_policy_returns_valid_model() -> None:
    policy = load_agility_policy()
    assert isinstance(policy, AgilityPolicy)
    assert policy.version.startswith("20")
    assert "kex" in policy.defaults
    assert "signature" in policy.defaults
    assert "encryption_at_rest" in policy.defaults


def test_kex_default_is_hybrid_ml_kem_768() -> None:
    policy = load_agility_policy()
    kex = policy.defaults["kex"]
    assert kex.mode == "hybrid"
    assert kex.target == "ML-KEM-768"
    assert kex.hybrid_group == "X25519MLKEM768"
    assert kex.fips == "FIPS-203"


def test_signature_default_is_pure_ml_dsa_65() -> None:
    policy = load_agility_policy()
    sig = policy.defaults["signature"]
    assert sig.mode == "pure"
    assert sig.target == "ML-DSA-65"
    assert sig.fips == "FIPS-204"


def test_encryption_at_rest_default() -> None:
    policy = load_agility_policy()
    eat = policy.defaults["encryption_at_rest"]
    assert eat.target == "AES-256"


def test_resolve_target_kex_returns_ml_kem() -> None:
    asset = _make_asset("kex")
    result = resolve_target(asset)
    assert result is not None
    assert result.target == "ML-KEM-768"
    assert result.mode == "hybrid"


def test_resolve_target_signature_returns_ml_dsa() -> None:
    asset = _make_asset("signature")
    result = resolve_target(asset)
    assert result is not None
    assert result.target == "ML-DSA-65"
    assert result.mode == "pure"


def test_resolve_target_tls_maps_to_kex_bucket() -> None:
    """TLS context should be bucketed as kex."""
    asset = _make_asset("tls")
    result = resolve_target(asset)
    assert result is not None
    assert result.target == "ML-KEM-768"


def test_resolve_target_unknown_context_returns_none() -> None:
    """Unknown usage_context with no matching override → None."""
    asset = _make_asset("password")
    result = resolve_target(asset)
    assert result is None


def test_resolve_target_override_wins() -> None:
    """token+credentials override should return pure ML-DSA-65."""
    asset = _make_asset("token", sensitivity="credentials")
    result = resolve_target(asset)
    assert result is not None
    assert result.mode == "pure"
    assert result.target == "ML-DSA-65"


def test_policy_file_hash_is_hex_string() -> None:
    digest = policy_file_hash()
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_load_agility_policy_cache() -> None:
    load_agility_policy.cache_clear()
    p1 = load_agility_policy()
    p2 = load_agility_policy()
    assert p1 is p2
    load_agility_policy.cache_clear()
