"""Tests for E5 Migration Knowledge Base (qubit_migrate.kb)."""

from __future__ import annotations

from qubit_migrate.kb import (
    KBEntry,
    MigrationKB,
    kb_file_hash,
    load_migration_kb,
    lookup_kb,
)


def test_load_migration_kb_returns_valid_model() -> None:
    """The bundled KB file loads without errors and passes Pydantic validation."""
    kb = load_migration_kb()
    assert isinstance(kb, MigrationKB)
    assert kb.version.startswith("20")  # e.g. "2026.08"
    assert len(kb.entries) >= 6, "KB must have at least 6 entries"


def test_all_entries_have_required_fields() -> None:
    kb = load_migration_kb()
    for entry in kb.entries:
        assert isinstance(entry, KBEntry)
        assert entry.vuln.family
        assert entry.vuln.usage_context
        assert entry.target.algorithm
        assert entry.target.mode in {"pure", "hybrid"}
        assert entry.guidance


def test_lookup_rsa_kex() -> None:
    entry = lookup_kb("RSA", "kex")
    assert entry is not None
    assert entry.target.algorithm == "ML-KEM-768"
    assert entry.target.mode == "hybrid"
    assert entry.target.fips == "FIPS-203"
    assert entry.library.python is not None
    assert entry.library.python.name == "cryptography"


def test_lookup_ecdsa_signature() -> None:
    entry = lookup_kb("ECDSA", "signature")
    assert entry is not None
    assert entry.target.algorithm == "ML-DSA-65"
    assert entry.target.mode == "pure"


def test_lookup_sha1_hash() -> None:
    entry = lookup_kb("SHA-1", "hash")
    assert entry is not None
    assert entry.target.algorithm == "SHA3-256"


def test_lookup_md5_hash() -> None:
    entry = lookup_kb("MD5", "hash")
    assert entry is not None
    assert entry.target.algorithm == "SHA3-256"


def test_lookup_case_insensitive() -> None:
    """Family matching is case-insensitive."""
    entry_lower = lookup_kb("rsa", "kex")
    entry_upper = lookup_kb("RSA", "kex")
    assert entry_lower is not None
    assert entry_upper is not None
    assert entry_lower.target.algorithm == entry_upper.target.algorithm


def test_lookup_miss_returns_none() -> None:
    """Non-existent family + context returns None."""
    result = lookup_kb("UNKNOWN_ALGO", "tls")
    assert result is None


def test_lookup_wrong_usage_context_returns_none() -> None:
    """RSA in a usage context not covered by the KB returns None."""
    result = lookup_kb("RSA", "password")
    assert result is None


def test_kb_file_hash_is_hex_string() -> None:
    digest = kb_file_hash()
    assert len(digest) == 64  # SHA-256 hex digest
    assert all(c in "0123456789abcdef" for c in digest)


def test_load_migration_kb_cache(tmp_path) -> None:
    """load_migration_kb() is cached; calling it twice returns the same object."""
    load_migration_kb.cache_clear()
    kb1 = load_migration_kb()
    kb2 = load_migration_kb()
    assert kb1 is kb2  # same cached object
    load_migration_kb.cache_clear()
