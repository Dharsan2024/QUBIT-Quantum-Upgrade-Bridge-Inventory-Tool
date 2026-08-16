from __future__ import annotations

import pytest
from qubit_core import algorithms
from qubit_core.schemas import QuantumAttack


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("RSA-2048", "RSA-2048"),
        ("rsa2048", "RSA-2048"),
        ("RSA/2048", "RSA-2048"),
        ("rsa_2048", "RSA-2048"),
        ("Kyber768", "ML-KEM-768"),
        ("mlkem768", "ML-KEM-768"),
        ("prime256v1", "ECDSA-P256"),
        ("des", "DES"),
        ("DES", "DES"),
        ("x25519mlkem768", "X25519MLKEM768"),
        # JOSE/JWT alg identifiers (RFC 7518) — added to ground the Go/JS JWT rule packs.
        ("es256", "ECDSA-P256"),
        ("es384", "ECDSA-P384"),
        ("es512", "ECDSA-P521"),
        ("eddsa", "Ed25519"),
        ("RS256", "RS256"),
        ("ps256", "PS256"),
        ("HS256", "HS256"),
        ("hmac-sha384", "HS384"),
    ],
)
def test_resolve_aliases(raw: str, expected: str) -> None:
    got = algorithms.resolve(raw)
    assert got is not None and got.canonical == expected


def test_jose_alg_quantum_verdicts() -> None:
    # RSA-signature and ECDSA-based JOSE algs are Shor-broken.
    for name in ("RS256", "PS256", "ES256", "ES512", "EdDSA"):
        entry = algorithms.resolve(name)
        assert entry is not None, name
        assert entry.vulnerable is True and entry.attack is QuantumAttack.shor, name

    # The HMAC algs are quantum-SAFE, and this assertion was inverted until 2026-08-16. Grover only
    # halves symmetric strength, so an HMAC-SHA-256 key leaves 128 bits — the same reasoning that
    # makes AES-256 and SHA-256 `_safe` here, and HMAC is strictly stronger than the hash it wraps.
    # Rating HS256 vulnerable while rating SHA-256 safe contradicted itself, and it had a real
    # consequence: every HMAC variant was flagged, HS512 included, so an HMAC finding had no safe
    # target to migrate TO and could never be cleared. CNSA 2.0 approves HMAC-SHA-384.
    for name in ("HS256", "HS384", "HS512"):
        entry = algorithms.resolve(name)
        assert entry is not None, name
        assert entry.vulnerable is False and entry.attack is QuantumAttack.none, name

    # Built on a classically broken hash, so still flagged — on the hash, not on Grover.
    for name in ("hmac-sha1", "hmac-md5"):
        entry = algorithms.resolve(name)
        assert entry is not None and entry.vulnerable is True, name


def test_resolve_rsa_by_key_size() -> None:
    got = algorithms.resolve("rsa", key_size=4096)
    assert got is not None and got.canonical == "RSA-4096"


def test_quantum_verdicts() -> None:
    assert algorithms.get("RSA-2048").attack is QuantumAttack.shor  # type: ignore[union-attr]
    assert algorithms.get("ML-KEM-768").vulnerable is False  # type: ignore[union-attr]
    assert algorithms.get("AES-128").attack is QuantumAttack.grover  # type: ignore[union-attr]
    assert algorithms.get("AES-256").vulnerable is False  # type: ignore[union-attr]


def test_bare_public_key_family_stays_shor_vulnerable() -> None:
    # a size-less "RSA" (Cipher.getInstance("RSA"), JWT RS256) must NOT degrade to safe/unknown
    rsa = algorithms.resolve("RSA")
    assert rsa is not None and rsa.canonical == "RSA"
    assert rsa.vulnerable is True and rsa.attack is QuantumAttack.shor
    ec = algorithms.resolve("EC")
    assert ec is not None and ec.attack is QuantumAttack.shor


def test_size_wins_over_bare_family() -> None:
    # explicit key size must still parameterize even though a bare "RSA" entry now exists
    assert algorithms.resolve("RSA", key_size=3072).canonical == "RSA-3072"  # type: ignore[union-attr]
    assert algorithms.resolve("RSA-2048").canonical == "RSA-2048"  # type: ignore[union-attr]


def test_unknown_returns_none() -> None:
    assert algorithms.resolve("totally-made-up-cipher") is None
    assert algorithms.resolve("") is None


# ---------------------------------------------------------------------------
# OpenSSL-spelled cipher suites (nginx `ssl_ciphers` / Apache `SSLCipherSuite`)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "suite,expected",
    [
        # ECDHE-prefixed: the key exchange governs harvest-now-decrypt-later exposure.
        ("ECDHE-RSA-AES128-GCM-SHA256", "ECDH-P256"),
        ("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDH-P256"),
        ("ECDHE-RSA-AES128-SHA", "ECDH-P256"),
        ("DHE-RSA-AES256-SHA", "DH"),
        # No kex prefix is OpenSSL's spelling for static RSA key transport - no forward secrecy at
        # all, so one recovered RSA key opens every recorded session. These are the worst suites for
        # HNDL and they must not come back unresolved.
        ("AES128-SHA", "RSA"),
        ("DES-CBC3-SHA", "RSA"),
        ("RC4-MD5", "RSA"),
    ],
)
def test_openssl_cipher_suite_names_resolve(suite: str, expected: str) -> None:
    """Real nginx and Apache configs use OpenSSL's hyphenated suite spelling, not the IANA
    `TLS_..._WITH_...` form. Until these resolved, every `ssl_ciphers` line in every real config
    became `UNKNOWN(...)`, which `normalize()` rates NOT vulnerable - so a server pinned to
    `ECDHE-RSA-AES128-SHA` was reported clean."""
    resolved = algorithms.resolve(suite)
    assert resolved is not None, f"{suite} did not resolve"
    assert resolved.canonical == expected
    assert resolved.vulnerable, f"{suite} resolved to {expected} but is rated not vulnerable"


@pytest.mark.parametrize(
    "name,expected",
    [
        ("aes-128-cbc", "AES-128"),
        ("aes-256-gcm", "AES-256"),
        ("des-ede3-cbc", "3DES"),
        ("chacha20-poly1305", "ChaCha20-Poly1305"),
        ("hmac-sha256", "HS256"),
        ("DESede/CBC/PKCS5Padding", "3DES"),
    ],
)
def test_plain_cipher_strings_are_not_hijacked_by_suite_reduction(name: str, expected: str) -> None:
    """The OpenSSL suite reducer runs LAST in `resolve()` precisely so it cannot pre-empt an
    ordinary cipher string. `aes-128-cbc` is a cipher, not a suite, and must stay AES-128."""
    resolved = algorithms.resolve(name)
    assert resolved is not None and resolved.canonical == expected


def test_null_cipher_is_flagged_rather_than_reported_safe() -> None:
    """A NULL cipher is plaintext on the wire. No quantum attack is involved, but reporting it as
    "not vulnerable" would be badly misleading - it is already harvested, no CRQC needed."""
    resolved = algorithms.resolve("NULL")
    assert resolved is not None
    assert resolved.vulnerable


def test_psk_suite_resolves_and_is_honestly_rated_quantum_safe() -> None:
    """A PSK suite has no public-key key exchange, so there is nothing for Shor to factor - a long,
    secret pre-shared key really is a quantum-safe stopgap. What matters is that it RESOLVES: as
    `UNKNOWN(...)` it would also read as not-vulnerable, but for the wrong reason and with no way to
    tell the two apart."""
    resolved = algorithms.resolve("PSK-AES128-CBC-SHA")
    assert resolved is not None and resolved.canonical == "PSK"
    assert not resolved.vulnerable
    assert resolved.attack is QuantumAttack.none


def test_iana_psk_and_null_suites_no_longer_fall_through() -> None:
    """`PSK` and `NULL` were named by the IANA suite-reduction tables but never existed as registry
    entries, so `TLS_PSK_WITH_*` reduced to a name nothing could resolve."""
    assert algorithms.resolve("TLS_PSK_WITH_AES_128_CBC_SHA") is not None
