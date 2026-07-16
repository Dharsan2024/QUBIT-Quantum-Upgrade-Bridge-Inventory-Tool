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
    ],
)
def test_resolve_aliases(raw: str, expected: str) -> None:
    got = algorithms.resolve(raw)
    assert got is not None and got.canonical == expected


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
