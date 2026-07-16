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


def test_unknown_returns_none() -> None:
    assert algorithms.resolve("totally-made-up-cipher") is None
    assert algorithms.resolve("") is None
