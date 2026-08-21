"""`qubit rules examples` publishes what the scanner can actually recognise.

qubit-migrate may not import scanner internals (doc 03 §2), but its generator has to know which
code shapes the rescan will accept as a completed migration — otherwise it guesses, and a guess
that the scanner cannot see is rejected however correct the cryptography is. That is what happened:
a Rust file was migrated to `mlkem::GenerateKey768(&mut rng)`, which is Go's standard-library API
spelled in Rust, and failed three attempts running.

This command is the boundary that closes the gap. Every shape it emits is scanned before it is
emitted, so the contract it publishes is verified rather than asserted.
"""

from __future__ import annotations

import json

from qubit_cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def _examples(*args: str) -> list[dict]:
    res = runner.invoke(app, ["rules", "examples", *args])
    assert res.exit_code == 0, res.output
    start = res.output.find("[")
    assert start != -1, res.output
    parsed = json.loads(res.output[start:])
    assert isinstance(parsed, list)
    return parsed


def test_rust_ml_kem_shape_is_published() -> None:
    shapes = _examples("--language", "rust", "--algorithm-prefix", "ML-KEM")
    assert shapes, "the scanner detects ML-KEM in Rust, so it must publish a shape for it"
    assert all(any(a.startswith("ML-KEM") for a in s["algorithms"]) for s in shapes)
    assert any("MlKem768" in s["source"] for s in shapes)


def test_go_shape_is_gos_not_rusts() -> None:
    shapes = _examples("--language", "go", "--algorithm-prefix", "ML-KEM")
    assert shapes
    assert any("crypto/mlkem" in s["source"] for s in shapes)
    assert not any("MlKem768::" in s["source"] for s in shapes)


def test_a_language_with_no_pqc_rule_publishes_nothing() -> None:
    """An empty answer is the useful one: it says no rewrite here can ever be confirmed."""
    assert _examples("--language", "swift", "--algorithm-prefix", "ML-KEM") == []


def test_the_prefix_filter_actually_filters() -> None:
    """Guarding the guard — without this, an unfiltered dump would pass the tests above."""
    everything = _examples("--language", "rust")
    filtered = _examples("--language", "rust", "--algorithm-prefix", "ML-KEM")
    assert len(everything) > len(filtered), (
        "Rust has weak-algorithm rules too; the ML-KEM filter must exclude them"
    )
    assert any(not any(a.startswith("ML-KEM") for a in s["algorithms"]) for s in everything)


def test_every_published_shape_names_the_rule_that_verifies_it() -> None:
    for shape in _examples("--language", "rust"):
        assert shape["rule_id"]
        assert shape["language"] == "rust"
        assert shape["source"].strip()
        assert shape["algorithms"], "a shape with no algorithm proves nothing and must not ship"
