"""The metamorphic harness, run for real against correct and broken migrations.

These tests execute the generated harness in a subprocess against real
`cryptography` primitives. They are the ones that matter, because the whole claim
of the `behaves` stage rests on a single property:

    **a patch that installs something which accepts everything must FAIL.**

Both broken cases below pass their POSITIVE relation. A round-trip check alone
accepts both. Only the negatives catch them — which is why a relation family
without negatives cannot award evidence, and why these tests exercise the
negatives specifically rather than asserting an overall verdict.

Every case here also passes `applies`, `parses`, `symbols`, `compiles` and
`rescan`: they are syntactically valid, their names resolve, they import cleanly,
and the scanner sees ML-DSA where ECDSA used to be. L2 says migrated; L3 says the
signature check accepts forgeries.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from qubit_migrate.oracles import relations_for
from qubit_migrate.oracles.harness import HarnessPlan, build, find_primitive_expression

# --------------------------------------------------------------------------- fixtures in source

CORRECT_SIGNATURE = """
from cryptography.hazmat.primitives.asymmetric import mldsa


def make_key():
    return mldsa.MLDSA65PrivateKey.generate()
"""

#: Passes every syntactic gate. `verify` swallows whatever it is given, and `sign`
#: returns something of exactly the right length so even the size advisory reads
#: correct. This is the shape of defect the entire stage exists for.
SIGNATURE_ACCEPTS_ANYTHING = """
from cryptography.hazmat.primitives.asymmetric import mldsa


class _AlwaysValid:
    def verify(self, sig, data):
        return None


class _Key:
    def public_key(self):
        return _AlwaysValid()

    def sign(self, data):
        return b"x" * 3309

    @classmethod
    def generate(cls):
        return cls()


mldsa.MLDSA65PrivateKey = _Key
"""

CORRECT_KEX = """
from cryptography.hazmat.primitives.asymmetric import mlkem


def make_key():
    return mlkem.MLKEM768PrivateKey.generate()
"""

#: Agreement holds trivially because both sides return the same constant. The
#: positive relation passes; only disagreement under a mismatched key exposes it.
KEX_CONSTANT_SECRET = """
from cryptography.hazmat.primitives.asymmetric import mlkem


class _Pub:
    def encapsulate(self):
        return (b"S" * 32, b"C" * 1088)


class _Key:
    def public_key(self):
        return _Pub()

    def decapsulate(self, ct):
        return b"S" * 32

    @classmethod
    def generate(cls):
        return cls()


mlkem.MLKEM768PrivateKey = _Key
"""

IMPORT_MISSING = """
def make_key():
    return mldsa.MLDSA65PrivateKey.generate()
"""


def _run(plan: HarnessPlan, patched_source: str) -> dict:
    """Execute the harness against the patched file and return its verdict."""
    with tempfile.TemporaryDirectory() as d:
        module = Path(d) / "patched.py"
        module.write_text(patched_source, encoding="utf-8")
        # The plan was built for a placeholder path; point it at the real file.
        source = plan.source.replace("/work/patched.py", str(module).replace("\\", "/"))
        harness = Path(d) / "harness.py"
        harness.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(harness)], capture_output=True, text=True, timeout=180
        )
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert lines, f"harness produced no output\nstdout={proc.stdout}\nstderr={proc.stderr}"
    return json.loads(lines[-1])


def _plan(usage: str, source: str, algorithm: str) -> HarnessPlan:
    return build(relations_for(usage), source, algorithm)


def _outcome(verdict: dict, relation_id: str) -> str:
    for relation in verdict["relations"]:
        if relation["id"] == relation_id:
            return relation["outcome"]
    raise AssertionError(f"{relation_id} did not run: {verdict}")


# --------------------------------------------------------------------------- the correct cases


def test_a_correct_signature_migration_passes() -> None:
    """The baseline. If this fails, every `fail` the stage reports is suspect —
    which is exactly what the negative admission control checks for a corpus."""
    verdict = _run(_plan("signature", CORRECT_SIGNATURE, "ML-DSA-65"), CORRECT_SIGNATURE)

    assert verdict["status"] == "pass", verdict
    assert _outcome(verdict, "sig-roundtrip") == "pass"
    for negative in ("sig-wrong-key", "sig-tampered-message", "sig-truncated"):
        assert _outcome(verdict, negative) == "pass", f"{negative} should have rejected"


def test_a_correct_kex_migration_passes() -> None:
    """Exercises the tuple-order trap: `encapsulate()` returns (secret, ciphertext).

    Binding it the intuitive way passes a 32-byte secret to `decapsulate`, which
    raises `Invalid ML-KEM-768 ciphertext` — so a harness written from
    documentation rather than probed would fail this correct patch for a reason
    with nothing to do with the patch.
    """
    verdict = _run(_plan("kex", CORRECT_KEX, "ML-KEM-768"), CORRECT_KEX)

    assert verdict["status"] == "pass", verdict
    assert _outcome(verdict, "kem-agreement") == "pass"
    assert _outcome(verdict, "kem-mismatched-keypair") == "pass"
    assert _outcome(verdict, "kem-corrupted-ciphertext") == "pass"


# --------------------------------------------------------------------------- the cases that matter


def test_a_signature_that_verifies_anything_fails() -> None:
    """The defect no earlier gate can see.

    It parses, its names resolve, it compiles, and the scanner sees ML-DSA where
    ECDSA was — so `applies`, `parses`, `symbols`, `compiles` and `rescan` all
    pass. The signature check accepts forgeries.
    """
    verdict = _run(
        _plan("signature", SIGNATURE_ACCEPTS_ANYTHING, "ML-DSA-65"), SIGNATURE_ACCEPTS_ANYTHING
    )

    assert verdict["status"] == "fail", verdict
    assert _outcome(verdict, "sig-roundtrip") == "pass", (
        "the positive relation SHOULD pass here — that is the point: a round-trip "
        "check alone accepts this patch"
    )
    for negative in ("sig-wrong-key", "sig-tampered-message", "sig-truncated"):
        assert _outcome(verdict, negative) == "fail", f"{negative} failed to catch a forgery"


def test_a_kem_returning_a_constant_secret_fails() -> None:
    """Agreement holds trivially when both sides return the same constant, so the
    positive relation passes. Only disagreement under a mismatched key exposes it."""
    verdict = _run(_plan("kex", KEX_CONSTANT_SECRET, "ML-KEM-768"), KEX_CONSTANT_SECRET)

    assert verdict["status"] == "fail", verdict
    assert _outcome(verdict, "kem-agreement") == "pass", "the round-trip alone accepts this"
    assert _outcome(verdict, "kem-mismatched-keypair") == "fail"
    assert _outcome(verdict, "kem-corrupted-ciphertext") == "fail"


def test_a_patch_naming_an_unresolvable_class_fails() -> None:
    """A verdict, not a skip. The patch references a name that does not resolve in
    its own import context — the failure `symbols` can miss when a name is imported
    from a module that has no such attribute."""
    verdict = _run(_plan("signature", IMPORT_MISSING, "ML-DSA-65"), IMPORT_MISSING)

    assert verdict["status"] == "fail", verdict
    assert "does not resolve" in verdict["reason"]


# --------------------------------------------------------------------------- refusing to guess


def test_an_unsupported_target_is_skipped_not_guessed() -> None:
    """SLH-DSA has no probed API shape. Inventing one would produce a verdict about
    a call the harness made up rather than one the patch made."""
    plan = _plan("signature", CORRECT_SIGNATURE, "SLH-DSA-128s")

    assert not plan.runnable
    assert "no probed API shape" in plan.skip_reason


def test_a_patch_that_never_names_the_target_is_skipped() -> None:
    """There is no primitive to exercise, so there is nothing to conclude. A patch
    that migrated by some other route is not judged by a harness that cannot find
    its subject."""
    plan = _plan("signature", "x = 1\n", "ML-DSA-65")

    assert not plan.runnable
    # The message must name what it looked for, so a reviewer can tell "the patch migrated by
    # another route" apart from "the harness looked for the wrong symbol".
    assert "references none of" in plan.skip_reason
    assert "MLDSA65PrivateKey" in plan.skip_reason


def test_an_unclaimed_usage_context_is_skipped() -> None:
    """No relations means no oracle. Reported as skipped rather than passed —
    an oracle that did not run has established nothing."""
    plan = build(relations_for("password_storage"), CORRECT_SIGNATURE, "ML-DSA-65")

    assert not plan.runnable
    assert "no metamorphic relations" in plan.skip_reason


# --------------------------------------------------------------------------- expression capture


@pytest.mark.parametrize(
    ("source", "algorithm", "expected"),
    [
        ("mldsa.MLDSA65PrivateKey.generate()", "ML-DSA-65", "mldsa.MLDSA65PrivateKey"),
        ("MLDSA65PrivateKey.generate()", "ML-DSA-65", "MLDSA65PrivateKey"),
        ("a.b.MLKEM768PrivateKey.generate()", "ML-KEM-768", "a.b.MLKEM768PrivateKey"),
        ("nothing here", "ML-DSA-65", ""),
    ],
)
def test_the_expression_is_read_from_the_patch(source: str, algorithm: str, expected: str) -> None:
    """How the patch SPELLS the name is part of what is verified.

    A patch that wrote `mldsa65.MLDSA65PrivateKey` against a module that does not
    exist must fail, and it only can if the wrong spelling is carried through to
    the harness instead of being reconstructed from the target algorithm.
    """
    assert find_primitive_expression(source, algorithm) == expected
