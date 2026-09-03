"""Injected-defect tests for the AEAD and hash relation families.

Each test builds a patch that would be ACCEPTED by every other gate — it parses, its names
resolve, it compiles, and the scanner reads the new algorithm straight out of the source — and
asserts that the metamorphic oracle rejects it anyway. That gap is the contribution; a family
whose defects are not demonstrated here has not earned its place in the ladder.

Runs the real harness in the real container. A mocked verdict would prove only that the test's own
fixture agrees with itself.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from qubit_migrate.oracles import relations_for
from qubit_migrate.oracles.harness import build

_IMAGE = "qubit-eval/oracle:py312"


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True, timeout=60)
    return probe.returncode == 0


requires_oracle = pytest.mark.skipif(
    not _docker_ready(),
    reason=(
        f"needs the {_IMAGE} image — build it with: docker build -t {_IMAGE} "
        "-f qubit-v2/02-verification/Dockerfile.oracle ."
    ),
)


def _run(usage_context: str, source: str, target: str, construction: str = "pure") -> dict:
    """Render the harness for `source` and execute it in the sandbox."""
    plan = build(relations_for(usage_context, construction), source, target)
    assert plan.runnable, plan.skip_reason
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "patched.py").write_text(source, encoding="utf-8", newline="\n")
        (work / "harness.py").write_text(plan.source, encoding="utf-8", newline="\n")
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--memory=1g",
                "--cpus=1",
                "--pids-limit=128",
                "-v",
                f"{tmp}:/work:ro",
                _IMAGE,
                "python",
                "/work/harness.py",
            ],
            capture_output=True,
            timeout=180,
        )
    out = result.stdout.decode("utf-8", errors="replace").strip().splitlines()
    assert out, result.stderr.decode("utf-8", errors="replace")
    return json.loads(out[-1])


def _failed(verdict: dict) -> set[str]:
    return {r["id"] for r in verdict["relations"] if r["outcome"] == "fail"}


def _passed(verdict: dict) -> set[str]:
    return {r["id"] for r in verdict["relations"] if r["outcome"] == "pass"}


# --------------------------------------------------------------------------------------- AEAD

_AEAD_CORRECT = """from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(key, nonce, data, aad):
    return AESGCM(key).encrypt(nonce, data, aad)
"""

#: Encrypts correctly and decrypts correctly, but NEVER CHECKS THE TAG. The round trip is perfect.
#: This is the defect `rescan` cannot see: the scanner reads AESGCM out of the source and reports a
#: successful migration to authenticated encryption.
_AEAD_NO_TAG_CHECK = """import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESGCM:
    def __init__(self, key):
        self._key = key

    @classmethod
    def generate_key(cls, bit_length=256):
        return os.urandom(bit_length // 8)

    def encrypt(self, nonce, data, aad):
        enc = Cipher(algorithms.AES(self._key), modes.GCM(nonce)).encryptor()
        if aad:
            enc.authenticate_additional_data(aad)
        return enc.update(data) + enc.finalize() + enc.tag

    def decrypt(self, nonce, data, aad):
        # The tag is sliced off and thrown away. Nothing is authenticated.
        counter = modes.CTR(nonce + b"\\x00\\x00\\x00\\x02")
        dec = Cipher(algorithms.AES(self._key), counter).decryptor()
        return dec.update(data[:-16]) + dec.finalize()
"""

#: Honours the tag, but ignores the nonce it was handed and uses a constant. Round-trips, rejects
#: tampering, rejects a wrong key, rejects a wrong AAD — passes every relation but one.
_AEAD_CONSTANT_NONCE = """import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _Real

_FIXED = b"AAAAAAAAAAAA"


class AESGCM:
    def __init__(self, key):
        self._inner = _Real(key)

    @classmethod
    def generate_key(cls, bit_length=256):
        return os.urandom(bit_length // 8)

    def encrypt(self, nonce, data, aad):
        return self._inner.encrypt(_FIXED, data, aad)

    def decrypt(self, nonce, data, aad):
        return self._inner.decrypt(_FIXED, data, aad)
"""


@requires_oracle
class TestAead:
    def test_a_correct_aead_migration_passes(self) -> None:
        verdict = _run("aead", _AEAD_CORRECT, "AES-256-GCM")
        assert verdict["status"] == "pass", verdict["reason"]

    def test_a_removed_tag_check_is_caught(self) -> None:
        """The whole point of the family: the round trip still holds."""
        verdict = _run("aead", _AEAD_NO_TAG_CHECK, "AES-256-GCM")
        assert verdict["status"] == "fail", verdict
        assert "aead-roundtrip" in _passed(verdict), "the defect must survive the positive relation"
        assert "aead-tampered-ciphertext" in _failed(verdict), verdict

    def test_a_constant_nonce_is_caught(self) -> None:
        """Passes every authentication relation. Only nonce uniqueness sees it."""
        verdict = _run("aead", _AEAD_CONSTANT_NONCE, "AES-256-GCM")
        assert verdict["status"] == "fail", verdict
        assert {"aead-roundtrip", "aead-tampered-ciphertext", "aead-wrong-key"} <= _passed(verdict)
        assert _failed(verdict) == {"aead-nonce-uniqueness"}, verdict


# --------------------------------------------------------------------------------------- hash

_HASH_CORRECT = """import hashlib


def fingerprint(data):
    return hashlib.sha384(data).hexdigest()
"""

#: Deterministic, input-sensitive, and named `sha384` in a file the scanner will read as SHA-384.
#: It returns 16 bytes. Grover against a 128-bit digest is 2^64 work.
_HASH_TRUNCATED = """import hashlib as _hashlib


def sha384(data=b""):
    class _Truncated:
        def __init__(self):
            self._inner = _hashlib.sha384(data)

        def update(self, more):
            self._inner.update(more)

        def digest(self):
            return self._inner.digest()[:16]

        def hexdigest(self):
            return self.digest().hex()

    return _Truncated()
"""

#: Ignores its input entirely. Deterministic, and the digest is exactly 48 bytes.
_HASH_CONSTANT = """def sha384(data=b""):
    class _Constant:
        def update(self, more):
            pass

        def digest(self):
            return bytes(range(48))

        def hexdigest(self):
            return self.digest().hex()

    return _Constant()
"""


#: Hashes only the first 8 bytes of its input. Deterministic, full 48-byte digest, and it
#: genuinely distinguishes most inputs — it fails ONLY on a pair that shares a prefix. This is the
#: fixture that justifies the spec's claim that the one-byte difference is load-bearing.
_HASH_PREFIX_ONLY = """import hashlib as _hashlib


def sha384(data=b""):
    class _PrefixOnly:
        def __init__(self):
            self._buf = bytearray(data)

        def update(self, more):
            self._buf.extend(more)

        def digest(self):
            return _hashlib.sha384(bytes(self._buf[:8])).digest()

        def hexdigest(self):
            return self.digest().hex()

    return _PrefixOnly()
"""


@requires_oracle
class TestHash:
    def test_a_correct_hash_migration_passes(self) -> None:
        verdict = _run("hash", _HASH_CORRECT, "SHA-384")
        assert verdict["status"] == "pass", verdict["reason"]

    def test_a_truncated_digest_is_caught(self) -> None:
        """Deterministic and input-sensitive, so only the length relation can see it."""
        verdict = _run("hash", _HASH_TRUNCATED, "SHA-384")
        assert verdict["status"] == "fail", verdict
        assert {"hash-determinism", "hash-distinct-inputs"} <= _passed(verdict)
        assert _failed(verdict) == {"hash-digest-length"}, verdict

    def test_a_constant_digest_is_caught(self) -> None:
        """Right length, perfectly deterministic, and completely worthless."""
        verdict = _run("hash", _HASH_CONSTANT, "SHA-384")
        assert verdict["status"] == "fail", verdict
        assert {"hash-determinism", "hash-digest-length"} <= _passed(verdict)
        assert _failed(verdict) == {"hash-distinct-inputs"}, verdict

    def test_a_prefix_only_digest_is_caught(self) -> None:
        """Right length, deterministic, and it distinguishes most inputs — but not a pair that
        shares a prefix.

        The harness probes with MSG and MSG_TAMPERED, which differ in their LAST byte. That choice
        is load-bearing and this is the only test that proves it: two wildly different messages
        would both survive a prefix-hashing rewrite and the relation would report a pass.
        """
        verdict = _run("hash", _HASH_PREFIX_ONLY, "SHA-384")
        assert verdict["status"] == "fail", verdict
        assert {"hash-determinism", "hash-digest-length"} <= _passed(verdict)
        assert _failed(verdict) == {"hash-distinct-inputs"}, verdict

    def test_an_unknown_digest_size_drops_the_length_relation(self) -> None:
        """Rather than defaulting to a comparison that always holds.

        `BLAKE2b` has a probed shape but no entry in `EXPECTED_SIZES`, so the length relation has
        no number to check against. It must vanish from the plan, not run permissively.
        """
        plan = build(
            relations_for("hash", "pure"), "import hashlib\nh = hashlib.blake2b\n", "BLAKE2B"
        )
        assert plan.runnable, plan.skip_reason
        assert "hash-digest-length" not in plan.source
        assert "hash-distinct-inputs" in plan.source


# ---------------------------------------------------------------------------------- composite

#: A real composite: signs with Ed25519 AND ML-DSA-65, verifies BOTH. Layout is
#: `ed25519_sig (64) || mldsa_sig (3309)`.
_COMPOSITE_CORRECT = """from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa


class CompositeSignature:
    def __init__(self, classical=None, pqc=None):
        self._classical = classical or ed25519.Ed25519PrivateKey.generate()
        self._pqc = pqc or mldsa.MLDSA65PrivateKey.generate()

    @classmethod
    def generate(cls):
        return cls()

    def sign(self, data):
        return self._classical.sign(data) + self._pqc.sign(data)

    def public_key(self):
        return _CompositePublic(self._classical.public_key(), self._pqc.public_key())


class _CompositePublic:
    def __init__(self, classical, pqc):
        self._classical = classical
        self._pqc = pqc

    def verify(self, signature, data):
        self._classical.verify(signature[:64], data)
        self._pqc.verify(signature[64:], data)
"""

#: The dangerous one. Signs with both, but `verify` checks ONLY the ML-DSA half. It round-trips,
#: it satisfies a hybrid mandate on paper, and the classical component is decorative — so it gives
#: no protection at all against a flaw in the PQC implementation, which is precisely why BSI and
#: ANSSI require hybrid in the first place.
_COMPOSITE_CLASSICAL_IGNORED = _COMPOSITE_CORRECT.replace(
    "        self._classical.verify(signature[:64], data)\n", ""
)

#: The mirror image: only the classical half is checked, so a quantum adversary is unopposed.
_COMPOSITE_PQC_IGNORED = _COMPOSITE_CORRECT.replace(
    "        self._pqc.verify(signature[64:], data)\n", "        return None\n"
)

_COMPOSITE_TARGET = "ML-DSA-65+ED25519"


@requires_oracle
class TestComposite:
    """A composite that ignores either half is the most dangerous output this project can produce.

    `cryptography` 49.0.0 ships no composite primitive, so the patch defines the construction and
    owns the wire format. The relations are positional for that reason — see the shape's comment.
    """

    def test_a_correct_composite_passes(self) -> None:
        verdict = _run("signature", _COMPOSITE_CORRECT, _COMPOSITE_TARGET, construction="hybrid")
        assert verdict["status"] == "pass", verdict["reason"]

    def test_a_decorative_classical_half_is_caught(self) -> None:
        """Round-trips perfectly. Only the prefix probe sees it."""
        verdict = _run(
            "signature", _COMPOSITE_CLASSICAL_IGNORED, _COMPOSITE_TARGET, construction="hybrid"
        )
        assert verdict["status"] == "fail", verdict
        assert "composite-roundtrip" in _passed(verdict)
        assert "composite-suffix-corrupted" in _passed(verdict)
        assert _failed(verdict) == {"composite-prefix-corrupted"}, verdict

    def test_a_decorative_pqc_half_is_caught(self) -> None:
        """The mirror image, caught by the other probe. Both are needed."""
        verdict = _run(
            "signature", _COMPOSITE_PQC_IGNORED, _COMPOSITE_TARGET, construction="hybrid"
        )
        assert verdict["status"] == "fail", verdict
        assert "composite-roundtrip" in _passed(verdict)
        assert "composite-prefix-corrupted" in _passed(verdict)
        assert _failed(verdict) == {"composite-suffix-corrupted"}, verdict

    def test_the_hybrid_target_does_not_resolve_to_the_pure_family(self) -> None:
        """`ML-DSA-65+ED25519` starts with `ML-DSA`, so dict-order matching would have sent it to
        the pure signature shape and silently verified only one half."""
        from qubit_migrate.oracles.shapes import shape_for

        assert shape_for(_COMPOSITE_TARGET).family == "composite_signature"
        assert shape_for("ML-DSA-65").family == "signature"

    def test_a_signature_too_short_to_have_two_halves_is_rejected(self) -> None:
        """The prefix and suffix probes must land on different bytes.

        Below 8 bytes `_corrupt(1)` and `_corrupt(len(SIG) - 2)` can be the same byte, so the two
        relations stop being independent and a decorative half goes unseen. A composite whose
        signature is 4 bytes is also, separately, not a composite of anything.
        """
        stub = _COMPOSITE_CORRECT.replace(
            "        return self._classical.sign(data) + self._pqc.sign(data)",
            '        return b"stub"',
        )
        verdict = _run("signature", stub, _COMPOSITE_TARGET, construction="hybrid")
        assert verdict["status"] == "fail", verdict
        assert "too short to probe halves" in verdict["reason"], verdict
