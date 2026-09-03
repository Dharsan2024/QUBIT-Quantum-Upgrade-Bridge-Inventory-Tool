"""Admission controls: prove the oracle can fail before believing that it passed.

An oracle that reports `pass` for everything is indistinguishable from a working one by looking at
its output. The only way to tell them apart is to hand it something that MUST fail and check that
it does. Until that has happened, a `behaves: pass` is not evidence — it is an untested assertion,
and the whole point of the evidence ladder is to stop counting those.

This is not hypothetical. The failure mode has a specific shape here: if the container's
`cryptography` shadows what the patched module imports, or the harness resolves a class from the
library rather than from the patch, every relation exercises a correct library implementation and
passes regardless of what the model wrote. Nothing in the verdict would look wrong.

Two controls per family, both published:

* **negative control** — a correct migration. Must PASS. If it fails, the oracle is rejecting good
  patches and any acceptance rate measured with it is a floor on a broken instrument.
* **positive control** — a migration carrying a known defect that every OTHER gate accepts. Must
  FAIL, *and* must fail on the specific relations that are supposed to catch it. A positive control
  that fails for the wrong reason (an import error, a missing symbol) proves nothing: it would also
  "fail" if the oracle rejected everything.

The `caught_by` set is what makes the second check meaningful. Without it a control passes as long
as SOMETHING went wrong, which is satisfied by an oracle that is simply broken.

No Docker dependency here. The runner is injected, so these are ordinary data plus a comparison and
can be exercised without a container — which matters, because a control suite that only runs where
the thing it validates runs cannot be used to decide whether that thing may run.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

# --------------------------------------------------------------------------------- the fixtures

_SIG_CORRECT = """from cryptography.hazmat.primitives.asymmetric import mldsa


def make_key():
    return mldsa.MLDSA65PrivateKey.generate()
"""

#: Signs bytes of exactly the right length and verifies ANYTHING. Passes `parses`, `symbols`,
#: `compiles` and `rescan` — the scanner reads ML-DSA-65 straight out of the source — and passes
#: its own round-trip relation. Only the negatives see it.
_SIG_ACCEPTS_ANYTHING = """from cryptography.hazmat.primitives.asymmetric import mldsa


class _Public:
    def verify(self, signature, data):
        return None


class MLDSA65PrivateKey:
    @classmethod
    def generate(cls):
        return cls()

    def public_key(self):
        return _Public()

    def sign(self, data):
        return b"x" * 3309


mldsa.MLDSA65PrivateKey = MLDSA65PrivateKey


def make_key():
    return mldsa.MLDSA65PrivateKey.generate()
"""

_KEX_CORRECT = """from cryptography.hazmat.primitives.asymmetric import mlkem


def make_key():
    return mlkem.MLKEM768PrivateKey.generate()
"""

#: `decapsulate` returns a constant, so the two sides always "agree". The agreement relation passes.
_KEX_CONSTANT_AGREEMENT = """import os

from cryptography.hazmat.primitives.asymmetric import mlkem

_CONSTANT = b"\\x00" * 32


class MLKEM768PrivateKey:
    @classmethod
    def generate(cls):
        return cls()

    def public_key(self):
        return _Public()

    def decapsulate(self, ciphertext):
        return _CONSTANT


class _Public:
    def encapsulate(self):
        return _CONSTANT, os.urandom(1088)


mlkem.MLKEM768PrivateKey = MLKEM768PrivateKey


def make_key():
    return mlkem.MLKEM768PrivateKey.generate()
"""

_AEAD_CORRECT = """from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(key, nonce, data, aad):
    return AESGCM(key).encrypt(nonce, data, aad)
"""

#: Encrypts under real GCM, decrypts under bare CTR with the tag sliced off unread. Round-trips
#: perfectly; authenticates nothing.
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
        counter = modes.CTR(nonce + b"\\x00\\x00\\x00\\x02")
        dec = Cipher(algorithms.AES(self._key), counter).decryptor()
        return dec.update(data[:-16]) + dec.finalize()
"""

_HASH_CORRECT = """import hashlib


def fingerprint(data):
    return hashlib.sha384(data).hexdigest()
"""

#: 16 bytes under a SHA-384 name. Deterministic, input-sensitive, and a 128-bit hash.
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

#: Signs with both halves, verifies only the PQC one. Satisfies a hybrid mandate on paper and
#: protects against nothing that hybrid exists to protect against.
_COMPOSITE_CLASSICAL_IGNORED = _COMPOSITE_CORRECT.replace(
    "        self._classical.verify(signature[:64], data)\n", ""
)


# ---------------------------------------------------------------------------------- the controls


@dataclass(frozen=True)
class Control:
    """One fixture the oracle must judge correctly before its verdicts count."""

    id: str
    family: str
    usage_context: str
    target: str
    source: str
    expect: Literal["pass", "fail"]
    construction: str = "pure"
    #: For a positive control, the relations that must be the ones reporting the failure.
    #:
    #: Without this a control is satisfied by an oracle that is simply broken: an import error, a
    #: missing symbol or a container that never starts all produce "fail", and a check that accepts
    #: any failure would call that a working oracle.
    caught_by: frozenset[str] = frozenset()
    #: Relations that must still PASS, proving the defect is invisible to them. This is the claim
    #: the whole project rests on, so it is asserted rather than assumed.
    survives: frozenset[str] = frozenset()
    rationale: str = ""


CONTROLS: tuple[Control, ...] = (
    Control(
        id="signature-negative",
        family="signature",
        usage_context="signature",
        target="ML-DSA-65",
        source=_SIG_CORRECT,
        expect="pass",
        rationale="A correct ML-DSA migration. If this fails, the oracle rejects good patches.",
    ),
    Control(
        id="signature-positive",
        family="signature",
        usage_context="signature",
        target="ML-DSA-65",
        source=_SIG_ACCEPTS_ANYTHING,
        expect="fail",
        caught_by=frozenset({"sig-wrong-key", "sig-tampered-message", "sig-truncated"}),
        survives=frozenset({"sig-roundtrip"}),
        rationale=(
            "Verifies anything, and signs 3309 bytes so even the size advisory reads correct. "
            "Passes every other gate in the pipeline."
        ),
    ),
    Control(
        id="kex-negative",
        family="kex",
        usage_context="kex",
        target="ML-KEM-768",
        source=_KEX_CORRECT,
        expect="pass",
        rationale="A correct ML-KEM migration.",
    ),
    Control(
        id="kex-positive",
        family="kex",
        usage_context="kex",
        target="ML-KEM-768",
        source=_KEX_CONSTANT_AGREEMENT,
        expect="fail",
        caught_by=frozenset({"kem-mismatched-keypair", "kem-corrupted-ciphertext"}),
        survives=frozenset({"kem-agreement"}),
        rationale="A constant shared secret makes both sides agree, so agreement proves nothing.",
    ),
    Control(
        id="aead-negative",
        family="aead",
        usage_context="aead",
        target="AES-256-GCM",
        source=_AEAD_CORRECT,
        expect="pass",
        rationale="A correct AES-256-GCM migration.",
    ),
    Control(
        id="aead-positive",
        family="aead",
        usage_context="aead",
        target="AES-256-GCM",
        source=_AEAD_NO_TAG_CHECK,
        expect="fail",
        caught_by=frozenset({"aead-tampered-ciphertext"}),
        survives=frozenset({"aead-roundtrip"}),
        rationale="Decrypts under bare CTR with the tag discarded. Authenticates nothing.",
    ),
    Control(
        id="hash-negative",
        family="hash",
        usage_context="hash",
        target="SHA-384",
        source=_HASH_CORRECT,
        expect="pass",
        rationale="A correct digest-widening migration.",
    ),
    Control(
        id="hash-positive",
        family="hash",
        usage_context="hash",
        target="SHA-384",
        source=_HASH_TRUNCATED,
        expect="fail",
        caught_by=frozenset({"hash-digest-length"}),
        survives=frozenset({"hash-determinism", "hash-distinct-inputs"}),
        rationale="16 bytes under a SHA-384 name. Only the length relation can see it.",
    ),
    Control(
        id="composite-negative",
        family="composite_signature",
        usage_context="signature",
        construction="hybrid",
        target="ML-DSA-65+ED25519",
        source=_COMPOSITE_CORRECT,
        expect="pass",
        rationale="A real composite: signs with both halves and verifies both.",
    ),
    Control(
        id="composite-positive",
        family="composite_signature",
        usage_context="signature",
        construction="hybrid",
        target="ML-DSA-65+ED25519",
        source=_COMPOSITE_CLASSICAL_IGNORED,
        expect="fail",
        caught_by=frozenset({"composite-prefix-corrupted"}),
        survives=frozenset({"composite-roundtrip", "composite-suffix-corrupted"}),
        rationale="The classical half is decorative — compliant on paper, protecting nothing.",
    ),
)

#: Every family the oracle can award evidence for. A family absent here has no controls, and
#: therefore no basis on which its verdicts should be believed.
CONTROLLED_FAMILIES: frozenset[str] = frozenset(c.family for c in CONTROLS)


# --------------------------------------------------------------------------------- evaluating it


@dataclass(frozen=True)
class ControlOutcome:
    control: Control
    ok: bool
    detail: str
    status: str = ""
    #: Relation ids that reported `fail`, for the published artifact.
    failed_relations: frozenset[str] = frozenset()


@dataclass
class ControlReport:
    """What the controls established, per family."""

    outcomes: list[ControlOutcome] = field(default_factory=list)

    def trustworthy(self, family: str) -> bool:
        """Did BOTH controls for `family` behave? Absent controls mean no, never yes."""
        seen = [o for o in self.outcomes if o.control.family == family]
        return len(seen) >= 2 and all(o.ok for o in seen)

    @property
    def families(self) -> frozenset[str]:
        return frozenset(
            o.control.family for o in self.outcomes if self.trustworthy(o.control.family)
        )

    def as_dict(self) -> dict[str, Any]:
        """The published artifact. Without this, every `behaves` number is unfalsifiable."""
        return {
            "controls": [
                {
                    "id": o.control.id,
                    "family": o.control.family,
                    "expected": o.control.expect,
                    "observed": o.status,
                    "ok": o.ok,
                    "detail": o.detail,
                    "failed_relations": sorted(o.failed_relations),
                    "rationale": o.control.rationale,
                }
                for o in self.outcomes
            ],
            "trustworthy_families": sorted(self.families),
        }


def evaluate(control: Control, verdict: Mapping[str, Any]) -> ControlOutcome:
    """Judge one harness verdict against what the control demanded.

    `skipped` is never acceptable for either direction. A control that did not run establishes
    nothing, and the entire purpose of this module is to refuse to treat "did not run" as evidence.
    """
    status = str(verdict.get("status", "skipped"))
    relations = verdict.get("relations") or []
    failed = frozenset(str(r.get("id")) for r in relations if str(r.get("outcome")) == "fail")
    passed = frozenset(str(r.get("id")) for r in relations if str(r.get("outcome")) == "pass")

    def out(ok: bool, detail: str) -> ControlOutcome:
        return ControlOutcome(control, ok, detail, status, failed)

    if status == "skipped":
        return out(False, f"the oracle did not run: {verdict.get('reason', '')}"[:400])

    if status != control.expect:
        return out(
            False,
            f"expected {control.expect}, observed {status}: {verdict.get('reason', '')}"[:400],
        )

    if control.expect == "pass":
        return out(True, f"{len(passed)} relations held")

    # A positive control must fail for the RIGHT reason. Any failure would otherwise satisfy it,
    # including an oracle so broken that it rejects everything — which is the second way to get a
    # meaningless measurement, and the harder one to notice.
    missing = control.caught_by - failed
    if missing:
        return out(
            False,
            f"failed, but not on the relations that are supposed to catch this defect: "
            f"{sorted(control.caught_by)} expected, {sorted(failed)} observed",
        )
    # And the defect must genuinely be invisible to the weaker relations, or the claim that the
    # negatives are load-bearing is not supported by this fixture.
    leaked = control.survives - passed
    if leaked:
        return out(
            False,
            f"the defect was also caught by {sorted(leaked)}, which was supposed to pass — this "
            "fixture no longer demonstrates that the negative relations are load-bearing",
        )
    return out(True, f"caught by {sorted(failed)}, invisible to {sorted(control.survives)}")


#: `(source, target, usage_context, construction) -> verdict mapping`.
Runner = Callable[[str, str, str, str], Mapping[str, Any]]


def run_controls(runner: Runner, families: frozenset[str] | None = None) -> ControlReport:
    """Run every control (or just those for `families`) through `runner`."""
    report = ControlReport()
    for control in CONTROLS:
        if families is not None and control.family not in families:
            continue
        try:
            verdict = runner(
                control.source, control.target, control.usage_context, control.construction
            )
        except Exception as exc:
            report.outcomes.append(
                ControlOutcome(control, False, f"{type(exc).__name__}: {exc}"[:400])
            )
            continue
        report.outcomes.append(evaluate(control, verdict))
    return report
