"""How to actually construct and call each primitive the oracle can exercise.

Every fact here was **probed against the installed library**, never taken from documentation,
because the traps below would each make the harness fail every CORRECT patch — or, worse, pass
every broken one:

1. ``pub.encapsulate()`` returns ``(shared_secret, ciphertext)`` — **secret first**. The intuitive
   ``(ct, ss)`` binding hands a 32-byte secret to ``decapsulate``, which raises
   ``Invalid ML-KEM-768 ciphertext``: every correct key-exchange migration fails, for a reason
   that has nothing to do with the patch.
2. ML-DSA ``verify`` **raises** ``InvalidSignature`` rather than returning ``False``. A relation
   written as ``verify(...) == False`` is vacuously true and passes for every patch, broken ones
   included.
3. ML-KEM rejection is **implicit**: a corrupted ciphertext returns a *different* shared secret
   rather than raising, though a wrong-*length* one does raise. A negative must accept either.
4. For AEAD, ``aad=None`` and ``aad=b""`` are **the same thing** — measured, ``decrypt`` succeeds
   across that pair. A "wrong associated data" negative built on it is unfailable.
5. Every AEAD rejection is ``InvalidTag``, including a wrong key and a wrong nonce. The exception
   type carries no information, so the relations must differ in what they *do*, not in what they
   catch.
6. A constant nonce is invisible to every other gate and to the scanner, but it is directly
   observable here: encrypting the SAME plaintext twice yields byte-identical ciphertext under a
   fixed nonce and different ciphertext under a fresh one. Measured both ways.

Probed 2026-09-02 against ``cryptography`` 49.0.0 inside ``qubit-eval/oracle:py312``. Re-probe on
a version bump; see the version floor in ``qubit-v2/10-repo-integration.md``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PrimitiveShape:
    """How to construct and exercise one primitive family.

    The fragments are Python source spliced into the generated harness, and they run in the
    **patched module's own namespace**, so the names they use are the names the patch imported.
    That is the whole point: a patch that imported the wrong module, named a class that does not
    exist, or asked for a parameter set the installed version lacks, fails here.
    """

    family: str
    #: Symbols the patch may name, most specific first. ``{compact}`` is the target algorithm with
    #: its separators stripped — ``ML-DSA-65`` becomes ``MLDSA65``. Several candidates because a
    #: hash migration may be written against ``hashlib`` or against ``cryptography``'s ``hashes``,
    #: and which one the patch chose is not knowable in advance.
    symbols: tuple[str, ...]
    #: Preamble that binds the names the ops fragments use. Runs after the symbol resolves, and its
    #: failure is reported as a construction failure rather than as a relation failure — those are
    #: different verdicts, and conflating them blames the patch for the harness's own limits.
    #:
    #: Generalised out of the template, which hardcoded ``priv``/``pub``/``other`` from
    #: ``.generate()``. That shape describes an asymmetric keypair and nothing else, so AEAD (a key
    #: and a nonce) and hashing (no key at all) could not be expressed at all.
    setup: str
    #: Fragments keyed by the relation id they serve.
    ops: dict[str, str]


#: Both asymmetric families share the keypair preamble. ``other`` is an INDEPENDENT key, and every
#: negative relation depends on it: without a second key there is nothing a wrong-key check can be
#: wrong with respect to.
_KEYPAIR_SETUP = """priv = KEY_CLASS.generate()
pub = priv.public_key()
other = KEY_CLASS.generate()"""


#: ML-DSA — FIPS 204 digital signatures.
_MLDSA = PrimitiveShape(
    family="signature",
    symbols=("{compact}PrivateKey",),
    setup=_KEYPAIR_SETUP,
    ops={
        # verify() returns None and raises InvalidSignature, so every negative asserts that an
        # exception WAS raised — never that a boolean came back False.
        "sig-roundtrip": "pub.verify(priv.sign(MSG), MSG)",
        "sig-wrong-key": "other.public_key().verify(priv.sign(MSG), MSG)",
        "sig-tampered-message": "pub.verify(priv.sign(MSG), MSG_TAMPERED)",
        "sig-truncated": "pub.verify(priv.sign(MSG)[:-1], MSG)",
        "sig-size-class": "len(priv.sign(MSG))",
    },
)

#: ML-KEM — FIPS 203 key encapsulation.
_MLKEM = PrimitiveShape(
    family="kex",
    symbols=("{compact}PrivateKey",),
    setup=_KEYPAIR_SETUP,
    ops={
        # NOTE THE ORDER. `encapsulate()` yields the SECRET first.
        "kem-agreement": "ss, ct = pub.encapsulate(); result = (priv.decapsulate(ct) == ss)",
        "kem-mismatched-keypair": (
            "ss, ct = pub.encapsulate(); result = (other.decapsulate(ct) != ss)"
        ),
        "kem-corrupted-ciphertext": (
            "ss, ct = pub.encapsulate(); "
            "flipped = bytearray(ct); flipped[0] ^= 1; "
            "result = (priv.decapsulate(bytes(flipped)) != ss)"
        ),
        "kem-secret-length": "len(pub.encapsulate()[0])",
    },
)

#: AEAD — authenticated encryption. Not post-quantum in the lattice sense; the migration here is
#: Grover-driven (AES-128 to AES-256) or unauthenticated-to-authenticated (CBC to GCM), and both
#: are ordinary outputs of this tool.
#:
#: ``generate_key`` is not uniform: AESGCM REQUIRES ``bit_length``, ChaCha20Poly1305 REFUSES it.
#: Probed, not assumed, and handled by asking rather than by branching on the class name.
_AEAD_SETUP = """def _fresh_key():
    try:
        return KEY_CLASS.generate_key(bit_length=256)
    except TypeError:
        return KEY_CLASS.generate_key()


aead = KEY_CLASS(_fresh_key())
other = KEY_CLASS(_fresh_key())
NONCE = b"qubit-nonce1"
AAD = b"qubit-associated-data"
AAD_OTHER = b"qubit-different-aad!!"
SEALED = aead.encrypt(NONCE, MSG, AAD)"""

_AEAD = PrimitiveShape(
    family="aead",
    symbols=("AESGCM", "AESCCM", "ChaCha20Poly1305", "AESOCB3", "AESSIV"),
    setup=_AEAD_SETUP,
    ops={
        "aead-roundtrip": "result = (aead.decrypt(NONCE, SEALED, AAD) == MSG)",
        # Every AEAD negative below assigns NOTHING to `result`, so the only way it can pass is by
        # RAISING. That is deliberate, and it is stronger than the inequality the negative block
        # also accepts.
        #
        # The inequality branch exists for ML-KEM, whose rejection is implicit — a corrupted
        # ciphertext legitimately returns a different secret rather than raising. Allowing it for
        # AEAD as well was a hole this suite found: an implementation that decrypts with a bare
        # CTR stream and slices the tag off unread returns GARBAGE for a flipped ciphertext, the
        # garbage is unequal to the plaintext, and the relation recorded a correct rejection. It
        # was measuring "the output changed", which a stream cipher does for free, instead of
        # "the tag was checked". Probed: every real rejection here raises InvalidTag.
        "aead-tampered-ciphertext": (
            "broken = bytearray(SEALED); broken[0] ^= 1; aead.decrypt(NONCE, bytes(broken), AAD)"
        ),
        "aead-truncated-tag": "aead.decrypt(NONCE, SEALED[:-1], AAD)",
        "aead-wrong-key": "other.decrypt(NONCE, SEALED, AAD)",
        # AAD_OTHER, never None or b"" — measured, those two are interchangeable and a relation
        # built on that pair cannot fail.
        "aead-tampered-aad": "aead.decrypt(NONCE, SEALED, AAD_OTHER)",
        # Nonce discipline. A fixed nonce is invisible to the scanner, to the parser, and to a
        # round-trip check — the ciphertext still decrypts perfectly. It shows up only as
        # determinism: same plaintext, same output. Measured True under a constant nonce, False
        # under a fresh one.
        "aead-nonce-uniqueness": (
            "import os as _os; "
            "a = aead.encrypt(_os.urandom(len(NONCE)), MSG, AAD); "
            "b = aead.encrypt(_os.urandom(len(NONCE)), MSG, AAD); "
            "result = (a != b)"
        ),
        "aead-ciphertext-expansion": "len(SEALED) - len(MSG)",
    },
)

#: Hashes. Grover halves preimage security, so the migration is to a LONGER digest — there is no
#: lattice here, and pretending otherwise is the most common misreading of PQC guidance.
#:
#: The patch may name ``hashlib.sha384`` or ``hashes.SHA384``. Both are handled by asking the
#: constructed object what it can do rather than by matching the symbol, because the patch's choice
#: of library is exactly the thing that is not knowable ahead of time.
_HASH_SETUP = """def DIGEST(data):
    obj = KEY_CLASS()
    if hasattr(obj, "update") and hasattr(obj, "digest"):
        obj.update(data)          # hashlib: sha384() returns a hash OBJECT
        return obj.digest()
    from cryptography.hazmat.primitives import hashes as _hashes

    ctx = _hashes.Hash(obj)       # cryptography: SHA384() is an ALGORITHM, not a context
    ctx.update(data)
    return ctx.finalize()


DIGEST_LEN = len(DIGEST(MSG))"""

_HASH = PrimitiveShape(
    family="hash",
    symbols=(
        "sha3_512",
        "sha3_384",
        "sha3_256",
        "sha512",
        "sha384",
        "sha256",
        "SHA3_512",
        "SHA3_384",
        "SHA3_256",
        "SHA512",
        "SHA384",
        "SHA256",
        "BLAKE2b",
        "blake2b",
    ),
    setup=_HASH_SETUP,
    ops={
        "hash-determinism": "result = (DIGEST(MSG) == DIGEST(MSG))",
        # A truncated digest is the defect that survives every other gate: it hashes, it is
        # deterministic, the scanner sees SHA-384 in the source, and the security is that of a
        # 128-bit hash. Only the length says so.
        # `__EXPECTED_DIGEST__` is substituted at build time, and the relation is DROPPED
        # when the size is unknown. It previously read just `DIGEST_LEN` -- a bare int, in a
        # block that only fails on `result is False`, so `result` stayed None and a truncated
        # digest PASSED the length check. The relation existed and measured nothing.
        "hash-digest-length": "result = (DIGEST_LEN >= __EXPECTED_DIGEST__)",
        # An implementation that ignores its input entirely — a stub, or a rewrite that hashes
        # a constant — passes determinism and passes length. It fails only this. A ONE-BYTE
        # difference, deliberately: a rewrite that hashes a prefix of its input is caught by
        # a near-identical pair and missed by two wildly different ones.
        "hash-distinct-inputs": "result = (DIGEST(MSG) != DIGEST(MSG_TAMPERED))",
    },
)


#: Composite / hybrid signatures. `cryptography` 49.0.0 ships NO composite primitive — probed, the
#: `composite` and `compositemldsa` modules do not exist — so a hybrid patch defines the
#: construction itself and its wire format is the patch's own choice.
#:
#: That rules out corrupting "the classical component" by name: the harness cannot know which bytes
#: those are. The relations are realised POSITIONALLY instead, and named for what they actually do.
#: Corrupting the signature's prefix and then its suffix covers both halves in whichever order the
#: patch encoded them, and together they establish that no contiguous region of the signature is
#: ignored — which is the property the regimes are asking for when they require hybrid.
#:
#: A composite that ignores one half is the most dangerous output this whole project can produce,
#: because it satisfies a hybrid mandate on paper and protects against nothing.
_COMPOSITE_SETUP = """try:
    priv = KEY_CLASS.generate()
except AttributeError:
    priv = KEY_CLASS()        # a patch-defined class need not follow the library convention
pub = priv.public_key()
SIG = priv.sign(MSG)
if len(SIG) < 8:
    raise ValueError("composite signature is %d bytes; too short to probe halves" % len(SIG))


def _corrupt(index):
    broken = bytearray(SIG)
    broken[index] ^= 1
    return bytes(broken)"""

_COMPOSITE = PrimitiveShape(
    family="composite_signature",
    symbols=(
        "CompositeMLDSAPrivateKey",
        "CompositeSignaturePrivateKey",
        "CompositeSignature",
        "HybridSignature",
        "HybridSigner",
        "{compact}PrivateKey",
    ),
    setup=_COMPOSITE_SETUP,
    ops={
        "composite-roundtrip": "pub.verify(SIG, MSG)",
        # Both negatives assign nothing to `result`, so only an exception passes them — a composite
        # `verify` that returns False rather than raising still fails here, which is correct: the
        # relation is about rejection, and a caller that ignores a return value is the norm.
        "composite-prefix-corrupted": "pub.verify(_corrupt(1), MSG)",
        "composite-suffix-corrupted": "pub.verify(_corrupt(len(SIG) - 2), MSG)",
        "composite-size-class": "len(SIG)",
    },
)


#: Registry keyed by the prefix of the algorithm the rule targets.
SHAPES: dict[str, PrimitiveShape] = {
    "ML-DSA": _MLDSA,
    "MLDSA": _MLDSA,
    "ML-KEM": _MLKEM,
    "MLKEM": _MLKEM,
    "AES-256-GCM": _AEAD,
    "AES-256-CCM": _AEAD,
    "AES-GCM": _AEAD,
    "CHACHA20-POLY1305": _AEAD,
    "CHACHA20": _AEAD,
    "SHA3-512": _HASH,
    "SHA3-384": _HASH,
    "SHA3-256": _HASH,
    "SHA-512": _HASH,
    "SHA-384": _HASH,
    "SHA-256": _HASH,
    "SHA512": _HASH,
    "SHA384": _HASH,
    "SHA256": _HASH,
    "BLAKE2B": _HASH,
}

#: Expected sizes, used only by advisory invariants. A signature the size of an ECDSA one after a
#: claimed ML-DSA migration means the old path is still live.
EXPECTED_SIZES: dict[str, dict[str, int]] = {
    # (bytes) probed: ML-DSA-65 signature is 3309.
    "ML-DSA-44": {"signature_min": 2000},
    "ML-DSA-65": {"signature_min": 3000},
    "ML-DSA-87": {"signature_min": 4000},
    # ML-KEM shared secrets are 32 bytes at every parameter set.
    "ML-KEM-512": {"secret": 32},
    "ML-KEM-768": {"secret": 32},
    "ML-KEM-1024": {"secret": 32},
    # Probed digest lengths. The floor is the whole point of a Grover-driven migration: a truncated
    # SHA-384 is a 128-bit hash wearing a 192-bit name.
    "SHA-256": {"digest": 32},
    "SHA-384": {"digest": 48},
    "SHA-512": {"digest": 64},
    "SHA3-256": {"digest": 32},
    "SHA3-384": {"digest": 48},
    "SHA3-512": {"digest": 64},
    # AEAD expansion is the tag: 16 bytes for GCM, CCM at the default, ChaCha20-Poly1305 and OCB3.
    # A rewrite that expands by 0 has dropped authentication entirely.
    "AES-256-GCM": {"expansion": 16},
    "AES-GCM": {"expansion": 16},
    "CHACHA20-POLY1305": {"expansion": 16},
}


def shape_for(target_algorithm: str | None) -> PrimitiveShape | None:
    """The shape for a target like ``ML-DSA-65``, or None if unsupported.

    None is the honest answer for a primitive with no probed shape, and the caller must report
    `skipped`. Guessing an API here would produce a verdict about a call the harness invented
    rather than one the patch made.

    LONGEST prefix wins, so ``SHA3-256`` cannot be captured by a ``SHA`` entry — dict order is not
    load-bearing, which matters because a reordering during an unrelated edit would silently route
    every SHA-3 target to the SHA-2 shape.

    Composite targets are decided before the prefix table is consulted at all; see below.
    """
    if not target_algorithm:
        return None
    upper = target_algorithm.strip().upper()
    # Composite is decided STRUCTURALLY, before any prefix match. `ML-DSA-65+ED25519` starts with
    # `ML-DSA`, so a prefix table would route it to the pure signature shape and verify one half of
    # a two-half construction — reporting a hybrid as sound while the classical component went
    # entirely unexercised. Enumerating the pairs instead was tried and is a losing game: the
    # registry listed `ML-DSA-44+ED25519` and the first real target was `ML-DSA-65+ED25519`.
    if "+" in upper or "COMPOSITE" in upper or "HYBRID" in upper:
        return _COMPOSITE
    best: tuple[int, PrimitiveShape] | None = None
    for prefix, shape in SHAPES.items():
        if upper.startswith(prefix) and (best is None or len(prefix) > best[0]):
            best = (len(prefix), shape)
    return best[1] if best else None


def expected_size(target_algorithm: str | None, key: str) -> int | None:
    if not target_algorithm:
        return None
    return EXPECTED_SIZES.get(target_algorithm.strip().upper(), {}).get(key)
