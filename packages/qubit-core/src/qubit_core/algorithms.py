"""Canonical algorithm registry — the single source of truth for algorithm identity and
quantum properties.

Detection rules only *name* algorithms; this registry decides their canonical name, family,
key size, and ``quantum_vulnerable`` verdict. Resolution is case- and separator-insensitive and
applies key size to parameterize families (``("rsa", 4096) -> RSA-4096``).

Data-driven: entries live in ``ALGORITHMS`` below (moved to YAML later if it grows). Keeping it in
Python for now keeps qubit-core dependency-light and import-fast.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .schemas import QuantumAttack, QuantumVulnerability


@dataclass(frozen=True)
class CanonicalAlgorithm:
    canonical: str
    family: str
    kind: str  # asymmetric | symmetric | hash | kdf | mac | pqc-kem | pqc-sig | protocol
    attack: QuantumAttack
    vulnerable: bool
    key_size: int | None = None
    oid: str | None = None
    aliases: tuple[str, ...] = ()
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None

    def quantum_vulnerable(self) -> QuantumVulnerability:
        return QuantumVulnerability(vulnerable=self.vulnerable, attack=self.attack)


def _shor(**kw: object) -> CanonicalAlgorithm:
    return CanonicalAlgorithm(attack=QuantumAttack.shor, vulnerable=True, **kw)  # type: ignore[arg-type]


def _safe(**kw: object) -> CanonicalAlgorithm:
    return CanonicalAlgorithm(attack=QuantumAttack.none, vulnerable=False, **kw)  # type: ignore[arg-type]


def _grover(**kw: object) -> CanonicalAlgorithm:
    # Grover only halves symmetric strength — a tiered concern, not an outright break.
    return CanonicalAlgorithm(attack=QuantumAttack.grover, vulnerable=True, **kw)  # type: ignore[arg-type]


# One entry per canonical algorithm. Parameterized families (RSA/ECDSA sizes) are resolved
# dynamically in resolve(); only representative anchors are listed explicitly.
ALGORITHMS: tuple[CanonicalAlgorithm, ...] = (
    # --- RSA (Shor-broken) ---
    _shor(
        canonical="RSA-2048",
        family="RSA",
        kind="asymmetric",
        key_size=2048,
        oid="1.2.840.113549.1.1.1",
        classical_security_level=112,
        aliases=("rsa2048", "rsa-2048", "rsa/2048"),
    ),
    _shor(
        canonical="RSA-3072",
        family="RSA",
        kind="asymmetric",
        key_size=3072,
        classical_security_level=128,
        aliases=("rsa3072",),
    ),
    _shor(
        canonical="RSA-4096",
        family="RSA",
        kind="asymmetric",
        key_size=4096,
        classical_security_level=152,
        aliases=("rsa4096",),
    ),
    _shor(
        canonical="RSA-1024",
        family="RSA",
        kind="asymmetric",
        key_size=1024,
        classical_security_level=80,
        aliases=("rsa1024",),
    ),
    # --- Elliptic curve (Shor-broken) ---
    _shor(
        canonical="ECDSA-P256",
        family="ECDSA",
        kind="asymmetric",
        key_size=256,
        classical_security_level=128,
        aliases=("ecdsa", "prime256v1", "secp256r1", "p-256", "p256"),
    ),
    _shor(
        canonical="ECDSA-P384",
        family="ECDSA",
        kind="asymmetric",
        key_size=384,
        aliases=("secp384r1", "p-384", "p384"),
    ),
    _shor(
        canonical="ECDH-P256",
        family="ECDH",
        kind="asymmetric",
        key_size=256,
        aliases=("ecdh", "ecdhe"),
    ),
    _shor(
        canonical="X25519",
        family="ECDH",
        kind="asymmetric",
        key_size=256,
        aliases=("curve25519", "x25519"),
    ),
    _shor(
        canonical="Ed25519", family="EdDSA", kind="asymmetric", key_size=256, aliases=("ed25519",)
    ),
    _shor(
        canonical="DH-2048",
        family="DH",
        kind="asymmetric",
        key_size=2048,
        aliases=("diffie-hellman", "dh"),
    ),
    # --- Symmetric (Grover / safe) ---
    _grover(
        canonical="AES-128",
        family="AES",
        kind="symmetric",
        key_size=128,
        aliases=("aes128", "aes-128", "aes/128"),
    ),
    _safe(
        canonical="AES-256",
        family="AES",
        kind="symmetric",
        key_size=256,
        aliases=("aes256", "aes-256"),
    ),
    _grover(
        canonical="3DES",
        family="3DES",
        kind="symmetric",
        key_size=112,
        aliases=("3des", "des-ede3", "tripledes", "des3"),
    ),
    _grover(canonical="DES", family="DES", kind="symmetric", key_size=56, aliases=("des",)),
    # --- Hashes ---
    _safe(canonical="SHA-256", family="SHA-2", kind="hash", aliases=("sha256", "sha-256")),
    _safe(canonical="SHA-384", family="SHA-2", kind="hash", aliases=("sha384",)),
    _safe(canonical="SHA-512", family="SHA-2", kind="hash", aliases=("sha512",)),
    _grover(canonical="SHA-1", family="SHA-1", kind="hash", aliases=("sha1", "sha-1")),
    _grover(canonical="MD5", family="MD5", kind="hash", aliases=("md5",)),
    # --- PQC targets (quantum-safe) ---
    _safe(
        canonical="ML-KEM-512",
        family="ML-KEM",
        kind="pqc-kem",
        nist_quantum_security_level=1,
        oid="2.16.840.1.101.3.4.4.1",
        aliases=("kyber512", "mlkem512"),
    ),
    _safe(
        canonical="ML-KEM-768",
        family="ML-KEM",
        kind="pqc-kem",
        nist_quantum_security_level=3,
        oid="2.16.840.1.101.3.4.4.2",
        aliases=("kyber768", "mlkem768", "kyber-768"),
    ),
    _safe(
        canonical="ML-KEM-1024",
        family="ML-KEM",
        kind="pqc-kem",
        nist_quantum_security_level=5,
        oid="2.16.840.1.101.3.4.4.3",
        aliases=("kyber1024", "mlkem1024"),
    ),
    _safe(
        canonical="ML-DSA-44",
        family="ML-DSA",
        kind="pqc-sig",
        nist_quantum_security_level=2,
        aliases=("dilithium2", "mldsa44"),
    ),
    _safe(
        canonical="ML-DSA-65",
        family="ML-DSA",
        kind="pqc-sig",
        nist_quantum_security_level=3,
        aliases=("dilithium3", "mldsa65", "dilithium-3"),
    ),
    _safe(
        canonical="ML-DSA-87",
        family="ML-DSA",
        kind="pqc-sig",
        nist_quantum_security_level=5,
        aliases=("dilithium5", "mldsa87"),
    ),
    _safe(canonical="SLH-DSA", family="SLH-DSA", kind="pqc-sig", aliases=("sphincs+", "sphincs")),
    # --- Hybrid TLS groups (safe: at least one PQC component) ---
    _safe(
        canonical="X25519MLKEM768",
        family="hybrid-kem",
        kind="protocol",
        aliases=("x25519mlkem768", "x25519kyber768"),
    ),
    _safe(
        canonical="SecP256r1MLKEM768",
        family="hybrid-kem",
        kind="protocol",
        aliases=("secp256r1mlkem768",),
    ),
)


# --- lookup indexes (built once at import) ---
_BY_CANONICAL: dict[str, CanonicalAlgorithm] = {a.canonical: a for a in ALGORITHMS}
_BY_KEY: dict[str, CanonicalAlgorithm] = {}
for _a in ALGORITHMS:
    _BY_KEY[
        _normkey_seed := _a.canonical.lower().replace("-", "").replace("/", "").replace("_", "")
    ] = _a
    for _alias in _a.aliases:
        _BY_KEY[_alias.lower().replace("-", "").replace("/", "").replace("_", "")] = _a

_RSA_SIZE_RE = re.compile(r"rsa[-_/ ]?(\d{3,5})")


def _normkey(name: str) -> str:
    return name.strip().lower().replace("-", "").replace("/", "").replace("_", "").replace(" ", "")


def resolve(name: str, key_size: int | None = None) -> CanonicalAlgorithm | None:
    """Resolve a raw algorithm name (+ optional key size) to a canonical entry, or None.

    Case/separator-insensitive; understands aliases; parameterizes RSA by key size
    (``resolve("rsa", 4096) -> RSA-4096``; ``resolve("RSA/2048") -> RSA-2048``).
    """
    if not name:
        return None
    key = _normkey(name)

    # exact canonical/alias hit
    hit = _BY_KEY.get(key)
    if hit is not None:
        return hit

    # RSA-family with size in the name
    m = _RSA_SIZE_RE.match(key)
    if m:
        return _BY_CANONICAL.get(f"RSA-{m.group(1)}")

    # bare family + explicit key size
    if key == "rsa" and key_size:
        return _BY_CANONICAL.get(f"RSA-{key_size}")
    if key in ("aes",) and key_size:
        return _BY_CANONICAL.get(f"AES-{key_size}")

    return None


def get(canonical: str) -> CanonicalAlgorithm | None:
    """Fetch by exact canonical name."""
    return _BY_CANONICAL.get(canonical)


__all__ = ["ALGORITHMS", "CanonicalAlgorithm", "get", "resolve"]
