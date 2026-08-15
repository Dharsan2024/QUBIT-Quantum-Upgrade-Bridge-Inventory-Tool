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
    # --- JOSE/JWT RSA signature algs (RFC 7518) — kept as their own canonical identities rather
    # than collapsed into bare "RSA": PSS vs PKCS1-v1.5 is a real, worth-preserving distinction in
    # CBOM output, and a JOSE `alg` header never carries a key size. Cross-verified against two
    # independent implementations (go-jose `shared.go`, golang-jwt `rsa.go`/`rsa_pss.go`). ---
    _shor(canonical="RS256", family="RSA", kind="asymmetric", aliases=("rs256",)),
    _shor(canonical="RS384", family="RSA", kind="asymmetric", aliases=("rs384",)),
    _shor(canonical="RS512", family="RSA", kind="asymmetric", aliases=("rs512",)),
    _shor(canonical="PS256", family="RSA", kind="asymmetric", aliases=("ps256",)),
    _shor(canonical="PS384", family="RSA", kind="asymmetric", aliases=("ps384",)),
    _shor(canonical="PS512", family="RSA", kind="asymmetric", aliases=("ps512",)),
    # --- Elliptic curve (Shor-broken) ---
    _shor(
        canonical="ECDSA-P256",
        family="ECDSA",
        kind="asymmetric",
        key_size=256,
        classical_security_level=128,
        aliases=("ecdsa", "prime256v1", "secp256r1", "p-256", "p256", "es256"),
    ),
    _shor(
        canonical="ECDSA-P384",
        family="ECDSA",
        kind="asymmetric",
        key_size=384,
        aliases=("secp384r1", "p-384", "p384", "es384"),
    ),
    _shor(
        # JOSE ES512 means P-521 (not P-512/P-384) — the curve is named for its ~521-bit prime
        # field while the "512" in ES512 refers to the paired SHA-512 hash. Easy to get wrong.
        canonical="ECDSA-P521",
        family="ECDSA",
        kind="asymmetric",
        key_size=521,
        aliases=("secp521r1", "p-521", "p521", "es512"),
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
        canonical="Ed25519",
        family="EdDSA",
        kind="asymmetric",
        key_size=256,
        aliases=("ed25519", "eddsa"),
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
    # AES-192 gives ~96-bit post-quantum security under Grover — below the 128-bit bar AES-256
    # clears, and CNSA 2.0 approves only AES-256, so it is flagged like AES-128 rather than treated
    # as safe. (Also emitted by the Vault connector for the `aes192-cmac` transit key type.)
    _grover(
        canonical="AES-192",
        family="AES",
        kind="symmetric",
        key_size=192,
        aliases=("aes192", "aes-192"),
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
    # --- Legacy / classically-broken symmetric (still found in real code, so still inventoried) ---
    _grover(canonical="RC4", family="RC4", kind="symmetric", aliases=("rc4", "arc4", "arcfour")),
    _grover(
        canonical="Blowfish",
        family="Blowfish",
        kind="symmetric",
        aliases=("blowfish", "bf"),
    ),
    # ChaCha20-Poly1305 uses a 256-bit key, so Grover leaves ~128-bit security: quantum-safe.
    _safe(
        canonical="ChaCha20-Poly1305",
        family="ChaCha20",
        kind="symmetric",
        key_size=256,
        aliases=("chacha20", "chacha20poly1305", "chacha20-poly1305"),
    ),
    # --- JOSE/JWT HMAC algs (RFC 7518) — symmetric-keyed MAC, Grover-only (not Shor-broken). ---
    _grover(canonical="HS256", family="HMAC", kind="mac", aliases=("hs256", "hmac-sha256")),
    _grover(canonical="HS384", family="HMAC", kind="mac", aliases=("hs384", "hmac-sha384")),
    _grover(canonical="HS512", family="HMAC", kind="mac", aliases=("hs512", "hmac-sha512")),
    # --- Hashes ---
    _safe(canonical="SHA-256", family="SHA-2", kind="hash", aliases=("sha256", "sha-256")),
    _safe(canonical="SHA-384", family="SHA-2", kind="hash", aliases=("sha384",)),
    _safe(canonical="SHA-512", family="SHA-2", kind="hash", aliases=("sha512",)),
    _grover(canonical="SHA-1", family="SHA-1", kind="hash", aliases=("sha1", "sha-1")),
    _grover(canonical="MD5", family="MD5", kind="hash", aliases=("md5",)),
    # --- SHA-3 (FIPS-202). These are the migration KB's recommended replacement for SHA-1/MD5, so
    # without them a *successfully migrated* asset re-scanned as UNKNOWN(SHA3-256) and the
    # remediation could not be verified as landing on something quantum-safe. ---
    _safe(canonical="SHA3-256", family="SHA-3", kind="hash", aliases=("sha3256", "sha3-256")),
    _safe(canonical="SHA3-384", family="SHA-3", kind="hash", aliases=("sha3384", "sha3-384")),
    _safe(canonical="SHA3-512", family="SHA-3", kind="hash", aliases=("sha3512", "sha3-512")),
    # --- Password KDFs. Not broken by a quantum computer (they are memory/CPU-hard, not
    # number-theoretic), so `safe` here means "no quantum break", NOT "well configured" — an
    # under-iterated PBKDF2 is a classical problem this registry deliberately does not judge. ---
    _safe(canonical="PBKDF2", family="PBKDF2", kind="kdf", aliases=("pbkdf2", "pbkdf2hmac")),
    _safe(canonical="scrypt", family="scrypt", kind="kdf", aliases=("scrypt",)),
    _safe(canonical="argon2id", family="Argon2", kind="kdf", aliases=("argon2", "argon2id")),
    _safe(canonical="bcrypt", family="bcrypt", kind="kdf", aliases=("bcrypt",)),
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

# Bare family names with no size. Public-key families are ALWAYS Shor-vulnerable regardless of key
# size, so a bare "RSA"/"EC"/"DSA" must keep that verdict rather than degrading to "unknown/safe".
# Kept OUT of _BY_KEY so exact/size resolution wins first; consulted only as a fallback.
#
# The symmetric/MAC entries matter just as much in practice: source code very often names an
# algorithm without its key size (`Cipher(algorithms.AES(key))`, a Vault `hmac` key type), and
# without a bare entry those resolved to nothing and were reported as `UNKNOWN(AES)` with a
# not-vulnerable verdict — i.e. real AES usage vanished from the inventory and looked safe. Bare
# symmetric families take the WEAKEST plausible verdict (AES -> Grover-relevant, as AES-128 would
# be) so an unsized name is never more optimistic than the sized one it might turn out to be.
_BARE_FAMILY: dict[str, CanonicalAlgorithm] = {
    "rsa": CanonicalAlgorithm("RSA", "RSA", "asymmetric", QuantumAttack.shor, vulnerable=True),
    "ec": CanonicalAlgorithm("EC", "EC", "asymmetric", QuantumAttack.shor, vulnerable=True),
    "dsa": CanonicalAlgorithm("DSA", "DSA", "asymmetric", QuantumAttack.shor, vulnerable=True),
    "aes": CanonicalAlgorithm("AES", "AES", "symmetric", QuantumAttack.grover, vulnerable=True),
    "hmac": CanonicalAlgorithm("HMAC", "HMAC", "mac", QuantumAttack.grover, vulnerable=True),
    # No bare "eddsa" entry: it is already an alias of Ed25519 in _BY_KEY, which resolves first.
}
for _b in _BARE_FAMILY.values():
    _BY_CANONICAL.setdefault(_b.canonical, _b)

_SIZED_FAMILIES = {"rsa": "RSA", "aes": "AES"}

# Block/stream cipher mode-of-operation suffixes used by OpenSSL and Node cipher strings. A mode
# says nothing about quantum security, so it is stripped when resolving (see resolve() step 4).
_CIPHER_MODES = frozenset(
    {
        "cbc",
        "ecb",
        "gcm",
        "ccm",
        "ctr",
        "ofb",
        "cfb",
        "cfb1",
        "cfb8",
        "xts",
        "ocb",
        "siv",
        "wrap",
        "poly1305",
    }
)


def _normkey(name: str) -> str:
    return name.strip().lower().replace("-", "").replace("/", "").replace("_", "").replace(" ", "")


def resolve(name: str, key_size: int | None = None) -> CanonicalAlgorithm | None:
    """Resolve a raw algorithm name (+ optional key size) to a canonical entry, or None.

    Case/separator-insensitive; understands aliases; parameterizes by key size
    (``resolve("rsa", 4096) -> RSA-4096``; ``resolve("RSA/2048") -> RSA-2048``); and falls back to a
    Shor-vulnerable bare family entry for a size-less public-key name (``resolve("RSA") -> RSA``).
    """
    if not name:
        return None
    key = _normkey(name)

    # 1. size embedded in the name, e.g. "RSA2048"
    m = _RSA_SIZE_RE.match(key)
    if m:
        sized = _BY_CANONICAL.get(f"RSA-{m.group(1)}")
        if sized is not None:
            return sized

    # 2. bare sized-family + explicit key size -> parameterized canonical (size wins over bare)
    if key_size and key in _SIZED_FAMILIES:
        sized = _BY_CANONICAL.get(f"{_SIZED_FAMILIES[key]}-{key_size}")
        if sized is not None:
            return sized

    # 3. exact canonical / alias hit
    hit = _BY_KEY.get(key)
    if hit is not None:
        return hit

    # 4. OpenSSL/Node-style "<alg>[-<size>]-<mode>" cipher strings, e.g. "aes-128-cbc",
    #    "des-ede3-cbc", "aes-256-gcm". Node's crypto module and OpenSSL name ciphers this way, so
    #    without this step real AES/3DES usage resolved to nothing and was reported as
    #    UNKNOWN(aes-128-cbc) with a not-vulnerable verdict. Modes carry no quantum-security
    #    meaning, so they are stripped from the right until something resolves; enumerating every
    #    alg x size x mode combination as an alias would be combinatorial and unmaintainable.
    tokens = name.strip().lower().replace("_", "-").replace("/", "-").split("-")
    while len(tokens) > 1 and tokens[-1] in _CIPHER_MODES:
        tokens.pop()
        stripped = _BY_KEY.get(_normkey("-".join(tokens)))
        if stripped is not None:
            return stripped

    # 5. bare public-key family with unknown size -> keep the Shor-vulnerable verdict
    return _BARE_FAMILY.get(key)


def get(canonical: str) -> CanonicalAlgorithm | None:
    """Fetch by exact canonical name."""
    return _BY_CANONICAL.get(canonical)


__all__ = ["ALGORITHMS", "CanonicalAlgorithm", "get", "resolve"]
