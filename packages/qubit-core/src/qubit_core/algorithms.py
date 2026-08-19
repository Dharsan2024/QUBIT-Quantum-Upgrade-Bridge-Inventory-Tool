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
        # "rsassa-pkcs1-v1_5" / "rsa-oaep" / "rsa-pss" are WebCrypto's algorithm names; they name
        # a padding scheme, not a key size, so they land on the bare-RSA verdict via the family
        # fallback rather than here. Only genuinely 2048-bit spellings belong on this entry.
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
        aliases=(
            "ecdsa",
            "prime256v1",
            "secp256r1",
            "p-256",
            "p256",
            "es256",
            "ecdsa-sha2-nistp256",  # OpenSSH HostKeyAlgorithms spelling
        ),
    ),
    _shor(
        canonical="ECDSA-P384",
        family="ECDSA",
        kind="asymmetric",
        key_size=384,
        aliases=("secp384r1", "p-384", "p384", "es384", "ecdsa-sha2-nistp384"),
    ),
    _shor(
        # JOSE ES512 means P-521 (not P-512/P-384) — the curve is named for its ~521-bit prime
        # field while the "512" in ES512 refers to the paired SHA-512 hash. Easy to get wrong.
        canonical="ECDSA-P521",
        family="ECDSA",
        kind="asymmetric",
        key_size=521,
        aliases=("secp521r1", "p-521", "p521", "es512", "ecdsa-sha2-nistp521"),
    ),
    _shor(
        canonical="ECDH-P256",
        family="ECDH",
        kind="asymmetric",
        key_size=256,
        # `ecdh-sha2-nistp256` is the SSH KEX spelling (RFC 5656). Without it a hardened
        # sshd_config resolved to UNKNOWN(...) and inherited a not-vulnerable verdict.
        aliases=("ecdh", "ecdhe", "ecdh-sha2-nistp256", "ecdhsha2nistp256"),
    ),
    _shor(
        canonical="X25519",
        family="ECDH",
        kind="asymmetric",
        key_size=256,
        # `curve25519-sha256` / `sntrup761x25519-sha512` are OpenSSH KexAlgorithms names.
        aliases=("curve25519", "x25519", "curve25519-sha256"),
    ),
    _shor(
        canonical="Ed25519",
        family="EdDSA",
        kind="asymmetric",
        key_size=256,
        aliases=("ed25519", "eddsa", "ssh-ed25519"),
    ),
    _shor(
        canonical="DH-2048",
        family="DH",
        kind="asymmetric",
        key_size=2048,
        # Deliberately NOT aliased to bare "dh"/"diffie-hellman": a size-less name must not silently
        # claim 2048 bits. Bare DH resolves via _BARE_FAMILY below, which keeps the Shor verdict
        # without inventing a key size.
        aliases=("dh2048",),
    ),
    _shor(canonical="DH-1024", family="DH", kind="asymmetric", key_size=1024, aliases=("dh1024",)),
    _shor(canonical="DH-3072", family="DH", kind="asymmetric", key_size=3072, aliases=("dh3072",)),
    _shor(canonical="DH-4096", family="DH", kind="asymmetric", key_size=4096, aliases=("dh4096",)),
    # DSA is Shor-broken at every size. Sizes are listed so a keygen call that DOES name one keeps
    # the precise identity instead of collapsing to the bare family.
    _shor(
        canonical="DSA-1024", family="DSA", kind="asymmetric", key_size=1024, aliases=("dsa1024",)
    ),
    _shor(
        canonical="DSA-2048", family="DSA", kind="asymmetric", key_size=2048, aliases=("dsa2048",)
    ),
    _shor(
        canonical="DSA-3072", family="DSA", kind="asymmetric", key_size=3072, aliases=("dsa3072",)
    ),
    _shor(canonical="RSA-512", family="RSA", kind="asymmetric", key_size=512, aliases=("rsa512",)),
    _shor(
        canonical="RSA-8192", family="RSA", kind="asymmetric", key_size=8192, aliases=("rsa8192",)
    ),
    # secp256k1 (Bitcoin/Ethereum) and the remaining standard curves. Shor breaks all of them.
    _shor(
        canonical="ECDSA-secp256k1",
        family="ECDSA",
        kind="asymmetric",
        key_size=256,
        aliases=("secp256k1", "p256k1"),
    ),
    _shor(canonical="X448", family="ECDH", kind="asymmetric", key_size=448, aliases=("x448",)),
    _shor(canonical="Ed448", family="EdDSA", kind="asymmetric", key_size=448, aliases=("ed448",)),
    _shor(
        canonical="ECDH-P384",
        family="ECDH",
        kind="asymmetric",
        key_size=384,
        aliases=("ecdhp384", "ecdh-sha2-nistp384", "ecdhsha2nistp384"),
    ),
    _shor(
        canonical="ECDH-P521",
        family="ECDH",
        kind="asymmetric",
        key_size=521,
        aliases=("ecdhp521", "ecdh-sha2-nistp521", "ecdhsha2nistp521"),
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
        # "ede" is Encrypt-Decrypt-Encrypt, not a cipher mode, so mode-stripping alone cannot reduce
        # node-forge's "3DES-EDE-CBC" or JCA's "DESede" to a known name — without these aliases real
        # 3DES usage resolved to UNKNOWN(...) and inherited a NOT-vulnerable verdict.
        aliases=("3des", "des-ede3", "tripledes", "des3", "desede", "3desede", "desede3"),
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
        aliases=("chacha20poly1305", "chacha20-poly1305", "xchacha20poly1305"),
    ),
    # Bare ChaCha20 / Salsa20 stream ciphers (256-bit keys, so also quantum-safe on their own).
    _safe(
        canonical="ChaCha20", family="ChaCha20", kind="symmetric", key_size=256, aliases=("chacha",)
    ),
    _safe(
        canonical="Salsa20", family="Salsa20", kind="symmetric", key_size=256, aliases=("salsa20",)
    ),
    _safe(
        canonical="Twofish", family="Twofish", kind="symmetric", key_size=256, aliases=("twofish",)
    ),
    _safe(
        canonical="Camellia-256",
        family="Camellia",
        kind="symmetric",
        key_size=256,
        aliases=("camellia256",),
    ),
    # --- Legacy 64-bit-block / short-key ciphers. Grover-relevant, and additionally weak for
    # classical reasons this registry deliberately does not judge. ---
    _grover(
        canonical="Camellia-128",
        family="Camellia",
        kind="symmetric",
        key_size=128,
        aliases=("camellia", "camellia128"),
    ),
    _grover(
        canonical="CAST5", family="CAST5", kind="symmetric", key_size=128, aliases=("cast5", "cast")
    ),
    _grover(canonical="IDEA", family="IDEA", kind="symmetric", key_size=128, aliases=("idea",)),
    _grover(canonical="SEED", family="SEED", kind="symmetric", key_size=128, aliases=("seed",)),
    _grover(canonical="RC2", family="RC2", kind="symmetric", key_size=128, aliases=("rc2",)),
    _grover(canonical="TEA", family="TEA", kind="symmetric", key_size=128, aliases=("tea", "xtea")),
    # --- JOSE/JWT HMAC algs (RFC 7518) — symmetric-keyed MAC, so never Shor-broken. ---
    # The `hmac-sha*` spellings also cover OpenSSH's MACs directive.
    #
    # These are QUANTUM-SAFE, and were previously flagged `grover`, which was inconsistent with the
    # rest of this registry and actively harmful. This file's own rule is that Grover halves
    # symmetric strength and what matters is whether >=128 bits survive: that is exactly why
    # AES-256 and SHA-256 are `_safe` here while AES-128 and SHA-224 are flagged. HMAC-SHA-256 with
    # a 256-bit key leaves 128 bits under Grover, and HMAC is strictly stronger than the bare hash
    # it is built on — so rating HS256 vulnerable while rating SHA-256 safe contradicted itself.
    #
    # The practical damage was worse than a cosmetic mislabel: HMAC was reported as a finding that
    # no migration could ever clear, because every HMAC variant in the registry — HS512 included —
    # was vulnerable. There was no safe target to migrate TO, so those assets were permanently
    # un-remediable. CNSA 2.0 approves HMAC-SHA-384; NIST treats HMAC-SHA-2 as post-quantum
    # adequate.
    #
    # A short or guessable HMAC key is a real problem, but it is a classical key-management one that
    # an algorithm registry cannot see and must not imply a quantum verdict about.
    _safe(
        canonical="HS256",
        family="HMAC",
        kind="mac",
        aliases=("hs256", "hmac-sha256", "hmac-sha2-256"),
    ),
    _safe(
        canonical="HS384",
        family="HMAC",
        kind="mac",
        aliases=("hs384", "hmac-sha384", "hmac-sha2-384"),
    ),
    _safe(
        canonical="HS512",
        family="HMAC",
        kind="mac",
        aliases=("hs512", "hmac-sha512", "hmac-sha2-512"),
    ),
    # hmac-sha1 / hmac-md5 are OpenSSH MACs built on broken hashes — flagged, not silently allowed.
    _grover(canonical="HMAC-SHA1", family="HMAC", kind="mac", aliases=("hmac-sha1", "hmacsha1")),
    _grover(canonical="HMAC-MD5", family="HMAC", kind="mac", aliases=("hmac-md5", "hmacmd5")),
    # --- Hashes ---
    _safe(canonical="SHA-256", family="SHA-2", kind="hash", aliases=("sha256", "sha-256")),
    _safe(canonical="SHA-384", family="SHA-2", kind="hash", aliases=("sha384",)),
    _safe(canonical="SHA-512", family="SHA-2", kind="hash", aliases=("sha512",)),
    _grover(canonical="SHA-1", family="SHA-1", kind="hash", aliases=("sha1", "sha-1")),
    _grover(canonical="MD5", family="MD5", kind="hash", aliases=("md5",)),
    # SHA-224 gives ~112-bit classical / ~56-bit Grover preimage margin: below the 128-bit bar the
    # SHA-256+ family clears, so it is flagged rather than treated as safe.
    _grover(canonical="SHA-224", family="SHA-2", kind="hash", aliases=("sha224",)),
    _grover(canonical="MD4", family="MD4", kind="hash", aliases=("md4",)),
    _grover(canonical="MD2", family="MD2", kind="hash", aliases=("md2",)),
    _grover(
        canonical="RIPEMD-160",
        family="RIPEMD",
        kind="hash",
        aliases=("ripemd160", "ripemd", "rmd160"),
    ),
    _safe(canonical="SHA-512/256", family="SHA-2", kind="hash", aliases=("sha512256",)),
    _safe(canonical="SHA3-224", family="SHA-3", kind="hash", aliases=("sha3224",)),
    # SHAKE is an XOF: security tracks the capacity, so SHAKE128 sits at the AES-128 tier.
    _grover(canonical="SHAKE128", family="SHA-3", kind="hash", aliases=("shake128",)),
    _safe(canonical="SHAKE256", family="SHA-3", kind="hash", aliases=("shake256",)),
    _safe(canonical="BLAKE2b", family="BLAKE2", kind="hash", aliases=("blake2b", "blake2")),
    _safe(canonical="BLAKE2s", family="BLAKE2", kind="hash", aliases=("blake2s",)),
    _safe(canonical="BLAKE3", family="BLAKE3", kind="hash", aliases=("blake3",)),
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
    _safe(canonical="HKDF", family="HKDF", kind="kdf", aliases=("hkdf", "hkdfexpand", "kbkdfhmac")),
    # X.509 is a certificate FORMAT, not an algorithm. It is registered so that "this code parses
    # certificates" is inventoried rather than reported as UNKNOWN(X.509) — the concrete key
    # algorithm inside a certificate is what the cert scanner reports separately.
    _safe(canonical="X.509", family="X.509", kind="protocol", aliases=("x509", "x.509")),
    # --- OpenSSH algorithm names (sshd_config Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms).
    # Without these, `ssh-rsa` and `diffie-hellman-group1-sha1` resolved to UNKNOWN(...) and
    # inherited a NOT-vulnerable verdict — genuinely weak SSH configuration reading as safe.
    # `@openssh.com`-suffixed names are handled by suffix stripping in resolve(). ---
    _shor(
        canonical="ssh-rsa",
        family="RSA",
        kind="asymmetric",
        # ssh-rsa specifically means RSA with a SHA-1 signature, deprecated by OpenSSH 8.8+ for that
        # reason. It must NOT absorb `rsa-sha2-256/512`, which are the recommended SHA-2 variants:
        # aliasing them together made a hardened sshd_config still report `ssh-rsa` present, so the
        # remediation looked like it had achieved nothing.
        aliases=("sshrsa",),
    ),
    _shor(
        canonical="rsa-sha2",
        family="RSA",
        kind="asymmetric",
        # Still RSA and therefore still Shor-breakable — the honest verdict — but not the
        # deprecated SHA-1 variant. The real fix for an SSH host key is Ed25519 today, and a
        # post-quantum signature once one is available for SSH.
        aliases=("rsa-sha2-256", "rsa-sha2-512", "rsasha2256", "rsasha2512"),
    ),
    _shor(
        canonical="ssh-dss",
        family="DSA",
        kind="asymmetric",
        key_size=1024,
        aliases=("sshdss", "ssh-dsa"),
    ),
    # Diffie-Hellman group numbers map to fixed modulus sizes (RFC 3526): group1 = 1024-bit, which
    # is the weakest thing OpenSSH will still negotiate, group14 = 2048, group16 = 4096.
    _shor(
        canonical="DH-1024-group1",
        family="DH",
        kind="asymmetric",
        key_size=1024,
        aliases=("diffiehellmangroup1sha1", "diffiehellmangroupexchangesha1"),
    ),
    _shor(
        canonical="DH-2048-group14",
        family="DH",
        kind="asymmetric",
        key_size=2048,
        aliases=("diffiehellmangroup14sha1", "diffiehellmangroup14sha256"),
    ),
    _shor(
        canonical="DH-4096-group16",
        family="DH",
        kind="asymmetric",
        key_size=4096,
        aliases=("diffiehellmangroup16sha512", "diffiehellmangroup18sha512"),
    ),
    _safe(canonical="ConcatKDF", family="ConcatKDF", kind="kdf", aliases=("concatkdf",)),
    _safe(canonical="X963KDF", family="X963KDF", kind="kdf", aliases=("x963kdf", "ansix963kdf")),
    # PBKDF1 is classically obsolete (single hash iteration family, no salt guarantees) but, like
    # every KDF here, is not broken by a quantum computer — `safe` is strictly the quantum verdict.
    _safe(canonical="PBKDF1", family="PBKDF1", kind="kdf", aliases=("pbkdf1",)),
    # --- MACs. Keyed and symmetric, so Grover-relevant like HMAC, never Shor-broken. ---
    _grover(canonical="CMAC", family="CMAC", kind="mac", aliases=("cmac", "aescmac")),
    _grover(canonical="GMAC", family="GMAC", kind="mac", aliases=("gmac",)),
    _grover(canonical="KMAC", family="KMAC", kind="mac", aliases=("kmac", "kmac128", "kmac256")),
    _safe(canonical="Poly1305", family="Poly1305", kind="mac", aliases=("poly1305",)),
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
    # Bare PQC family names, for APIs that do not name a parameter set at the call site
    # (Vault's `ml-dsa` key type, Go's crypto/mlkem, BouncyCastle's "ML-KEM" JCA name).
    _safe(canonical="ML-KEM", family="ML-KEM", kind="pqc-kem", aliases=("mlkem", "kyber")),
    _safe(canonical="ML-DSA", family="ML-DSA", kind="pqc-sig", aliases=("mldsa", "dilithium")),
    # Other PQC families. FN-DSA (Falcon) is FIPS-206 draft; the hash-based schemes are RFC/NIST
    # SP 800-208. All quantum-safe, so their presence is inventory evidence, never a risk.
    _safe(
        canonical="FN-DSA",
        family="FN-DSA",
        kind="pqc-sig",
        aliases=("falcon", "falcon512", "falcon1024", "fndsa"),
    ),
    _safe(canonical="XMSS", family="XMSS", kind="pqc-sig", aliases=("xmss", "xmssmt")),
    _safe(canonical="LMS", family="LMS", kind="pqc-sig", aliases=("lms", "hsslms")),
    _safe(canonical="HQC", family="HQC", kind="pqc-kem", aliases=("hqc",)),
    _safe(canonical="BIKE", family="BIKE", kind="pqc-kem", aliases=("bike",)),
    _safe(canonical="FrodoKEM", family="FrodoKEM", kind="pqc-kem", aliases=("frodokem", "frodo")),
    _safe(
        canonical="Classic-McEliece",
        family="Classic-McEliece",
        kind="pqc-kem",
        aliases=("classicmceliece", "mceliece"),
    ),
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
    _safe(
        canonical="SecP384r1MLKEM1024",
        family="hybrid-kem",
        kind="protocol",
        aliases=("secp384r1mlkem1024",),
    ),
    # OpenSSH's post-quantum hybrid key exchange (Streamlined NTRU Prime 761 + X25519), default
    # since OpenSSH 9.x. This is the algorithm the SSH hardening codemod WRITES, so leaving it
    # unresolvable meant a freshly hardened sshd_config reported its strongest algorithm as
    # UNKNOWN(...) — the remediation could not be verified as having landed on anything PQC.
    _safe(
        canonical="sntrup761x25519-sha512",
        family="hybrid-kem",
        kind="protocol",
        aliases=("sntrup761x25519sha512", "sntrup761x25519"),
    ),
    # OpenSSH 10's ML-KEM hybrid, for configurations that have moved to the standardized KEM.
    _safe(
        canonical="mlkem768x25519-sha256",
        family="hybrid-kem",
        kind="protocol",
        aliases=("mlkem768x25519sha256", "mlkem768x25519"),
    ),
    # `PSK` and `NULL` were already NAMED by the IANA suite-reduction tables (_SUITE_KEX /
    # _SUITE_CIPHERS) but never existed as entries, so every `TLS_PSK_*` and NULL-cipher suite
    # reduced to a name the registry could not resolve and came back as UNKNOWN(...).
    #
    # TLS-PSK carries no public-key key exchange, so there is nothing for Shor to factor — a
    # sufficiently long, secret pre-shared key is a genuine quantum-safe stopgap. That verdict
    # assumes the PSK's own entropy is adequate; a short or shared-by-default PSK is a classical
    # problem this registry does not judge.
    _safe(canonical="PSK", family="PSK", kind="symmetric", aliases=("psk", "tlspsk")),
    # A NULL cipher means the traffic is not encrypted at all. No quantum attack is involved — there
    # is nothing to break — but reporting it as "not vulnerable" would be badly misleading, since
    # plaintext on the wire is already harvested with no CRQC required. It therefore goes in the
    # same flagged bucket this registry already uses for classically-broken symmetric
    # primitives (MD5, RC4, DES): `vulnerable=True` with `grover` as the tiered-concern marker.
    _grover(canonical="NULL", family="NULL", kind="symmetric", aliases=("null", "enull")),
    # --- TLS/SSH protocol versions. `kind="protocol"` follows the hybrid-group precedent above.
    # These are emitted by the config and network scanners (`ssl_protocols TLSv1.2;`), which
    # previously produced UNKNOWN(TLSv1) with a not-vulnerable verdict — a deprecated protocol
    # reading as safe. The verdict here is the QUANTUM one: TLS 1.0/1.1 are additionally broken for
    # classical reasons (RC4/CBC padding oracles, SHA-1 signatures) and are marked vulnerable on
    # that basis too, since their mandatory cipher suites cannot be made post-quantum at all.
    _grover(
        canonical="TLSv1.0",
        family="TLS",
        kind="protocol",
        aliases=("tlsv1", "tls1", "tls10", "sslv3.1"),
    ),
    _grover(canonical="TLSv1.1", family="TLS", kind="protocol", aliases=("tlsv11", "tls11")),
    _grover(canonical="SSLv3", family="SSL", kind="protocol", aliases=("sslv3", "ssl3")),
    _grover(canonical="SSLv2", family="SSL", kind="protocol", aliases=("sslv2", "ssl2")),
    # TLS 1.2/1.3 are not themselves broken; whether a given handshake is quantum-safe depends on
    # the negotiated group, which the network scanner reports as its own separate asset.
    _safe(canonical="TLSv1.2", family="TLS", kind="protocol", aliases=("tlsv12", "tls12")),
    _safe(canonical="TLSv1.3", family="TLS", kind="protocol", aliases=("tlsv13", "tls13")),
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
    # WebCrypto names an RSA *padding scheme* rather than a key size ("RSASSA-PKCS1-v1_5",
    # "RSA-PSS", "RSA-OAEP"). The scheme does not change the Shor verdict, so each maps onto the
    # bare-RSA family entry instead of guessing a modulus size.
    "rsassapkcs1v15": CanonicalAlgorithm(
        "RSA", "RSA", "asymmetric", QuantumAttack.shor, vulnerable=True
    ),
    "rsapss": CanonicalAlgorithm("RSA", "RSA", "asymmetric", QuantumAttack.shor, vulnerable=True),
    "rsaoaep": CanonicalAlgorithm("RSA", "RSA", "asymmetric", QuantumAttack.shor, vulnerable=True),
    "hmac": CanonicalAlgorithm("HMAC", "HMAC", "mac", QuantumAttack.grover, vulnerable=True),
    "dh": CanonicalAlgorithm("DH", "DH", "asymmetric", QuantumAttack.shor, vulnerable=True),
    "diffiehellman": CanonicalAlgorithm(
        "DH", "DH", "asymmetric", QuantumAttack.shor, vulnerable=True
    ),
    # No bare "eddsa"/"ecdh" entries: both are already aliases in _BY_KEY, which resolves first
    # (to Ed25519 and ECDH-P256). Both targets carry the same Shor verdict a bare family would, so
    # only the reported curve name differs — precision, not safety.
    #
    # "ecdsa" IS listed, unlike those two, because `_x509_signature_component` needs a curve-less
    # target: `ecdsa-with-SHA384` names the signature algorithm without naming a curve, and
    # resolving it through _BY_KEY would report ECDSA-P256 — a specific curve the certificate never
    # claimed. This entry does not change `resolve("ecdsa")`, which still hits the _BY_KEY alias
    # (step 3) and returns ECDSA-P256 before the bare-family step is reached.
    "ecdsa": CanonicalAlgorithm(
        "ECDSA", "ECDSA", "asymmetric", QuantumAttack.shor, vulnerable=True
    ),
}
for _b in _BARE_FAMILY.values():
    _BY_CANONICAL.setdefault(_b.canonical, _b)

# Families whose canonical name is "<FAMILY>-<bits>", so an explicit key_size can parameterize a
# bare family name. Omitting a family here is NOT harmless: `resolve("DH", 1024)` skipped step 2,
# fell through to the alias table, and returned DH-2048 — reporting a weak 1024-bit Diffie-Hellman
# as a 2048-bit one, which is worse than returning nothing.
_SIZED_FAMILIES = {"rsa": "RSA", "aes": "AES", "dh": "DH", "dsa": "DSA", "camellia": "Camellia"}

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
        "kw",  # AES-KW / AES-KWP key wrapping (WebCrypto, JCA)
        "kwp",
        "poly1305",
    }
)

# Padding schemes that can trail a JCA transformation string. Like modes, a padding scheme carries
# no quantum-security meaning, so it is stripped when resolving.
_CIPHER_PADDINGS = frozenset(
    {
        "nopadding",
        "pkcs1padding",
        "pkcs5padding",
        "pkcs7padding",
        "oaeppadding",
        "iso10126padding",
        "zeropadding",
        "ansix923padding",
        "pkcs1",
        "oaep",
    }
)


def _normkey(name: str) -> str:
    return name.strip().lower().replace("-", "").replace("/", "").replace("_", "").replace(" ", "")


# Symmetric ciphers as they appear inside IANA TLS suite names, longest first so AES_256 wins over
# AES and CHACHA20_POLY1305 over CHACHA20.
_SUITE_CIPHERS: tuple[tuple[str, str], ...] = (
    ("chacha20_poly1305", "ChaCha20-Poly1305"),
    ("aes_256", "AES-256"),
    ("aes_128", "AES-128"),
    ("3des_ede", "3DES"),
    ("camellia_256", "Camellia-256"),
    ("camellia_128", "Camellia-128"),
    ("seed", "SEED"),
    ("rc4_128", "RC4"),
    ("des_cbc", "DES"),
    ("null", "NULL"),
)

# Key-exchange component of an IANA TLS 1.2-and-earlier suite name. This is the component that
# decides HNDL exposure: harvested traffic is decrypted by breaking the key exchange, so when a
# suite name has to collapse to ONE algorithm, the KEX is the honest choice.
_SUITE_KEX: tuple[tuple[str, str], ...] = (
    ("tls_ecdhe_ecdsa", "ECDH-P256"),
    ("tls_ecdhe_rsa", "ECDH-P256"),
    ("tls_ecdh_ecdsa", "ECDH-P256"),
    ("tls_ecdh_rsa", "ECDH-P256"),
    ("tls_dhe_rsa", "DH"),
    ("tls_dhe_dss", "DH"),
    ("tls_dh_anon", "DH"),
    ("tls_srp", "DH"),
    ("tls_psk", "PSK"),
    ("tls_rsa", "RSA"),
)


# Key-exchange prefixes in OpenSSL's *own* cipher-suite spelling, which is what nginx `ssl_ciphers`
# and Apache `SSLCipherSuite` actually contain — `ECDHE-RSA-AES128-GCM-SHA256`, not the IANA
# `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. Longest first so `ecdhe` wins over `ecdh`.
_OPENSSL_SUITE_KEX: tuple[tuple[str, str], ...] = (
    ("ecdhe-", "ECDH-P256"),
    ("aecdh-", "ECDH-P256"),
    ("ecdh-", "ECDH-P256"),
    ("dhe-", "DH"),
    ("edh-", "DH"),
    ("adh-", "DH"),
    ("srp-", "DH"),
    ("psk-", "PSK"),
    ("rsa-psk-", "RSA"),
    ("dhe-psk-", "DH"),
    ("ecdhe-psk-", "ECDH-P256"),
)

# MAC/PRF tokens that terminate an OpenSSL suite name. Their presence is what distinguishes a SUITE
# (`AES128-SHA`) from a plain cipher string (`aes-128-cbc`), which must keep resolving as a cipher.
_OPENSSL_SUITE_MACS = frozenset({"sha", "sha1", "sha256", "sha384", "md5", "poly1305"})


# X.509 signature-algorithm names (RFC 3279 / 4055 / 5758) as they appear in a certificate's
# `signatureAlgorithm` field and in Vault's PKI responses. The KEY algorithm is what Shor breaks —
# the hash half only bounds collision resistance — so each reduces to its key algorithm.
# "ecdsa" precedes "dsa" because "ecdsa" contains "dsa" and would otherwise match it.
_X509_SIG_KEY_ALGS: tuple[tuple[str, str], ...] = (
    ("ecdsa", "ECDSA"),
    ("rsassapss", "RSA"),
    ("rsaencryption", "RSA"),
    ("rsa", "RSA"),
    ("ed25519", "Ed25519"),
    ("ed448", "Ed448"),
    ("dsa", "DSA"),
)


def _x509_signature_component(name: str) -> CanonicalAlgorithm | None:
    """Reduce an X.509 signature-algorithm name to the key algorithm that governs its quantum risk.

    `sha256WithRSAEncryption` -> RSA, `ecdsa-with-SHA384` -> ECDSA, `rsassa-pss` -> RSA.

    Every one of these previously resolved to nothing, and `normalize()` rates an unresolved name as
    UNKNOWN **and not vulnerable** — so the signature algorithm of every RSA-signed certificate,
    including `sha1WithRSAEncryption` and `md5WithRSAEncryption`, was reported as quantum-safe. That
    is the exact silent-risk failure this registry exists to prevent, and it was reachable from two
    real sources: the certificate scanner and Vault's PKI mount.

    Worse, `ecdsa-with-SHA256` did not merely fall through — it ended in a hash token, so
    `_openssl_suite_component` mistook it for an OpenSSL cipher suite with no KEX prefix and
    returned **RSA**, confidently reporting an ECDSA certificate as RSA. This runs before that.

    Parsed structurally rather than by enumerating aliases: the name space is
    `<hash>With<KeyAlg>` or `<KeyAlg>-with-<hash>` across several RFCs, and a fixed alias list
    would keep missing members.
    """
    key = _normkey(name)
    if key == "rsassapss":  # RFC 4055 spells this one without a "with"
        return _BY_KEY.get("rsa") or _BARE_FAMILY.get("rsa")
    if "with" not in key:
        return None
    left, _, right = key.partition("with")
    # The key algorithm sits on whichever side is not the hash; check the right first, since
    # `<hash>With<KeyAlg>` is the more common spelling.
    for side in (right, left):
        for token, canonical in _X509_SIG_KEY_ALGS:
            if token in side:
                probe = _normkey(canonical)
                # Bare family FIRST here (the reverse of everywhere else): these names carry no key
                # size or curve, so the alias table's sized entry would invent one.
                return _BARE_FAMILY.get(probe) or _BY_KEY.get(probe)
    return None


def _openssl_suite_component(name: str) -> CanonicalAlgorithm | None:
    """Reduce an OpenSSL-spelled TLS cipher-suite name to the algorithm governing its quantum risk.

    Same principle as `_suite_component` for IANA names: harvested traffic is decrypted by breaking
    the KEY EXCHANGE, so a suite collapses to its KEX.

    The subtle and important case is a suite with NO kex prefix — `AES128-SHA`, `DES-CBC3-SHA`,
    `RC4-MD5`. In OpenSSL's naming those mean static **RSA key transport**, so they resolve to RSA.
    Those are the worst suites for harvest-now-decrypt-later precisely because they have no forward
    secrecy at all: one recovered RSA key opens every session ever recorded under it.

    Until this existed, every `ssl_ciphers` / `SSLCipherSuite` value in every real nginx and Apache
    config resolved to `UNKNOWN(...)`, and `normalize()` rates UNKNOWN as **not vulnerable** — so a
    server pinned to `ECDHE-RSA-AES128-SHA` was reported clean. This runs as a LATE fallback in
    `resolve()`, after ordinary cipher resolution, so `aes-128-cbc` and friends are untouched.
    """
    lowered = name.strip().lower()
    if "-" not in lowered:
        return None

    tokens = lowered.split("-")
    # Require a terminating MAC/PRF token: that is what makes this a suite rather than a cipher.
    if tokens[-1] not in _OPENSSL_SUITE_MACS:
        return None
    # "with" never appears in an OpenSSL suite name — that is the IANA spelling (`TLS_..._WITH_...`)
    # and, more importantly here, the X.509 signature-algorithm spelling. Without this guard the
    # static-RSA fallback below claimed `ecdsa-with-SHA256` was RSA, because it is hyphenated and
    # ends in a hash token. `_x509_signature_component` now resolves those names properly; this
    # keeps an unrecognized `*-with-*` name landing on a loud UNKNOWN rather than a wrong answer.
    if "with" in tokens:
        return None

    for prefix, kex in _OPENSSL_SUITE_KEX:
        if lowered.startswith(prefix):
            return _BY_KEY.get(_normkey(kex)) or _BARE_FAMILY.get(_normkey(kex))

    # An anonymous/PSK suite has no public-key kex to break; report the bulk cipher instead.
    if lowered.startswith(("anon-", "null-")):
        return _BY_KEY.get(_normkey("NULL"))

    # No kex prefix => static RSA key transport (no forward secrecy).
    return _BY_KEY.get(_normkey("RSA")) or _BARE_FAMILY.get(_normkey("RSA"))


def _suite_component(name: str) -> CanonicalAlgorithm | None:
    """Reduce an IANA TLS cipher-suite name to the one algorithm that governs its quantum risk.

    ``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`` -> ECDH (the key exchange), because breaking the key
    exchange is what lets a harvest-now-decrypt-later adversary read recorded traffic.
    ``TLS_AES_256_GCM_SHA384`` (a TLS 1.3 name) carries no key exchange at all — TLS 1.3 negotiates
    the group separately, and the network scanner reports that as its own asset — so the bulk
    cipher is reported instead.

    Returns None for anything that is not a suite name, leaving normal resolution to continue.
    """
    lowered = name.strip().lower()
    if not lowered.startswith("tls_"):
        return None

    for prefix, kex in _SUITE_KEX:
        if lowered.startswith(prefix + "_"):
            return _BY_KEY.get(_normkey(kex)) or _BARE_FAMILY.get(_normkey(kex))

    # No recognized KEX prefix => a TLS 1.3 suite; fall back to the bulk cipher.
    for token, cipher in _SUITE_CIPHERS:
        if token in lowered:
            return _BY_KEY.get(_normkey(cipher))
    return None


def resolve(name: str, key_size: int | None = None) -> CanonicalAlgorithm | None:
    """Resolve a raw algorithm name (+ optional key size) to a canonical entry, or None.

    Case/separator-insensitive; understands aliases; parameterizes by key size
    (``resolve("rsa", 4096) -> RSA-4096``; ``resolve("RSA/2048") -> RSA-2048``); and falls back to a
    Shor-vulnerable bare family entry for a size-less public-key name (``resolve("RSA") -> RSA``).
    """
    if not name:
        return None

    # OpenSSH qualifies vendor extensions with a domain: `aes256-gcm@openssh.com`,
    # `chacha20-poly1305@openssh.com`, `hmac-sha2-256-etm@openssh.com`. The suffix carries no
    # algorithm information, so it is dropped before anything else — otherwise every hardened
    # OpenSSH cipher resolved to UNKNOWN(...) and inherited a not-vulnerable verdict.
    name = name.split("@", 1)[0]
    # `-etm` (encrypt-then-MAC) is likewise a mode marker on OpenSSH MAC names.
    if name.lower().endswith("-etm"):
        name = name[: -len("-etm")]

    key = _normkey(name)

    # IANA / OpenSSH composite names describe a SUITE, not one algorithm. Reduce them to the single
    # component that governs harvest-now-decrypt-later risk (see _suite_component).
    suite = _suite_component(name)
    if suite is not None:
        return suite

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
    # Also strip trailing PADDING tokens, so a full JCA transformation string
    # ("DESede/CBC/PKCS5Padding") reduces the same way an OpenSSL cipher name does. Rules normally
    # pre-split these via `jca-transformation`, but any scanner source that hands resolve() a raw
    # transformation should not fall through to UNKNOWN and inherit a not-vulnerable verdict.
    while len(tokens) > 1 and (tokens[-1] in _CIPHER_MODES or tokens[-1] in _CIPHER_PADDINGS):
        tokens.pop()
        stem = _normkey("-".join(tokens))
        # Check the bare-family table too, not just the alias index: WebCrypto's "AES-GCM" and
        # "AES-CBC" name no key size, so they reduce to bare "aes", which lives in _BARE_FAMILY.
        stripped = _BY_KEY.get(stem) or _BARE_FAMILY.get(stem)
        if stripped is not None:
            return stripped

    # 5. bare public-key family with unknown size -> keep the Shor-vulnerable verdict
    bare = _BARE_FAMILY.get(key)
    if bare is not None:
        return bare

    # 6. X.509 signature-algorithm name (`sha256WithRSAEncryption`, `ecdsa-with-SHA384`). Must run
    #    BEFORE the suite fallback, which would otherwise mistake `ecdsa-with-SHA256` for a
    #    prefix-less OpenSSL suite and report it as static RSA.
    x509_sig = _x509_signature_component(name)
    if x509_sig is not None:
        return x509_sig

    # 7. OpenSSL-spelled cipher SUITE (`ECDHE-RSA-AES128-GCM-SHA256`). Deliberately last: it must
    #    never pre-empt a plain cipher string, only rescue a name that would otherwise be UNKNOWN.
    return _openssl_suite_component(name)


def get(canonical: str) -> CanonicalAlgorithm | None:
    """Fetch by exact canonical name."""
    return _BY_CANONICAL.get(canonical)


__all__ = ["ALGORITHMS", "CanonicalAlgorithm", "get", "resolve"]
