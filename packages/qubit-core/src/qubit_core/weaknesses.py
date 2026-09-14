"""Cryptographic weaknesses that are properties of a CALL, not of an algorithm name.

The algorithm registry answers "is this primitive broken?". It cannot answer "is this *use* of an
unbroken primitive broken?" - and in real code that second question accounts for a large share of
what commercial scanners report. AES-256 is a fine cipher; ``AES-256/ECB`` leaks the structure of
every plaintext it encrypts. RSA-3072 is a fine key; ``RSA/ECB/PKCS1Padding`` is
Bleichenbacher-attackable. PBKDF2 is an approved KDF; PBKDF2 at 1 000 iterations is a password
table waiting to be cracked offline.

Each weakness here is derived from facts the scanner captured at the call site
(``evidence.context.extra``: ``mode``, ``padding``, ``iterations``, ``prf``) rather than from the
algorithm name, carries the authority that says it is a weakness, and names its remedy. The
migration layer matches rules against these ids, so adding a weakness here is what makes it
migratable.

Sources are cited per entry and are all primary: NIST SP 800-38A (modes of operation), NIST
SP 800-56B rev.2 (RSA key establishment), FIPS 186-5 and RFC 8017 (signatures), NIST SP 800-131A
rev.3 (key-length transitions), and OWASP's Cryptographic Storage and Password Storage cheat
sheets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Symmetric block-cipher families for which ECB is a real weakness. Deliberately a list of
#: families rather than "kind == symmetric": JCA spells RSA as ``RSA/ECB/PKCS1Padding``, where
#: "ECB" is a naming artefact of the provider interface and not a mode of operation at all.
#: Reading that as an ECB finding would report a weakness that does not exist, on nearly every
#: Java RSA call site in existence.
BLOCK_CIPHER_FAMILIES = frozenset(
    {"AES", "DES", "3DES", "Blowfish", "CAST5", "IDEA", "SEED", "Camellia", "SM4", "RC2", "ARIA"}
)

#: OWASP Password Storage Cheat Sheet, PBKDF2 section: iteration floors by PRF, as published.
PBKDF2_FLOORS: dict[str, int] = {
    "SHA-1": 1_400_000,
    "SHA-256": 600_000,
    "SHA-512": 220_000,
}

#: Used when the PRF is not recoverable from the call. The LOWEST published floor, so an unknown
#: PRF can only ever be flagged when it is below every one of them - an under-report by design,
#: because a false "your KDF is too weak" costs the user trust in every other finding.
PBKDF2_FLOOR_UNKNOWN_PRF = min(PBKDF2_FLOORS.values())


@dataclass(frozen=True)
class Weakness:
    """One classical weakness found at a call site."""

    id: str
    title: str
    cwe: str
    #: The primary publication that says this is a weakness. Shown to the user with the finding.
    authority: str
    #: What to do about it, in one imperative sentence.
    remedy: str
    #: The facts that made the call: the observed mode, the iteration count, the floor applied.
    detail: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "cwe": self.cwe,
            "authority": self.authority,
            "remedy": self.remedy,
            "detail": self.detail,
        }


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalised_prf(raw: Any) -> str:
    """``sha1`` / ``SHA1`` / ``hmacSHA256`` -> ``SHA-1`` / ``SHA-256``; unknown -> ``""``."""
    text = str(raw or "").upper()
    for spelling, canonical in (
        ("SHA512", "SHA-512"),
        ("SHA-512", "SHA-512"),
        ("SHA384", "SHA-384"),
        ("SHA-384", "SHA-384"),
        ("SHA256", "SHA-256"),
        ("SHA-256", "SHA-256"),
        ("SHA224", "SHA-224"),
        ("SHA1", "SHA-1"),
        ("SHA-1", "SHA-1"),
        ("MD5", "MD5"),
    ):
        if spelling in text:
            return canonical
    return ""


def _ecb_mode(family: str | None, extra: dict[str, Any]) -> Weakness | None:
    if family not in BLOCK_CIPHER_FAMILIES:
        return None
    if str(extra.get("mode", "")).upper() != "ECB":
        return None
    return Weakness(
        id="ecb-mode",
        title="Block cipher used in ECB mode",
        cwe="CWE-327",
        authority=(
            "NIST SP 800-38A Appendix A; OWASP Cryptographic Storage Cheat Sheet "
            "(use authenticated encryption)"
        ),
        remedy=(
            "Encrypt with an AEAD mode - AES-256-GCM, or ChaCha20-Poly1305 where AES hardware "
            "acceleration is absent - generating a fresh nonce per message and storing it "
            "alongside the ciphertext."
        ),
        detail={"mode": "ECB", "family": family},
    )


def _cbc_unauthenticated(family: str | None, extra: dict[str, Any]) -> Weakness | None:
    """The CBC counterpart to `_ecb_mode`. Unauthenticated CBC provides no integrity --
    ciphertext can be truncated, reordered or bit-flipped undetected, padding-oracle territory --
    and is otherwise a sound cipher, differing from the ECB case in no field the registry reads.

    Distinct from `_ecb_mode`'s remedy: the fix here is the MODE, not necessarily the key, and a
    backward-compatible dual-path migration reusing the same key works exactly the way
    `code-ecb-01` already handles ECB. See `code-cbc-01.yaml`.
    """
    if family not in BLOCK_CIPHER_FAMILIES:
        return None
    if str(extra.get("mode", "")).upper() != "CBC":
        return None
    return Weakness(
        id="cbc-unauthenticated",
        title="Block cipher used in CBC mode without a MAC",
        cwe="CWE-327",
        authority=(
            "NIST SP 800-38A; OWASP Cryptographic Storage Cheat Sheet "
            "(use authenticated encryption)"
        ),
        remedy=(
            "Encrypt with an AEAD mode - AES-GCM, or ChaCha20-Poly1305 where AES hardware "
            "acceleration is absent - using the SAME key already in use, generating a fresh "
            "nonce per message and storing it with the ciphertext."
        ),
        detail={"mode": "CBC", "family": family},
    )


def _pkcs1v15(family: str | None, usage: str | None, extra: dict[str, Any]) -> Weakness | None:
    if family != "RSA":
        return None
    if str(extra.get("padding", "")).upper() != "PKCS1V15":
        return None
    signing = (usage or "").lower() in {"signature", "token"}
    return Weakness(
        id="pkcs1v15-padding",
        title=(
            "RSA signature with PKCS#1 v1.5 padding"
            if signing
            else "RSA encryption with PKCS#1 v1.5 padding"
        ),
        cwe="CWE-327" if signing else "CWE-780",
        authority=(
            "NIST SP 800-56B rev.2 (RSA-OAEP for key transport); RFC 8017 and FIPS 186-5 "
            "(RSASSA-PSS preferred over RSASSA-PKCS1-v1_5)"
        ),
        remedy=(
            "Sign with RSASSA-PSS while RSA remains in use, and plan the move to ML-DSA-65."
            if signing
            else "Encrypt with RSA-OAEP (SHA-256) while RSA remains in use, and plan the move "
            "to ML-KEM-768; PKCS#1 v1.5 decryption is Bleichenbacher-attackable."
        ),
        detail={"padding": "PKCS1v15", "operation": "signature" if signing else "encryption"},
    )


def _kdf_iterations(algorithm: str | None, extra: dict[str, Any]) -> Weakness | None:
    if (algorithm or "").upper().replace("-", "") not in {"PBKDF2", "PBKDF2HMAC"}:
        return None
    count = _int_or_none(extra.get("iterations"))
    if count is None:
        return None
    prf = _normalised_prf(extra.get("prf"))
    floor = PBKDF2_FLOORS.get(prf, PBKDF2_FLOOR_UNKNOWN_PRF)
    if count >= floor:
        return None
    return Weakness(
        id="kdf-iterations-below-floor",
        title=f"PBKDF2 at {count:,} iterations, below the published floor of {floor:,}",
        cwe="CWE-916",
        authority="OWASP Password Storage Cheat Sheet (PBKDF2 work factors); NIST SP 800-132",
        remedy=(
            f"Raise the iteration count to at least {floor:,} for this PRF, or move to Argon2id "
            "(m=19456 KiB, t=2, p=1), re-deriving each stored hash on its owner's next successful "
            "sign-in so existing credentials keep working."
        ),
        detail={"iterations": count, "floor": floor, "prf": prf or "unknown"},
    )


def _short_rsa(algorithm: str | None, key_size: int | None) -> Weakness | None:
    if (algorithm or "").upper().split("-")[0] != "RSA":
        return None
    if key_size is None or key_size >= 2048:
        return None
    return Weakness(
        id="rsa-key-too-short",
        title=f"RSA key of {key_size} bits, below the classical minimum of 2048",
        cwe="CWE-326",
        authority=(
            "NIST SP 800-131A rev.3 (RSA below 2048 bits disallowed); BSI TR-02102-1 "
            "(3000 bits recommended from 2026)"
        ),
        remedy=(
            "This key is breakable classically, before any quantum consideration. Re-key to at "
            "least RSA-3072 as an immediate stopgap and migrate the primitive to ML-KEM-768 or "
            "ML-DSA-65 according to its actual usage."
        ),
        detail={"key_size": key_size, "classical_minimum": 2048},
    )


#: What each spelling of a JWT verification bypass means, and what to do about it.
_JWT_BYPASS = {
    "signature-check-disabled": (
        "JWT signature verification is switched off",
        "Remove the option that disables verification and pass the key and an explicit "
        "`algorithms` list. A token whose signature is never checked is a token anyone can write.",
    ),
    "alg-none-accepted": (
        'JWT accepts the "none" algorithm',
        'Remove "none" from the accepted algorithms and pin the exact algorithm the issuer signs '
        "with. Accepting `none` lets an attacker strip the signature and be believed.",
    ),
    "decoded-without-verifying": (
        "JWT decoded without verifying the signature",
        "Use the verifying call (`jwt.verify`, not `jwt.decode`) with the key and an explicit "
        "`algorithms` list wherever the claims drive an authorization decision. `decode` reads "
        "the token and checks nothing.",
    ),
}


def _jwt_unverified(usage: str | None, extra: dict[str, Any]) -> Weakness | None:
    """A JWT read without its signature being checked - the classic authentication bypass.

    Not a quantum finding at all, and not one the algorithm registry can see: the algorithm named
    in the code may be perfectly good and simply never applied. It belongs here because it is a
    property of the CALL, and because a crypto scanner that reports the token algorithm while
    missing that nothing verifies it has reported the least important half.
    """
    kind = str(extra.get("jwt_verification") or "")
    entry = _JWT_BYPASS.get(kind)
    if entry is None:
        return None
    title, remedy = entry
    return Weakness(
        id="jwt-signature-not-verified",
        title=title,
        cwe="CWE-347",
        authority=(
            "RFC 8725 (JSON Web Token Best Current Practices) sections 3.1 and 3.2 - reject the "
            "`none` algorithm and pin the expected one; OWASP JWT guidance"
        ),
        remedy=remedy,
        detail={"bypass": kind, "usage": usage or "token"},
    )


def derive(
    *,
    algorithm: str | None,
    family: str | None,
    key_size: int | None,
    usage_context: str | None,
    extra: dict[str, Any] | None,
) -> list[Weakness]:
    """Every classical weakness implied by this finding's captured facts.

    Order is stable (declaration order) so a report does not reshuffle between runs.
    """
    facts = extra or {}
    found = [
        _ecb_mode(family, facts),
        _cbc_unauthenticated(family, facts),
        _pkcs1v15(family, usage_context, facts),
        _kdf_iterations(algorithm, facts),
        _short_rsa(algorithm, key_size),
        _jwt_unverified(usage_context, facts),
    ]
    return [w for w in found if w is not None]


#: Every weakness id this module can produce. Migration rules match on these, and a rule naming an
#: id that is not here is a typo the rule loader rejects rather than a rule that silently never
#: fires.
KNOWN_WEAKNESS_IDS = frozenset(
    {
        "ecb-mode",
        "cbc-unauthenticated",
        "pkcs1v15-padding",
        "kdf-iterations-below-floor",
        "rsa-key-too-short",
        "jwt-signature-not-verified",
    }
)

__all__ = [
    "BLOCK_CIPHER_FAMILIES",
    "KNOWN_WEAKNESS_IDS",
    "PBKDF2_FLOORS",
    "PBKDF2_FLOOR_UNKNOWN_PRF",
    "Weakness",
    "derive",
]
