"""Normalizing TLS key-exchange GROUP names to the right algorithm role.

An elliptic curve name on its own does not say what the curve is being used FOR. `prime256v1` is
the same curve whether it signs a certificate (ECDSA-P256) or agrees a session key (ECDH-P256), and
the canonical registry has to pick one meaning for the bare name — it picks the signature one,
which is right for a certificate's key algorithm.

That is wrong for a key-exchange group list, and not merely cosmetically:

* **Risk.** Key exchange is the whole harvest-now-decrypt-later story — recorded traffic becomes
  readable once the group is broken. A signature is not retroactively forgeable from a recording,
  so it carries no HNDL exposure. Labelling a kex group as ECDSA understates the urgency of the
  single most time-critical finding in a TLS deployment.
* **Migration routing.** Transform rules match on `usage_context` and algorithm, so an
  `ssl_ecdh_curve` finding reported as ECDSA-P256 is handed to a signature migration instead of the
  config hardening that would actually enable a hybrid post-quantum group.

The directives feeding this (`ssl_ecdh_curve`, `SSLECDHCurve`, `SSLOpenSSLConfCmd Curves`) are
unambiguously key exchange, so the caller knows the role even though the name does not carry it.
Names already unambiguous as key exchange (`X25519`, `X25519MLKEM768`) and anything unrecognised are
passed through untouched, so a new group name still reaches the registry and is still flagged if it
does not resolve.
"""

from __future__ import annotations

# Curve names as they appear in OpenSSL-family config, mapped to the ECDH (key-agreement) canonical
# spelling. Keys are compared case-insensitively.
_CURVE_TO_KEX_GROUP: dict[str, str] = {
    "prime256v1": "ECDH-P256",
    "secp256r1": "ECDH-P256",
    "p-256": "ECDH-P256",
    "p256": "ECDH-P256",
    "prime384v1": "ECDH-P384",
    "secp384r1": "ECDH-P384",
    "p-384": "ECDH-P384",
    "p384": "ECDH-P384",
    "secp521r1": "ECDH-P521",
    "p-521": "ECDH-P521",
    "p521": "ECDH-P521",
}


def normalize_kex_group(name: str) -> str:
    """Return `name` re-spelled as a key-agreement algorithm where it names a bare EC curve."""
    return _CURVE_TO_KEX_GROUP.get(name.strip().lower(), name)
