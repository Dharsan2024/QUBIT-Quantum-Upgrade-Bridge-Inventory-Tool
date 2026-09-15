"""The weakness catalogue: properties of a CALL that the algorithm registry cannot see.

Every case here is one the registry gets right and would still leave the finding wrong. AES-256 is
a sound cipher; AES-256 in ECB mode is not, and they differ in no field the registry reads. The
tests that matter most are the NEGATIVE ones - a weakness catalogue that over-reports costs the
tool its credibility on the findings it gets right.
"""

from __future__ import annotations

import pytest
from qubit_core import weaknesses


def ids(**kwargs: object) -> list[str]:
    kwargs.setdefault("algorithm", None)
    kwargs.setdefault("family", None)
    kwargs.setdefault("key_size", None)
    kwargs.setdefault("usage_context", None)
    kwargs.setdefault("extra", {})
    return [w.id for w in weaknesses.derive(**kwargs)]  # type: ignore[arg-type]


def test_ecb_mode_is_a_weakness_of_a_sound_cipher() -> None:
    """The case the registry cannot express: the algorithm is fine, the call is not."""
    assert ids(
        algorithm="AES-256",
        family="AES",
        key_size=256,
        usage_context="encryption-at-rest",
        extra={"mode": "ECB"},
    ) == ["ecb-mode"]


def test_aead_modes_are_not_flagged() -> None:
    for mode in ("GCM", "CCM", "OCB", "GCM-SIV"):
        assert (
            ids(
                algorithm="AES-256",
                family="AES",
                key_size=256,
                usage_context="encryption-at-rest",
                extra={"mode": mode},
            )
            == []
        ), mode


def test_rsa_ecb_is_not_an_ecb_finding() -> None:
    """JCA spells RSA as `RSA/ECB/PKCS1Padding`, where ECB is a naming artefact of the provider
    interface and not a mode of operation at all.

    Reading it literally would report a weakness that does not exist on nearly every Java RSA call
    site in existence - the single highest-volume false positive this catalogue could produce.
    """
    found = ids(
        algorithm="RSA-3072",
        family="RSA",
        key_size=3072,
        usage_context="signature",
        extra={"mode": "ECB", "padding": "PKCS1v15"},
    )
    assert "ecb-mode" not in found
    assert found == ["pkcs1v15-padding"]


def test_pkcs1v15_names_the_right_operation() -> None:
    signing = weaknesses.derive(
        algorithm="RSA-2048",
        family="RSA",
        key_size=2048,
        usage_context="signature",
        extra={"padding": "PKCS1v15"},
    )
    encrypting = weaknesses.derive(
        algorithm="RSA-2048",
        family="RSA",
        key_size=2048,
        usage_context="kex",
        extra={"padding": "PKCS1v15"},
    )
    assert "PSS" in signing[0].remedy
    assert "OAEP" in encrypting[0].remedy
    assert "Bleichenbacher" in encrypting[0].remedy


def test_oaep_and_pss_are_not_flagged() -> None:
    for padding in ("OAEP", "PSS"):
        assert (
            ids(
                algorithm="RSA-3072",
                family="RSA",
                key_size=3072,
                usage_context="kex",
                extra={"padding": padding},
            )
            == []
        ), padding


def test_pbkdf2_floor_is_per_prf_and_matches_owasp() -> None:
    """The published floors, quoted. OWASP Password Storage Cheat Sheet, PBKDF2 section."""
    assert weaknesses.PBKDF2_FLOORS["SHA-256"] == 600_000
    assert weaknesses.PBKDF2_FLOORS["SHA-512"] == 220_000
    assert weaknesses.PBKDF2_FLOORS["SHA-1"] == 1_400_000

    # At the floor is fine; one below it is not.
    for prf, floor in weaknesses.PBKDF2_FLOORS.items():
        base = {"algorithm": "PBKDF2", "family": "PBKDF2", "usage_context": "password"}
        assert ids(**base, extra={"iterations": str(floor), "prf": prf}) == [], prf
        assert ids(**base, extra={"iterations": str(floor - 1), "prf": prf}) == [
            "kdf-iterations-below-floor"
        ], prf


def test_unknown_prf_uses_the_lowest_floor_so_it_under_reports() -> None:
    """An unknown PRF can only be flagged when it is below EVERY published floor.

    Deliberately an under-report: a false "your KDF is too weak" costs the reader trust in every
    other finding, and the count is recoverable later while credibility is not.
    """
    base = {"algorithm": "PBKDF2", "family": "PBKDF2", "usage_context": "password"}
    assert ids(**base, extra={"iterations": "300000"}) == []  # above 220_000, below 600_000
    assert ids(**base, extra={"iterations": "1000"}) == ["kdf-iterations-below-floor"]


def test_a_kdf_with_no_literal_iteration_count_is_not_flagged() -> None:
    """The count came from a variable or a config lookup, so nothing is known about it.

    Reporting "unknown" as "too low" would flag correctly-configured code; the honest answer is
    silence, and the guided path can still ask.
    """
    assert ids(algorithm="PBKDF2", family="PBKDF2", usage_context="password", extra={}) == []


def test_short_rsa_is_a_classical_finding_before_it_is_a_quantum_one() -> None:
    found = weaknesses.derive(
        algorithm="RSA-1024", family="RSA", key_size=1024, usage_context="kex", extra={}
    )
    assert [w.id for w in found] == ["rsa-key-too-short"]
    assert "classically" in found[0].remedy
    assert found[0].detail["classical_minimum"] == 2048


def test_rsa_at_or_above_2048_is_not_a_short_key() -> None:
    for size in (2048, 3072, 4096):
        assert (
            ids(algorithm=f"RSA-{size}", family="RSA", key_size=size, usage_context="kex", extra={})
            == []
        ), size


def test_every_weakness_carries_an_authority_and_a_remedy() -> None:
    """A finding without a source is an opinion, and a finding without a remedy is a complaint."""
    cases = [
        {"algorithm": "AES", "family": "AES", "usage_context": "e", "extra": {"mode": "ECB"}},
        {"algorithm": "AES", "family": "AES", "usage_context": "e", "extra": {"mode": "CBC"}},
        {
            "algorithm": "RSA-2048",
            "family": "RSA",
            "key_size": 2048,
            "usage_context": "signature",
            "extra": {"padding": "PKCS1v15"},
        },
        {
            "algorithm": "PBKDF2",
            "family": "PBKDF2",
            "usage_context": "password",
            "extra": {"iterations": "1", "prf": "sha256"},
        },
        {"algorithm": "RSA-1024", "family": "RSA", "key_size": 1024, "usage_context": "kex"},
        {
            "algorithm": "RUNTIME-SELECTED",
            "family": None,
            "usage_context": "token",
            "extra": {"jwt_verification": "alg-none-accepted"},
        },
    ]
    seen = set()
    for case in cases:
        case.setdefault("key_size", None)
        case.setdefault("extra", {})
        for w in weaknesses.derive(**case):  # type: ignore[arg-type]
            seen.add(w.id)
            assert w.cwe.startswith("CWE-"), w.id
            assert len(w.authority.split()) >= 4, f"{w.id} authority is too thin: {w.authority}"
            assert len(w.remedy.split()) >= 10, f"{w.id} remedy is too thin: {w.remedy}"
    assert seen == weaknesses.KNOWN_WEAKNESS_IDS, (
        "every id the catalogue can produce must be exercised here; "
        f"missing {weaknesses.KNOWN_WEAKNESS_IDS - seen}"
    )


@pytest.mark.parametrize(
    "bypass",
    ["signature-check-disabled", "alg-none-accepted", "decoded-without-verifying"],
)
def test_every_jwt_bypass_spelling_is_a_finding(bypass: str) -> None:
    """Three ways to read a token without checking it, one weakness.

    Not a quantum finding, and more urgent than most that are: a JWT whose signature is never
    verified is a claim set anyone can write. RFC 8725 names both halves - reject `none`, and pin
    the expected algorithm rather than trusting the token's own header.
    """
    found = weaknesses.derive(
        algorithm="RUNTIME-SELECTED",
        family=None,
        key_size=None,
        usage_context="token",
        extra={"jwt_verification": bypass},
    )
    assert [w.id for w in found] == ["jwt-signature-not-verified"]
    assert "RFC 8725" in found[0].authority
    assert found[0].detail["bypass"] == bypass


def test_a_verified_jwt_produces_no_weakness() -> None:
    assert (
        ids(algorithm="RS256", family="RSA", usage_context="token", extra={"jwt_verification": ""})
        == []
    )


def test_cbc_mode_without_a_mac_is_a_weakness_of_a_sound_cipher() -> None:
    """The CBC counterpart to `test_ecb_mode_is_a_weakness_of_a_sound_cipher`. Unauthenticated
    CBC provides no integrity -- ciphertext can be truncated, reordered or bit-flipped
    undetected -- and AES-256 in CBC is otherwise a sound cipher, differing from the ECB case
    in no field the registry reads."""
    assert ids(
        algorithm="AES-256",
        family="AES",
        key_size=256,
        usage_context="encryption-at-rest",
        extra={"mode": "CBC"},
    ) == ["cbc-unauthenticated"]


def test_cbc_and_ecb_are_mutually_exclusive() -> None:
    """A call is in exactly one mode; the two weaknesses must never both fire on one asset."""
    assert ids(
        algorithm="AES-256",
        family="AES",
        key_size=256,
        usage_context="encryption-at-rest",
        extra={"mode": "ECB"},
    ) == ["ecb-mode"]
    assert ids(
        algorithm="AES-256",
        family="AES",
        key_size=256,
        usage_context="encryption-at-rest",
        extra={"mode": "CBC"},
    ) == ["cbc-unauthenticated"]


def test_aead_modes_are_not_flagged_as_unauthenticated_cbc() -> None:
    for mode in ("GCM", "CCM", "OCB", "GCM-SIV", "CTR"):
        assert (
            ids(
                algorithm="AES-256",
                family="AES",
                key_size=256,
                usage_context="encryption-at-rest",
                extra={"mode": mode},
            )
            == []
        ), mode


def test_rsa_is_never_flagged_cbc_unauthenticated() -> None:
    """RSA is not a block cipher in the sense this weakness cares about; the family gate must
    exclude it regardless of anything a scanner might put in `extra["mode"]`."""
    found = ids(
        algorithm="RSA-3072",
        family="RSA",
        key_size=3072,
        usage_context="signature",
        extra={"mode": "CBC"},
    )
    assert "cbc-unauthenticated" not in found
