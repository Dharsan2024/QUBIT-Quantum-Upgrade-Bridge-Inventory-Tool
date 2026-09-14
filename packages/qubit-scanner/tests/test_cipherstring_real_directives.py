"""`expand_cipher_string` opens with its own admission: "A simplified mock of a vendored OpenSSL
cipher string parser for M2." It is not a mock in a test tree -- it is imported by
`config/directives.py` and `config/parsers.py`, so it decides what cipher findings the nginx/
apache/openssl config scanners actually produce.

Two measured failure modes, neither exercised by the existing coverage in
`test_coverage_boost.py` (which only ever excludes a full literal suite NAME, never a real
OpenSSL group token):

1. Exclusion is exact-match against the tiny alias table, so `!aNULL`, `!MD5`, `!RC4`, `!EXPORT`,
   `!LOW` -- the vocabulary every real hardening directive actually uses -- remove nothing.
2. An unrecognised token is appended AS IF it were a literal suite name, so `ALL` (present in
   real directives constantly, absent from the 3-entry alias table) becomes a single fictional
   suite `['ALL']` instead of expanding to anything. `expand_cipher_string("ALL:!aNULL")` should
   describe a maximally permissive cipher set; it instead describes one cipher that does not
   exist, and the config scanner reports no weak-cipher finding for a config that permits
   RC4/DES/3DES/export-grade ciphers. A false negative -- the worst direction for a security
   scanner to be wrong in.

See RESUME.md "BUG 10" for the full measurement. This file's scope is narrower than a full
vendored IANA table (see the plan's explicit scoping decision) -- it fixes these two measured
modes for the alias tokens that actually occur in real configs and in this corpus, not every
OpenSSL alias that has ever existed.
"""

from __future__ import annotations

from qubit_scanner.config.cipherstring import expand_cipher_string


class TestRealWorldExclusionDirectives:
    """`!aNULL:!MD5` and friends are the single most common real-world OpenSSL hardening
    vocabulary. Excluding by literal suite name alone means these are silently no-ops today."""

    def test_high_with_the_common_exclusion_suffix_still_produces_suites(self) -> None:
        """`HIGH` already contains no anonymous-auth or MD5-keyed suite by definition, so this
        does not exercise exclusion itself (see the ALL-based tests below for that) -- it only
        guards against the combination crashing or emptying a result that has nothing to remove.
        """
        result = expand_cipher_string("HIGH:!aNULL:!MD5")

        assert result == expand_cipher_string("HIGH")

    def test_all_with_anonymous_excluded_is_not_a_single_fictional_suite(self) -> None:
        """The sharpest measured case: a maximally permissive config must not scan clean.

        `result != ["ALL"]` alone is too weak a check -- it is satisfied just as well by `[]`
        (ALL silently expanding to nothing) as by ALL correctly describing a real permissive
        set, and only the second is the actual fix. Asserting non-empty AND that the anonymous
        suites specifically are gone is what pins the real behavior.
        """
        result = expand_cipher_string("ALL:!aNULL")

        assert result, "ALL must expand to real suites, not vanish to nothing"
        assert "TLS_DH_anon_WITH_AES_128_CBC_SHA" not in result
        assert "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" not in result
        assert any(s.startswith("TLS_AES") for s in result), "the strong suites must still be there"

    def test_legacy_hardening_string_is_not_a_single_fictional_suite(self) -> None:
        result = expand_cipher_string("ALL:!EXPORT:!LOW")

        assert result, "ALL must expand to real suites, not vanish to nothing"
        assert not any("EXPORT" in s for s in result)
        assert any(s.startswith("TLS_AES") for s in result)

    def test_mixed_groups_with_exclusion_still_produce_multiple_suites(self) -> None:
        result = expand_cipher_string("HIGH:MEDIUM:!aNULL")

        assert len(result) >= 2


class TestUnknownTokensDoNotBecomeFictionalSuites:
    def test_an_unrecognised_bare_token_is_not_appended_as_a_suite(self) -> None:
        result = expand_cipher_string("NOTAREALALIAS")

        assert "NOTAREALALIAS" not in result

    def test_all_alone_is_not_a_single_fictional_suite(self) -> None:
        result = expand_cipher_string("ALL")

        assert result != ["ALL"]
        assert len(result) > 1, "ALL must expand to real suites, not vanish to nothing"


class TestExistingBehaviorIsNotRegressed:
    """The near-miss guards: the two forms `test_coverage_boost.py` already covers must keep
    working exactly as before."""

    def test_excluding_a_literal_suite_name_still_works(self) -> None:
        high = expand_cipher_string("HIGH")
        target = high[0]

        assert target not in expand_cipher_string(f"HIGH:!{target}")

    def test_a_bare_literal_suite_name_still_passes_through(self) -> None:
        assert "TLS_AES_256_GCM_SHA384" in expand_cipher_string("TLS_AES_256_GCM_SHA384")

    def test_empty_string_is_still_empty(self) -> None:
        assert expand_cipher_string("") == []
