"""An HMAC whose digest is an OBJECT, not a string.

`hmac-of-digest` read a string literal and, failing that, took the argument's raw source text as the
algorithm name. Every rule example used the string form — `OpenSSL::HMAC.hexdigest("SHA1", …)` — so
every test passed, and the idiomatic Ruby form was never exercised.

Found by scanning the Ruby twin through the running desktop app, not by a unit test:

    algorithms: {..., 'UNKNOWN(HMAC-OpenSSL::Digest::SHA1.new)': 1}

An algorithm the registry cannot resolve has no quantum verdict, no risk score and no migration
rule, so an HMAC-SHA1 written the way Ruby is normally written was invisible to everything
downstream — inventory, risk, and migration alike.

The same shape occurs in Java (`Mac.getInstance` with a digest constant), Python (`hashlib.sha1`
passed to `hmac.new`) and Go, so the fix is a normaliser rather than a Ruby special case.
"""

from __future__ import annotations

import pytest

from qubit_scanner.api import scan_paths
from qubit_scanner.code.scanner import _digest_name


class TestTheNormaliser:
    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            # The form that was broken, exactly as the twin writes it.
            ("OpenSSL::Digest::SHA1.new", "SHA-1"),
            ("OpenSSL::Digest::SHA256.new", "SHA256"),
            ("Digest::MD5", "MD5"),
            ("hashlib.sha1", "SHA-1"),
            ('MessageDigest.getInstance("SHA-256")', "SHA256"),
            ("sha512", "SHA512"),
            ("SHA3-256", "SHA3-256"),
            ("RIPEMD160", "RIPEMD160"),
        ],
    )
    def test_a_digest_expression_resolves_to_its_algorithm(self, expression, expected) -> None:
        assert _digest_name(expression) == expected

    @pytest.mark.parametrize("text", ["nothing here", "", "encrypt(payload)", "sha1_migration_done"])
    def test_text_naming_no_digest_resolves_to_nothing(self, text: str) -> None:
        """Returning None is what lets the caller emit no algorithm rather than a fabricated one.

        `sha1_migration_done` is the case the word boundary exists for: matching inside arbitrary
        identifiers would turn a variable name into an HMAC-SHA1 finding.
        """
        assert _digest_name(text) is None


class TestTheScannerEndToEnd:
    def test_the_ruby_object_form_is_identified(self, tmp_path) -> None:
        """The regression itself, at the level the app sees it."""
        source = tmp_path / "partners.rb"
        source.write_text(
            'require "openssl"\n'
            "def sign(secret, payload)\n"
            '  "sha1=" + OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, payload)\n'
            "end\n",
            encoding="utf-8",
        )
        result = scan_paths([source], scanners={"code"})
        assets = result.assets if hasattr(result, "assets") else result
        algorithms = {a.algorithm for a in assets}

        assert "HMAC-SHA1" in algorithms, algorithms
        assert not any("UNKNOWN" in a for a in algorithms), (
            f"an unresolvable algorithm has no quantum verdict and no migration rule: {algorithms}"
        )

    def test_the_string_form_still_works(self, tmp_path) -> None:
        """The path that always worked, kept under test so the fix cannot regress it.

        The reported name is `HS256`, not `HMAC-SHA256`: the registry canonicalises the HMAC-SHA-2
        family to its JWA identifier and marks it SAFE, because HMAC-SHA-2 is post-quantum adequate.
        Asserting the pre-canonical spelling would be testing the resolver's intermediate value
        rather than what the tool reports.
        """
        source = tmp_path / "s.rb"
        source.write_text(
            'require "openssl"\ndef f(k, d) = OpenSSL::HMAC.hexdigest("SHA256", k, d)\n',
            encoding="utf-8",
        )
        result = scan_paths([source], scanners={"code"})
        assets = result.assets if hasattr(result, "assets") else result
        algorithms = {a.algorithm for a in assets}
        assert "HS256" in algorithms, algorithms
        assert not any(a.quantum_vulnerable.vulnerable for a in assets if a.algorithm == "HS256"), (
            "HMAC-SHA-2 is post-quantum adequate; flagging it would be a false positive"
        )

    def test_the_identified_hmac_carries_a_quantum_verdict(self, tmp_path) -> None:
        """The reason this mattered: an UNKNOWN algorithm is not merely mislabelled.

        It cannot be scored, cannot be prioritised and cannot be matched by a migration rule, so
        the finding is silently absent from every number the tool reports.
        """
        source = tmp_path / "p.rb"
        source.write_text(
            'require "openssl"\n'
            "def f(k, d) = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, k, d)\n",
            encoding="utf-8",
        )
        result = scan_paths([source], scanners={"code"})
        assets = result.assets if hasattr(result, "assets") else result
        hmac = [a for a in assets if a.algorithm == "HMAC-SHA1"]
        assert hmac, {a.algorithm for a in assets}
        assert hmac[0].quantum_vulnerable.vulnerable is True
