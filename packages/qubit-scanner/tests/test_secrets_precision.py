"""What the HNDL pass reports that is not a secret, found by hand-reading its own output.

The design note at the top of `secrets/scanner.py` says the patterns "are chosen for high precision
-- a noisy secret scanner is worse than none". That was an intention, and until this session it had
never been checked against anything but invented input: five unit tests, all of which passed while
the scanner reported `icon@2x.png` as an email address.

Hand-adjudicating 152 of its findings across 26 real repositories (`benchmarks/adjudication/`)
measured it instead. **47 were not instances of the category at all** -- 31 %:

    'icon@2x.png', // Retina image naming              PII-EMAIL
    'package@1.0.0.tgz', // NPM package versioning     PII-EMAIL
    ssh ubuntu@host.redis.io "cd /var/www/download;    PII-EMAIL
    git@github.com:multica-ai/multica.git              PII-EMAIL
    0.4365079365079365                                 PII-CREDIT-CARD  (a doctest float)
    Password = "password",                             SECRET-HARDCODED-PW  (an enum member)

Every case below is a real line from that corpus. The filters they pin removed all 47 and cost
nothing: the 31 findings labelled as genuine secrets or genuine addresses are all still reported.

That last clause is why the true-positive tests are in this file rather than left to the existing
suite. A filter that drops everything scores perfectly on the false-positive half.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_scanner.secrets import SecretScanner


def _findings(tmp_path: Path, content: str, name: str = "sample.py") -> list[str]:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return [d.rule_id for d in SecretScanner().scan_file(path)]


class TestAtSignIsNotAlwaysAnAddress:
    @pytest.mark.parametrize(
        "line",
        [
            "icon = 'icon@2x.png'",
            "pkg = 'package@1.0.0.tgz'",
            "style = 'sprite@mobile.css'",
            "dump = 'backup@2024.sql'",
            "snap = 'snapshot@latest.json'",
            "path = '/path/to/file@2x.png'",
        ],
    )
    def test_a_filename_is_not_an_email(self, tmp_path: Path, line: str) -> None:
        """`local@domain.tld` parses perfectly when the tld is a file extension."""
        assert "PII-EMAIL" not in _findings(tmp_path, line)

    @pytest.mark.parametrize(
        "line",
        [
            "url = 'ssh://user@host.com'",
            "url = 'http://google.com@evil.com'",
            "url = '//root:22@server.com'",
            "url = 'root:toor@evil.com/payload'",
            "url = 'https://x-access-token:v1.6abc@github.com/user/repo'",
            "unc = '\\\\\\\\google.com@evil.com'",
        ],
    )
    def test_url_userinfo_is_a_location_not_a_mailbox(self, tmp_path: Path, line: str) -> None:
        assert "PII-EMAIL" not in _findings(tmp_path, line)

    def test_an_scp_style_remote_is_not_an_email(self, tmp_path: Path) -> None:
        line = 'repos = [{"url": "git@github.com:multica-ai/multica.git"}]'
        assert "PII-EMAIL" not in _findings(tmp_path, line)

    def test_an_ssh_command_argument_is_not_an_email(self, tmp_path: Path) -> None:
        assert "PII-EMAIL" not in _findings(tmp_path, "ssh ubuntu@host.redis.io", "deploy.sh")

    def test_protobuf_descriptor_bytes_are_not_an_email(self, tmp_path: Path) -> None:
        """A domain whose first label is empty is not a domain."""
        line = 'x = "\\x06tokens\\x18\\x01 \\x03(\\v2@.memos.store.PersonalAccessToken"'
        assert "PII-EMAIL" not in _findings(tmp_path, line)


class TestRealAddressesSurvive:
    """The constraint on all of the above."""

    @pytest.mark.parametrize(
        ("line", "name"),
        [
            ("customer_email = 'alice.smith@acmecorp.io'", "app.py"),
            ("# Author email: joaogustavoamorim@gmail.com", "index_calculation.py"),
            ('"""Author Anurag Kumar(mailto:anuragkumarak95@gmail.com)"""', "k_means.py"),
            ('_createdBy: "najeeb.thangal@orkes.io",', "fixtures.js"),
            ('echo "greearb@candelatech.com" >> report.txt', "bugcheck.sh"),
        ],
    )
    def test_a_real_address_is_still_reported(self, tmp_path: Path, line: str, name: str) -> None:
        assert "PII-EMAIL" in _findings(tmp_path, line, name)


class TestCardNumbers:
    @pytest.mark.parametrize(
        "line",
        [
            "value = 0.4365079365079365",
            "coords = [0.8509035245341184, 0.5253219888177297]",
            "result = (3.130524675073759, 2.0, 0.4470070007889556)",
            "# 5.348480500048026, 2.6477354579837993",
        ],
    )
    def test_a_float_is_not_a_card_number(self, tmp_path: Path, line: str) -> None:
        """Sixteen digits after a decimal point, starting with 4 or 3, match Visa and Amex exactly.

        `\\b` is no help: `.` is a word boundary. All 13 credit-card false positives in the
        adjudicated sample were doctest output like these.
        """
        assert "PII-CREDIT-CARD" not in _findings(tmp_path, line)

    def test_a_number_that_fails_luhn_is_not_a_card(self, tmp_path: Path) -> None:
        assert "PII-CREDIT-CARD" not in _findings(tmp_path, "card = '4111111111111112'")

    def test_a_valid_card_number_is_still_reported(self, tmp_path: Path) -> None:
        assert "PII-CREDIT-CARD" in _findings(tmp_path, "card = '4012888888881881'")


class TestSecretValues:
    @pytest.mark.parametrize(
        ("line", "name"),
        [
            ('password="$updatekey"', "6in4.sh"),
            ('password = "${VAULT_PW}"', "deploy.sh"),
            ("api_key = process.env.API_KEY_VALUE", "config.js"),
        ],
    )
    def test_a_reference_to_a_secret_is_not_a_secret(
        self, tmp_path: Path, line: str, name: str
    ) -> None:
        assert "SECRET-HARDCODED-PW" not in _findings(tmp_path, line, name)

    def test_a_value_equal_to_its_own_key_is_a_label(self, tmp_path: Path) -> None:
        """code-server's `AuthType` enum: `Password = "password"`. Nothing to harvest."""
        assert "SECRET-HARDCODED-PW" not in _findings(tmp_path, 'Password = "password",', "cli.ts")

    def test_a_real_hardcoded_password_is_still_reported(self, tmp_path: Path) -> None:
        assert "SECRET-HARDCODED-PW" in _findings(tmp_path, 'password = "hunter2!swordfish"')


class TestReservedNamesAreFixtures:
    """RFC 2606 and RFC 6761 reserve these so they can never resolve."""

    @pytest.mark.parametrize(
        "domain", ["multica.test", "conductor.test", "host.example", "thing.invalid"]
    )
    def test_a_reserved_tld_is_a_placeholder(self, tmp_path: Path, domain: str) -> None:
        assert "PII-EMAIL" not in _findings(tmp_path, f"addr = 'someone@{domain}'")


class TestPrefixedKeywords:
    """A recall gap, found by scanning a fixture through the running desktop app.

    `\b` does not fire between `_` and `P`, so the keyword in `DB_PASSWORD` was unreachable and
    `DB_PASSWORD = "hunter2"` -- one of the commonest shapes a hardcoded credential takes -- was
    never reported, while the bare `password = "hunter2"` was. Every unit test in the suite had
    used the bare form.
    """

    @pytest.mark.parametrize(
        "line",
        [
            "DB_PASSWORD = 'hunter2!swordfish'",
            "SERVICE_SECRET = 'aVeryLongSharedSecret'",
            "stripe_api_key = 'not_a_real_key_value'",
            "my-access-token = 'abc123def456ghi'",
        ],
    )
    def test_a_prefixed_keyword_is_still_the_keyword(self, tmp_path: Path, line: str) -> None:
        assert "SECRET-HARDCODED-PW" in _findings(tmp_path, line)

    def test_a_suffix_still_blocks_the_match(self, tmp_path: Path) -> None:
        """`PASSWORD_HASH = "..."` is a digest, not a credential. The trailing `\b` keeps it out."""
        line = "PASSWORD_HASH = 'ef92b778bafe771e89245b89ecbc08a44a4e166c'"
        assert "SECRET-HARDCODED-PW" not in _findings(tmp_path, line)

    def test_a_specific_rule_wins_over_the_generic_one(self, tmp_path: Path) -> None:
        """One line, one finding -- and the one naming the provider is the one worth keeping.

        Widening the keyword made the generic rule reach `GOOGLE_API_KEY = "AIza..."`, which the
        provider rule had already claimed. The two match at different columns, so the existing
        column-level de-duplication could not see the collision.
        """
        line = "GOOGLE_API_KEY = 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI'"
        found = _findings(tmp_path, line)
        assert found == ["SECRET-GOOGLE-API"], found
