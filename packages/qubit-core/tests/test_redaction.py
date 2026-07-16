from __future__ import annotations

from qubit_core import redaction

_PEM = """\
key_setup()
priv = \"\"\"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1c3Rtqe7Hk9m0Zx8fWq2v3n4l5o6p7q8r9s0t1u2v3w4x5y6z7
QIDAQABAoIBAQC9aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnop
-----END RSA PRIVATE KEY-----\"\"\"
"""


def test_pem_private_key_is_redacted() -> None:
    out = redaction.redact_snippet(_PEM)
    assert not redaction.contains_private_key(out)
    assert "BEGIN RSA PRIVATE KEY" not in out
    assert redaction.REDACTED in out


def test_secret_assignment_redacted() -> None:
    out = redaction.redact_snippet('password = "hunter2SuperSecret!"')
    assert "hunter2SuperSecret!" not in out
    assert redaction.REDACTED in out


def test_high_entropy_literal_redacted() -> None:
    token = "aG7xQ2pL9zR4tYv8Nw1Kc3Bs6Df0Mh5Jk2Ll8Zx4Qe7Rt"  # 46 chars, high entropy
    out = redaction.redact_snippet(f'api_key = "{token}"')
    assert token not in out


def test_ordinary_code_untouched() -> None:
    code = "cipher = Cipher.getInstance('RSA/ECB/PKCS1Padding')\nkey_size = 2048"
    assert redaction.redact_snippet(code) == code


def test_idempotent() -> None:
    once = redaction.redact_snippet(_PEM)
    twice = redaction.redact_snippet(once)
    assert once == twice
