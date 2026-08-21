"""The model answered the demonstration instead of migrating the file.

Asked to migrate 3DES in the polyglot corpus's 15-line `app.py` — a flat list of unrelated crypto
calls — the local model returned `py-weakcipher-01`'s `example.after` block character for
character, comment included:

    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        # key must be 32 bytes; the nonce is fresh per message and stored with the ciphertext.
        nonce = os.urandom(12)
        return nonce, AESGCM(key).encrypt(nonce, plaintext, None)

Nothing in the user's file was migrated. The prompt already tells the model the examples
"demonstrate the intended shape of the change, not the file you must edit", and it copied one
anyway. The only reason this was not stored as the user's migrated file is that the truncation
guard noticed 6 non-blank lines where 15 were expected — a file of similar length to the example
would have passed every check and presented someone else's code as a migration of yours.

That is a correctness hazard rather than a lost task, so it is now a check rather than an
instruction. The exemption is the case that must keep working: when the file being migrated IS the
example's `before` block, reproducing its `after` block is the correct answer.
"""

from __future__ import annotations

from qubit_migrate.transform.llm import check_rewrite
from qubit_migrate.transform.rules import load_rules

APP_PY = (
    "import hashlib, hmac\n"
    "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305\n"
    "from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding\n"
    "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    "dsa.generate_private_key(key_size=1024)\n"
    "Cipher(algorithms.AES(k), modes.GCM(i))\n"
    "Cipher(algorithms.TripleDES(k), modes.CBC(i))\n"
    "AESGCM(k)\n"
    "ChaCha20Poly1305(k)\n"
    "hmac.new(k, m, 'sha256')\n"
    "hashlib.md5(b'')\n"
    "hashlib.sha384(b'')\n"
    "hashlib.pbkdf2_hmac('sha256', p, s, 1)\n"
    "public_key.encrypt(m, padding.PKCS1v15())\n"
)


def _weakcipher_rule():  # type: ignore[no-untyped-def]
    rule = next((r for r in load_rules() if r.id == "py-weakcipher-01"), None)
    assert rule is not None, "py-weakcipher-01 is the rule this failure was measured on"
    assert rule.example.get("after"), "the rule must carry the worked example being echoed"
    return rule


def test_returning_the_worked_example_is_rejected() -> None:
    rule = _weakcipher_rule()
    reason = check_rewrite(APP_PY, rule.example["after"], "python", rule)
    assert reason is not None, (
        "the model returned the rule's demonstration verbatim; accepting it would present "
        "someone else's code as this file's migration"
    )
    assert "worked example" in reason


def test_re_indenting_the_example_does_not_disguise_it() -> None:
    rule = _weakcipher_rule()
    disguised = "\n".join("    " + ln for ln in rule.example["after"].splitlines())
    assert check_rewrite(APP_PY, disguised, "python", rule) is not None


def test_migrating_the_example_itself_is_still_correct() -> None:
    """The exemption. Rule fixtures migrate the `before` block, and must keep passing."""
    rule = _weakcipher_rule()
    assert check_rewrite(rule.example["before"], rule.example["after"], "python", rule) is None


def test_a_real_rewrite_of_the_real_file_is_accepted() -> None:
    """Guarding the guard: a genuine migration of app.py must not trip this."""
    rule = _weakcipher_rule()
    migrated = APP_PY.replace(
        "Cipher(algorithms.TripleDES(k), modes.CBC(i))",
        "AESGCM(k).encrypt(nonce, m, None)",
    )
    assert check_rewrite(APP_PY, migrated, "python", rule) is None


def test_no_rule_means_no_echo_check() -> None:
    """`check_rewrite` is called without a rule elsewhere; it must stay usable."""
    rule = _weakcipher_rule()
    assert (
        check_rewrite(APP_PY, rule.example["after"], "python") is not None
    )  # truncation catches it
    long_echo = rule.example["after"] + "\n" + "\n".join(f"x{i} = {i}" for i in range(20))
    assert check_rewrite(APP_PY, long_echo, "python") is None, (
        "without a rule there is nothing to compare against, and that must not crash or refuse"
    )
