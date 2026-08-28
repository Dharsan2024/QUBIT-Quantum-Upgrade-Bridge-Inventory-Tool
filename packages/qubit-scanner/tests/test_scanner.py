from __future__ import annotations

import pytest
from qubit_scanner import CodeScanner, RuleCatalog


@pytest.fixture(scope="module")
def scanner() -> CodeScanner:
    return CodeScanner(RuleCatalog.load())


def _detect(scanner: CodeScanner, src: str) -> dict[str, str]:
    dets = scanner.scan_source(src.encode(), "python", file_path="t.py")
    return {d.rule_id: d.raw_algorithm for d in dets}


def test_detects_md5_and_sha1(scanner: CodeScanner) -> None:
    got = _detect(scanner, "import hashlib\na = hashlib.md5()\nb = hashlib.sha1()\n")
    assert got.get("PY-HASHLIB-MD5") == "MD5"
    assert got.get("PY-HASHLIB-SHA1") == "SHA-1"


def test_detects_rsa_keygen_with_size(scanner: CodeScanner) -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
    )
    dets = scanner.scan_source(src.encode(), "python", file_path="t.py")
    rsa = next(d for d in dets if d.rule_id == "PY-CRYPTOGRAPHY-RSA-KEYGEN")
    assert rsa.raw_algorithm == "RSA"
    assert rsa.key_size == 3072


def test_import_gate_suppresses_unrelated_rules(scanner: CodeScanner) -> None:
    # no `import hashlib` => the hashlib rules must not fire even if the text looks similar
    got = _detect(scanner, "hashlib = FakeShim()\nx = hashlib.md5()\n")
    assert "PY-HASHLIB-MD5" not in got


def test_line_numbers_reported(scanner: CodeScanner) -> None:
    src = "import hashlib\n\n\nh = hashlib.md5()\n"
    det = scanner.scan_source(src.encode(), "python", file_path="t.py")[0]
    assert det.location.line == 4


def test_unparseable_file_yields_no_crash(scanner: CodeScanner) -> None:
    # mostly-garbage input must not raise
    assert scanner.scan_source(b"@#$%^&*(){}][\n\x00\x01", "python", file_path="t.py") == []


class TestHmacDigestIsNotHardcoded:
    """Six rules (C, Go, Java, JS, Python, TS) used to report every HMAC call as the bare
    literal "HMAC" regardless of which digest it actually named. That made a call correctly
    pinning HMAC-SHA-256 — already quantum-adequate — indistinguishable from one running on
    SHA-1, which is exactly the class of finding `code-mac-01` exists to catch and exactly the
    class it deliberately does NOT match on strong digests. The visible symptom, on a real
    corpus repository: a migration task was built for code that needed no migration, and
    generating a patch for it answered "already meets what code-mac-01 asks for" — the model
    was never even called.

    Found by reading `stripe/_webhook.py:105` (`hmac.new(secret, msg=payload,
    digestmod=sha256)`) after it kept showing that message across a live stress-test run.
    """

    def test_python_strong_digest_is_not_bare_hmac(self, scanner: CodeScanner) -> None:
        got = _detect(
            scanner,
            "import hmac\nfrom hashlib import sha256\nm = hmac.new(k, msg=p, digestmod=sha256)\n",
        )
        assert got.get("PY-HMAC-NEW") == "HMAC-SHA256"

    def test_python_weak_digest_is_still_caught(self, scanner: CodeScanner) -> None:
        got = _detect(scanner, "import hmac, hashlib\nm = hmac.new(k, msg, hashlib.sha1)\n")
        assert got.get("PY-HMAC-NEW") == "HMAC-SHA1"

    def test_python_unspecified_digest_stays_bare_hmac(self, scanner: CodeScanner) -> None:
        # A dynamic/variable digest can't be resolved — the honest answer is "unspecified",
        # which the migration rule already treats as "may be running on SHA-1".
        got = _detect(scanner, "import hmac\nm = hmac.new(k, msg, some_digest_var)\n")
        assert got.get("PY-HMAC-NEW") == "HMAC"

    def test_go_strong_digest_is_not_bare_hmac(self) -> None:
        scanner = CodeScanner(RuleCatalog.load())
        src = (
            'import (\n\t"crypto/hmac"\n\t"crypto/sha256"\n)\n\n'
            "func tag(key, msg []byte) []byte {\n"
            "\tm := hmac.New(sha256.New, key)\n\tm.Write(msg)\n\treturn m.Sum(nil)\n}\n"
        )
        dets = scanner.scan_source(src.encode(), "go", file_path="t.go")
        got = {d.rule_id: d.raw_algorithm for d in dets}
        assert got.get("GO-CRYPTO-HMAC-NEW") == "HMAC-SHA256"

    def test_java_strong_digest_is_not_bare_hmac(self) -> None:
        scanner = CodeScanner(RuleCatalog.load())
        src = (
            "import javax.crypto.Mac;\n"
            'class A { void f() throws Exception { Mac.getInstance("HmacSHA256"); } }\n'
        )
        dets = scanner.scan_source(src.encode(), "java", file_path="t.java")
        got = {d.rule_id: d.raw_algorithm for d in dets}
        assert got.get("JAVA-JCA-MAC") == "HMAC-SHA256"

    def test_javascript_strong_digest_is_not_bare_hmac(self) -> None:
        scanner = CodeScanner(RuleCatalog.load())
        src = 'const crypto = require("crypto");\nconst t = crypto.createHmac("sha256", key);\n'
        dets = scanner.scan_source(src.encode(), "javascript", file_path="t.js")
        got = {d.rule_id: d.raw_algorithm for d in dets}
        assert got.get("JS-NODE-CREATEHMAC") == "HMAC-SHA256"

    def test_c_strong_digest_is_not_bare_hmac(self) -> None:
        scanner = CodeScanner(RuleCatalog.load())
        src = "unsigned char *out = HMAC(EVP_sha256(), key, klen, msg, mlen, NULL, NULL);\n"
        dets = scanner.scan_source(src.encode(), "c", file_path="t.c")
        got = {d.rule_id: d.raw_algorithm for d in dets}
        assert got.get("C-OPENSSL-HMAC") == "HMAC-SHA256"
