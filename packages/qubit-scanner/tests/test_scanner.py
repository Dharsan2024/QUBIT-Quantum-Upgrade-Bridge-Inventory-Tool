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
