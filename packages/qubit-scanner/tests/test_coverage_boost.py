from __future__ import annotations

import asyncio
import datetime
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from qubit_scanner.certs.scanner import CertScanner
from qubit_scanner.code.resolve import extract_imports, int_literal_value, resolve_string_constant
from qubit_scanner.config.cipherstring import expand_cipher_string
from qubit_scanner.network.active import TlsEnumerator
from tree_sitter import Parser
from tree_sitter_language_pack import get_language


def _rsa_pem(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qubit-test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(sub)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / "rsa.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return p


def _ec_pem(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec-test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(sub)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / "ec.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return p


def test_cert_rsa(tmp_path):
    dets = CertScanner().parse_file(_rsa_pem(tmp_path))
    assert any(d.raw_algorithm == "RSA" for d in dets)


def test_cert_ec(tmp_path):
    dets = CertScanner().parse_file(_ec_pem(tmp_path))
    assert any(d.raw_algorithm == "ECDSA" for d in dets)


def test_cert_sigalgo(tmp_path):
    dets = CertScanner().parse_file(_rsa_pem(tmp_path))
    assert any(d.rule_id == "CERT-SIGALGO-001" for d in dets)


def test_cert_malformed(tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"not a cert")
    assert CertScanner().parse_file(p) == []


def test_cert_der(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "der-test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(sub)
        .issuer_name(sub)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / "cert.der"
    p.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    assert any(d.raw_algorithm == "RSA" for d in CertScanner().parse_file(p))


def test_expand_empty():
    assert expand_cipher_string("") == []


def test_expand_high():
    assert len(expand_cipher_string("HIGH")) > 0


def test_expand_bang():
    high = expand_cipher_string("HIGH")
    exc = high[0]
    assert exc not in expand_cipher_string("HIGH:!" + exc)


def test_expand_dash():
    high = expand_cipher_string("HIGH")
    exc = high[0]
    assert exc not in expand_cipher_string("HIGH:-" + exc)


def test_expand_plus_literal():
    high = expand_cipher_string("HIGH")
    mv = high[0]
    suites = expand_cipher_string("HIGH:+" + mv)
    assert suites[-1] == mv


def test_expand_plus_alias():
    suites = expand_cipher_string("HIGH:+HIGH")
    assert len(suites) == len(expand_cipher_string("HIGH"))


def test_expand_literal_suite():
    assert "TLS_AES_256_GCM_SHA384" in expand_cipher_string("TLS_AES_256_GCM_SHA384")


def test_expand_dedup():
    s = expand_cipher_string("HIGH:HIGH")
    assert len(s) == len(set(s))


def test_expand_default():
    assert len(expand_cipher_string("DEFAULT")) > 0


def test_expand_bang_unknown():
    assert expand_cipher_string("HIGH:!NONEXISTENT") == expand_cipher_string("HIGH")


def test_expand_plus_not_present():
    assert expand_cipher_string("+TLS_AES_256_GCM_SHA384") == []


class _FakeSslObj:
    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)


class _FakeWriter:
    def get_extra_info(self, key):
        return _FakeSslObj() if key == "ssl_object" else None

    def close(self):
        pass

    async def wait_closed(self):
        pass


def test_tls_success():
    async def fake_open(*a, **kw):
        return (MagicMock(), _FakeWriter())

    async def run():
        with patch("asyncio.open_connection", new=fake_open):
            return await TlsEnumerator().enumerate("127.0.0.1", 443)

    ids = {d.rule_id for d in asyncio.run(run())}
    assert "NET-TLS-PROTO" in ids and "NET-TLS-CIPHER" in ids


def test_tls_no_ssl_obj():
    class _NoSsl:
        def get_extra_info(self, key):
            return None

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open(*a, **kw):
        return (MagicMock(), _NoSsl())

    async def run():
        with patch("asyncio.open_connection", new=fake_open):
            return await TlsEnumerator().enumerate("127.0.0.1", 8443)

    assert asyncio.run(run()) == []


def test_tls_refused():
    async def fake_open(*a, **kw):
        raise ConnectionRefusedError

    async def run():
        with patch("asyncio.open_connection", new=fake_open):
            return await TlsEnumerator().enumerate("127.0.0.1", 9999)

    assert asyncio.run(run()) == []


def test_tls_timeout():
    async def fake_open(*a, **kw):
        raise TimeoutError

    async def run():
        with patch("asyncio.open_connection", new=fake_open):
            return await TlsEnumerator().enumerate("10.0.0.1", 443)

    assert asyncio.run(run()) == []


def _py(src):
    return Parser(get_language("python")).parse(src.encode()).root_node


def test_imports_py():
    mods = extract_imports(_py("import hashlib\nfrom cryptography import hazmat\n"), "python")
    assert "hashlib" in mods


def test_imports_unknown():
    assert extract_imports(_py("import foo\n"), "cobol") == set()


def test_resolve_single():
    assert resolve_string_constant("algo", _py('algo = "RSA"\n')) == "RSA"


def test_resolve_multi():
    assert resolve_string_constant("algo", _py('algo = "RSA"\nalgo = "AES"\n')) is None


def test_resolve_nomatch():
    assert resolve_string_constant("algo", _py("x = 42\n")) is None


def test_int_literal():
    root = _py("n = 2048\n")
    stmt = root.children[0]
    if stmt.type == "expression_statement":
        stmt = stmt.children[0]
    right = stmt.child_by_field_name("value") or stmt.child_by_field_name("right")
    if right is not None:
        assert int_literal_value(right) == 2048


def test_int_literal_non_int():
    root = _py('n = "foo"\n')
    stmt = root.children[0]
    if stmt.type == "expression_statement":
        stmt = stmt.children[0]
    right = stmt.child_by_field_name("value") or stmt.child_by_field_name("right")
    if right is not None:
        assert int_literal_value(right) is None
