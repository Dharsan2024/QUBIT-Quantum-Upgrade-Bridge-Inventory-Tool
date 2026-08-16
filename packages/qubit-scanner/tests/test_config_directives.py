"""Tests for the Apache / OpenSSH config parsers and the composite-name resolution they depend on.

The whole point of these parsers is that a weak setting must come out VULNERABLE, not as an
UNKNOWN(...) that silently inherits a not-vulnerable verdict — so the assertions here are about the
normalized verdict, not just that a finding was produced.
"""

from __future__ import annotations

from pathlib import Path

from qubit_core import algorithms
from qubit_scanner.config.directives import ApacheConfigParser, SshConfigParser
from qubit_scanner.normalize import normalize

_APACHE = """\
# a comment
SSLProtocol -all +TLSv1 +TLSv1.2
SSLCipherSuite HIGH:!aNULL:!MD5
SSLCertificateFile /etc/ssl/certs/server.crt
"""

_SSHD = """\
# comment line
Ciphers aes128-cbc,3des-cbc,aes256-gcm@openssh.com
MACs hmac-sha1,hmac-sha2-256
KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256
HostKeyAlgorithms ssh-rsa,ssh-ed25519
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def _normalized(dets: list) -> dict[str, object]:
    return {a.algorithm: a for a in (normalize(d, occurrence=i) for i, d in enumerate(dets, 1))}


# ---------------------------------------------------------------------------
# Apache
# ---------------------------------------------------------------------------


def test_apache_reports_enabled_protocols_only(tmp_path: Path) -> None:
    """`SSLProtocol -all +TLSv1 +TLSv1.2`: the DISABLED `-all` must not be reported. Flagging a
    switched-off protocol as present would mark a hardened config as vulnerable."""
    dets = ApacheConfigParser().parse(_write(tmp_path, "httpd.conf", _APACHE))
    protos = {d.raw_algorithm for d in dets if d.rule_id == "CFG-APACHE-PROTO-001"}
    assert protos == {"TLSv1", "TLSv1.2"}
    assert "all" not in protos


def test_apache_legacy_tls_is_vulnerable_not_unknown(tmp_path: Path) -> None:
    dets = ApacheConfigParser().parse(_write(tmp_path, "httpd.conf", _APACHE))
    by_algo = _normalized([d for d in dets if d.rule_id == "CFG-APACHE-PROTO-001"])
    assert by_algo["TLSv1.0"].quantum_vulnerable.vulnerable is True  # type: ignore[union-attr]
    assert by_algo["TLSv1.2"].quantum_vulnerable.vulnerable is False  # type: ignore[union-attr]


def test_apache_cert_is_not_reported_as_a_filename(tmp_path: Path) -> None:
    """A certificate PATH must never land in `algorithm` — that produced assets literally named
    UNKNOWN(/etc/ssl/certs/server.crt)."""
    dets = ApacheConfigParser().parse(_write(tmp_path, "httpd.conf", _APACHE))
    cert = next(d for d in dets if d.rule_id == "CFG-APACHE-CERT-001")
    assert cert.raw_algorithm == "X.509"
    assert "/etc/ssl" in cert.evidence_snippet  # path preserved as evidence


def test_apache_nothing_resolves_to_unknown(tmp_path: Path) -> None:
    dets = ApacheConfigParser().parse(_write(tmp_path, "httpd.conf", _APACHE))
    unknown = [
        normalize(d, occurrence=i).algorithm
        for i, d in enumerate(dets, 1)
        if normalize(d, occurrence=i).algorithm.startswith("UNKNOWN")
    ]
    assert not unknown, f"unresolved Apache findings: {unknown}"


# ---------------------------------------------------------------------------
# OpenSSH
# ---------------------------------------------------------------------------


def test_ssh_weak_settings_are_vulnerable(tmp_path: Path) -> None:
    dets = SshConfigParser().parse(_write(tmp_path, "sshd_config", _SSHD))
    by_algo = _normalized(dets)
    for weak in ("AES-128", "3DES", "HMAC-SHA1", "DH-1024-group1", "ssh-rsa"):
        assert weak in by_algo, f"{weak} not detected"
        assert by_algo[weak].quantum_vulnerable.vulnerable is True, weak  # type: ignore[union-attr]


def test_ssh_openssh_vendor_suffix_is_stripped(tmp_path: Path) -> None:
    """`aes256-gcm@openssh.com` must resolve to AES-256 — the `@domain` suffix is a vendor
    namespace, not algorithm information, and leaving it on made every hardened OpenSSH cipher
    resolve to UNKNOWN(...) with a not-vulnerable verdict."""
    dets = SshConfigParser().parse(_write(tmp_path, "sshd_config", _SSHD))
    assert "AES-256" in _normalized(dets)


def test_ssh_dh_group_number_maps_to_modulus_size() -> None:
    """RFC 3526 fixes the group sizes, so group1 is 1024-bit and group14 is 2048-bit. Collapsing
    them to a bare DH would lose that group1 is the weakest thing OpenSSH still negotiates."""
    assert algorithms.resolve("diffie-hellman-group1-sha1").canonical == "DH-1024-group1"  # type: ignore[union-attr]
    assert algorithms.resolve("diffie-hellman-group14-sha256").canonical == "DH-2048-group14"  # type: ignore[union-attr]


def test_ssh_nothing_resolves_to_unknown(tmp_path: Path) -> None:
    dets = SshConfigParser().parse(_write(tmp_path, "sshd_config", _SSHD))
    unknown = [
        normalize(d, occurrence=i).algorithm
        for i, d in enumerate(dets, 1)
        if normalize(d, occurrence=i).algorithm.startswith("UNKNOWN")
    ]
    assert not unknown, f"unresolved SSH findings: {unknown}"


def test_malformed_config_does_not_raise(tmp_path: Path) -> None:
    for name, parser in (("httpd.conf", ApacheConfigParser()), ("sshd_config", SshConfigParser())):
        p = _write(tmp_path, name, "\x00\x01 garbage\nSSLProtocol\nCiphers\n")
        assert isinstance(parser.parse(p), list)


def test_missing_file_returns_empty(tmp_path: Path) -> None:
    assert ApacheConfigParser().parse(tmp_path / "nope.conf") == []
    assert SshConfigParser().parse(tmp_path / "nope") == []


# ---------------------------------------------------------------------------
# IANA cipher-suite reduction
# ---------------------------------------------------------------------------


def test_tls12_suite_reduces_to_its_key_exchange() -> None:
    """A suite name is a composite but an asset carries one algorithm, so it reduces to the KEX —
    breaking the key exchange is what lets a harvest-now-decrypt-later adversary read recorded
    traffic, which makes it the HNDL-relevant component."""
    assert algorithms.resolve("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").canonical == "ECDH-P256"  # type: ignore[union-attr]
    assert algorithms.resolve("TLS_RSA_WITH_AES_256_CBC_SHA").canonical == "RSA"  # type: ignore[union-attr]
    assert algorithms.resolve("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256").canonical == "DH"  # type: ignore[union-attr]


def test_tls13_suite_reduces_to_its_bulk_cipher() -> None:
    """TLS 1.3 suite names carry no key exchange — the group is negotiated separately and reported
    by the network scanner as its own asset — so the bulk cipher is the honest answer."""
    assert algorithms.resolve("TLS_AES_256_GCM_SHA384").canonical == "AES-256"  # type: ignore[union-attr]
    assert algorithms.resolve("TLS_CHACHA20_POLY1305_SHA256").canonical == "ChaCha20-Poly1305"  # type: ignore[union-attr]
