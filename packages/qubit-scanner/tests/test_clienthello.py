"""Tests for the raw ClientHello PQC-group prober (Probe B, doc 01 §6.3).

Unit tests exercise the wire-format builder/parser directly with hand-crafted bytes (independent
of the module's own encoding helpers, so the parser isn't just agreeing with itself) — no network,
always run. One integration test spins up the real ``qubit-nginx-hybrid`` image (OpenSSL 3.5,
configured for X25519MLKEM768 only) and proves the byte-crafting is correct against a real server,
not just internally self-consistent.
"""

from __future__ import annotations

import asyncio
import shutil
import struct
import subprocess
import time

import pytest
from qubit_scanner.network.clienthello import (
    HYBRID_GROUPS,
    RawClientHelloProber,
    build_probe_client_hello,
    parse_probe_response,
)

_HRR_MAGIC = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


# ---------------------------------------------------------------------------
# Standalone fixture builders (deliberately not reusing the module's own encoders)
# ---------------------------------------------------------------------------


def _server_hello_record(*, random_value: bytes, extensions: bytes, msg_type: int = 0x02) -> bytes:
    body = (
        struct.pack(">H", 0x0303)  # legacy_version
        + random_value
        + bytes([0])  # empty session_id echo
        + struct.pack(">H", 0x1302)  # cipher_suite
        + bytes([0])  # legacy_compression_method
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = bytes([msg_type]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16]) + struct.pack(">H", 0x0303) + struct.pack(">H", len(handshake)) + handshake


def _hrr_record(selected_group: int) -> bytes:
    key_share_ext = struct.pack(">HH", 0x0033, 2) + struct.pack(">H", selected_group)
    sv_ext = struct.pack(">HH", 0x002B, 2) + struct.pack(">H", 0x0304)
    return _server_hello_record(random_value=_HRR_MAGIC, extensions=sv_ext + key_share_ext)


def _alert_record(level: int, description: int) -> bytes:
    fragment = bytes([level, description])
    return bytes([0x15]) + struct.pack(">H", 0x0303) + struct.pack(">H", len(fragment)) + fragment


# ---------------------------------------------------------------------------
# build_probe_client_hello — structural correctness
# ---------------------------------------------------------------------------


def _parse_extensions(ext_bytes: bytes) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(ext_bytes):
        ext_type, ext_len = struct.unpack(">HH", ext_bytes[pos : pos + 4])
        out[ext_type] = ext_bytes[pos + 4 : pos + 4 + ext_len]
        pos += 4 + ext_len
    return out


def test_build_probe_client_hello_structure() -> None:
    record = build_probe_client_hello("example.com", 0x11EC)

    assert record[0] == 0x16  # ContentType.handshake
    record_len = struct.unpack(">H", record[3:5])[0]
    assert len(record) == 5 + record_len

    handshake = record[5:]
    assert handshake[0] == 0x01  # HandshakeType.client_hello
    hs_len = int.from_bytes(handshake[1:4], "big")
    body = handshake[4 : 4 + hs_len]

    offset = 2 + 32  # legacy_version + random
    session_id_len = body[offset]
    offset += 1 + session_id_len
    cipher_suites_len = struct.unpack(">H", body[offset : offset + 2])[0]
    offset += 2 + cipher_suites_len
    offset += 1 + body[offset]  # compression methods
    ext_len = struct.unpack(">H", body[offset : offset + 2])[0]
    offset += 2
    extensions = _parse_extensions(body[offset : offset + ext_len])

    assert 0x000A in extensions  # supported_groups
    groups_body = extensions[0x000A]
    assert struct.unpack(">H", groups_body[:2])[0] == 2  # exactly one group listed
    assert struct.unpack(">H", groups_body[2:4])[0] == 0x11EC

    assert 0x0033 in extensions  # key_share
    # KeyShareClientHello wraps client_shares<0..2^16-1>: extension_data is just the 2-byte
    # length prefix of that inner vector, which is 0 here (deliberately empty client_shares).
    assert extensions[0x0033] == struct.pack(">H", 0)

    assert 0x002B in extensions  # supported_versions
    assert extensions[0x002B][1:3] == struct.pack(">H", 0x0304)

    assert 0x000D in extensions  # signature_algorithms (mandatory in TLS 1.3)


def test_build_probe_client_hello_embeds_sni() -> None:
    record = build_probe_client_hello("qubit-demo.local", 0x11EB)
    assert b"qubit-demo.local" in record


# ---------------------------------------------------------------------------
# parse_probe_response — the actual detection logic
# ---------------------------------------------------------------------------


def test_hrr_naming_candidate_group_is_confirmed() -> None:
    resp = _hrr_record(0x11EC)
    result = parse_probe_response(resp, candidate_group=0x11EC)
    assert result.confirmed is True
    assert "HelloRetryRequest" in result.reason


def test_hrr_naming_different_group_is_not_confirmed() -> None:
    resp = _hrr_record(0x11EB)  # server wants a different group than we asked about
    result = parse_probe_response(resp, candidate_group=0x11EC)
    assert result.confirmed is False


def test_handshake_failure_alert_is_not_confirmed() -> None:
    resp = _alert_record(level=2, description=40)  # fatal, handshake_failure
    result = parse_probe_response(resp, candidate_group=0x11EC)
    assert result.confirmed is False
    assert "alert" in result.reason


def test_real_server_hello_without_hrr_is_not_confirmed() -> None:
    # A spec-compliant server shouldn't send a full ServerHello given our empty key_share, but
    # the parser must not crash or false-positive if one arrives anyway.
    resp = _server_hello_record(random_value=b"\x01" * 32, extensions=b"")
    result = parse_probe_response(resp, candidate_group=0x11EC)
    assert result.confirmed is False


def test_truncated_response_does_not_crash() -> None:
    for garbage in (b"", b"\x16", b"\x16\x03\x01\x00", b"\x16\x03\x01\x00\x05\x02\x00"):
        result = parse_probe_response(garbage, candidate_group=0x11EC)
        assert result.confirmed is False


def test_hrr_missing_key_share_extension_is_not_confirmed() -> None:
    sv_ext = struct.pack(">HH", 0x002B, 2) + struct.pack(">H", 0x0304)
    resp = _server_hello_record(random_value=_HRR_MAGIC, extensions=sv_ext)
    result = parse_probe_response(resp, candidate_group=0x11EC)
    assert result.confirmed is False
    assert "no-key-share" in result.reason


# ---------------------------------------------------------------------------
# Integration: the real nginx-hybrid image (OpenSSL 3.5, X25519MLKEM768 only)
# ---------------------------------------------------------------------------


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


pytest.importorskip("testcontainers")
if not _docker_up():
    pytest.skip("docker daemon unavailable", allow_module_level=True)

from testcontainers.core.container import DockerContainer  # noqa: E402


@pytest.mark.integration
def test_probe_against_real_nginx_hybrid() -> None:
    """qubit-nginx-hybrid is configured `ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1` —
    exactly one of the three standardized hybrid groups should be confirmed, the other two not."""
    with DockerContainer("qubit-nginx-hybrid:latest").with_exposed_ports(8443) as container:
        time.sleep(2)  # let nginx finish generating its self-signed cert and start listening
        host = container.get_container_host_ip()
        port = int(container.get_exposed_port(8443))

        async def run() -> list:
            return await RawClientHelloProber().probe_pqc_group(host, port)

        detections = asyncio.run(run())

        confirmed = {d.raw_algorithm for d in detections}
        assert confirmed == {"X25519MLKEM768"}
        assert set(HYBRID_GROUPS) - confirmed == {"SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
