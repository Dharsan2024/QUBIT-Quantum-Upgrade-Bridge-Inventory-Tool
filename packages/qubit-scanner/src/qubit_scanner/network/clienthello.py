"""Raw TLS 1.3 ClientHello PQC-group probe (Probe B, doc 01 §6.3): detect hybrid-KEM group
support without a host OpenSSL dependency, and without ever generating a real ML-KEM/X25519 key.

Technique (RFC 8446 §4.1.4): for each candidate hybrid group, send a ClientHello that lists
*only* that one group in ``supported_groups`` but an *empty* ``key_share`` list. A server that
supports the group has no client key share to work with and MUST answer with a
HelloRetryRequest naming the group so the client can retry with a real share; a server that
does not support it has no group in common with the client at all and sends an Alert instead.
We never complete a second round-trip — the HelloRetryRequest itself is the signal we want, so
this needs no key generation, no crypto library, just wire bytes in and wire bytes out.

A HelloRetryRequest is wire-identical to a ServerHello (``msg_type=2``); RFC 8446 §4.1.3
distinguishes it by a fixed magic value in the ``random`` field.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct

from qubit_core import Location

from qubit_scanner.models import Detection

# IANA TLS Supported Groups codepoints for the 3 standardized hybrid KEM groups
# (draft-ietf-tls-ecdhe-mlkem). Source of truth: qubit_bridge/registry.py — duplicated here
# because qubit-scanner cannot import qubit-bridge across the package boundary (frame rule: no
# cross-package private imports). Keep in sync if that registry ever changes.
HYBRID_GROUPS: dict[str, int] = {
    "X25519MLKEM768": 0x11EC,
    "SecP256r1MLKEM768": 0x11EB,
    "SecP384r1MLKEM1024": 0x11ED,
}

# TLS 1.3 cipher suites (RFC 8446 §B.4). Any interoperable set works — the handshake never
# completes far enough for a cipher to actually be used.
_TLS13_CIPHER_SUITES = (0x1301, 0x1302, 0x1303)  # AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305

# A minimal, broadly-accepted signature_algorithms list. TLS 1.3 servers MUST see this
# extension in a ClientHello (RFC 8446 §9.2) or may reject it outright.
# ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256
_SIGNATURE_ALGORITHMS = (0x0403, 0x0804, 0x0401)

_HRR_RANDOM_MAGIC = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

_CONTENT_TYPE_HANDSHAKE = 0x16
_CONTENT_TYPE_ALERT = 0x15
_HANDSHAKE_TYPE_SERVER_HELLO = 0x02
_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_KEY_SHARE = 0x0033

_CONNECT_TIMEOUT = 5.0
_READ_TIMEOUT = 5.0


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def _extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(body)) + body


def build_probe_client_hello(sni: str, group_codepoint: int) -> bytes:
    """Build a TLS 1.3 ClientHello record offering exactly one ``supported_groups`` entry with
    an empty ``key_share`` — see module docstring for why."""
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)  # non-empty "legacy" session id: TLS 1.3 middlebox-compat mode

    cipher_suites = b"".join(_u16(c) for c in _TLS13_CIPHER_SUITES)
    sig_algos = b"".join(_u16(s) for s in _SIGNATURE_ALGORITHMS)
    sni_bytes = sni.encode("ascii")

    extensions = (
        _extension(
            _EXT_SERVER_NAME,
            _u16(len(sni_bytes) + 3) + b"\x00" + _u16(len(sni_bytes)) + sni_bytes,
        )
        + _extension(_EXT_SUPPORTED_VERSIONS, bytes([2]) + _u16(0x0304))  # TLS 1.3 only
        + _extension(_EXT_SUPPORTED_GROUPS, _u16(2) + _u16(group_codepoint))  # exactly one group
        + _extension(_EXT_KEY_SHARE, _u16(0))  # deliberately empty client_shares
        + _extension(_EXT_SIGNATURE_ALGORITHMS, _u16(len(sig_algos)) + sig_algos)
    )

    body = (
        _u16(0x0303)  # legacy_version (TLS 1.2, for compatibility)
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + _u16(len(cipher_suites))
        + cipher_suites
        + bytes([1, 0x00])  # legacy_compression_methods = [null]
        + _u16(len(extensions))
        + extensions
    )

    handshake = bytes([0x01]) + _u24(len(body)) + body  # msg_type = client_hello
    record = bytes([_CONTENT_TYPE_HANDSHAKE]) + _u16(0x0301) + _u16(len(handshake)) + handshake
    return record


class ProbeResult:
    """Outcome of a single group probe, independent of any Detection/network concerns."""

    def __init__(self, *, confirmed: bool, reason: str) -> None:
        self.confirmed = confirmed
        # short human-readable evidence, e.g. "HelloRetryRequest" / "alert(level=2,desc=40)"
        self.reason = reason


def parse_probe_response(data: bytes, candidate_group: int) -> ProbeResult:
    """Interpret one TLS record received in response to :func:`build_probe_client_hello`.

    Only the handshake_failure/illegal_parameter Alert and HelloRetryRequest cases are
    meaningful here; anything else (garbage, a real ServerHello, a truncated record) is treated
    as "not confirmed" rather than raising — this is a best-effort network probe.
    """
    if len(data) < 5:
        return ProbeResult(confirmed=False, reason="short-record")

    content_type = data[0]
    record_len = struct.unpack(">H", data[3:5])[0]
    fragment = data[5 : 5 + record_len]

    if content_type == _CONTENT_TYPE_ALERT:
        if len(fragment) >= 2:
            reason = f"alert(level={fragment[0]},desc={fragment[1]})"
            return ProbeResult(confirmed=False, reason=reason)
        return ProbeResult(confirmed=False, reason="alert")

    if content_type != _CONTENT_TYPE_HANDSHAKE or len(fragment) < 4:
        return ProbeResult(confirmed=False, reason="unexpected-record")

    msg_type = fragment[0]
    hs_len = int.from_bytes(fragment[1:4], "big")
    hs_body = fragment[4 : 4 + hs_len]

    if msg_type != _HANDSHAKE_TYPE_SERVER_HELLO or len(hs_body) < 34:
        return ProbeResult(confirmed=False, reason="not-server-hello")

    server_random = hs_body[2:34]
    if server_random != _HRR_RANDOM_MAGIC:
        # A real ServerHello, not a HelloRetryRequest: the server proceeded despite our empty
        # key_share, which a spec-compliant TLS 1.3 server shouldn't do here. Not a confirmation.
        return ProbeResult(confirmed=False, reason="server-hello-not-hrr")

    offset = 34
    session_id_len = hs_body[offset]
    offset += 1 + session_id_len
    offset += 2  # cipher_suite
    offset += 1  # legacy_compression_method
    if offset + 2 > len(hs_body):
        return ProbeResult(confirmed=False, reason="hrr-truncated")
    ext_total_len = struct.unpack(">H", hs_body[offset : offset + 2])[0]
    offset += 2
    extensions = hs_body[offset : offset + ext_total_len]

    pos = 0
    while pos + 4 <= len(extensions):
        ext_type = struct.unpack(">H", extensions[pos : pos + 2])[0]
        ext_len = struct.unpack(">H", extensions[pos + 2 : pos + 4])[0]
        ext_body = extensions[pos + 4 : pos + 4 + ext_len]
        if ext_type == _EXT_KEY_SHARE and len(ext_body) >= 2:
            selected_group = struct.unpack(">H", ext_body[:2])[0]
            if selected_group == candidate_group:
                return ProbeResult(confirmed=True, reason="HelloRetryRequest")
            reason = f"hrr-selected-other-group(0x{selected_group:04x})"
            return ProbeResult(confirmed=False, reason=reason)
        pos += 4 + ext_len

    return ProbeResult(confirmed=False, reason="hrr-no-key-share-ext")


async def _read_one_record(reader: asyncio.StreamReader) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(5), timeout=_READ_TIMEOUT)
    record_len = struct.unpack(">H", header[3:5])[0]
    fragment = await asyncio.wait_for(reader.readexactly(record_len), timeout=_READ_TIMEOUT)
    return header + fragment


class RawClientHelloProber:
    """Raw TLS ClientHello probe (Probe B): detect PQC hybrid-group support with no OpenSSL
    dependency and no real key generation — see module docstring for the technique."""

    async def probe_pqc_group(self, host: str, port: int) -> list[Detection]:
        """Probe all 3 standardized hybrid groups against ``host:port`` and return one
        Detection per group actually confirmed via HelloRetryRequest."""
        detections: list[Detection] = []
        loc = Location(host=host, service=str(port))

        for group_name, group_codepoint in HYBRID_GROUPS.items():
            result = await self._probe_one(host, port, group_codepoint)
            if result.confirmed:
                detections.append(
                    Detection(
                        scanner="network",
                        rule_id="NET-TLS-GROUP",
                        raw_algorithm=group_name,
                        asset_type="algorithm-use",
                        usage_context="kex",
                        location=loc,
                        evidence_snippet=f"HelloRetryRequest selected_group={group_name}",
                        confidence="high",
                    )
                )

        return detections

    async def _probe_one(self, host: str, port: int, group_codepoint: int) -> ProbeResult:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=_CONNECT_TIMEOUT
            )
        except Exception:
            return ProbeResult(confirmed=False, reason="connect-failed")

        try:
            record = build_probe_client_hello(host, group_codepoint)
            writer.write(record)
            await writer.drain()
            response = await _read_one_record(reader)
            return parse_probe_response(response, group_codepoint)
        except Exception:
            return ProbeResult(confirmed=False, reason="io-error")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
