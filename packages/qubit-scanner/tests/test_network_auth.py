import asyncio
import json

import pytest
from qubit_scanner.api import ScanAuthorizationError, scan_network, verify_scan_authorization
from qubit_scanner.network.auth import is_rfc1918_or_loopback


def test_is_rfc1918_or_loopback() -> None:
    assert is_rfc1918_or_loopback("localhost") is True
    assert is_rfc1918_or_loopback("127.0.0.1") is True
    assert is_rfc1918_or_loopback("10.0.0.1") is True
    assert is_rfc1918_or_loopback("192.168.1.100") is True
    assert is_rfc1918_or_loopback("172.16.0.5") is True
    assert is_rfc1918_or_loopback("::1") is True
    assert is_rfc1918_or_loopback("8.8.8.8") is False


def test_authorization_rfc1918_auto_approved(tmp_path) -> None:
    audit_file = tmp_path / "scan-audit.log"
    verify_scan_authorization("127.0.0.1", 443, audit_path=audit_file)

    assert audit_file.is_file()
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["target"] == "127.0.0.1"
    assert record["allowed"] is True


def test_authorization_public_refused_without_authorized_flag(tmp_path) -> None:
    audit_file = tmp_path / "scan-audit.log"
    allow_file = tmp_path / "allowlist.txt"

    with pytest.raises(ScanAuthorizationError, match="authorized flag was not supplied"):
        verify_scan_authorization(
            "8.8.8.8", 443, authorized=False, allowlist_path=allow_file, audit_path=audit_file
        )

    assert audit_file.is_file()
    record = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
    assert record["target"] == "8.8.8.8"
    assert record["allowed"] is False


def test_authorization_public_refused_if_not_in_allowlist(tmp_path) -> None:
    audit_file = tmp_path / "scan-audit.log"
    allow_file = tmp_path / "allowlist.txt"
    allow_file.write_text("other-domain.com\n", encoding="utf-8")

    with pytest.raises(ScanAuthorizationError, match="not listed in"):
        verify_scan_authorization(
            "8.8.8.8", 443, authorized=True, allowlist_path=allow_file, audit_path=audit_file
        )


def test_authorization_public_allowed_when_listed_and_authorized(tmp_path) -> None:
    audit_file = tmp_path / "scan-audit.log"
    allow_file = tmp_path / "allowlist.txt"
    allow_file.write_text("8.8.8.8\nexample.com\n", encoding="utf-8")

    verify_scan_authorization(
        "8.8.8.8", 443, authorized=True, allowlist_path=allow_file, audit_path=audit_file
    )

    record = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
    assert record["target"] == "8.8.8.8"
    assert record["allowed"] is True
    assert record["authorized_flag"] is True


def test_scan_network_refuses_unauthorized_public_target(tmp_path) -> None:
    audit_file = tmp_path / "scan-audit.log"
    allow_file = tmp_path / "allowlist.txt"

    with pytest.raises(ScanAuthorizationError):
        asyncio.run(
            scan_network(
                ["8.8.8.8"],
                ports=[443],
                authorized=False,
                allowlist_path=allow_file,
                audit_path=audit_file,
            )
        )
