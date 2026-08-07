"""Scan authorization and audit logging per doc 06 §13 contract."""

from __future__ import annotations

import getpass
import ipaddress
import json
import socket
import time
from pathlib import Path


class ScanAuthorizationError(PermissionError):
    """Raised when a network scan target is outside RFC1918/loopback and not authorized."""


ALLOWLIST_PATH = Path.home() / ".config" / "qubit" / "scan-allowlist.txt"
AUDIT_LOG_PATH = Path.home() / ".local" / "state" / "qubit" / "scan-audit.log"


def is_rfc1918_or_loopback(host: str) -> bool:
    """Return True if host resolves to an RFC1918 private address or loopback."""
    if host.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except Exception:
        return False


def load_allowlist(path: Path = ALLOWLIST_PATH) -> set[str]:
    """Load authorized targets/IPs/domains from the allowlist file."""
    if not path.is_file():
        return set()
    entries = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line.lower())
    return entries


def write_audit_log(
    target: str,
    port: int,
    *,
    authorized: bool,
    allowed: bool,
    audit_path: Path = AUDIT_LOG_PATH,
) -> None:
    """Append a JSON audit entry for every network scan attempt."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": target,
        "port": port,
        "user": getpass.getuser(),
        "authorized_flag": authorized,
        "allowed": allowed,
    }
    with audit_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def verify_scan_authorization(
    target: str,
    port: int = 443,
    *,
    authorized: bool = False,
    allowlist_path: Path = ALLOWLIST_PATH,
    audit_path: Path = AUDIT_LOG_PATH,
) -> None:
    """Verify target authorization per doc 06 §13 contract.

    Target is allowed if:
    1. Host is RFC1918 private or loopback (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, ::1).
    2. Host matches an entry in scan-allowlist.txt AND authorized=True is passed.

    Appends JSON entry to scan-audit.log for every attempt.
    """
    if is_rfc1918_or_loopback(target):
        write_audit_log(target, port, authorized=authorized, allowed=True, audit_path=audit_path)
        return

    # Public / non-RFC1918 target
    allowlist = load_allowlist(allowlist_path)
    target_lower = target.lower()

    in_allowlist = target_lower in allowlist
    if not in_allowlist:
        try:
            ip_str = socket.gethostbyname(target)
            if ip_str.lower() in allowlist:
                in_allowlist = True
        except Exception:
            pass

    allowed = in_allowlist and authorized
    write_audit_log(target, port, authorized=authorized, allowed=allowed, audit_path=audit_path)

    if not allowed:
        if not authorized:
            reason = "the --authorized flag was not supplied"
        else:
            reason = f"target '{target}' is not listed in {allowlist_path}"
        msg = (
            f"Network scan of target '{target}:{port}' refused: "
            f"target outside RFC1918 and {reason}."
        )
        raise ScanAuthorizationError(msg)
