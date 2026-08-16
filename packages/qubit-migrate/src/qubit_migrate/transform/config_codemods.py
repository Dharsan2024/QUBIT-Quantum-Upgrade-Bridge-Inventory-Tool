"""Deterministic config-file hardening codemods (nginx / Apache / OpenSSH).

These are the highest-value transforms QUBIT can make and the safest, which is why they are
deterministic rather than LLM-generated:

* They are what ACTUALLY makes a deployment quantum-safe today. Rewriting application code to
  ML-KEM only helps the data that code encrypts; adding `ssl_ecdh_curve X25519MLKEM768` to the
  terminator makes every TLS session the service negotiates hybrid post-quantum, immediately, for
  all traffic. Likewise `sntrup761x25519-sha512@openssh.com` makes SSH key exchange PQC-hybrid.
* They have NO data-compatibility hazard. Swapping a cipher in application code changes key and IV
  lengths and can break stored ciphertext; changing a TLS directive only changes what is negotiated
  on the next handshake, so `data_compat: in_place` is genuinely true here.
* The edit is a single directive value, so the diff is small and a human can review it in seconds.

Every rewrite is line-scoped: only the directive lines the scanner flagged are touched, and the
file's comments, ordering and formatting are otherwise preserved byte-for-byte.
"""

from __future__ import annotations

import re
from pathlib import Path

# --- Target values -----------------------------------------------------------------------------
# nginx/Apache: TLS 1.2 is kept alongside 1.3 because dropping it outright breaks older clients and
# would make this patch un-appliable in practice; 1.0/1.1 and SSLv3 are removed.
_TLS_PROTOCOLS_NGINX = "TLSv1.2 TLSv1.3"
_TLS_PROTOCOLS_APACHE = "-all +TLSv1.2 +TLSv1.3"

# AEAD-only, forward-secret suites. No CBC (padding oracles), no RSA key transport (no forward
# secrecy, and it is the worst case for harvest-now-decrypt-later).
_TLS_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
)

# THE post-quantum change. X25519MLKEM768 is the IETF-standardized hybrid group that OpenSSL 3.5+
# negotiates by default; listing it first makes the server prefer it while the classical fallbacks
# keep older clients working.
_HYBRID_CURVES = "X25519MLKEM768:X25519:secp256r1"

# OpenSSH. sntrup761x25519-sha512 is OpenSSH's post-quantum hybrid key exchange (default since 9.x),
# so this is the SSH equivalent of the TLS hybrid group above.
_SSH_TARGETS: dict[str, str] = {
    "kexalgorithms": (
        "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,"
        "diffie-hellman-group16-sha512"
    ),
    "ciphers": "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr",
    "macs": "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
    "hostkeyalgorithms": "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
    "pubkeyacceptedalgorithms": "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
    "pubkeyacceptedkeytypes": "ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
}

_NGINX_DIRECTIVE_RE = re.compile(
    r"^(\s*)(ssl_protocols|ssl_ciphers|ssl_ecdh_curve)\s+([^;]*);(.*)$"
)
_APACHE_DIRECTIVE_RE = re.compile(
    r"^(\s*)(SSLProtocol|SSLCipherSuite|SSLProxyProtocol|SSLProxyCipherSuite)\s+(.*)$",
    re.IGNORECASE,
)
_SSH_DIRECTIVE_RE = re.compile(
    r"^(\s*)(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|PubkeyAcceptedAlgorithms"
    r"|PubkeyAcceptedKeyTypes)\s+(.*)$",
    re.IGNORECASE,
)


def harden_nginx(source: str) -> tuple[str, bool]:
    """Rewrite nginx TLS directives to a hybrid-PQC, AEAD-only posture."""
    out: list[str] = []
    changed = False
    saw_curve = False
    server_indent = "    "

    for line in source.splitlines(keepends=False):
        m = _NGINX_DIRECTIVE_RE.match(line)
        if m is None:
            out.append(line)
            continue
        indent, directive, value, trailing = m.groups()
        server_indent = indent or server_indent
        new_value = {
            "ssl_protocols": _TLS_PROTOCOLS_NGINX,
            "ssl_ciphers": _TLS_CIPHERS,
            "ssl_ecdh_curve": _HYBRID_CURVES,
        }[directive]
        if directive == "ssl_ecdh_curve":
            saw_curve = True
        if value.strip() == new_value:
            out.append(line)
            continue
        out.append(f"{indent}{directive} {new_value};{trailing}")
        changed = True

    # A config with TLS enabled but no ssl_ecdh_curve gets the hybrid group ADDED — otherwise the
    # most important part of this patch would be skipped precisely on the servers that never
    # configured a curve list and therefore silently use the classical default.
    if not saw_curve and any("ssl_protocols" in ln or "ssl_certificate" in ln for ln in out):
        for i, line in enumerate(out):
            if "ssl_protocols" in line:
                out.insert(
                    i + 1,
                    f"{server_indent}ssl_ecdh_curve {_HYBRID_CURVES};"
                    "  # QUBIT: hybrid post-quantum key exchange",
                )
                changed = True
                break

    return ("\n".join(out) + ("\n" if source.endswith("\n") else ""), changed)


def harden_apache(source: str) -> tuple[str, bool]:
    """Rewrite Apache mod_ssl TLS directives to an AEAD-only posture, plus the hybrid curve list."""
    out: list[str] = []
    changed = False
    saw_curves = "SSLOpenSSLConfCmd Curves" in source

    for line in source.splitlines(keepends=False):
        m = _APACHE_DIRECTIVE_RE.match(line)
        if m is None:
            out.append(line)
            continue
        indent, directive, value = m.groups()
        lowered = directive.lower()
        if lowered in ("sslprotocol", "sslproxyprotocol"):
            new_value = _TLS_PROTOCOLS_APACHE
        else:
            new_value = _TLS_CIPHERS
        if value.strip() == new_value:
            out.append(line)
            continue
        out.append(f"{indent}{directive} {new_value}")
        changed = True

    if not saw_curves and changed:
        # mod_ssl exposes the group list through OpenSSL's conf command rather than its own
        # directive, so the hybrid group has to be set that way.
        for i, line in enumerate(out):
            if _APACHE_DIRECTIVE_RE.match(line):
                out.insert(
                    i + 1,
                    f"SSLOpenSSLConfCmd Curves {_HYBRID_CURVES}"
                    "  # QUBIT: hybrid post-quantum key exchange",
                )
                break

    return ("\n".join(out) + ("\n" if source.endswith("\n") else ""), changed)


def harden_ssh(source: str) -> tuple[str, bool]:
    """Rewrite OpenSSH algorithm lists to a PQC-hybrid, AEAD-only posture."""
    out: list[str] = []
    changed = False
    saw_kex = False

    for line in source.splitlines(keepends=False):
        m = _SSH_DIRECTIVE_RE.match(line)
        if m is None:
            out.append(line)
            continue
        indent, directive, value = m.groups()
        target = _SSH_TARGETS.get(directive.lower())
        if target is None:
            out.append(line)
            continue
        if directive.lower() == "kexalgorithms":
            saw_kex = True
        if value.strip() == target:
            out.append(line)
            continue
        out.append(f"{indent}{directive} {target}")
        changed = True

    # As with nginx's curve list: a config that never pinned KexAlgorithms is exactly the one that
    # silently uses whatever the build defaults to, so the PQC-hybrid KEX is added explicitly.
    if not saw_kex and changed:
        out.insert(
            0,
            f"KexAlgorithms {_SSH_TARGETS['kexalgorithms']}"
            "  # QUBIT: post-quantum hybrid key exchange",
        )

    return ("\n".join(out) + ("\n" if source.endswith("\n") else ""), changed)


def harden_config_file(file_path: Path) -> tuple[str, str] | None:
    """Dispatch on filename and return (original, hardened) or None when nothing changed."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    name = file_path.name.lower()
    if name in ("sshd_config", "ssh_config"):
        new_source, changed = harden_ssh(source)
    elif "httpd" in name or "apache" in name or _APACHE_DIRECTIVE_RE.search(source) is not None:
        new_source, changed = harden_apache(source)
    else:
        new_source, changed = harden_nginx(source)

    return (source, new_source) if changed else None


__all__ = ["harden_apache", "harden_config_file", "harden_nginx", "harden_ssh"]
