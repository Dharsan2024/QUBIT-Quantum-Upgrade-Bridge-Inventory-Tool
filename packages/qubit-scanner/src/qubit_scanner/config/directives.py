"""Line-oriented config parsers for the formats where TLS/SSH posture actually lives.

The config scanner previously understood only nginx, so an Apache-fronted service or any SSH host
configuration was invisible. Apache and OpenSSH configs are simple `Directive value...` lines, so
they need no external parser — which also keeps this dependency-free next to nginx's `crossplane`.

Every parser is best-effort and swallows its own errors: one malformed config must never abort a
bulk scan (doc 01 NFR, matching NginxConfigParser).
"""

from __future__ import annotations

from pathlib import Path

from qubit_core import Location

from qubit_scanner.models import Detection

from .cipherstring import expand_cipher_string

# --- Apache httpd / mod_ssl -------------------------------------------------------------------
# `SSLProtocol -all +TLSv1.2` — tokens may carry +/- prefixes, which are stripped before resolving.
_APACHE_PROTOCOL_DIRECTIVES = {"sslprotocol", "sslproxyprotocol"}
_APACHE_CIPHER_DIRECTIVES = {"sslciphersuite", "sslproxyciphersuite"}
_APACHE_CERT_DIRECTIVES = {"sslcertificatefile", "sslcertificatechainfile", "sslcacertificatefile"}

# --- OpenSSH sshd_config / ssh_config ---------------------------------------------------------
# Comma-separated algorithm lists. Each element is a real algorithm name, so each becomes a finding.
_SSH_LIST_DIRECTIVES: dict[str, tuple[str, str]] = {
    # directive -> (usage_context, rule suffix)
    "ciphers": ("encryption-at-rest", "CIPHERS"),
    "macs": ("token", "MACS"),
    "kexalgorithms": ("kex", "KEX"),
    "hostkeyalgorithms": ("signature", "HOSTKEY"),
    "pubkeyacceptedalgorithms": ("signature", "PUBKEY"),
    "pubkeyacceptedkeytypes": ("signature", "PUBKEY"),
}


def _iter_directives(text: str) -> list[tuple[int, str, str]]:
    """Yield (line_number, lowercased directive, raw value) for each non-comment config line."""
    out: list[tuple[int, str, str]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # Both formats accept `Directive value` and `Directive=value`.
        if "=" in line and " " not in line.split("=", 1)[0]:
            name, _, value = line.partition("=")
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            name, value = parts
        out.append((lineno, name.strip().lower(), value.strip()))
    return out


class ApacheConfigParser:
    """Parses Apache httpd / mod_ssl configuration for TLS posture."""

    def parse(self, file_path: Path) -> list[Detection]:
        detections: list[Detection] = []
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return detections

        try:
            for lineno, name, value in _iter_directives(text):
                loc = Location(file_path=str(file_path), line=lineno)
                if name in _APACHE_PROTOCOL_DIRECTIVES:
                    for token in value.split():
                        # `-all`, `+TLSv1.2`, `all`, `-SSLv3`. A DISABLED protocol is not a finding,
                        # so tokens explicitly turned off with `-` are skipped rather than reported
                        # as present — the opposite would flag a hardened config as vulnerable.
                        if token.startswith("-") or token.lower() in ("all",):
                            continue
                        proto = token.lstrip("+")
                        detections.append(
                            Detection(
                                scanner="config",
                                rule_id="CFG-APACHE-PROTO-001",
                                raw_algorithm=proto,
                                asset_type="protocol",
                                usage_context="tls",
                                location=loc,
                                evidence_snippet=f"{name} {value}",
                            )
                        )
                elif name in _APACHE_CIPHER_DIRECTIVES:
                    for suite in expand_cipher_string(value):
                        detections.append(
                            Detection(
                                scanner="config",
                                rule_id="CFG-APACHE-CIPHERS-001",
                                raw_algorithm=suite,
                                asset_type="protocol",
                                usage_context="tls",
                                location=loc,
                                evidence_snippet=f"{name} {value}",
                            )
                        )
                elif name in _APACHE_CERT_DIRECTIVES:
                    detections.append(
                        Detection(
                            scanner="config",
                            rule_id="CFG-APACHE-CERT-001",
                            raw_algorithm="X.509",
                            asset_type="certificate",
                            usage_context="tls",
                            location=loc,
                            evidence_snippet=f"{name} {value}",
                        )
                    )
        except Exception:
            pass
        return detections


class SshConfigParser:
    """Parses OpenSSH sshd_config / ssh_config algorithm lists."""

    def parse(self, file_path: Path) -> list[Detection]:
        detections: list[Detection] = []
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return detections

        try:
            for lineno, name, value in _iter_directives(text):
                spec = _SSH_LIST_DIRECTIVES.get(name)
                if spec is None:
                    continue
                usage, suffix = spec
                loc = Location(file_path=str(file_path), line=lineno)
                for item in value.split(","):
                    algorithm = item.strip().lstrip("+-^")  # OpenSSH list-modifier prefixes
                    if not algorithm:
                        continue
                    detections.append(
                        Detection(
                            scanner="config",
                            rule_id=f"CFG-SSH-{suffix}-001",
                            raw_algorithm=algorithm,
                            asset_type="protocol",
                            usage_context=usage,
                            location=loc,
                            evidence_snippet=f"{name} {value}",
                        )
                    )
        except Exception:
            pass
        return detections


__all__ = ["ApacheConfigParser", "SshConfigParser"]
