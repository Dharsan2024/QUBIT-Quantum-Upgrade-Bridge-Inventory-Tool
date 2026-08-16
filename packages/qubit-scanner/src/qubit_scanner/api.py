"""Public Python API for the scanner (the contract qubit-api's service layer calls).

``scan_paths`` returns a COMPLETE ``ScanResult`` (non-streaming) per doc 01 §5.2; progress is
reported via an optional callback rather than by yielding.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pathspec

from .catalog import RuleCatalog
from .certs.scanner import CertScanner
from .code import CodeScanner, language_for
from .config.directives import ApacheConfigParser, SshConfigParser
from .config.parsers import NginxConfigParser
from .deps.scanner import ManifestParser
from .models import Detection, ScanError, ScanResult, ScanStats
from .network.active import TlsEnumerator
from .network.auth import (
    ALLOWLIST_PATH,
    AUDIT_LOG_PATH,
    ScanAuthorizationError,
    verify_scan_authorization,
)
from .normalize import normalize
from .secrets import SecretScanner

# Directories never worth scanning.
_DEFAULT_IGNORES = [
    ".git/",
    "node_modules/",
    ".venv/",
    "venv/",
    "dist/",
    "build/",
    "__pycache__/",
    "*.min.js",
]

_MAX_FILE_BYTES = 2_000_000  # 2 MB per-file cap (NFR-8)

# Dependency-manifest filenames the SCA scanner dispatches on (matched by exact name, not suffix).
_MANIFEST_NAMES = {"go.mod", "package.json", "requirements.txt", "pyproject.toml", "pom.xml"}

# Config files whose format is identifiable by name.
_SSH_CONFIG_NAMES = {"sshd_config", "ssh_config"}
_APACHE_CONFIG_NAMES = {"httpd.conf", "apache2.conf", "ssl.conf", "vhost.conf", "000-default.conf"}

ProgressFn = Callable[[str, int, int], None]  # (stage, done, total)


def scan_paths(
    paths: list[Path],
    *,
    scanners: set[str] | None = None,
    catalog: RuleCatalog | None = None,
    repo: str | None = None,
    progress: ProgressFn | None = None,
) -> ScanResult:
    """Scan files and directories for cryptographic assets in source code, configs, and certs."""
    t0 = time.perf_counter()
    catalog = catalog or RuleCatalog.load()
    scanners = scanners or {"code", "config", "cert", "secret", "dependency"}

    code_scanner = CodeScanner(catalog)
    config_scanner = NginxConfigParser()
    apache_scanner = ApacheConfigParser()
    ssh_scanner = SshConfigParser()
    cert_scanner = CertScanner()
    secret_scanner = SecretScanner()
    manifest_scanner = ManifestParser()
    spec = pathspec.PathSpec.from_lines("gitignore", _DEFAULT_IGNORES)

    files = _collect_files(paths, spec)
    result = ScanResult(stats=ScanStats())
    detections: list[Detection] = []

    for i, f in enumerate(files):
        if progress is not None:
            progress("file", i, len(files))

        try:
            if f.stat().st_size > _MAX_FILE_BYTES:
                result.stats.files_skipped += 1
                continue

            # Code scanner
            if "code" in scanners and language_for(f) is not None:
                found = code_scanner.scan_file(f, repo=repo)
                detections.extend(found)
                result.stats.files_scanned += 1

            # Config scanner. Format is chosen by name/suffix rather than content-sniffing: nginx
            # needs crossplane, while Apache and OpenSSH are line-oriented and share a parser style.
            if "config" in scanners and f.suffix in {".conf", ".cnf", ".cfg", ".yaml", ".yml", ""}:
                lowered = f.name.lower()
                if lowered in _SSH_CONFIG_NAMES:
                    found = ssh_scanner.parse(f)
                elif lowered in _APACHE_CONFIG_NAMES or "apache" in lowered or "httpd" in lowered:
                    found = apache_scanner.parse(f)
                else:
                    found = config_scanner.parse(f)
                    if not found:
                        # An unrecognised .conf could still be Apache-style; try it before giving up
                        # rather than losing the file to nginx's stricter grammar.
                        found = apache_scanner.parse(f)
                if found:
                    detections.extend(found)
                    result.stats.files_scanned += 1

            # Cert scanner
            if "cert" in scanners and f.suffix in {".pem", ".crt", ".cer", ".der", ".key"}:
                found = cert_scanner.parse_file(f)
                if found:
                    detections.extend(found)
                    result.stats.files_scanned += 1

            # HNDL exposure-surface scanner: secrets, keys, tokens, PII (beyond crypto algorithms)
            if "secret" in scanners:
                found = secret_scanner.scan_file(f, repo=repo)
                if found:
                    detections.extend(found)

            # Dependency/SCA manifest scanner
            if "dependency" in scanners and f.name in _MANIFEST_NAMES:
                found = manifest_scanner.parse(f)
                if found:
                    detections.extend(found)
                    result.stats.files_scanned += 1

        except Exception as e:  # never let one file abort the scan
            result.errors.append(ScanError(file=str(f), reason=repr(e)))
            result.stats.parse_failures += 1
            continue

    result.stats.detections = len(detections)
    # occurrence ordinal disambiguates identical (rule, algorithm, file) findings deterministically
    seen: dict[tuple[str, str | None, str | None], int] = {}
    for det in detections:
        key = (det.rule_id, det.raw_algorithm, det.location.file_path)
        seen[key] = seen.get(key, 0) + 1
        result.assets.append(normalize(det, occurrence=seen[key]))

    result.stats.assets = len(result.assets)
    result.stats.duration_s = round(time.perf_counter() - t0, 4)
    if progress is not None:
        progress("file", len(files), len(files))
    return result


async def scan_network(
    targets: list[str],
    *,
    ports: list[int] | None = None,
    probe_pqc: bool = True,
    rate_limit: float = 20.0,
    authorized: bool = False,
    allowlist_path: Path | None = None,
    audit_path: Path | None = None,
) -> ScanResult:
    """Active TLS enumeration against targets with doc 06 §13 authorization enforcement."""
    ports = ports or [443]
    t0 = time.perf_counter()
    result = ScanResult(stats=ScanStats())
    detections: list[Detection] = []

    enumerator = TlsEnumerator()

    for target in targets:
        for port in ports:
            verify_scan_authorization(
                target,
                port,
                authorized=authorized,
                allowlist_path=allowlist_path or ALLOWLIST_PATH,
                audit_path=audit_path or AUDIT_LOG_PATH,
            )

            # Active probe A (standard)
            found = await enumerator.enumerate(target, port)
            detections.extend(found)

            # Active probe B (Raw PQC) — probes all 3 standardized hybrid groups internally
            if probe_pqc:
                from .network.clienthello import RawClientHelloProber

                pqc_prober = RawClientHelloProber()
                found_pqc = await pqc_prober.probe_pqc_group(target, port)
                detections.extend(found_pqc)

    result.stats.detections = len(detections)

    seen: dict[tuple[str, str | None, str | None, str | None], int] = {}
    for det in detections:
        key = (det.rule_id, det.raw_algorithm, det.location.host, det.location.service)
        seen[key] = seen.get(key, 0) + 1
        result.assets.append(normalize(det, occurrence=seen[key]))

    result.stats.assets = len(result.assets)
    result.stats.duration_s = round(time.perf_counter() - t0, 4)
    return result


async def scan_vault(
    addr: str,
    token: str,
    *,
    mount_transit: str = "transit",
    mount_pki: str = "pki",
) -> ScanResult:
    """Poll a HashiCorp Vault server's transit/PKI mounts for managed keys and certs (backlog
    item B1). Opt-in only — never runs as part of a default scan; requires an explicit Vault
    address and token. Neither ``scan_paths`` (filesystem) nor ``scan_network`` (TLS-handshake)
    fits this shape, so it's its own entry point — the same design ``scan_network`` itself uses
    (not yet wired into qubit-api's job runner either; both are CLI-only for now)."""
    from .vault.connector import scan_vault as _scan_vault

    t0 = time.perf_counter()
    result = ScanResult(stats=ScanStats())
    detections = await _scan_vault(addr, token, mount_transit=mount_transit, mount_pki=mount_pki)

    result.stats.detections = len(detections)
    seen: dict[tuple[str, str | None, str | None, str | None], int] = {}
    for det in detections:
        key = (det.rule_id, det.raw_algorithm, det.location.host, det.location.service)
        seen[key] = seen.get(key, 0) + 1
        result.assets.append(normalize(det, occurrence=seen[key]))

    result.stats.assets = len(result.assets)
    result.stats.duration_s = round(time.perf_counter() - t0, 4)
    return result


def _collect_files(paths: list[Path], spec: pathspec.PathSpec) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and not spec.match_file(child.relative_to(p).as_posix()):
                    out.append(child)
    return out


__all__ = [
    "ALLOWLIST_PATH",
    "AUDIT_LOG_PATH",
    "ScanAuthorizationError",
    "ScanResult",
    "scan_network",
    "scan_paths",
    "scan_vault",
    "verify_scan_authorization",
]
