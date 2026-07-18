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
from .config.parsers import NginxConfigParser
from .models import Detection, ScanError, ScanResult, ScanStats
from .network.active import TlsEnumerator
from .normalize import normalize

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
    scanners = scanners or {"code", "config", "cert"}

    code_scanner = CodeScanner(catalog)
    config_scanner = NginxConfigParser()
    cert_scanner = CertScanner()
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

            # Config scanner
            if "config" in scanners and f.suffix in {".conf", ".cnf", ".cfg", ".yaml", ".yml", ""}:
                # Basic heuristic for nginx config
                found = config_scanner.parse(f)
                if found:
                    detections.extend(found)
                    result.stats.files_scanned += 1

            # Cert scanner
            if "cert" in scanners and f.suffix in {".pem", ".crt", ".cer", ".der", ".key"}:
                found = cert_scanner.parse_file(f)
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
) -> ScanResult:
    """Active TLS enumeration against targets."""
    ports = ports or [443]
    t0 = time.perf_counter()
    result = ScanResult(stats=ScanStats())
    detections: list[Detection] = []

    enumerator = TlsEnumerator()

    for target in targets:
        for port in ports:
            # Active probe A (standard)
            found = await enumerator.enumerate(target, port)
            detections.extend(found)

            # Active probe B (Raw PQC)
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


__all__ = ["ScanResult", "scan_network", "scan_paths"]
