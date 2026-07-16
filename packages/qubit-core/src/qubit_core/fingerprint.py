"""Deterministic, cross-platform asset fingerprints.

The fingerprint is the stable cross-scan identity of an asset — it powers dedup, trend queries,
scan diffs, and the phase-4 "the vulnerable asset is gone" remediation proof. It MUST be identical
whether the same repo is scanned from a Windows host or a Linux container, so every path component
is normalized to POSIX form (and casefolded) before hashing (doc 01 §6.5; BUILD_PLAN §4.5).

Line numbers are deliberately excluded for code assets (lines drift); a per-scan occurrence ordinal
disambiguates multiple same-algorithm findings in one file.
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath, PureWindowsPath

from .schemas import CryptoAsset, SourceScanner


def _posix(path: str | None) -> str:
    """Normalize any path (Windows or POSIX) to a casefolded POSIX string."""
    if not path:
        return ""
    # Interpret backslashes as Windows separators, then emit POSIX.
    p = PureWindowsPath(path) if "\\" in path else PurePosixPath(path)
    return p.as_posix().casefold()


def fingerprint(asset: CryptoAsset, *, occurrence: int = 1) -> str:
    """Return a 16-hex stable identity for ``asset``.

    ``occurrence`` disambiguates identical (scanner, algorithm, file) findings within one scan;
    callers assign it deterministically in file/scan order at ingest time.
    """
    loc = asset.location
    if asset.source_scanner in (SourceScanner.code, SourceScanner.config):
        where = f"{loc.repo or ''}:{_posix(loc.file_path)}"
    elif asset.source_scanner == SourceScanner.network:
        proto = asset.protocol_detail.protocol if asset.protocol_detail else "?"
        # protocol asset keyed by endpoint+algorithm so an endpoint offering both a classical and a
        # hybrid group yields two distinct assets with distinct verdicts.
        where = f"{loc.host or ''}:{loc.service or ''}:{proto}:{asset.algorithm}"
    else:  # cert | key — content fingerprint in the evidence is already stable
        where = (asset.evidence.snippet or "").splitlines()[0] if asset.evidence.snippet else ""

    raw = "|".join(
        (
            asset.source_scanner.value,
            asset.asset_type.value,
            asset.algorithm,
            asset.usage_context.value,
            where,
            str(occurrence),
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


__all__ = ["fingerprint"]
