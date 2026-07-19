"""Normalize raw ``Detection`` values into canonical ``qubit_core.CryptoAsset`` values:

- resolve the raw algorithm to its canonical form + quantum verdict (via the qubit-core registry)
- redact the evidence snippet (security-critical) BEFORE it is persisted
- compute the stable cross-platform fingerprint

Unknown algorithms are kept (as ``UNKNOWN(...)``) with a low-confidence, not-vulnerable verdict —
the risk engine applies worst-case assumptions later. Nothing is silently dropped.
"""

from __future__ import annotations

import hashlib

from qubit_core import (
    AssetType,
    Confidence,
    CryptoAsset,
    Evidence,
    EvidenceContext,
    LibraryRef,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
    algorithms,
    fingerprint,
    redaction,
)

from .models import Detection

_VALID_USAGE = {u.value for u in UsageContext}
_VALID_ASSET_TYPE = {a.value for a in AssetType}


def normalize(det: Detection, *, occurrence: int = 1) -> CryptoAsset:
    canon = algorithms.resolve(det.raw_algorithm, det.key_size)
    if canon is not None:
        algorithm = canon.canonical
        qv = canon.quantum_vulnerable()
        key_size = det.key_size or canon.key_size
    else:
        algorithm = f"UNKNOWN({det.raw_algorithm})"
        qv = QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none)
        key_size = det.key_size

    clean = redaction.redact_snippet(det.evidence_snippet)
    raw_ctx = det.evidence_context or {}
    context = EvidenceContext(
        symbols=raw_ctx.get("symbols", {}) or {},
        imports=raw_ctx.get("imports", []) or [],
        extra=raw_ctx.get("extra", {}) or {},
    )
    evidence = Evidence(
        snippet=clean,
        snippet_sha256=hashlib.sha256(clean.encode("utf-8")).hexdigest() if clean else None,
        context=context,
    )

    usage = det.usage_context if det.usage_context in _VALID_USAGE else "unknown"
    asset_type = det.asset_type if det.asset_type in _VALID_ASSET_TYPE else "algorithm-use"
    confidence = det.confidence if canon is not None else "low"

    asset = CryptoAsset(
        source_scanner=SourceScanner(det.scanner)
        if det.scanner in {s.value for s in SourceScanner}
        else SourceScanner.code,
        location=det.location,
        asset_type=AssetType(asset_type),
        algorithm=algorithm,
        key_size=key_size,
        usage_context=UsageContext(usage),
        quantum_vulnerable=qv,
        evidence=evidence,
        rule_id=det.rule_id,
        confidence=Confidence(confidence if confidence in {"high", "medium", "low"} else "low"),
        library=LibraryRef(name=det.library_name) if det.library_name else None,
    )
    asset.fingerprint = fingerprint(asset, occurrence=occurrence)
    return asset


__all__ = ["normalize"]
