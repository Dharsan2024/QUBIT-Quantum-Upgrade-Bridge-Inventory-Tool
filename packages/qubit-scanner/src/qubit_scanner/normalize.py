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

# Asymmetric families that can ONLY sign, and families that can ONLY agree a key. These are
# capabilities of the mathematics, not conventions: Ed25519 and ECDSA have no key-agreement
# operation, and ECDH has no signing operation. RSA is absent from both because it genuinely does
# both, and DH is agreement-only but shares its family name with nothing ambiguous.
_SIGNATURE_ONLY_FAMILIES = frozenset({"EdDSA", "ECDSA", "DSA"})
_AGREEMENT_ONLY_FAMILIES = frozenset({"ECDH", "DH"})


def _reconcile_usage_with_algorithm(usage: str, canon: object) -> str:
    """Correct a rule's declared usage when the resolved algorithm makes it impossible.

    A detection rule that captures its algorithm DYNAMICALLY cannot know the usage statically. The
    concrete case: `JS-NODE-GENERATEKEYPAIR-RSA` matches `crypto.generateKeyPairSync(<alg>, …)` and
    hard-codes `usage_context: kex`, but `<alg>` may be `ed25519` or `ec` — signature primitives
    with no key-agreement operation at all. Every such asset was reported as key exchange.

    That is not cosmetic. `usage_context` drives HNDL scoring, and key exchange is the whole
    harvest-now-decrypt-later story: recorded traffic becomes readable once the key exchange breaks,
    whereas a signature cannot be retroactively forged from a recording. Mislabelling a signature as
    kex therefore invents HNDL exposure that does not exist — and it misroutes migration, since
    transform rules match on usage.

    Fixed here rather than per-rule so it holds for every rule, including ones added later.
    """
    family = getattr(canon, "family", None)
    if family is None:
        return usage
    if usage == "kex" and family in _SIGNATURE_ONLY_FAMILIES:
        return "signature"
    if usage == "signature" and family in _AGREEMENT_ONLY_FAMILIES:
        return "kex"
    return usage


def normalize(det: Detection, *, occurrence: int = 1) -> CryptoAsset:
    # HNDL exposure-surface findings (secrets, sensitive data) aren't crypto algorithms — skip the
    # algorithm registry and label them by what they are, so they don't become "UNKNOWN(...)".
    if det.asset_type in {"secret", "sensitive-data"}:
        algorithm = det.raw_algorithm  # e.g. "AWS Access Key", "Hardcoded password", "PII: email"
        qv = QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none)
        key_size = det.key_size
        canon = None
    else:
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
    usage = _reconcile_usage_with_algorithm(usage, canon)
    asset_type = det.asset_type if det.asset_type in _VALID_ASSET_TYPE else "algorithm-use"
    # Crypto findings drop to "low" when unresolved; HNDL findings keep the detector's confidence.
    is_hndl = det.asset_type in {"secret", "sensitive-data"}
    confidence = det.confidence if (canon is not None or is_hndl) else "low"

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
