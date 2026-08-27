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
    weaknesses,
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

#: Families that genuinely do BOTH, so the mathematics cannot settle the usage and the surrounding
#: code has to. RSA is the whole list: it signs and it transports keys, and a detection rule that
#: matches a constructor cannot know which.
_AMBIGUOUS_FAMILIES = frozenset({"RSA"})

#: Words in an enclosing function or class name that say what the key is FOR. Deliberately narrow
#: - each one has to be unambiguous on its own, because a wrong reclassification sends the finding
#: to the wrong migration rule and the rule will confidently carry it out.
#: The operation vocabulary the scanner records in `scope_operations`, mapped to what it implies.
#: Kept here rather than imported from the scanner's tree-sitter layer so this module stays a pure
#: classifier over recorded facts.
_OPERATION_USAGE: dict[str, str] = {
    "sign": "signature",
    "signdata": "signature",
    "signhash": "signature",
    "createsignature": "signature",
    "verifydata": "signature",
    "verifyhash": "signature",
    "verifysignature": "signature",
    "signpkcs1v15": "signature",
    "verifypkcs1v15": "signature",
    "signpss": "signature",
    "verifypss": "signature",
    "encrypt": "kex",
    "decrypt": "kex",
    "encryptoaep": "kex",
    "decryptoaep": "kex",
    "wrapkey": "kex",
    "unwrapkey": "kex",
    "encapsulate": "kex",
    "decapsulate": "kex",
}

_SIGNING_WORDS = ("sign", "signer", "signing", "signature", "verify", "verifier", "attest")
_TRANSPORT_WORDS = ("encrypt", "decrypt", "wrap", "unwrap", "keyexchange", "exchange", "kem")


def _usage_from_surroundings(extra: dict[str, object]) -> str | None:
    """What the enclosing function and class say this key is for, or None if they say nothing.

    The scanner already records `enclosing_function` and `enclosing_class` on every code finding
    and nothing read them. Measured cost of that: a C# class named `InvoiceSigner`, whose
    constructor calls `new RSACryptoServiceProvider(1024)`, was classified `kex` — so `code-kex-01`
    claimed it, targeted ML-KEM-768, and the model produced a "migration" replacing a signing key
    with a key-encapsulation mechanism. Every stage passed it: the file parsed, RSA was gone and
    ML-KEM was present, which is all the rescan asks. A human would not have made that mistake for
    a second, and the evidence needed to avoid it was already in the finding.

    Signing is checked first. `verify` appears in both vocabularies and belongs to signatures;
    nothing in the transport list is a plausible name for a signing routine.
    """
    # What is DONE with the key outranks what anything is CALLED. This is the signal CogniCrypt
    # and CryptoGuard derive from typestate and data-flow analysis: a key passed to `SignData` is
    # a signing key however its class is named, and a class named `Thing` gives no name signal at
    # all while its operations give a decisive one.
    operations = str(extra.get("scope_operations", ""))
    if operations:
        verdicts = {_OPERATION_USAGE[op] for op in operations.split(",") if op in _OPERATION_USAGE}
        # Only when the scope is unanimous. A class that both signs and encrypts with the same
        # field is genuinely ambiguous, and guessing there would be worse than deferring to the
        # names below.
        if len(verdicts) == 1:
            return verdicts.pop()

    # The FUNCTION is asked next and answered alone if it says anything. It is the more local
    # fact: a `TokenVerifier` class with an `EncryptPayload` method is doing key transport in that
    # method whatever the class is called, and letting the class name outvote it would relabel the
    # one call site that was unambiguous.
    for key in ("enclosing_function", "enclosing_class"):
        name = str(extra.get(key, "")).lower()
        if not name:
            continue
        if any(word in name for word in _SIGNING_WORDS):
            return "signature"
        if any(word in name for word in _TRANSPORT_WORDS):
            return "kex"
    return None


def _reconcile_usage_with_algorithm(
    usage: str, canon: object, extra: dict[str, object] | None = None
) -> str:
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
    # RSA does both, so the mathematics settles nothing and the surrounding code has to. Only
    # applied when the two DISAGREE — a rule that already said `signature` for a signing routine
    # needs no help, and the reclassification is what decides which migration rule claims the
    # finding, so it must not fire on agreement.
    if family in _AMBIGUOUS_FAMILIES and usage in {"kex", "signature", "unknown"}:
        surrounding = _usage_from_surroundings(extra or {})
        if surrounding is not None and surrounding != usage:
            return surrounding
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
    usage = det.usage_context if det.usage_context in _VALID_USAGE else "unknown"
    usage = _reconcile_usage_with_algorithm(usage, canon, context.extra)

    # Classical weaknesses of the CALL, not of the algorithm name. The registry cannot see these:
    # it knows AES-256 is a sound cipher and has no way to know this call runs it in ECB, or that
    # this PBKDF2 was handed 1 000 iterations. They are derived from the facts the detection rule
    # captured at the site (`mode`, `padding`, `iterations`, `prf`) and recorded on the evidence,
    # where the migration layer matches rules against them and the UI can cite their authority.
    #
    # A finding that carries one is marked vulnerable even when its primitive is not. That is the
    # same convention the registry already uses for MD5 and SHA-1 - flagged `vulnerable=True`
    # although their real problem is classical collisions, not Grover - and it is the difference
    # between reporting AES-256/ECB and silently passing it.
    found = weaknesses.derive(
        algorithm=algorithm,
        family=getattr(canon, "family", None),
        key_size=key_size,
        usage_context=usage,
        extra=context.extra,
    )
    if found:
        context.extra["weaknesses"] = [w.as_dict() for w in found]
        if not qv.vulnerable:
            qv = QuantumVulnerability(vulnerable=True, attack=QuantumAttack.none)
    evidence = Evidence(
        snippet=clean,
        snippet_sha256=hashlib.sha256(clean.encode("utf-8")).hexdigest() if clean else None,
        context=context,
    )

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
