"""Export a set of ``CryptoAsset`` values as a CycloneDX 1.7 Cryptographic Bill of Materials (CBOM).

The DB is the source of truth; the CBOM is the exportable compliance artifact (ECMA-424 / CycloneDX
1.7). This is an in-house serializer that emits the 1.7 structure directly — the JSON Schema (not a
third-party model layer) is the compatibility contract, because third-party crypto-property coverage
historically lags the spec (doc 01 §11.3).

Evidence is omitted by default (``include_evidence=False``) — the redaction guarantee means the
snippet is already scrubbed, but the compliance artifact still should not carry source by default.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from .. import algorithms
from ..schemas import AssetType, CryptoAsset, utcnow

CYCLONEDX_SPEC_VERSION = "1.7"
_FIXED_TIMESTAMP = "1970-01-01T00:00:00Z"  # used in reproducible mode

# CryptoAsset.asset_type -> CycloneDX cryptoProperties.assetType
_ASSET_TYPE_MAP = {
    AssetType.algorithm_use: "algorithm",
    AssetType.protocol: "protocol",
    AssetType.certificate: "certificate",
    AssetType.key: "related-crypto-material",
    AssetType.library: "related-crypto-material",
}

# valid CycloneDX 1.7 execution environments
_EXEC_ENV = "software-plain-ram"


def _primitive(family: str | None, kind: str | None, usage: str) -> str:
    """Map to a CycloneDX ``algorithmProperties.primitive`` enum value."""
    if kind == "hash":
        return "hash"
    if kind == "pqc-kem":
        return "kem"
    if kind == "pqc-sig":
        return "signature"
    if kind == "symmetric":
        return "block-cipher"
    if kind == "protocol":  # hybrid KEM group
        return "kem"
    if kind == "asymmetric":
        if family in ("ECDH", "DH", "EC"):
            return "key-agree"
        if usage == "signature":
            return "signature"
        if usage == "kex":
            return "pke"  # RSA key transport
        return "pke"
    return "unknown"


def _crypto_functions(usage: str) -> list[str]:
    return {
        "signature": ["sign"],
        "hash": ["digest"],
        "kex": ["keygen"],
        "encryption-at-rest": ["encrypt"],
        "tls": ["keygen"],
    }.get(usage, [])


def _component(asset: CryptoAsset, *, include_evidence: bool) -> dict[str, Any]:
    canon = algorithms.get(asset.algorithm)
    usage = asset.usage_context.value
    asset_type = _ASSET_TYPE_MAP.get(asset.asset_type, "related-crypto-material")

    crypto_props: dict[str, Any] = {"assetType": asset_type}
    if asset_type == "algorithm":
        algo_props: dict[str, Any] = {
            "primitive": _primitive(
                canon.family if canon else None, canon.kind if canon else None, usage
            ),
            "executionEnvironment": _EXEC_ENV,
        }
        if asset.key_size is not None:
            algo_props["parameterSetIdentifier"] = str(asset.key_size)
        funcs = _crypto_functions(usage)
        if funcs:
            algo_props["cryptoFunctions"] = funcs
        if canon and canon.classical_security_level is not None:
            algo_props["classicalSecurityLevel"] = canon.classical_security_level
        if canon and canon.nist_quantum_security_level is not None:
            algo_props["nistQuantumSecurityLevel"] = canon.nist_quantum_security_level
        crypto_props["algorithmProperties"] = algo_props
    if canon and canon.oid:
        crypto_props["oid"] = canon.oid

    # qubit-namespaced properties carry risk/verdict/provenance without polluting spec fields
    props: list[dict[str, str]] = [
        {
            "name": "qubit:quantum-vulnerable",
            "value": str(asset.quantum_vulnerable.vulnerable).lower(),
        },
        {"name": "qubit:quantum-attack", "value": asset.quantum_vulnerable.attack.value},
        {"name": "qubit:usage-context", "value": usage},
        {"name": "qubit:source-scanner", "value": asset.source_scanner.value},
        {"name": "qubit:confidence", "value": asset.confidence.value},
    ]
    if asset.fingerprint:
        props.append({"name": "qubit:fingerprint", "value": asset.fingerprint})
    if asset.rule_id:
        props.append({"name": "qubit:rule-id", "value": asset.rule_id})
    if asset.risk is not None:
        props.append({"name": "qubit:risk-score", "value": f"{asset.risk.score:.4f}"})
        props.append(
            {"name": "qubit:mosca-margin-years", "value": f"{asset.risk.mosca_margin_years:.2f}"}
        )

    # Key the component on the stable fingerprint (not the random uuid id) so re-scanning the same
    # code yields a byte-identical CBOM — required for the paper's reproducible artifacts.
    ref = asset.fingerprint or asset.id.hex
    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": f"urn:qubit:asset:{ref}",
        "name": asset.algorithm,
        "cryptoProperties": crypto_props,
        "properties": props,
    }
    if asset.library is not None:
        component["publisher"] = asset.library.name

    loc = asset.location
    if include_evidence and (loc.file_path or loc.host):
        where = loc.file_path or f"{loc.host}:{loc.service or ''}"
        occ: dict[str, Any] = {"location": where}
        if loc.line is not None:
            occ["line"] = loc.line
        component["evidence"] = {"occurrences": [occ]}
    return component


def export_cbom(
    assets: list[CryptoAsset],
    *,
    reproducible: bool = False,
    include_evidence: bool = False,
    serial_number: str | None = None,
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    """Build a CycloneDX 1.7 CBOM document (as a dict) from ``assets``.

    ``reproducible=True`` pins the timestamp and drops the random serial so the output is
    byte-identical across runs (for the paper's reproducible experiments).
    """
    components = [_component(a, include_evidence=include_evidence) for a in assets]
    components.sort(key=lambda c: c["bom-ref"])  # deterministic ordering

    if reproducible:
        serial = "urn:uuid:00000000-0000-0000-0000-000000000000"
        timestamp = _FIXED_TIMESTAMP
    else:
        serial = serial_number or f"urn:uuid:{uuid4()}"
        timestamp = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [{"type": "application", "name": "qubit", "version": tool_version}]
            },
        },
        "components": components,
    }


def validate_cbom_structure(doc: dict[str, Any]) -> list[str]:
    """Lightweight structural validation (required fields + enum sanity). Returns a list of problems
    (empty == OK). Full JSON-Schema validation against the vendored official 1.7 schema is a planned
    follow-up; this catches the mistakes an in-house serializer can actually make.
    """
    problems: list[str] = []
    if doc.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be 'CycloneDX'")
    if doc.get("specVersion") != CYCLONEDX_SPEC_VERSION:
        problems.append(f"specVersion must be '{CYCLONEDX_SPEC_VERSION}'")
    if not str(doc.get("serialNumber", "")).startswith("urn:uuid:"):
        problems.append("serialNumber must be a urn:uuid:")
    if not isinstance(doc.get("components"), list):
        problems.append("components must be a list")
        return problems
    valid_asset_types = {"algorithm", "certificate", "protocol", "related-crypto-material"}
    for i, c in enumerate(doc["components"]):
        if c.get("type") != "cryptographic-asset":
            problems.append(f"components[{i}].type must be 'cryptographic-asset'")
        if not c.get("bom-ref"):
            problems.append(f"components[{i}] missing bom-ref")
        at = c.get("cryptoProperties", {}).get("assetType")
        if at not in valid_asset_types:
            problems.append(f"components[{i}].cryptoProperties.assetType invalid: {at!r}")
    return problems


__all__ = ["CYCLONEDX_SPEC_VERSION", "export_cbom", "validate_cbom_structure"]
