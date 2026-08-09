from uuid import uuid4

import httpx
from qubit_core.schemas import CryptoAsset

from qubit_bridge.models import ProbeResult


def _pcap_or_transcript_ref(r: ProbeResult) -> dict:
    # We return the raw transcript as evidence if pcap is not available in the model
    return {"transcript": r.raw_output}


def _canon(alg: str, bits: int | None) -> str:
    if alg and bits:
        return f"{alg}-{bits}"
    return alg or "unknown"


def _is_classical_pk(r: ProbeResult) -> bool:
    # Heuristic for demo
    alg = r.cert_public_key_algorithm
    return alg in ["RSA", "EC", "ECDSA"]


def probe_to_assets(r: ProbeResult) -> list[CryptoAsset]:
    """Convert a ProbeResult to a list of CryptoAssets."""
    proto = CryptoAsset(
        id=uuid4(),
        source_scanner="network",
        location={"host": r.host, "service": f"tcp/{r.port}"},
        asset_type="protocol",
        algorithm=r.negotiated_group or "unknown",
        key_size=None,
        protocol_detail={
            "protocol": "tls",
            "version": r.tls_version,
            "cipher_suites": [r.cipher_suite] if r.cipher_suite else [],
            "group": r.negotiated_group,
            "group_codepoint": r.group_codepoint,
        },
        usage_context="kex",
        quantum_vulnerable={
            "vulnerable": not r.hybrid_pqc,
            "attack": "shor" if not r.hybrid_pqc else "none",
        },
        evidence=_pcap_or_transcript_ref(r),
        discovered_at=r.probed_at,
        risk=None,
        migration=None,
        sensitivity="unknown",
        shelf_life_years=None,
    )

    assets = [proto]
    if r.cert_public_key_algorithm:
        assets.append(
            CryptoAsset(
                id=uuid4(),
                source_scanner="cert",
                location={"host": r.host, "service": f"tcp/{r.port}"},
                asset_type="certificate",
                algorithm=_canon(r.cert_public_key_algorithm, r.cert_public_key_bits),
                key_size=r.cert_public_key_bits,
                usage_context="signature",
                quantum_vulnerable={
                    "vulnerable": _is_classical_pk(r),
                    "attack": "shor" if _is_classical_pk(r) else "none",
                },
                evidence={"cert_fingerprint_sha256": r.cert_fingerprint_sha256},
                discovered_at=r.probed_at,
                risk=None,
                migration=None,
                sensitivity="unknown",
                shelf_life_years=None,
            )
        )
    return assets


def push_assets_to_api(assets: list[CryptoAsset], api_url: str = "http://localhost:8000") -> bool:
    """POST assets to the QUBIT REST API. Returns True on success, False if the push failed.

    Returning a bool (rather than swallowing the error) lets the caller avoid reporting a false
    success when the API is unreachable.
    """
    url = f"{api_url}/api/v1/assets/batch"
    payload = [a.model_dump(mode="json") for a in assets]
    try:
        resp = httpx.post(url, json=payload, timeout=10.0)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        print(f"Warning: Failed to push assets to {url}: {e}")
        return False
    return True
