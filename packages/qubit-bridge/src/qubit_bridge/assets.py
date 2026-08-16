import os
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


# API base URLs tried in order when none is given. `qubit serve` binds 8000; the docker-compose
# stack deliberately does NOT publish the API port and instead reaches it through the dashboard's
# nginx on 8080, which proxies /api/v1 — so the single hardcoded 8000 could never work under
# compose.
_API_CANDIDATES = ("http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:8080")


def discover_api_url(timeout: float = 2.0) -> str | None:
    """First reachable QUBIT API base URL, or None.

    ``QUBIT_API_URL`` overrides the probe entirely, which is what a non-local deployment needs.
    """
    override = os.environ.get("QUBIT_API_URL")
    if override:
        return override.rstrip("/")
    for base in _API_CANDIDATES:
        try:
            if httpx.get(f"{base}/api/v1/health", timeout=timeout).status_code == 200:
                return base
        except httpx.HTTPError:
            continue
    return None


def push_assets_to_api(
    assets: list[CryptoAsset],
    api_url: str | None = None,
    *,
    token: str | None = None,
    project: str = "bridge",
    label: str | None = None,
    targets: list[str] | None = None,
) -> bool:
    """POST assets to the QUBIT REST API. Returns True on success, False if the push failed.

    Returning a bool (rather than swallowing the error) lets the caller avoid reporting a false
    success when the API is unreachable.

    Three things were wrong here and each one alone was enough to guarantee failure:

    * the target endpoint ``POST /api/v1/assets/batch`` **did not exist**, so a reachable API
      answered 404 — the push could never have succeeded on any port;
    * no ``Authorization`` header was sent, and every non-health route requires a bearer token, so
    it would have been 401 even once the route existed; * the base URL was hardcoded to
    ``localhost:8000``, which is right for ``qubit serve`` and wrong under docker-compose, where the
    API is reachable only via the dashboard proxy on 8080.

    The reported symptom — "Assets not pushed (API unreachable)" — named only the third of those, so
    the message was misleading as well as the behaviour being broken.
    """
    base = (api_url or discover_api_url() or _API_CANDIDATES[0]).rstrip("/")
    url = f"{base}/api/v1/assets/batch"
    headers = {"Authorization": f"Bearer {token or os.environ.get('QUBIT_API_TOKEN', '')}"}
    payload = {
        "assets": [a.model_dump(mode="json") for a in assets],
        "project": project,
        "label": label,
        "targets": targets or [],
    }
    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=10.0)
        resp.raise_for_status()
    except httpx.HTTPError as e:
        print(f"Warning: Failed to push assets to {url}: {e}")
        return False
    return True
