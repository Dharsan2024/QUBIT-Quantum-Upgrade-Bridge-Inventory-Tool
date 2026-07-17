"""TLS handshake probing using openssl s_client."""

import logging
import re
import subprocess
from datetime import UTC, datetime

from qubit_bridge.models import ProbeResult
from qubit_bridge.registry import codepoint, is_hybrid

logger = logging.getLogger(__name__)


def probe_host(
    host: str,
    port: int = 443,
    *,
    groups: str | None = None,
    sni: str | None = None,
    timeout: float = 10.0,
) -> ProbeResult:
    """Probe the target using openssl s_client to extract TLS handshake facts."""
    
    # We use docker run nginx:alpine to guarantee OpenSSL 3.5.x environment
    # since host OS (Windows/Linux) might have older OpenSSL without X25519MLKEM768 support.
    
    cmd = [
        "docker", "run", "--rm", 
        "nginx:alpine", 
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3",
        "-brief",
        "-servername", sni or host
    ]
    if groups:
        cmd.extend(["-groups", groups])
    
    probed_at = datetime.now(UTC)
    
    try:
        proc = subprocess.run(
            cmd,
            input=b"",  # Empty stdin closes connection immediately after handshake
            capture_output=True,
            timeout=timeout,
            text=True
        )
        raw_output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as e:
        return ProbeResult(
            host=host, port=port, reachable=False,
            error=f"Timeout ({timeout}s)", raw_output=e.stdout.decode() if e.stdout else "",
            probed_at=probed_at
        )
    except Exception as e:
        return ProbeResult(
            host=host, port=port, reachable=False,
            error=str(e), raw_output="",
            probed_at=probed_at
        )
    
    if proc.returncode != 0 and "CONNECTION ESTABLISHED" not in raw_output:
        # It could fail but still print CONNECTION ESTABLISHED if stdin closes and the server resets,
        # but if we don't see it, it's unreachable.
        return ProbeResult(
            host=host, port=port, reachable=False,
            error=f"Connection failed (exit {proc.returncode})", raw_output=raw_output,
            probed_at=probed_at
        )
        
    result = ProbeResult(
        host=host, port=port, reachable=True, raw_output=raw_output, probed_at=probed_at
    )
    
    # Parse output
    # Protocol version: TLSv1.3 or Protocol  : TLSv1.3 or New, TLSv1.3
    m_tls = re.search(r"Protocol(?: version)?\s*:\s*(TLS[^\n]+)", raw_output)
    if not m_tls:
        m_tls = re.search(r"New,\s*(TLS[^,]+)", raw_output)
    if m_tls:
        result.tls_version = m_tls.group(1).strip()
    
    # Negotiated TLS1.3 group: X25519MLKEM768
    m_group = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", raw_output)
    if not m_group:
        m_group = re.search(r"Server Temp Key:\s*(\S+)", raw_output)
    if m_group:
        result.negotiated_group = m_group.group(1).strip()
    
    # Ciphersuite: TLS_AES_256_GCM_SHA384
    m_cipher = re.search(r"Ciphersuite:\s*(\S+)", raw_output)
    if not m_cipher:
        m_cipher = re.search(r"Cipher\s*:\s*(\S+)", raw_output)
    if m_cipher:
        result.cipher_suite = m_cipher.group(1).strip()
        
    # Peer signature type: RSA-PSS
    m_sig = re.search(r"Peer signature type:\s*(.+)", raw_output)
    if m_sig:
        result.peer_signature_type = m_sig.group(1).strip()
        
    # Resolve registry mappings
    result.group_codepoint = codepoint(result.negotiated_group)
    result.hybrid_pqc = is_hybrid(result.negotiated_group)
    
    return result
