from unittest.mock import MagicMock, patch

from qubit_bridge.probe import probe_host

GOLDEN_OUTPUT = """
CONNECTED(00000003)
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 235 bytes and written 396 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 
    Session-ID-ctx: 
    Resumed   : no
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Negotiated TLS1.3 group: X25519MLKEM768
    Peer signature type: RSA-PSS
    Server Temp Key: X25519MLKEM768
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket max early data: 0 (bytes)
"""


@patch("qubit_bridge.probe.subprocess.run")
def test_probe_parsing(mock_run):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = GOLDEN_OUTPUT
    mock_proc.stderr = "CONNECTION ESTABLISHED"
    mock_run.return_value = mock_proc

    result = probe_host("example.com")

    assert result.reachable is True
    assert result.tls_version == "TLSv1.3"
    assert result.negotiated_group == "X25519MLKEM768"
    assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert result.peer_signature_type == "RSA-PSS"
    assert result.hybrid_pqc is True
    assert result.group_codepoint == 4588
