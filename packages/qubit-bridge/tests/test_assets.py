"""push_assets_to_api returns success/failure honestly (no false 'Pushed' on an unreachable API)."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx
from qubit_bridge.assets import probe_to_assets, push_assets_to_api
from qubit_bridge.models import ProbeResult
from qubit_core.schemas import QuantumAttack


def test_push_returns_true_on_success():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    with patch("qubit_bridge.assets.httpx.post", return_value=mock_resp) as post:
        assert push_assets_to_api([], api_url="http://localhost:8000") is True
        post.assert_called_once()


def test_push_returns_false_when_api_unreachable():
    with patch(
        "qubit_bridge.assets.httpx.post",
        side_effect=httpx.ConnectError("refused"),
    ):
        # Must NOT raise, and must report failure so the caller doesn't print a false success.
        assert push_assets_to_api([], api_url="http://localhost:8000") is False


class TestProbeEvidenceSurvives:
    """A bridge asset's evidence IS the handshake, and it used to be thrown away.

    `Evidence` declares `snippet`, `snippet_sha256` and `context`; it does not declare
    `transcript`. Pydantic ignores undeclared fields rather than rejecting them, so passing
    `{"transcript": raw_output}` produced a valid, empty `Evidence` and every asset the bridge
    wrote reached the database with no proof attached at all.
    """

    @staticmethod
    def _probe(**overrides: object) -> ProbeResult:
        fields: dict[str, object] = {
            "host": "127.0.0.1",
            "port": 8443,
            "reachable": True,
            "tls_version": "TLSv1.3",
            "negotiated_group": "X25519MLKEM768",
            "group_codepoint": 4588,
            "hybrid_pqc": True,
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cert_public_key_algorithm": "RSA",
            "cert_public_key_bits": 2048,
            "cert_fingerprint_sha256": "ab" * 32,
            "offered_groups": ["X25519MLKEM768", "x25519"],
            "raw_output": "RAW HANDSHAKE TRANSCRIPT",
            "probed_at": datetime.now(UTC),
        }
        fields.update(overrides)
        return ProbeResult(**fields)  # type: ignore[arg-type]

    def test_the_transcript_reaches_the_protocol_asset(self) -> None:
        protocol = probe_to_assets(self._probe())[0]
        assert protocol.evidence.snippet == "RAW HANDSHAKE TRANSCRIPT"
        assert protocol.evidence.context.extra["probe"] == "tls-handshake"
        assert protocol.evidence.context.extra["offered_groups"] == [
            "X25519MLKEM768",
            "x25519",
        ]

    def test_the_fingerprint_reaches_the_certificate_asset(self) -> None:
        certificate = probe_to_assets(self._probe())[1]
        assert certificate.evidence.context.extra["cert_fingerprint_sha256"] == "ab" * 32

    def test_a_long_transcript_is_truncated_and_says_so(self) -> None:
        """Evidence, not a payload: one probe must not put a megabyte into every row."""
        protocol = probe_to_assets(self._probe(raw_output="x" * 10_000))[0]
        assert len(protocol.evidence.snippet) == 4000
        assert protocol.evidence.context.extra["truncated"] is True

    def test_a_hybrid_group_is_not_marked_shor_vulnerable(self) -> None:
        protocol = probe_to_assets(self._probe())[0]
        assert protocol.quantum_vulnerable.vulnerable is False
        assert protocol.quantum_vulnerable.attack == QuantumAttack.none

    def test_a_classical_certificate_is_marked_shor_vulnerable(self) -> None:
        certificate = probe_to_assets(self._probe())[1]
        assert certificate.quantum_vulnerable.vulnerable is True
        assert certificate.quantum_vulnerable.attack == QuantumAttack.shor
