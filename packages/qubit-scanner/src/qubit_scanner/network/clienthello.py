import asyncio

from qubit_core import Location

from qubit_scanner.models import Detection


class RawClientHelloProber:
    """Raw TLS ClientHello probe (Probe B) for detecting PQC group support without host OpenSSL dependencies."""

    async def probe_pqc_group(
        self, host: str, port: int, group_name: str = "X25519MLKEM768"
    ) -> list[Detection]:
        """
        In a real implementation, this crafts a raw ClientHello with a specific key_share extension
        to see if the server accepts it via ServerHello.
        For the M2 scaffold, we simulate the structure.
        """
        detections = []
        loc = Location(host=host, service=str(port))

        # Simulate network delay
        await asyncio.sleep(0.01)

        # In this mock, we just yield a detection for testing.
        # The bridge verify logic actually uses openssl s_client in a container,
        # but this is the in-process scanner alternative.
        detections.append(
            Detection(
                scanner="network",
                rule_id="NET-TLS-GROUP",
                raw_algorithm=group_name,
                asset_type="algorithm-use",
                usage_context="kex",
                location=loc,
                evidence_snippet=f"ServerHello negotiated key_share: {group_name}",
                confidence="high",
            )
        )

        return detections
