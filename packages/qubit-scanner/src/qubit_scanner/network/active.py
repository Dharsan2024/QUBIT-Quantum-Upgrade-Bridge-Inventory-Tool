import asyncio
import ssl

from qubit_core import Location

from qubit_scanner.models import Detection


class TlsEnumerator:
    """Active TLS enumeration using standard library (Probe A)."""

    async def enumerate(self, host: str, port: int) -> list[Detection]:
        detections = []
        loc = Location(host=host, service=str(port))

        loop = asyncio.get_running_loop()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context), timeout=5.0
            )

            # Extract basic negotiated info (Probe A)
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                version = ssl_obj.version()
                cipher = ssl_obj.cipher()

                if version:
                    detections.append(
                        Detection(
                            scanner="network",
                            rule_id="NET-TLS-PROTO",
                            raw_algorithm=version,
                            asset_type="protocol",
                            usage_context="tls",
                            location=loc,
                            evidence_snippet=f"Negotiated {version}",
                            confidence="high",
                        )
                    )

                if cipher:
                    cipher_name = cipher[0]
                    detections.append(
                        Detection(
                            scanner="network",
                            rule_id="NET-TLS-CIPHER",
                            raw_algorithm=cipher_name,
                            asset_type="protocol",
                            usage_context="tls",
                            location=loc,
                            evidence_snippet=f"Negotiated cipher {cipher_name}",
                            confidence="high",
                        )
                    )

                # Feature-gate for Python 3.15+ (Probe A group)
                if hasattr(ssl.SSLSocket, "group"):
                    try:
                        # Dummy call just to show the feature check pattern per spec
                        # group = ssl_obj.group()
                        pass
                    except Exception:
                        pass

            writer.close()
            await writer.wait_closed()
        except Exception:
            # Handle connection refused, timeout, etc.
            pass

        return detections
