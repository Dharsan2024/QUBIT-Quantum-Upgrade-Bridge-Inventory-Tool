from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from qubit_core import Location

from qubit_scanner.models import Detection


class CertScanner:
    """Scans for and parses PEM/DER certificates."""

    def parse_file(self, file_path: Path) -> list[Detection]:
        detections = []
        try:
            content = file_path.read_bytes()
            # Basic heuristic to check if it's PEM or DER
            if b"-----BEGIN CERTIFICATE-----" in content:
                certs = x509.load_pem_x509_certificates(content)
            else:
                certs = [x509.load_der_x509_certificate(content)]

            for cert in certs:
                loc = Location(file_path=str(file_path))

                # Public Key Algorithm
                pub_key = cert.public_key()
                algo = "UNKNOWN"
                key_size = None

                if isinstance(pub_key, rsa.RSAPublicKey):
                    algo = "RSA"
                    key_size = pub_key.key_size
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    algo = "ECDSA"
                    key_size = pub_key.key_size
                elif isinstance(pub_key, dsa.DSAPublicKey):
                    algo = "DSA"
                    key_size = pub_key.key_size
                elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                    algo = "EdDSA"

                detections.append(
                    Detection(
                        scanner="cert",
                        rule_id="CERT-PUBKEY-001",
                        raw_algorithm=algo,
                        key_size=key_size,
                        asset_type="certificate",
                        usage_context="signature",
                        location=loc,
                        evidence_snippet=f"Subject: {cert.subject.rfc4514_string()}",
                        confidence="high",
                    )
                )

                # Signature Algorithm (e.g. SHA256withRSA)
                sig_algo = cert.signature_algorithm_oid._name
                if sig_algo:
                    detections.append(
                        Detection(
                            scanner="cert",
                            rule_id="CERT-SIGALGO-001",
                            raw_algorithm=sig_algo,
                            asset_type="algorithm-use",
                            usage_context="signature",
                            location=loc,
                            evidence_snippet=f"Signature Algorithm: {sig_algo}",
                            confidence="high",
                        )
                    )

        except ValueError:
            # Not a certificate or malformed
            pass
        except Exception:
            # Keep going
            pass

        return detections
