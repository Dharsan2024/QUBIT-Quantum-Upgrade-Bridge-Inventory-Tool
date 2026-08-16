from collections.abc import Iterator
from pathlib import Path

import crossplane
from qubit_core import Location

from qubit_scanner.models import Detection

from .cipherstring import expand_cipher_string
from .groups import normalize_kex_group


def _extract_directives(payload: list, target_directive: str) -> Iterator[dict]:
    """Recursively extract directives matching target_directive from crossplane payload."""
    for directive in payload:
        if directive.get("directive") == target_directive:
            yield directive
        if "block" in directive:
            yield from _extract_directives(directive["block"], target_directive)


class NginxConfigParser:
    """Parses nginx configurations to find cryptographic settings."""

    def parse(self, file_path: Path) -> list[Detection]:
        detections: list[Detection] = []
        try:
            # crossplane parses nginx config to JSON AST
            payload = crossplane.parse(
                str(file_path), check_ctx=False, check_args=False, single=True
            )
            if not payload or not payload.get("config"):
                return detections

            for config_file in payload["config"]:
                parsed = config_file.get("parsed", [])
                if not parsed:
                    continue

                # 1. ssl_protocols (protocol versions)
                for dr in _extract_directives(parsed, "ssl_protocols"):
                    loc = Location(file_path=str(file_path), line=dr.get("line"))
                    # Args are usually like ["TLSv1.2", "TLSv1.3"]
                    for proto in dr.get("args", []):
                        detections.append(
                            Detection(
                                scanner="config",
                                rule_id="CFG-NGINX-PROTO-001",
                                raw_algorithm=proto,
                                asset_type="protocol",
                                usage_context="tls",
                                location=loc,
                                evidence_snippet=f"ssl_protocols {' '.join(dr.get('args', []))};",
                            )
                        )

                # 2. ssl_ciphers (cipher suites)
                for dr in _extract_directives(parsed, "ssl_ciphers"):
                    loc = Location(file_path=str(file_path), line=dr.get("line"))
                    cipher_str = " ".join(dr.get("args", []))
                    suites = expand_cipher_string(cipher_str)
                    for suite in suites:
                        detections.append(
                            Detection(
                                scanner="config",
                                rule_id="CFG-NGINX-CIPHERS-001",
                                raw_algorithm=suite,
                                asset_type="protocol",
                                usage_context="tls",
                                location=loc,
                                evidence_snippet=f"ssl_ciphers {cipher_str};",
                            )
                        )

                # 3. ssl_ecdh_curve (the key-exchange GROUP)
                # This is the most consequential TLS directive for post-quantum readiness and it was
                # not being read at all: it is where `X25519MLKEM768` goes, and equally where a
                # server pinned to `prime256v1` advertises a Shor-breakable key exchange. Without
                # it, a hardened config could not be distinguished from a vulnerable one on rescan,
                # and the group governing HNDL exposure was simply absent from the inventory.
                for dr in _extract_directives(parsed, "ssl_ecdh_curve"):
                    loc = Location(file_path=str(file_path), line=dr.get("line"))
                    curve_str = " ".join(dr.get("args", []))
                    # nginx accepts a colon-separated preference list, `auto`, or a single name.
                    for curve in (c.strip() for c in curve_str.replace(" ", ":").split(":")):
                        # `auto` delegates the choice to OpenSSL, so it names no algorithm.
                        if not curve or curve.lower() == "auto":
                            continue
                        detections.append(
                            Detection(
                                scanner="config",
                                rule_id="CFG-NGINX-CURVE-001",
                                raw_algorithm=normalize_kex_group(curve),
                                asset_type="protocol",
                                usage_context="kex",
                                location=loc,
                                evidence_snippet=f"ssl_ecdh_curve {curve_str};",
                            )
                        )

                # 4. ssl_certificate (certificate path)
                for dr in _extract_directives(parsed, "ssl_certificate"):
                    loc = Location(file_path=str(file_path), line=dr.get("line"))
                    cert_path = " ".join(dr.get("args", []))
                    detections.append(
                        Detection(
                            scanner="config",
                            rule_id="CFG-NGINX-CERT-001",
                            # A file PATH is not an algorithm. Putting one here made the
                            # normalizer emit `UNKNOWN(/etc/nginx/certs/server.crt)` - an asset
                            # named after a filename, with a not-vulnerable verdict. The
                            # referenced file's real key algorithm is reported by the cert
                            # scanner; the honest statement here is "this config points at X.509
                            # material", with the path preserved as evidence.
                            raw_algorithm="X.509",
                            asset_type="certificate",
                            usage_context="tls",
                            location=loc,
                            evidence_snippet=f"ssl_certificate {cert_path};",
                        )
                    )
        except Exception:
            # We ignore parsing errors to gracefully handle invalid configs in bulk scans
            pass

        return detections
