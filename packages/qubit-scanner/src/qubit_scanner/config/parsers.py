from collections.abc import Iterator
from pathlib import Path

import crossplane
from qubit_core import Location

from qubit_scanner.models import Detection

from .cipherstring import expand_cipher_string


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

                # 3. ssl_certificate (certificate path)
                for dr in _extract_directives(parsed, "ssl_certificate"):
                    loc = Location(file_path=str(file_path), line=dr.get("line"))
                    cert_path = " ".join(dr.get("args", []))
                    detections.append(
                        Detection(
                            scanner="config",
                            rule_id="CFG-NGINX-CERT-001",
                            raw_algorithm=cert_path,  # the normalizer/cert scanner handles this
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
