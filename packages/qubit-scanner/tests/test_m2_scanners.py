import asyncio

from qubit_scanner.api import scan_network, scan_paths
from qubit_scanner.certs.scanner import CertScanner
from qubit_scanner.config.parsers import NginxConfigParser


def test_config_parser(tmp_path):
    config = tmp_path / "nginx.conf"
    config.write_text("ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL;\n")
    parser = NginxConfigParser()
    detections = parser.parse(config)

    assert any(d.raw_algorithm == "TLSv1.3" for d in detections)
    # The HIGH cipher string expansion
    assert any("AES_256_GCM" in d.raw_algorithm for d in detections)


def test_cert_scanner(tmp_path):
    # This just ensures it doesn't crash on dummy file
    dummy = tmp_path / "cert.pem"
    dummy.write_text("dummy")
    scanner = CertScanner()
    detections = scanner.parse_file(dummy)
    assert len(detections) == 0


def test_api_scan_paths(tmp_path):
    config = tmp_path / "nginx.conf"
    config.write_text("ssl_protocols TLSv1.2;\n")

    result = scan_paths([tmp_path], scanners={"config"})
    assert result.stats.files_scanned >= 1
    assert any("TLSv1.2" in a.algorithm for a in result.assets)


def test_scan_network():
    # Because this needs an active endpoint, we mock or test async logic
    async def run():
        res = await scan_network(["127.0.0.1"], ports=[443])
        assert res.stats.duration_s >= 0

    asyncio.run(run())
