import subprocess
import time
from pathlib import Path

import pytest
from qubit_bridge.probe import probe_host
from testcontainers.core.container import DockerContainer

IMAGES_DIR = Path(__file__).parent.parent / "images" / "nginx-hybrid"


@pytest.fixture(scope="session")
def nginx_hybrid_image():
    """Build the nginx-hybrid image for testing."""
    image_name = "qubit-nginx-hybrid:e2e-test"
    result = subprocess.run(
        ["docker", "build", "-t", image_name, str(IMAGES_DIR)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"Failed to build nginx-hybrid image:\n{result.stderr}")
    return image_name


@pytest.mark.integration
def test_nginx_hybrid_tls_probe(nginx_hybrid_image):
    """
    Spin up the hybrid nginx container and probe it to ensure
    it successfully negotiates the post-quantum X25519MLKEM768 group.
    """
    # Start the container
    with DockerContainer(nginx_hybrid_image).with_exposed_ports(8443) as container:
        # Wait a moment for nginx to start and generate certs
        time.sleep(2)
        
        # We need the probe (which runs inside its own docker container) 
        # to reach this server container. If testcontainers returns localhost, 
        # that means we need host.docker.internal or a similar trick.
        host = container.get_container_host_ip()
        if host in ("localhost", "127.0.0.1", "0.0.0.0"):
            import platform
            if platform.system() in ("Windows", "Darwin"):
                host = "host.docker.internal"
            else:
                # on linux, docker0 bridge is typically 172.17.0.1
                host = "172.17.0.1"
                
        port = container.get_exposed_port(8443)

        # Run the probe
        result = probe_host(host, int(port))

        logs = container.get_logs()
        assert result.reachable is True, (
            f"Host should be reachable. Raw: {result.raw_output}\nContainer Logs:\n{logs}"
        )
        assert result.tls_version == "TLSv1.3", f"Must negotiate TLS 1.3, got {result.tls_version}"
        assert result.negotiated_group == "X25519MLKEM768", (
            f"Must negotiate MLKEM768, got {result.negotiated_group}"
        )
