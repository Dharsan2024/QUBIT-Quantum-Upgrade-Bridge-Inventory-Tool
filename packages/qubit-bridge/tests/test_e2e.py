import shutil
import subprocess
import time
from pathlib import Path

import pytest
from qubit_bridge.probe import probe_host


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


# Skip the whole module (not error) when Docker or testcontainers is unavailable.
pytest.importorskip("testcontainers")
if not _docker_up():
    pytest.skip("docker daemon unavailable", allow_module_level=True)

from testcontainers.core.container import DockerContainer  # noqa: E402

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

        # The probe runs openssl s_client inside its OWN container, so it must reach this server
        # container via the host's published port. testcontainers gives the host IP + mapped port;
        # a loopback host is rewritten to host.docker.internal by probe_host (Docker Desktop), and
        # to the docker bridge gateway on Linux.
        host = container.get_container_host_ip()
        if host in ("localhost", "127.0.0.1", "0.0.0.0"):
            import platform

            if platform.system() in ("Windows", "Darwin"):
                host = "localhost"  # probe_host maps this -> host.docker.internal
            else:
                # on linux, docker0 bridge is typically 172.17.0.1
                host = "172.17.0.1"

        port = container.get_exposed_port(8443)

        # Probe from the SAME image we just built (it ships the openssl 3.5 CLI), so no apk-add.
        result = probe_host(host, int(port), image=nginx_hybrid_image)

        logs = container.get_logs()
        assert result.reachable is True, (
            f"Host should be reachable. Raw: {result.raw_output}\nContainer Logs:\n{logs}"
        )
        assert result.tls_version == "TLSv1.3", f"Must negotiate TLS 1.3, got {result.tls_version}"
        assert result.negotiated_group == "X25519MLKEM768", (
            f"Must negotiate MLKEM768, got {result.negotiated_group}"
        )
