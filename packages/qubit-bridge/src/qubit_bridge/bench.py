import statistics
import subprocess
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from qubit_bridge.capture import capture_handshake, extract_key_share_sizes
from qubit_bridge.models import HandshakeMeasurement
from qubit_bridge.registry import is_hybrid


def bench_group(
    host: str, port: int, group: str, *, n: int = 100, run_id: uuid.UUID | None = None
) -> HandshakeMeasurement:
    """Benchmark a TLS handshake against a target."""
    if run_id is None:
        run_id = uuid.uuid4()

    samples_ms = []

    for _ in range(n):
        t0 = time.perf_counter()

        # In Docker Desktop, localhost inside the container resolves to the container itself.
        docker_host = "host.docker.internal" if host in ("localhost", "127.0.0.1") else host

        # We invoke s_client directly via docker alpine, similar to probe.py
        shell_cmd = (
            "apk add --no-cache openssl > /dev/null 2>&1 && "
            f"openssl s_client -connect {docker_host}:{port} -tls1_3 -brief "
            f"-groups {group}"
        )

        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "",
            "nginx:alpine",
            "/bin/sh",
            "-c",
            shell_cmd,
        ]

        import contextlib

        with contextlib.suppress(subprocess.TimeoutExpired):
            subprocess.run(cmd, input=b"", capture_output=True, timeout=10.0)

        t1 = time.perf_counter()
        samples_ms.append((t1 - t0) * 1000)

    # Get sizes using one capture handshake
    sizes = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = Path(tmpdir) / "bench.pcap"
        capture_handshake(host, port, pcap_path, handshakes=1, timeout=5.0)
        sizes = extract_key_share_sizes(pcap_path)

    return HandshakeMeasurement(
        id=uuid.uuid4(),
        run_id=run_id,
        target_host=host,
        target_port=port,
        group=group,
        hybrid_pqc=is_hybrid(group),
        n_samples=n,
        handshake_ms_mean=statistics.mean(samples_ms) if samples_ms else 0.0,
        handshake_ms_p50=statistics.median(samples_ms) if samples_ms else 0.0,
        handshake_ms_p95=(
            statistics.quantiles(samples_ms, n=20)[18]
            if len(samples_ms) >= 20
            else (max(samples_ms) if samples_ms else 0.0)
        ),
        handshake_ms_stdev=statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0,
        client_hello_bytes=None,
        server_hello_bytes=None,
        client_key_share_bytes=sizes.get("client_key_share_bytes"),
        server_key_share_bytes=sizes.get("server_key_share_bytes"),
        tls_version="TLSv1.3",
        cipher_suite="unknown",
        openssl_version="OpenSSL 3.x",
        captured_at=datetime.now(UTC),
    )


def bench_matrix(
    host: str, port: int, groups: list[str], *, n: int = 100
) -> list[HandshakeMeasurement]:
    """Benchmark multiple TLS groups."""
    run_id = uuid.uuid4()
    results = []
    for group in groups:
        results.append(bench_group(host, port, group, n=n, run_id=run_id))
    return results
