import shutil
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console

console = Console()

# Resolve the installed `qubit` CLI next to the running interpreter (demo runs it as a subprocess).
_QUBIT = str(Path(sys.executable).parent / "qubit.exe")


def _wait_for_tls_port(host: str, port: int, timeout: float = 45.0) -> bool:
    """Block until ``host:port`` accepts a TCP connection, or ``timeout`` elapses.

    Replaces a fixed `time.sleep(3)`. Three seconds is not enough for nginx to come up behind a
    `depends_on` (and it silently is not enough when the image has to be rebuilt), so the capture
    that followed recorded a handful of TCP resets instead of a handshake — the pcap was a valid
    file with no TLS in it, and every downstream key_share size read 0 while the demo still passed.

    Returns False rather than raising: the phase should report an unusable capture, not abort the
    whole demo.
    """
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return True
        except OSError:
            time.sleep(1.0)
    console.print(
        f"[yellow]Warning:[/yellow] {host}:{port} never accepted a connection within "
        f"{timeout:.0f}s — the capture for this phase will contain no handshake. "
        "Check `docker compose -f demo-lab/compose.classical.yml logs`."
    )
    return False


def run_phase_1(out_dir: Path):
    """HARVEST: classical baseline."""
    console.print("[bold]Phase 1 — HARVEST (classical baseline)[/bold]")
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "demo-lab/compose.classical.yml",
            "up",
            "-d",
            "--remove-orphans",
        ],
        check=True,
    )
    _wait_for_tls_port("localhost", 8443)

    console.print("Capturing classical handshake...")
    out_pcap = out_dir / "harvest_classical.pcap"
    subprocess.run(
        [_QUBIT, "bridge", "capture", "localhost:8443", "--out", str(out_pcap), "--handshakes", "1"]
    )

    console.print("Probing classical handshake...")
    subprocess.run([_QUBIT, "bridge", "probe", "localhost:8443"])


def run_phase_2(out_dir: Path, canned: bool = False):
    """DISCOVERY / CBOM."""
    console.print("[bold]Phase 2 — DISCOVERY / CBOM[/bold]")
    if canned:
        console.print("Canned mode: using fixture cbom.")
    else:
        cbom_path = out_dir / "cbom.json"
        subprocess.run([_QUBIT, "scan", "demo-lab/vulnapp-python", "--cbom", str(cbom_path)])
        subprocess.run([_QUBIT, "bridge", "probe", "localhost:8443", "--push"])


def run_phase_3():
    """RISK."""
    console.print("[bold]Phase 3 — RISK[/bold]")
    console.print("Check the dashboard at http://localhost:3000/risk")


def run_phase_4(out_dir: Path, canned: bool = False):
    """REMEDIATE + HYBRID RE-CAPTURE.

    The code-level remediation proof (scan → LLM/template patch → re-scan shows the vulnerable asset
    gone) is the SOFTWARE loop `qubit demo run` (fresh scratch repo). This bridge phase proves the
    RUNTIME half: the same service on the same port now negotiates the hybrid PQC group. We do not
    re-apply code patches to the shared, checked-in `demo-lab/vulnapp-python` tree here — that would
    require a dirty-tree write to a git-tracked dir; the software loop already showed remediation on
    a clean scratch copy.
    """
    console.print("[bold]Phase 4 — REMEDIATE + HYBRID RE-CAPTURE[/bold]")
    if canned:
        console.print("Canned mode: hybrid re-capture from fixtures.")
    else:
        console.print(
            "Remediation already proven by the software loop (see the re-scan table above); "
            "this phase proves the runtime PQC swap on the same port."
        )

    subprocess.run(
        ["docker", "compose", "-f", "demo-lab/compose.classical.yml", "stop", "nginx-classical"],
        check=True,
    )
    subprocess.run(
        [
            _QUBIT,
            "bridge",
            "up",
            "hybrid",
            "--engine",
            "nginx",
            "--upstream",
            "vulnapp-python:5000",
            "--port",
            "8443",
        ]
    )
    _wait_for_tls_port("localhost", 8443)

    out_pcap = out_dir / "harvest_hybrid.pcap"
    subprocess.run(
        [_QUBIT, "bridge", "capture", "localhost:8443", "--out", str(out_pcap), "--handshakes", "1"]
    )

    console.print("Verifying hybrid...")
    subprocess.run([_QUBIT, "bridge", "verify", "localhost:8443", "--expect", "X25519MLKEM768"])

    if not canned:
        subprocess.run([_QUBIT, "bridge", "probe", "localhost:8443", "--push"])

    subprocess.run(
        [_QUBIT, "bridge", "diff", str(out_dir / "harvest_classical.pcap"), str(out_pcap)]
    )


def run_all(pcap_dir: Path, canned: bool = False):
    pcap_dir.mkdir(parents=True, exist_ok=True)
    run_phase_1(pcap_dir)
    run_phase_2(pcap_dir, canned)
    run_phase_3()
    run_phase_4(pcap_dir, canned)


def reset():
    """Reset the demo lab."""
    console.print("Resetting demo lab...")
    subprocess.run(["docker", "compose", "-f", "demo-lab/compose.classical.yml", "down"])
    subprocess.run(["docker", "compose", "-f", "demo-lab/compose.hybrid.yml", "down"])
    shutil.rmtree("out", ignore_errors=True)
