import shutil
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console

console = Console()

# Resolve the installed `qubit` CLI next to the running interpreter (demo runs it as a subprocess).
_QUBIT = str(Path(sys.executable).parent / "qubit.exe")


def run_phase_1(out_dir: Path):
    """HARVEST: classical baseline."""
    console.print("[bold]Phase 1 — HARVEST (classical baseline)[/bold]")
    subprocess.run(
        ["docker", "compose", "-f", "demo-lab/compose.classical.yml", "up", "-d"], check=True
    )
    time.sleep(3)

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
    """REMEDIATE + HYBRID RE-CAPTURE."""
    console.print("[bold]Phase 4 — REMEDIATE + HYBRID RE-CAPTURE[/bold]")
    if canned:
        console.print("Canned mode: applying fixture patch.")
    else:
        try:
            from qubit_core.db.session import default_db_url, get_engine, session_factory
            from qubit_migrate.orchestrator import MigrationOrchestrator

            engine = get_engine(default_db_url())
            sf = session_factory(engine)
            with sf() as session:
                orch = MigrationOrchestrator(session)
                plan = orch.build_plan()
                repo_root = Path("demo-lab/vulnapp-python")
                for task in plan.tasks:
                    try:
                        patch = orch.generate_patch(task.id, repo_root=repo_root)
                        orch.review_patch(patch.id, approve=True, actor="demo")
                        orch.apply_patch(patch.id, repo_root=repo_root, actor="demo")
                    except Exception as exc:
                        console.print(f"  Note during migration apply: {exc}")
        except Exception as exc:
            console.print(f"  Skipped live migration apply: {exc}")

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
    time.sleep(3)

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
