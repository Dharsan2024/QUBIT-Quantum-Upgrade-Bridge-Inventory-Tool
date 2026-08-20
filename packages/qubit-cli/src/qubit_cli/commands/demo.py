"""`qubit demo run` — the full M2 acceptance loop in one command (BUILD_PLAN Phase 2).

Copies the demo lab (or a given target) into a scratch git repo, then runs the entire
real pipeline: scan → risk annotation → migration plan → patch generation (template or
local LLM) → approve → apply → re-scan, and prints the before/after remediation proof.
Everything runs in-process against a throwaway SQLite DB — no server required.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.mapping import asset_to_row
from qubit_scanner import scan_paths
from rich.console import Console
from rich.table import Table
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

demo_app = typer.Typer(help="End-to-end demonstration of the QUBIT pipeline.")
console = Console()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, check=True)


def _vuln_counts(assets) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in assets:
        if a.quantum_vulnerable.vulnerable:
            counts[a.algorithm] = counts.get(a.algorithm, 0) + 1
    return counts


@demo_app.command("run")
def demo_run(
    target: Annotated[Path, typer.Option("--target", help="Directory to copy + migrate")] = Path(
        "demo-lab/vulnapp-python"
    ),
    generator: Annotated[str, typer.Option("--generator", help="auto | template | llm")] = "auto",
    keep: Annotated[bool, typer.Option("--keep", help="Keep the scratch repo")] = False,
    run_all_phases: Annotated[
        bool,
        typer.Option(
            "--all", help="Also run the bridge network loop (hybrid re-capture; needs Docker)"
        ),
    ] = False,
    canned: Annotated[bool, typer.Option("--canned", help="Bridge phases use fixtures")] = False,
) -> None:
    """Scan → risk → plan → generate → approve → apply → re-scan (remediation proof).

    With --all, chains the bridge network loop afterwards (the full M2 acceptance: classical harvest
    → discovery → risk → remediate → hybrid re-capture on the same port → verify X25519MLKEM768).
    """
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_risk import RiskPipeline, load_config

    if not target.is_dir():
        console.print(f"[red]error:[/red] target {target} not found")
        raise typer.Exit(2)

    # 1. Scratch git repo
    scratch = Path(tempfile.mkdtemp(prefix="qubit-demo-"))
    repo = scratch / "repo"
    shutil.copytree(target, repo)
    _git(repo, "init")
    _git(repo, "config", "user.email", "demo@qubit.local")
    _git(repo, "config", "user.name", "QUBIT Demo")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "baseline")
    console.print(f"[bold]1. scratch repo[/bold]  {repo}")

    # 2. Scan (real tree-sitter scanner)
    result = scan_paths([repo], repo="demo")
    before = _vuln_counts(result.assets)
    console.print(
        f"[bold]2. scan[/bold]          {result.stats.files_scanned} files, "
        f"{len(result.assets)} assets, vulnerable: {before or 'none'}"
    )
    if not before:
        console.print("[yellow]nothing vulnerable found — demo over[/yellow]")
        raise typer.Exit(0)

    # 3. Persist + risk annotation (real Monte-Carlo-backed pipeline)
    engine = create_engine(f"sqlite:///{scratch / 'demo.db'}")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="demo", slug="demo")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    annotated = RiskPipeline(load_config()).assess(result.assets)
    for asset in annotated:
        session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()
    scored = [a for a in annotated if a.risk]
    console.print(f"[bold]3. risk[/bold]          {len(scored)} assets annotated")

    # 4. Plan
    orch = MigrationOrchestrator(session)
    # Scoped, even though this scratch database holds exactly one project and one scan:
    # an unscoped plan records `project_id=None`, which the app reads as "built across
    # everything before plans had a scope". Saying what it was really built from costs
    # nothing and keeps one meaning for that null.
    plan = orch.build_plan(project_id=project.id, scan_id=scan.id)
    queue = orch.get_queue(plan.id)
    console.print(f"[bold]4. plan[/bold]          {len(queue)} tasks queued (WSJF-ranked)")

    # 5-7. Generate → approve → apply for every task with a rule
    applied = 0
    for task in queue:
        if not task.rule_id:
            console.print(f"   · task {str(task.id)[:8]}: no codemod rule — skipped")
            continue
        try:
            patch = orch.generate_patch(task.id, generator=generator, repo_root=repo)  # type: ignore[arg-type]
        except Exception as exc:
            console.print(f"   · task {str(task.id)[:8]}: generation failed — {exc}")
            continue
        stage_map = (patch.validation_json or {}).get("stages", {})
        stages = {k: v["status"] for k, v in stage_map.items()}
        if patch.status != "proposed":
            console.print(f"   · task {str(task.id)[:8]}: validation failed {stages}")
            continue
        try:
            orch.review_patch(patch.id, approve=True, note="demo auto-approve", actor="demo")
            orch.apply_patch(patch.id, repo_root=repo, actor="demo")
        except Exception as exc:
            console.print(f"   · task {str(task.id)[:8]}: apply failed — {exc}")
            continue
        # Commit each applied patch so the next apply sees a clean tree (operator flow).
        _git(repo, "add", "-A")
        _git(repo, "commit", "-m", f"QUBIT demo: migrate task {task.id}")
        applied += 1
        console.print(
            f"   · task {str(task.id)[:8]}: [green]{patch.generator} patch applied[/green] "
            f"({patch.file_path}) stages={stages}"
        )
    console.print(f"[bold]5-7. patches[/bold]     {applied} generated → approved → applied")

    # 8. Re-scan proves remediation
    result_after = scan_paths([repo], repo="demo")
    after = _vuln_counts(result_after.assets)

    table = Table(title="Remediation proof (re-scan)")
    table.add_column("Algorithm")
    table.add_column("Before", justify="right")
    table.add_column("After", justify="right")
    for algo in sorted(set(before) | set(after)):
        b, a = before.get(algo, 0), after.get(algo, 0)
        style = "green" if a < b else ("red" if a > b else "")
        table.add_row(algo, str(b), f"[{style}]{a}[/{style}]" if style else str(a))
    console.print(table)

    remediated = sum(before.values()) - sum(after.values())
    if remediated > 0:
        console.print(f"[bold green]✔ {remediated} vulnerable finding(s) remediated[/bold green]")
    else:
        console.print("[bold yellow]no findings remediated[/bold yellow]")

    if keep:
        console.print(f"scratch repo kept at {repo}")
    else:
        shutil.rmtree(scratch, ignore_errors=True)

    if run_all_phases:
        _run_bridge_phases(scratch.parent / "demo-pcaps", canned=canned)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _run_bridge_phases(pcap_dir: Path, *, canned: bool) -> None:
    """The network half of the M2 acceptance loop (classical harvest → hybrid re-capture)."""
    console.print("\n[bold]── Bridge network loop (M2 §4 acceptance) ──[/bold]")
    if not canned and not _docker_available():
        console.print(
            "[yellow]Docker not available — skipping the live bridge phases.[/yellow]\n"
            "Start Docker Desktop and re-run `qubit demo run --all`, or pass --canned for fixtures."
        )
        return
    from qubit_bridge.demo import run_all

    pcap_dir.mkdir(parents=True, exist_ok=True)
    run_all(pcap_dir, canned=canned)
    console.print(
        "[bold green]✔ Full M2 loop complete (software remediation + hybrid bridge).[/bold green]"
    )


@demo_app.command("bridge-4phase")
def demo_bridge_4phase(
    phase: Annotated[str, typer.Option("--phase", help="1|2|3|4|all")] = "all",
    pcap_dir: Annotated[Path, typer.Option("--pcap-dir", help="Output directory for pcaps")] = Path(
        "out"
    ),
    canned: Annotated[bool, typer.Option("--canned", help="Use canned fixture mode")] = False,
):
    """Run the bridge 4-phase committee demo."""
    from qubit_bridge.demo import run_all, run_phase_1, run_phase_2, run_phase_3, run_phase_4

    pcap_dir.mkdir(parents=True, exist_ok=True)
    if phase == "all":
        run_all(pcap_dir, canned=canned)
    elif phase == "1":
        run_phase_1(pcap_dir)
    elif phase == "2":
        run_phase_2(pcap_dir, canned=canned)
    elif phase == "3":
        run_phase_3()
    elif phase == "4":
        run_phase_4(pcap_dir, canned=canned)


@demo_app.command("reset")
def demo_reset():
    """Reset the bridge demo lab containers."""
    from qubit_bridge.demo import reset

    reset()
