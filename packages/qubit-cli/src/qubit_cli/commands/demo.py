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
    target: Annotated[
        Path, typer.Option("--target", help="Directory to copy + migrate")
    ] = Path("demo-lab/vulnapp-python"),
    generator: Annotated[
        str, typer.Option("--generator", help="auto | template | llm")
    ] = "auto",
    keep: Annotated[bool, typer.Option("--keep", help="Keep the scratch repo")] = False,
) -> None:
    """Scan → risk → plan → generate → approve → apply → re-scan (remediation proof)."""
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
    plan = orch.build_plan()
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
