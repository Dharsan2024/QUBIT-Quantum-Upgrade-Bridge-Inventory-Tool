"""`qubit run` — the one interactive flow: ask for a path → scan → risk score → migrate.

This is the plain-language product: you give it a folder or file, it finds the weak crypto,
scores each asset's Harvest-Now-Decrypt-Later risk, and offers to migrate it to post-quantum —
then proves the fix with a re-scan. No server, no Docker, no dashboard. Everything runs in-process
against a throwaway SQLite DB and (for migration) a scratch git copy of your code, so your real
files are never touched unless a patch applies and you asked for it.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from qubit_scanner import scan_paths
from rich.console import Console
from rich.table import Table

console = Console()
err_console = Console(stderr=True)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, check=True)  # noqa: S603, S607


def _risk_table(annotated) -> Table:  # type: ignore[no-untyped-def]
    table = Table(title="Risk-scored cryptographic assets (highest first)")
    table.add_column("Rank", justify="right")
    table.add_column("Algorithm", style="bold")
    table.add_column("Usage")
    table.add_column("Quantum")
    table.add_column("HNDL risk", justify="right")
    table.add_column("Mosca margin", justify="right")
    table.add_column("Location")

    def sort_key(a):  # type: ignore[no-untyped-def]
        return -(a.risk.score if a.risk else 0.0)

    for a in sorted(annotated, key=sort_key):
        qv = a.quantum_vulnerable
        if qv.vulnerable:
            colour = "red" if qv.attack.value == "shor" else "yellow"
            verdict = f"[{colour}]vuln · {qv.attack.value}[/{colour}]"
        else:
            verdict = "[green]safe[/green]"
        score = f"{a.risk.score:.2f}" if a.risk else "—"
        margin = f"{a.risk.mosca_margin_years:+.1f} yr" if a.risk else "—"
        rank = str(a.risk.priority_rank) if a.risk else "—"
        loc = a.location
        where = (
            f"{loc.file_path}:{loc.line}" if loc.file_path and loc.line else (loc.file_path or "")
        )
        table.add_row(rank, a.algorithm, a.usage_context.value, verdict, score, margin, where)
    return table


def run(
    path: Annotated[
        Path | None,
        typer.Argument(help="File or folder to scan. Omit to be prompted."),
    ] = None,
    generator: Annotated[
        str, typer.Option("--generator", help="Patch engine: auto | template | llm")
    ] = "auto",
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Skip the migrate confirmation prompt.")
    ] = False,
) -> None:
    """Scan a path, show its HNDL risk, then offer to migrate it to post-quantum crypto."""
    # 1. Ask for a path if not given.
    if path is None:
        answer = typer.prompt("Path to scan (file or folder)", default=".")
        path = Path(answer).expanduser()
    if not path.exists():
        err_console.print(f"[red]error:[/red] path not found: {path}")
        raise typer.Exit(2)

    # 2. Scan (real tree-sitter scanner).
    console.print(f"\n[bold]Scanning[/bold] {path} …")
    result = scan_paths([path], repo=str(path))
    if not result.assets:
        console.print("[green]No cryptographic assets found.[/green]")
        raise typer.Exit(0)

    # 3. Risk-score every asset (real HNDL pipeline).
    from qubit_risk import RiskPipeline, load_config

    annotated = RiskPipeline(load_config()).assess(result.assets)
    console.print(_risk_table(annotated))

    vuln = [a for a in annotated if a.quantum_vulnerable.vulnerable]
    if not vuln:
        console.print("\n[green]Nothing quantum-vulnerable — no migration needed.[/green]")
        raise typer.Exit(0)
    console.print(f"\n[bold]{len(vuln)}[/bold] of {len(annotated)} assets are quantum-vulnerable.")

    # 4. Offer to migrate.
    if not yes and not typer.confirm("Migrate these to post-quantum crypto now?", default=True):
        console.print("Skipped migration. Re-run with the same path when ready.")
        raise typer.Exit(0)

    _migrate(path, generator, result)


def _migrate(path: Path, generator: str, scan_result) -> None:  # type: ignore[no-untyped-def]
    """Apply patches on a scratch git copy of the target, then prove the fix with a re-scan."""
    from qubit_core.db import Base, ProjectRow, ScanRow
    from qubit_core.mapping import asset_to_row
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_risk import RiskPipeline, load_config
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    # Scratch git repo so real files are never edited in place.
    scratch = Path(tempfile.mkdtemp(prefix="qubit-run-"))
    repo = scratch / "repo"
    if path.is_dir():
        shutil.copytree(path, repo)
    else:
        repo.mkdir(parents=True)
        shutil.copy2(path, repo / path.name)
    _git(repo, "init")
    _git(repo, "config", "user.email", "run@qubit.local")
    _git(repo, "config", "user.name", "QUBIT Run")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "baseline")

    before = _counts(scan_paths([repo], repo="run").assets)

    engine = create_engine(f"sqlite:///{scratch / 'run.db'}")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="run", slug="run")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    annotated = RiskPipeline(load_config()).assess(scan_paths([repo], repo="run").assets)
    for asset in annotated:
        session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    applied = 0
    for task in orch.get_queue(plan.id):
        if not task.rule_id:
            continue
        try:
            patch = orch.generate_patch(task.id, generator=generator, repo_root=repo)  # type: ignore[arg-type]
            if patch.status != "proposed":
                continue
            orch.review_patch(patch.id, approve=True, note="qubit run", actor="run")
            orch.apply_patch(patch.id, repo_root=repo, actor="run")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", f"migrate {task.id}")
            applied += 1
            console.print(f"  [green]patched[/green] {patch.file_path}")
        except Exception as exc:  # report per-task, keep going
            console.print(f"  [yellow]skipped[/yellow] one asset: {exc}")

    after = _counts(scan_paths([repo], repo="run").assets)

    table = Table(title="Before → after (re-scan proof)")
    table.add_column("Algorithm")
    table.add_column("Before", justify="right")
    table.add_column("After", justify="right")
    for algo in sorted(set(before) | set(after)):
        b, a = before.get(algo, 0), after.get(algo, 0)
        style = "green" if a < b else ("red" if a > b else "")
        table.add_row(algo, str(b), f"[{style}]{a}[/{style}]" if style else str(a))
    console.print(table)

    fixed = sum(before.values()) - sum(after.values())
    if fixed > 0:
        console.print(
            f"[bold green]✔ {applied} patch(es) applied — {fixed} finding(s) fixed.[/bold green]"
        )
        console.print(f"[dim]Patched copy kept at {repo}[/dim]")
    else:
        console.print(
            "[yellow]No findings auto-fixed.[/yellow] Some algorithms (e.g. RSA key-exchange) "
            "need the LLM generator: re-run with [bold]--generator llm[/bold] and Ollama running."
        )


def _counts(assets) -> dict[str, int]:  # type: ignore[no-untyped-def]
    counts: dict[str, int] = {}
    for a in assets:
        if a.quantum_vulnerable.vulnerable:
            counts[a.algorithm] = counts.get(a.algorithm, 0) + 1
    return counts


__all__ = ["run"]
