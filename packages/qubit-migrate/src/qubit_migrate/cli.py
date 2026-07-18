"""QUBIT Migrate CLI (doc 03 §5.1)."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import typer
from qubit_core.db import session_factory as _make_session_factory
from qubit_core.db.session import default_db_url, get_engine
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from sqlalchemy.orm import Session

from .orchestrator import MigrationOrchestrator
from .transform import load_rules

migrate_app = typer.Typer(help="Migrate cryptographic assets to post-quantum standards.")
console = Console()


def session_factory() -> Session:
    """Open a DB Session against the default DB (env QUBIT_DB_URL or user-data-dir SQLite).

    Zero-arg so every ``with session_factory() as session`` call site works; the real
    qubit_core.db.session_factory needs an engine and returns a sessionmaker.
    """
    return _make_session_factory(get_engine(default_db_url()))()


@migrate_app.command("plan")
def plan_cmd(
    min_risk: float = typer.Option(0.0, help="Minimum risk score to include"),
) -> None:
    """Build graph+queue from risk-annotated assets."""
    with session_factory() as session:
        orch = MigrationOrchestrator(session)
        plan = orch.build_plan(min_risk=min_risk)

        console.print(f"[green]Created migration plan[/] {plan.id}")
        console.print(f"Status: {plan.status}")

        if plan.status == "completed":
            return

        queue = orch.get_queue(plan.id, limit=20)

        table = Table(title="Ready Frontier")
        table.add_column("Rank")
        table.add_column("Task ID")
        table.add_column("Rule")
        table.add_column("Priority (WSJF)")
        table.add_column("Effort (pts)")

        for task in queue:
            table.add_row(
                str(task.rank),
                str(task.id),
                task.rule_id or "none",
                f"{task.priority:.3f}",
                str(task.effort_points),
            )

        console.print(table)


@migrate_app.command("status")
def status_cmd(plan_id: UUID) -> None:
    """Show plan status and queue."""
    with session_factory() as session:
        orch = MigrationOrchestrator(session)
        queue = orch.get_queue(plan_id, limit=50)

        table = Table(title=f"Plan {plan_id} Tasks")
        table.add_column("Rank")
        table.add_column("Task ID")
        table.add_column("State")
        table.add_column("Rule")

        for task in queue:
            table.add_row(
                str(task.rank),
                str(task.id),
                task.state,
                task.rule_id or "none",
            )

        console.print(table)


@migrate_app.command("generate")
def generate_cmd(
    task_id: UUID,
    repo_root: Path = typer.Option(..., help="Path to the repository root"),
    generator: str = typer.Option("template", help="auto, llm, or template"),
) -> None:
    """Generate a patch for a task."""
    with session_factory() as session:
        orch = MigrationOrchestrator(session)
        try:
            patch = orch.generate_patch(task_id, generator=generator, repo_root=repo_root)  # type: ignore[arg-type]
            console.print(f"[green]Generated patch[/] {patch.id}")
            console.print(f"Status: {patch.status}")
            if patch.status == "failed":
                console.print(
                    f"[red]Validation failed:[/]\n{json.dumps(patch.validation_json, indent=2)}"
                )
        except Exception as e:
            console.print(f"[red]Error generating patch: {e}[/]")
            raise typer.Exit(2) from e


@migrate_app.command("review")
def review_cmd(
    patch_id: UUID,
    approve: bool = typer.Option(
        False, "--approve", "-a", help="Approve without prompting (auto-approve)"
    ),
    reject: bool = typer.Option(False, "--reject", "-r", help="Reject without prompting"),
) -> None:
    """Review and approve/reject a patch."""
    with session_factory() as session:
        from .state import PatchProposal

        patch = session.get(PatchProposal, patch_id)
        if not patch or patch.status != "proposed":
            console.print("[red]Patch not found or not in proposed state[/]")
            raise typer.Exit(5)

        console.print(f"Patch ID: {patch.id}")
        console.print(f"File: {patch.file_path}")

        syntax = Syntax(patch.diff_text, "diff", theme="monokai", line_numbers=False)
        console.print(syntax)

        if approve:
            choice = "a"
        elif reject:
            choice = "r"
        else:
            choice = typer.prompt("[a]pprove, [r]eject, or [s]kip", type=str).lower()

        orch = MigrationOrchestrator(session)
        if choice.startswith("a"):
            orch.review_patch(patch_id, approve=True)
            console.print("[green]Patch approved.[/]")
        elif choice.startswith("r"):
            orch.review_patch(patch_id, approve=False)
            console.print("[yellow]Patch rejected.[/]")
        else:
            console.print("Skipped.")


@migrate_app.command("apply")
def apply_cmd(
    patch_id: UUID,
    repo_root: Path = typer.Option(..., help="Path to the repository root"),
    branch: str = typer.Option(None, help="Branch to create (e.g. qubit/migration-abc)"),
) -> None:
    """Apply an approved patch to the target repository."""
    with session_factory() as session:
        orch = MigrationOrchestrator(session)
        try:
            p = orch.apply_patch(patch_id, repo_root=repo_root, branch=branch)
            console.print(f"[green]Applied patch {patch_id} successfully.[/]")
            if p.applied_branch:
                console.print(f"Branch: {p.applied_branch}")
                console.print(f"Commit: {p.applied_commit}")
        except Exception as e:
            console.print(f"[red]Error applying patch: {e}[/]")
            raise typer.Exit(3) from e


@migrate_app.command("verify")
def verify_cmd(task_id: UUID) -> None:
    """Re-scan to prove remediation."""
    with session_factory() as session:
        orch = MigrationOrchestrator(session)
        try:
            orch.verify_task(task_id)
            console.print(f"[green]Task {task_id} verified successfully.[/]")
        except Exception as e:
            console.print(f"[red]Error verifying task: {e}[/]")
            raise typer.Exit(2) from e


@migrate_app.command("rules")
def rules_cmd(
    action: str = typer.Argument("list", help="'list' or rule ID to show"),
) -> None:
    """List or show migration rules."""
    rules = load_rules()
    if action == "list":
        table = Table(title="Migration Rules")
        table.add_column("ID")
        table.add_column("Language")
        table.add_column("Title")

        for r in rules:
            table.add_row(r.id, r.language, r.title)
        console.print(table)
    else:
        for r in rules:
            if r.id == action:
                console.print(f"[bold]{r.id}[/]")
                console.print(f"Title: {r.title}")
                console.print(f"Language: {r.language}")
                console.print(f"Codemod: {r.codemod}")
                return
        console.print(f"[red]Rule {action} not found.[/]")


__all__ = ["migrate_app"]
