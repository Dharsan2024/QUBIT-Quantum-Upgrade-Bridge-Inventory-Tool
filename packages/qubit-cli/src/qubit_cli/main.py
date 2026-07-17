"""The ``qubit`` command-line interface.

Phase 1 delivers the frame's non-negotiable one-command promise:
``qubit scan <path> [--cbom out.json]`` -> discovered crypto assets + a CycloneDX 1.7 CBOM.
Risk / plan / migrate / serve subcommands land in later phases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from qubit_core import __version__ as core_version
from qubit_core import export_cbom, validate_cbom_structure
from qubit_scanner import RuleCatalog, scan_paths
from qubit_scanner.catalog import RuleLoadError
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="qubit",
    help="QUBIT - Quantum Upgrade Bridge & Inventory Tool. Discover and inventory crypto.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@app.command()
def version() -> None:
    """Print the QUBIT version."""
    console.print(f"QUBIT {core_version}")


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="File or directory to scan for crypto assets.")],
    cbom: Annotated[
        Path | None, typer.Option("--cbom", help="Also write a CycloneDX 1.7 CBOM to this path.")
    ] = None,
    repo: Annotated[
        str | None, typer.Option("--repo", help="Repository label recorded on each asset.")
    ] = None,
    reproducible: Annotated[
        bool, typer.Option("--reproducible", help="Deterministic CBOM (pinned serial/timestamp).")
    ] = False,
    with_evidence: Annotated[
        bool, typer.Option("--with-evidence", help="Include (redacted) evidence in the CBOM.")
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON instead of a table.")
    ] = False,
) -> None:
    """Scan a path for cryptographic assets (the one-command promise)."""
    if not target.exists():
        err_console.print(f"[red]error:[/red] path not found: {target}")
        raise typer.Exit(code=1)

    result = scan_paths([target], repo=repo)

    if cbom is not None:
        doc = export_cbom(result.assets, reproducible=reproducible, include_evidence=with_evidence)
        problems = validate_cbom_structure(doc)
        cbom.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        if problems:
            err_console.print(f"[yellow]warning:[/yellow] CBOM structural issues: {problems}")

    if as_json:
        console.print_json(
            data={
                "stats": result.stats.model_dump(),
                "assets": [a.model_dump(mode="json") for a in result.assets],
            }
        )
    else:
        _render_table(result)
        if cbom is not None:
            ok = not validate_cbom_structure(export_cbom(result.assets))
            valid = "[green]schema-valid[/green]" if ok else "[yellow]see warnings[/yellow]"
            console.print(f"CBOM (CycloneDX 1.7): {cbom}  {valid}")

    # exit codes: 0 ok, 3 no assets found (useful for scripting/CI)
    raise typer.Exit(code=0 if result.assets else 3)


def _render_table(result) -> None:
    stats = result.stats
    console.print(
        f"[bold]QUBIT[/bold] scan - {stats.files_scanned} files, "
        f"{stats.assets} assets, {stats.duration_s}s"
    )
    if not result.assets:
        console.print("[dim]no cryptographic assets found[/dim]")
        return

    table = Table(show_lines=False)
    table.add_column("Algorithm", style="bold")
    table.add_column("Usage")
    table.add_column("Quantum", justify="center")
    table.add_column("Location")
    table.add_column("Rule", style="dim")

    for a in sorted(
        result.assets, key=lambda x: (not x.quantum_vulnerable.vulnerable, x.algorithm)
    ):
        if a.quantum_vulnerable.vulnerable:
            attack = a.quantum_vulnerable.attack.value
            colour = "red" if attack == "shor" else "yellow"
            verdict = f"[{colour}]vuln/{attack}[/{colour}]"
        else:
            verdict = "[green]safe[/green]"
        loc = a.location
        where = (
            f"{loc.file_path}:{loc.line}" if loc.file_path and loc.line else (loc.file_path or "")
        )
        table.add_row(a.algorithm, a.usage_context.value, verdict, where, a.rule_id or "")

    console.print(table)
    vuln = sum(1 for a in result.assets if a.quantum_vulnerable.vulnerable)
    console.print(f"[bold]{vuln}[/bold] of {len(result.assets)} assets are quantum-vulnerable.")


rules_app = typer.Typer(help="Inspect and validate the detection-rule catalog.")
app.add_typer(rules_app, name="rules")


@rules_app.command("lint")
def rules_lint() -> None:
    """Load and compile the whole rule catalog; fail loudly if any rule is malformed."""
    try:
        catalog = RuleCatalog.load()
    except RuleLoadError as e:
        err_console.print(f"[red]invalid rule catalog:[/red] {e}")
        raise typer.Exit(code=1) from e
    console.print(f"[green]OK[/green] - {len(catalog)} rules compiled across {catalog.languages()}")


@rules_app.command("list")
def rules_list() -> None:
    """List every detection rule (id, language, title)."""
    catalog = RuleCatalog.load()
    table = Table()
    table.add_column("Rule ID", style="bold")
    table.add_column("Lang")
    table.add_column("Title", style="dim")
    for c in sorted(catalog.all_rules(), key=lambda x: (x.language, x.rule.id)):
        table.add_row(c.rule.id, c.language, c.rule.title)
    console.print(table)
    console.print(f"{len(catalog)} rules.")


if __name__ == "__main__":
    app()
