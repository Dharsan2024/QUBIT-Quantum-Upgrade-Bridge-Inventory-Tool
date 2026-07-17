"""The ``qubit`` command-line interface.

M1 scope (doc 05 §5.2 + §9 M1 table):
  qubit scan         — the frame's one-command promise
  qubit project      — create / list / delete projects
  qubit cbom         — export + validate CBOM
  qubit db           — Alembic upgrade / current
  qubit serve        — launch the FastAPI server
  qubit rules        — lint / list detection rules
  qubit version      — print version
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from qubit_core import __version__ as core_version
from qubit_core import export_cbom, validate_cbom_structure
from qubit_core.db.session import default_db_url, get_engine, session_factory
from qubit_scanner import RuleCatalog, scan_paths
from qubit_scanner.catalog import RuleLoadError
from rich.console import Console
from rich.table import Table

from qubit_cli.commands.risk import risk_app
from qubit_migrate.cli import migrate_app
from qubit_bridge.cli import bridge_app

app = typer.Typer(
    name="qubit",
    help="QUBIT — Quantum Upgrade Bridge & Inventory Tool. Discover and inventory crypto.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Global options — resolved via environment if not provided on the command line.
# ---------------------------------------------------------------------------


def _db_opt() -> Any:
    """Return a fresh typer.Option for the --db flag.

    Pass flag name as first positional arg; function default ``= None`` gives the default.
    Do NOT pass ``default=`` — Typer 0.26 routes it into Click decls and breaks parsing.
    """
    return typer.Option(
        "--db",
        envvar="QUBIT_DB_URL",
        help="SQLite/Postgres DB URL. Default: user-data-dir SQLite.",
        show_default=False,
    )


def _resolve_db_url(db: str | None) -> str:
    return db or os.getenv("QUBIT_DB_URL") or default_db_url()


# ---------------------------------------------------------------------------
# qubit version
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the QUBIT version."""
    console.print(f"QUBIT {core_version}")


# ---------------------------------------------------------------------------
# qubit scan
# ---------------------------------------------------------------------------


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


def _render_table(result) -> None:  # type: ignore[no-untyped-def]
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


# ---------------------------------------------------------------------------
# qubit project
# ---------------------------------------------------------------------------

project_app = typer.Typer(help="Manage QUBIT projects.")
app.add_typer(project_app, name="project")
app.add_typer(risk_app, name="risk")
app.add_typer(migrate_app, name="migrate")
app.add_typer(bridge_app, name="bridge")


@project_app.command("list")
def project_list(
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """List all projects."""
    from qubit_core.db import ProjectRow
    from sqlalchemy import select

    url = _resolve_db_url(db)
    engine = get_engine(url)
    sf = session_factory(engine)
    with sf() as session:
        rows = session.scalars(select(ProjectRow).order_by(ProjectRow.created_at.asc())).all()

    table = Table()
    table.add_column("ID", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Slug")
    table.add_column("Root path")
    for row in rows:
        table.add_row(
            str(row.id)[:8] + "…",
            row.name,
            row.slug,
            row.root_path or "—",
        )
    console.print(table)
    console.print(f"{len(rows)} project(s).")


@project_app.command("create")
def project_create(
    name: Annotated[str, typer.Argument(help="Project name.")],
    root: Annotated[
        str | None, typer.Option("--root", help="Path of the repo root (gates diff-apply).")
    ] = None,
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """Create a new project."""
    import re

    from qubit_core.db import ProjectRow

    url = _resolve_db_url(db)
    engine = get_engine(url)
    from qubit_core.db import Base

    Base.metadata.create_all(engine)  # idempotent — no-op if tables exist
    sf = session_factory(engine)

    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-") or "project"
    with sf() as session:
        row = ProjectRow(name=name, slug=slug, root_path=root)
        session.add(row)
        session.commit()
        session.refresh(row)
        console.print(f"[green]Created[/green] project [bold]{row.name}[/bold] (id: {row.id})")


@project_app.command("delete")
def project_delete(
    name: Annotated[str, typer.Argument(help="Project name to delete.")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation prompt.")] = False,
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """Delete a project and all its scans/assets (CASCADE)."""
    from qubit_core.db import ProjectRow
    from sqlalchemy import select

    if not yes:
        typer.confirm(f"Delete project '{name}' and ALL its data?", abort=True)

    url = _resolve_db_url(db)
    engine = get_engine(url)
    sf = session_factory(engine)
    with sf() as session:
        row = session.scalar(select(ProjectRow).where(ProjectRow.name == name))
        if row is None:
            err_console.print(f"[red]error:[/red] project '{name}' not found.")
            raise typer.Exit(code=1)
        session.delete(row)
        session.commit()
    console.print(f"[green]Deleted[/green] project [bold]{name}[/bold].")


# ---------------------------------------------------------------------------
# qubit cbom
# ---------------------------------------------------------------------------

cbom_app = typer.Typer(help="Export and validate CycloneDX 1.7 CBOMs.")
app.add_typer(cbom_app, name="cbom")


@cbom_app.command("export")
def cbom_export(
    output: Annotated[Path, typer.Option("-o", "--output", help="Output file path.")],
    project: Annotated[str, typer.Option("-p", "--project", help="Project name.")],
    scan_seq: Annotated[
        int | None, typer.Option("--scan", help="Scan sequence number (default: latest).")
    ] = None,
    validate: Annotated[
        bool, typer.Option("--validate", help="Run structural validation before writing.")
    ] = False,
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """Export a scan's assets as a CycloneDX 1.7 CBOM JSON file."""
    from qubit_core import row_to_asset  # type: ignore[attr-defined]
    from qubit_core.db import AssetRow, ProjectRow, ScanRow
    from sqlalchemy import select

    url = _resolve_db_url(db)
    engine = get_engine(url)
    sf = session_factory(engine)
    with sf() as session:
        proj = session.scalar(select(ProjectRow).where(ProjectRow.name == project))
        if proj is None:
            err_console.print(f"[red]error:[/red] project '{project}' not found.")
            raise typer.Exit(code=1)

        stmt = select(ScanRow).where(ScanRow.project_id == proj.id)
        if scan_seq is not None:
            stmt = stmt.where(ScanRow.seq == scan_seq)
        else:
            stmt = stmt.order_by(ScanRow.seq.desc())
        scan_row = session.scalar(stmt)
        if scan_row is None:
            err_console.print("[red]error:[/red] no scan found.")
            raise typer.Exit(code=1)

        asset_rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan_row.id)).all()
        assets = [row_to_asset(r) for r in asset_rows]

    doc = export_cbom(assets)
    if validate:
        problems = validate_cbom_structure(doc)
        if problems:
            err_console.print(f"[yellow]validation issues:[/yellow] {problems}")

    output.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    n = len(assets)
    console.print(f"[green]Wrote[/green] CBOM ({n} assets, scan #{scan_row.seq}) → {output}")


@cbom_app.command("validate")
def cbom_validate(
    file: Annotated[Path, typer.Argument(help="CBOM JSON file to validate.")],
) -> None:
    """Validate a CBOM JSON file against the CycloneDX 1.7 structure."""
    if not file.exists():
        err_console.print(f"[red]error:[/red] file not found: {file}")
        raise typer.Exit(code=1)
    doc = json.loads(file.read_text(encoding="utf-8"))
    problems = validate_cbom_structure(doc)
    if problems:
        err_console.print("[yellow]Validation issues:[/yellow]")
        for p in problems:
            err_console.print(f"  • {p}")
        raise typer.Exit(code=1)
    console.print("[green]OK[/green] — CBOM structure valid.")


# ---------------------------------------------------------------------------
# qubit db
# ---------------------------------------------------------------------------

db_app = typer.Typer(help="Database schema management (Alembic).")
app.add_typer(db_app, name="db")


def _alembic_cfg(db_url: str) -> object:
    """Build an Alembic Config object pointing at the qubit-core alembic.ini."""
    from alembic.config import Config

    # Locate alembic.ini relative to qubit_core package
    qubit_core_spec = importlib.util.find_spec("qubit_core")
    if qubit_core_spec is None or qubit_core_spec.origin is None:
        raise RuntimeError("qubit_core package not found on sys.path")
    pkg_root = Path(qubit_core_spec.origin).parent  # …/qubit_core/
    # alembic.ini is two levels up: qubit_core/ → qubit-core/src/qubit_core/
    # Actually it lives in packages/qubit-core/alembic.ini
    # Walk up until we find alembic.ini (stops at monorepo root)
    ini_candidates = [
        pkg_root.parent / "alembic.ini",  # packages/qubit-core/src → packages/qubit-core
        pkg_root.parent.parent / "alembic.ini",  # editable install layout
    ]
    ini_path: Path | None = None
    for candidate in ini_candidates:
        if candidate.exists():
            ini_path = candidate
            break
    if ini_path is None:
        raise RuntimeError(
            "alembic.ini not found near qubit_core package. "
            "Run `qubit db upgrade` from the qubit-core package directory, "
            "or set QUBIT_DB_URL."
        )
    cfg = Config(str(ini_path))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


@db_app.command("upgrade")
def db_upgrade(
    revision: Annotated[str, typer.Argument(help="Target revision.")] = "head",
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """Apply pending Alembic migrations (default: upgrade to head)."""
    from alembic import command as alembic_cmd

    url = _resolve_db_url(db)
    console.print(f"[bold]upgrading[/bold] {url} → {revision}")
    cfg = _alembic_cfg(url)
    alembic_cmd.upgrade(cfg, revision)  # type: ignore[arg-type]
    console.print("[green]done[/green]")


@db_app.command("current")
def db_current(
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """Show current Alembic revision of the DB."""
    from alembic import command as alembic_cmd

    url = _resolve_db_url(db)
    cfg = _alembic_cfg(url)
    # Suppress ValueError: logging handler may write to a closed stream in test contexts.
    with contextlib.suppress(ValueError):
        alembic_cmd.current(cfg, verbose=True)  # type: ignore[arg-type]


@db_app.command("revision")
def db_revision(
    message: Annotated[str, typer.Option("-m", help="Short revision message.")],
    autogenerate: Annotated[
        bool, typer.Option("--autogenerate", help="Compare models to DB and generate diff.")
    ] = False,
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """Create a new Alembic migration revision."""
    from alembic import command as alembic_cmd

    url = _resolve_db_url(db)
    cfg = _alembic_cfg(url)
    alembic_cmd.revision(cfg, message=message, autogenerate=autogenerate)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# qubit serve
# ---------------------------------------------------------------------------


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Bind host.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8787,
    reload: Annotated[
        bool, typer.Option("--reload", help="Enable auto-reload (dev only).")
    ] = False,
    db: Annotated[str | None, _db_opt()] = None,
) -> None:
    """Start the QUBIT FastAPI server (qubit-api)."""
    if importlib.util.find_spec("qubit_api") is None:
        err_console.print(
            "[red]error:[/red] qubit-api is not installed. Install it with: uv sync --all-packages"
        )
        raise typer.Exit(code=1)

    url = _resolve_db_url(db)
    # Pass DB URL via environment so the API settings picks it up.
    env = {**os.environ, "QUBIT_DB_URL": url}

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "qubit_api.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload:
        cmd.append("--reload")

    console.print(
        f"[bold]QUBIT[/bold] API starting on [link]http://{host}:{port}[/link] (db: {url})"
    )
    try:
        subprocess.run(cmd, env=env, check=True)  # noqa: S603
    except subprocess.CalledProcessError as exc:
        raise typer.Exit(code=exc.returncode) from exc
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# qubit rules
# ---------------------------------------------------------------------------

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
