"""Risk engine CLI commands."""

from __future__ import annotations

import os
from typing import Annotated
from uuid import UUID

import typer
from qubit_core.db.models import AssetRow, ScanRow
from qubit_core.db.session import default_db_url, get_engine, session_factory
from qubit_risk import CRQCTimelineSimulator, RiskPipeline, load_config
from rich.console import Console
from rich.table import Table

risk_app = typer.Typer(help="Risk Engine operations.")
console = Console()
err_console = Console(stderr=True)


def _resolve_db_url(db: str | None) -> str:
    return db or os.getenv("QUBIT_DB_URL") or default_db_url()


@risk_app.command("timeline")
def risk_timeline(
    algorithm: Annotated[
        str, typer.Option("--algorithm", help="Algorithm to simulate")
    ] = "RSA-2048",
    trials: Annotated[int, typer.Option("--trials", help="Monte Carlo trials")] = 10000,
    seed: Annotated[int | None, typer.Option("--seed", help="Random seed")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """Simulate CRQC timeline for an algorithm."""
    cfg = load_config()
    # Actually, we can override n_trials in the config.
    cfg.hardware_priors["n_trials"] = trials
    if seed is not None:
        cfg.hardware_priors["seed"] = seed
    sim = CRQCTimelineSimulator(cfg)

    with console.status(f"Simulating {algorithm} ({trials} trials)..."):
        curve = sim.simulate(algorithm)

    if curve is None:
        err_console.print(
            f"[red]error:[/red] Algorithm {algorithm} not supported or not vulnerable."
        )
        raise typer.Exit(1)

    if as_json:
        console.print_json(
            data={
                "algorithm": algorithm,
                "years": curve.years,
                "cdf": curve.cdf,
                "p05_year": curve.p05_year,
                "median_year": curve.median_year,
                "p95_year": curve.p95_year,
            }
        )
    else:
        console.print(f"[bold]Timeline Curve for {algorithm}[/bold]")
        console.print(f"p05: {curve.p05_year}, Median: {curve.median_year}, p95: {curve.p95_year}")
        table = Table()
        table.add_column("Year")
        table.add_column("Probability")
        for i, year in enumerate(curve.years):
            if year % 5 == 0:
                table.add_row(str(year), f"{curve.cdf[i]:.4f}")
        console.print(table)


@risk_app.command("assess")
def risk_assess(
    scan_id: Annotated[UUID, typer.Option("--scan-id", help="Scan ID to assess")],
    db: Annotated[str | None, typer.Option("--db", help="DB URL")] = None,
) -> None:
    """Run risk assessment over assets in a scan."""
    url = _resolve_db_url(db)
    engine = get_engine(url)
    sf = session_factory(engine)

    with sf() as session:
        scan = session.get(ScanRow, scan_id)
        if not scan:
            err_console.print("[red]error:[/red] scan not found")
            raise typer.Exit(1)

        assets = [AssetRow.to_schema(a) for a in scan.assets]

    pipe = RiskPipeline(load_config())

    with console.status("Assessing assets..."):
        annotated = pipe.assess(assets)

    with sf() as session:
        for a in annotated:
            row = session.query(AssetRow).filter(AssetRow.id == a.id).first()
            if row and a.risk:
                row.risk_score = a.risk.score
                row.risk_ci_low = a.risk.ci_low
                row.risk_ci_high = a.risk.ci_high
                row.mosca_margin_years = a.risk.mosca_margin_years
                row.priority_rank = a.risk.priority_rank
        session.commit()

    console.print(f"[green]Successfully assessed {len(annotated)} assets.[/green]")


@risk_app.command("explain")
def risk_explain(
    asset_id: Annotated[UUID, typer.Argument(help="Asset ID to explain")],
    db: Annotated[str | None, typer.Option("--db", help="DB URL")] = None,
) -> None:
    """Show explainable risk details for an asset."""
    url = _resolve_db_url(db)
    engine = get_engine(url)
    sf = session_factory(engine)

    with sf() as session:
        row = session.get(AssetRow, asset_id)
        if not row:
            err_console.print(f"[red]error:[/red] asset {asset_id} not found")
            raise typer.Exit(1)

        asset = AssetRow.to_schema(row)

        console.print(f"[bold]Risk Explanation for Asset {asset_id}[/bold]")
        console.print(f"Algorithm:   {asset.algorithm}")
        console.print(f"Sensitivity: {asset.sensitivity.value if asset.sensitivity else 'unknown'}")
        console.print(f"Shelf life:  {asset.shelf_life_years} years")

        if not asset.risk:
            console.print("[yellow]Asset has not been assessed yet.[/yellow]")
            raise typer.Exit(0)

        console.print(f"Score:       {asset.risk.score:.4f}")
        console.print(f"CI 90%:      [{asset.risk.ci_low:.4f}, {asset.risk.ci_high:.4f}]")
        console.print(f"Mosca margin:{asset.risk.mosca_margin_years:.1f} years")
        console.print(f"Priority rank:{asset.risk.priority_rank}")


@risk_app.command("mosca")
def risk_mosca(
    db: Annotated[str | None, typer.Option("--db", help="DB URL")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """Print the Mosca margin table for the entire inventory."""
    url = _resolve_db_url(db)
    engine = get_engine(url)
    sf = session_factory(engine)

    with sf() as session:
        from sqlalchemy import select

        rows = (
            session.execute(select(AssetRow).where(AssetRow.risk_score.isnot(None))).scalars().all()
        )
        assets = [AssetRow.to_schema(r) for r in rows]

    if not assets:
        console.print("No assessed assets found.")
        raise typer.Exit(0)

    assets.sort(key=lambda a: a.risk.priority_rank if a.risk else 9999)

    if as_json:
        console.print_json(data=[a.model_dump(mode="json") for a in assets])
    else:
        table = Table(title="Mosca Margins")
        table.add_column("Rank", justify="right")
        table.add_column("Asset ID")
        table.add_column("Algorithm")
        table.add_column("Sensitivity")
        table.add_column("Margin (years)", justify="right")

        for a in assets:
            if not a.risk:
                continue
            color = "red" if a.risk.mosca_margin_years < 0 else "green"
            table.add_row(
                str(a.risk.priority_rank),
                str(a.id)[:8],
                a.algorithm,
                a.sensitivity.value if a.sensitivity else "-",
                f"[{color}]{a.risk.mosca_margin_years:.1f}[/{color}]",
            )
        console.print(table)
