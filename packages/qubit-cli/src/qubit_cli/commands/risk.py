"""Risk engine CLI commands."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from qubit_core import row_to_asset
from qubit_core.db.models import AssetRow, ScanRow
from qubit_core.db.session import default_db_url, get_engine, session_factory
from qubit_risk import CRQCTimelineSimulator, RiskPipeline, load_config
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

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

        rows = session.execute(select(AssetRow).where(AssetRow.scan_id == scan.id)).scalars().all()
        assets = [row_to_asset(r) for r in rows]

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

        asset = row_to_asset(row)

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


@risk_app.command("gen-dataset")
def risk_gen_dataset(
    out: Annotated[Path, typer.Option("--out", help="Output JSONL path")] = Path(
        "datasets/sensitivity/synth.jsonl"
    ),
    per_class: Annotated[int, typer.Option("--per-class", help="Examples per class")] = 1500,
    seed: Annotated[int, typer.Option("--seed", help="RNG seed (reproducible)")] = 42,
) -> None:
    """Synthesize the Tier-1 sensitivity training corpus (doc 02 §6.3.4)."""
    from qubit_risk.ml import SYNTH_CLASSES, generate_dataset, write_jsonl

    data = generate_dataset(per_class=per_class, seed=seed)
    n = write_jsonl(data, out)
    console.print(
        f"[green]Wrote {n} examples[/green] across {len(SYNTH_CLASSES)} classes "
        f"({per_class}/class, seed={seed}) -> {out}"
    )


@risk_app.command("train-sensitivity")
def risk_train_sensitivity(
    out: Annotated[Path, typer.Option("--out", help="Checkpoint output dir")] = Path(
        "models/sensitivity-distilbert"
    ),
    per_class: Annotated[int, typer.Option("--per-class")] = 3000,
    max_epochs: Annotated[int, typer.Option("--max-epochs", help="Ceiling; early stop picks")] = 20,
    patience: Annotated[int, typer.Option("--patience")] = 3,
    batch_size: Annotated[int, typer.Option("--batch-size")] = 32,
) -> None:
    """Fine-tune the DistilBERT sensitivity classifier (needs the 'ml' extra + a GPU)."""
    from qubit_risk.ml.train import TrainConfig, train

    cfg = TrainConfig(
        out_dir=out,
        per_class=per_class,
        max_epochs=max_epochs,
        patience=patience,
        batch_size=batch_size,
    )
    console.print(
        f"[bold]Training DistilBERT[/bold] -> {out} "
        f"(per_class={per_class}, max_epochs={max_epochs})"
    )
    result = train(cfg)
    console.print(
        f"[green]Done.[/green] holdout macro-F1={result['holdout_macro_f1']:.4f} "
        f"(in-dist={result['in_distribution_macro_f1']:.4f}) on {result['device']}"
    )
    console.print_json(data=result["holdout_per_class_f1"])


@risk_app.command("train-regressor")
def risk_train_regressor(
    out: Annotated[Path, typer.Option("--out", help="Model output dir")] = Path(
        "models/risk-xgboost"
    ),
    n_assets: Annotated[int, typer.Option("--n-assets", help="Number of synthetic assets")] = 50000,
    k_draws: Annotated[int, typer.Option("--k-draws", help="Monte Carlo draws per asset")] = 200,
    seed: Annotated[int, typer.Option("--seed", help="RNG seed")] = 42,
    n_estimators: Annotated[int, typer.Option("--n-estimators")] = 600,
    max_depth: Annotated[int, typer.Option("--max-depth")] = 6,
    learning_rate: Annotated[float, typer.Option("--learning-rate")] = 0.05,
    n_jobs: Annotated[int | None, typer.Option("--n-jobs")] = None,
) -> None:
    """Train the XGBoost risk regressor + split-conformal calibration (doc 02 §6.4.4)."""
    from qubit_risk.regressor.train import RegressorConfig, train

    cfg = RegressorConfig(
        out_dir=out,
        n_assets=n_assets,
        k_draws=k_draws,
        seed=seed,
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        n_jobs=n_jobs,
    )
    console.print(
        f"[bold]Training XGBoost Regressor[/bold] -> {out} ({n_assets} assets, {k_draws} draws)"
    )
    metrics = train(cfg)
    console.print(
        f"[green]Done.[/green] Test MAE={metrics['test_mae']:.4f}, "
        f"Empirical Coverage={metrics['empirical_test_coverage']:.4f} "
        f"(target {metrics['target_coverage']:.2f})"
    )


@risk_app.command("eval")
def risk_eval_external(
    pairwise: Annotated[
        Path, typer.Option("--pairwise", help="CSV with winner_id,loser_id[,rater]")
    ],
    scores: Annotated[
        Path, typer.Option("--scores", help="CSV with asset_id plus model score columns")
    ],
    min_rho: Annotated[
        float, typer.Option("--min-rho", help="Target Spearman rho for xgb_score")
    ] = 0.7,
    as_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """Run the M3 external-validation study (doc 02 §6.4.5) against human rankings."""
    from qubit_risk.regressor.external_validation import evaluate_external_validation

    result = evaluate_external_validation(pairwise_csv=pairwise, scores_csv=scores)

    if as_json:
        console.print_json(
            data={
                "n_assets": result.n_assets,
                "n_comparisons": result.n_comparisons,
                "spearman_by_model": result.spearman_by_model,
            }
        )
    else:
        table = Table(title="External Validation (Spearman rho vs human consensus)")
        table.add_column("Model")
        table.add_column("Rho", justify="right")
        for model, rho in sorted(
            result.spearman_by_model.items(), key=lambda kv: kv[1], reverse=True
        ):
            color = "green" if rho >= min_rho else "yellow"
            table.add_row(model, f"[{color}]{rho:.4f}[/{color}]")
        console.print(table)
        console.print(
            f"Compared {result.n_assets} assets from {result.n_comparisons} pairwise judgments."
        )

    xgb = result.spearman_by_model.get("xgb_score")
    if xgb is None:
        return
    if xgb < min_rho:
        err_console.print(
            f"[red]error:[/red] xgb_score rho={xgb:.4f} is below target {min_rho:.2f}"
        )
        raise typer.Exit(3)
    for baseline in ("bn_score", "static_score"):
        baseline_val = result.spearman_by_model.get(baseline)
        if baseline_val is not None and xgb <= baseline_val:
            err_console.print(
                "[red]error:[/red] xgb_score must beat baseline "
                f"{baseline} ({xgb:.4f} <= {baseline_val:.4f})"
            )
            raise typer.Exit(3)


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
        rows = (
            session.execute(select(AssetRow).where(AssetRow.risk_score.isnot(None))).scalars().all()
        )
        assets = [row_to_asset(r) for r in rows]

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


@risk_app.command("eval")
def risk_eval(
    pairwise: Annotated[
        Path | None,
        typer.Option(
            "--pairwise",
            help="CSV with columns winner_id,loser_id[,rater] — human pairwise judgments.",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
    scores: Annotated[
        Path | None,
        typer.Option(
            "--scores",
            help="CSV with columns asset_id,<model1>[,<model2>,...] — model risk scores.",
            exists=True,
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
    component: Annotated[
        str | None,
        typer.Option(
            "--component",
            help="Eval component: xgb | bert | bn | timeline. Default: xgb (human ranking study).",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help="Model to test against rho-target (default: xgb_score or first xgb* column).",
        ),
    ] = None,
    rho_target: Annotated[
        float,
        typer.Option("--rho-target", help="Minimum Spearman rho to exit 0. Default: 0.7."),
    ] = 0.7,
    as_json: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """Paper-experiment evaluation harness (doc 02 §6.4.5, §8.3).

    Human-ranking study (default / --component xgb):
      Compute Bradley-Terry consensus from pairwise CSV, then Spearman rho
      between model scores (scores CSV) and human consensus.
      Exit 0 if target model rho >= rho-target, exit 3 otherwise.

    Other --component values (bert, bn, timeline) are stubs for future paper
    experiments -- they will print a placeholder message.
    """
    comp = (component or "xgb").lower()

    if comp not in {"xgb", "bert", "bn", "timeline"}:
        err_console.print(
            f"[red]error:[/red] Unknown --component {comp!r}. Use xgb|bert|bn|timeline."
        )
        raise typer.Exit(4)

    if comp != "xgb":
        console.print(
            f"[yellow]info:[/yellow] --component {comp!r} experiment not yet implemented. "
            "Only 'xgb' (human-ranking study) is wired in this release."
        )
        raise typer.Exit(0)

    # --- xgb: human ranking study ---
    if pairwise is None or scores is None:
        err_console.print(
            "[red]error:[/red] --pairwise and --scores are required for --component xgb."
        )
        raise typer.Exit(4)

    from qubit_risk.regressor.external_validation import evaluate_external_validation

    try:
        result = evaluate_external_validation(pairwise_csv=pairwise, scores_csv=scores)
    except ValueError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(4) from exc

    # Identify target model to evaluate against rho_target
    target_model_name = model
    if not target_model_name:
        candidates = [m for m in result.spearman_by_model if "xgb" in m.lower()]
        target_model_name = candidates[0] if candidates else next(iter(result.spearman_by_model))

    target_rho_val = result.spearman_by_model.get(target_model_name, 0.0)
    passed_target = target_rho_val >= rho_target

    if as_json:
        import json

        console.print_json(
            json.dumps(
                {
                    "n_assets": result.n_assets,
                    "n_comparisons": result.n_comparisons,
                    "spearman_by_model": result.spearman_by_model,
                    "spearman_rho": result.spearman_by_model,
                    "target_rho": rho_target,
                    "target_model": target_model_name,
                    "passed_target": passed_target,
                    "all_meet_target": passed_target,
                    "consensus_scores": result.consensus_scores,
                }
            )
        )
    else:
        console.print(
            f"\n[bold]External Validation (Bradley-Terry -> Spearman rho)[/bold]"
            f"  n_assets={result.n_assets}  n_comparisons={result.n_comparisons}"
            f"  target_rho>={rho_target}\n"
        )

        table = Table(title="Model vs Human Consensus")
        table.add_column("Model", style="cyan")
        table.add_column("Spearman rho", justify="right")
        table.add_column(">= target?", justify="center")

        for m_name, rho in sorted(result.spearman_by_model.items()):
            meets = rho >= rho_target
            color = "green" if meets else "red"
            is_target = " (target)" if m_name == target_model_name else ""
            table.add_row(
                f"{m_name}{is_target}",
                f"[{color}]{rho:.3f}[/{color}]",
                f"[{color}]{'✓' if meets else '✗'}[/{color}]",
            )
        console.print(table)

        if passed_target:
            console.print(
                f"\n[green bold]Target model '{target_model_name}' "
                f"meets rho >= {rho_target}[/green bold]"
                f" ({target_rho_val:.3f}) -- headline result ready for paper.\n"
            )
        else:
            console.print(
                f"\n[yellow]⚠ Target model '{target_model_name}' "
                f"below target ({target_rho_val:.3f} < {rho_target})[/yellow]\n"
            )

    raise typer.Exit(0 if passed_target else 3)
