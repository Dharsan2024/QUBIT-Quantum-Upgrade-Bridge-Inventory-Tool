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


def _git_out(repo: Path, *args: str) -> str:
    """Run git and return trimmed stdout, or "" if it fails (callers supply a fallback)."""
    proc = subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _is_git_url(s: str) -> bool:
    """True if the target looks like a remote git repo rather than a local path."""
    s = s.strip()
    return s.startswith(("http://", "https://", "git@", "ssh://", "git://")) or s.endswith(".git")


def _repo_name_from_url(url: str) -> str:
    """Best-effort repository name from a git URL, for defaulting the local checkout path."""
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    return tail[:-4] if tail.endswith(".git") else tail or "repo"


def _clone_repo(url: str, dest: Path, *, shallow: bool) -> Path:
    """Clone ``url`` into ``dest`` and return the checkout path.

    ``shallow`` is right for a read-only inspection pass; a migration needs full history so the
    patched branch can be diffed, reviewed and pushed like any other change.
    Raises typer.Exit on failure with the git error surfaced (no silent hang — an early version of
    this UI just spun forever because it never actually cloned).
    """
    depth = ["--depth", "1"] if shallow else []
    console.print(f"[bold]Cloning[/bold] {url} → {dest} …")
    proc = subprocess.run(  # noqa: S603
        ["git", "clone", *depth, url, str(dest)],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        err_console.print(f"[red]clone failed:[/red] {proc.stderr.strip() or 'git clone error'}")
        raise typer.Exit(2)
    return dest


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
    target: Annotated[
        str | None,
        typer.Argument(help="Local file/folder OR a git repo URL. Omit to be prompted."),
    ] = None,
    generator: Annotated[
        str, typer.Option("--generator", help="Patch engine: auto | template | llm")
    ] = "auto",
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Skip the migrate confirmation prompt.")
    ] = False,
) -> None:
    """Scan a local path OR a git repo, show its HNDL risk, then offer to migrate it to PQC.

    For a git URL the download is consented to in two separate steps, because they cost different
    things: first a temporary shallow clone purely to scan (discarded afterwards), and then — only
    if vulnerabilities were actually found and you choose to migrate — a full clone to a directory
    you pick, where the patches land on a `qubit/pqc-migration` branch you can diff and push.
    A local path is never edited in place; patches are applied to a throwaway copy.
    """
    # 1. Ask for a target if not given.
    if target is None:
        target = typer.prompt("Path or git URL to scan", default=".")

    # 2. Resolve: clone a git URL, or use the local path.
    cloned = _is_git_url(target)
    if cloned:
        # Cloning writes someone else's code to this machine over the network, so it is confirmed
        # rather than done silently. The inspection clone is shallow and lands in a temp dir; a
        # persistent working copy is only created later, if the user opts into migrating (step 5).
        if not yes and not typer.confirm(
            f"Download a temporary shallow copy of {target} to scan it?", default=True
        ):
            console.print("Nothing scanned.")
            raise typer.Exit(0)
        path = _clone_repo(
            target, Path(tempfile.mkdtemp(prefix="qubit-clone-")) / "repo", shallow=True
        )
    else:
        path = Path(target).expanduser()
        if not path.exists():
            err_console.print(f"[red]error:[/red] path not found: {path}")
            raise typer.Exit(2)

    # 3. Scan (real tree-sitter scanner).
    console.print(f"\n[bold]Scanning[/bold] {path if not cloned else target} …")
    result = scan_paths([path], repo=str(path))
    if not result.assets:
        console.print("[green]No cryptographic assets found.[/green]")
        if cloned:
            shutil.rmtree(path.parent, ignore_errors=True)
        raise typer.Exit(0)

    # 4. Risk-score every asset (real HNDL pipeline).
    from qubit_risk import RiskPipeline, load_config

    annotated = RiskPipeline(load_config()).assess(result.assets)
    console.print(_risk_table(annotated))

    vuln = [a for a in annotated if a.quantum_vulnerable.vulnerable]
    if not vuln:
        console.print("\n[green]Nothing quantum-vulnerable — no migration needed.[/green]")
        if cloned:
            shutil.rmtree(path.parent, ignore_errors=True)
        raise typer.Exit(0)
    console.print(f"\n[bold]{len(vuln)}[/bold] of {len(annotated)} assets are quantum-vulnerable.")

    # 5. Offer to migrate.
    if not yes and not typer.confirm("Migrate these to post-quantum crypto now?", default=True):
        console.print("Skipped migration.")
        if cloned:
            shutil.rmtree(path.parent, ignore_errors=True)  # discard the clone (user declined)
            console.print("[dim]Temporary copy discarded.[/dim]")
        raise typer.Exit(0)

    # 5b. For a remote repo, migrating on the throwaway shallow clone is not much use — the result
    # lives in a temp dir the user did not choose and has no history to diff or push. Ask where to
    # put a real working copy, then clone it properly (full history) and migrate there.
    work_path = path
    if cloned:
        default_dest = Path.cwd() / _repo_name_from_url(target)
        if yes:
            dest = default_dest
        else:
            console.print(
                "\nTo migrate properly this needs a full local checkout: real history, so the "
                "patched branch can be diffed, reviewed and pushed like any other change."
            )
            raw = typer.prompt(
                "Clone the repository to (blank to cancel)", default=str(default_dest)
            )
            if not raw.strip():
                console.print("Migration cancelled.")
                shutil.rmtree(path.parent, ignore_errors=True)
                raise typer.Exit(0)
            dest = Path(raw).expanduser()
        if dest.exists() and any(dest.iterdir()):
            err_console.print(f"[red]error:[/red] {dest} already exists and is not empty.")
            raise typer.Exit(2)
        work_path = _clone_repo(target, dest, shallow=False)
        shutil.rmtree(path.parent, ignore_errors=True)  # the shallow scan copy is done with
        console.print(f"[dim]Temporary scan copy discarded; working in {work_path}[/dim]")

    _migrate(work_path, generator, in_place=cloned)


def _migrate(path: Path, generator: str, *, in_place: bool = False) -> None:
    """Apply patches to a git repo, then prove the fix with a re-scan.

    ``in_place=False`` (a LOCAL target): patches are applied to a throwaway copy so the user's real
    files are never edited — they asked to scan a directory, not to have it rewritten.
    ``in_place=True`` (a repo this command cloned, with the user's consent and to a path they
    chose): patches are applied on a branch in that checkout, so the result is a normal reviewable
    git change instead of an orphan copy in a temp directory.
    """
    from qubit_core.db import Base, ProjectRow, ScanRow
    from qubit_core.mapping import asset_to_row
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_risk import RiskPipeline, load_config
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    scratch = Path(tempfile.mkdtemp(prefix="qubit-run-"))
    branch = "qubit/pqc-migration"
    base_branch = "main"
    if in_place:
        repo = path
        # Read the real base branch instead of assuming "main" — the review/push hints printed at
        # the end are copy-pasteable commands, and `git diff main...` is simply wrong on a repo
        # whose default branch is master (or anything else).
        base_branch = _git_out(repo, "rev-parse", "--abbrev-ref", "HEAD") or "main"
        _git(repo, "checkout", "-b", branch)
        console.print(f"[dim]Working on branch {branch} (base: {base_branch})[/dim]")
    else:
        # Scratch git repo so real files are never edited in place.
        repo = scratch / "repo"
        if path.is_dir():
            # `.git` is excluded deliberately. Copying it brought the SOURCE repo's history along,
            # so `git init` landed on an already-initialised repo whose files were all committed
            # already — `git add .` then staged nothing and `git commit -m baseline` exited 1,
            # crashing the whole run. This only shows up when the target is itself a git repo,
            # which is the common case for a real project.
            shutil.copytree(path, repo, ignore=shutil.ignore_patterns(".git"))
        else:
            repo.mkdir(parents=True)
            shutil.copy2(path, repo / path.name)
        _git(repo, "init")
        _git(repo, "config", "user.email", "run@qubit.local")
        _git(repo, "config", "user.name", "QUBIT Run")
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "baseline")

    # ONE pre-patch scan feeds both the "before" counts and the risk annotation. These were two
    # separate scan_paths() calls over the identical unpatched tree — pure duplicated work (~0.2 s
    # on the demo app, ~0.4 s on a 40-file package, and it scales with repo size). `_counts` only
    # reads algorithm/quantum_vulnerable, which assess() does not modify, so the order is safe.
    pre_assets = scan_paths([repo], repo="run").assets
    before = _counts(pre_assets)

    engine = create_engine(f"sqlite:///{scratch / 'run.db'}")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="run", slug="run")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    annotated = RiskPipeline(load_config()).assess(pre_assets)
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
                # This used to `continue` in silence, which is the worst possible outcome: a patch
                # rejected by the validation pipeline left NO trace, so a finding that stayed
                # unfixed in the before/after table had no explanation anywhere. Name the stage that
                # rejected it — that is the difference between "the tool did nothing" and "the tool
                # refused an unsafe patch, here is why".
                reasons = _validation_failure_reasons(patch)
                console.print(f"  [yellow]rejected[/yellow] patch for {patch.file_path}: {reasons}")
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

    # A raw count delta (`sum(before) - sum(after)`) is NOT a fix metric, and reported one as zero
    # on a run that had just correctly remediated eight weak algorithms. Two reasons it cannot work:
    #
    #  * Hardening changes the GRANULARITY of the inventory. One `ssl_ciphers HIGH:!aNULL` line
    #    becomes six explicit AEAD suites, so the number of findings rises while the posture
    #    improves. Comparing the cardinality of two differently-grained sets is meaningless.
    #  * The replacements are modern but mostly still quantum-vulnerable. Swapping 3DES/TLSv1.0/
    #    ssh-rsa for ECDHE/X25519/Ed25519/rsa-sha2 is a real classical win and Shor still breaks all
    #    of the latter, so a vulnerable-count delta understates the classical progress AND
    #    overstates the quantum progress at the same time.
    #
    # What is honest is set membership: which weak algorithms are GONE, and what took their place.
    eliminated = sorted(a for a in before if after.get(a, 0) == 0)
    introduced = sorted(a for a in after if before.get(a, 0) == 0)

    if applied and eliminated:
        console.print(
            f"[bold green]✔ {applied} patch(es) applied — "
            f"{len(eliminated)} weak algorithm(s) eliminated:[/bold green] "
            f"{', '.join(eliminated)}"
        )
        if introduced:
            # Never let a replacement pass as post-quantum just because it is modern.
            console.print(
                f"[dim]Replaced by (still quantum-vulnerable, so not the end of the job): "
                f"{', '.join(introduced)}[/dim]"
            )
        if in_place:
            console.print(f"[dim]Patched on branch [bold]{branch}[/bold] in {repo}[/dim]")
            console.print(
                f'[dim]Review with:  git -C "{repo}" diff {base_branch}...{branch}'
                f'   ·   push with:  git -C "{repo}" push -u origin {branch}[/dim]'
            )
        else:
            console.print(f"[dim]Patched copy kept at {repo} (your files were not touched)[/dim]")
        if after:
            console.print(
                f"[yellow]{sum(after.values())} quantum-vulnerable finding(s) remain.[/yellow] "
                f"{_next_step_hint(generator)}"
            )
    else:
        console.print(f"[yellow]No findings auto-fixed.[/yellow] {_next_step_hint(generator)}")


def _validation_failure_reasons(patch: object) -> str:
    """Summarize which validation stages rejected a patch, for the operator reading the terminal.

    `validation_json` holds `{stages: {name: {status, detail}}, passed, partial}`. Only the failing
    stages are reported, with their detail trimmed — a full compiler or pytest dump would bury the
    one line that matters.
    """
    report = getattr(patch, "validation_json", None) or {}
    stages = report.get("stages", {}) if isinstance(report, dict) else {}
    failed = [
        f"{name} ({(info.get('detail') or 'no detail').splitlines()[0][:140]})"
        for name, info in stages.items()
        if isinstance(info, dict) and info.get("status") == "fail"  # StageStatus literal is "fail"
    ]
    if failed:
        return "failed " + ", ".join(failed)
    return f"status={getattr(patch, 'status', 'unknown')} with no failing stage recorded"


def _next_step_hint(generator: str) -> str:
    """What to actually do about the findings that are still there.

    Telling someone to "re-run with --generator llm" on a run that ALREADY used the LLM generator is
    worse than saying nothing: it implies an untried option exists and hides the real reason those
    findings survived. Once the LLM has had its three attempts, what remains is either work the
    rewrite guard rejected (a patch that did not preserve the file) or work no code patch can do at
    all — reissuing a certificate, rotating an HSM/Vault key, upgrading a peer that has to agree on
    the algorithm.

    `auto` counts as having used the LLM: the orchestrator routes every rule WITHOUT a codemod to
    it, which is precisely the set — key exchange, signatures, cipher rewrites — that the hint used
    to point at. Only `template` genuinely leaves the LLM untried.
    """
    if generator in ("llm", "auto"):
        return (
            "The LLM generator has already run. What is left needs a human: rewrites its "
            "preservation guard rejected, plus assets no patch can fix — certificate reissue, "
            "HSM/Vault key rotation, and peers that must agree on the new algorithm."
        )
    return (
        "Key exchange and signatures need the LLM generator: re-run with "
        "[bold]--generator llm[/bold] and Ollama running."
    )


def _counts(assets) -> dict[str, int]:  # type: ignore[no-untyped-def]
    counts: dict[str, int] = {}
    for a in assets:
        if a.quantum_vulnerable.vulnerable:
            counts[a.algorithm] = counts.get(a.algorithm, 0) + 1
    return counts


__all__ = ["run"]
