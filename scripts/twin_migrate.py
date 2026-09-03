"""Duplicate the MediVault twin, migrate the copy, and run the twin's own tests against it.

This is the end-to-end demonstration the corpus evaluation could not produce. On `pyload` and
`flexget` nobody knew how many findings existed, which ones were safe to change, or whether an
accepted patch had broken the application — the suites did not cover the crypto, so `tests` skipped
on 39 of 39 patches and the only available verdict was "our own syntactic gates said yes".

Here all three are known:

* **`GROUND_TRUTH.json`** says what SHOULD happen to every planted finding, written before the run.
* **The twin's 96-test suite** covers every crypto path, runs in under a second with no network,
  and was proven to discriminate: `tools/mutation_matrix.py` applies each migration by hand and
  confirms the suite goes red on the ten that break the application and stays green on the four
  that do not.
* **The copy is thrown away**, so the run is repeatable and the original twin is never touched.

So a patch here can be scored three ways at once: did the tool propose it, was proposing it
correct, and did applying it break the program.

## What this is not

One application, purpose-built by the same author as the tool. The findings are planted, so the
*detection* result says only that the scanner sees what it was aimed at. What it does establish is
the **disposition** result — migrate versus refuse — because the twin's constraints (a persisted
digest column, a remote party's header format) are the same constraints that made eleven pyload
patches wrong, reproduced where they can be measured instead of merely observed after the fact.

Usage::

    uv run python scripts/twin_migrate.py --generator template
    uv run python scripts/twin_migrate.py --generator auto --out test-output/run-llm
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
#: The twins live in `demo-lab`, each its own git repository — which is what lets the
#: `applies` rung run `git apply` against one at all.
TWIN_ROOT = Path(os.getenv("QUBIT_TWINS", str(REPO_ROOT / "demo-lab")))


@dataclass(frozen=True)
class Twin:
    """One fixture, and how to run its suite.

    The suite command differs per ecosystem, and every one of them runs inside a container: Java,
    Go and Ruby are not installed on the development host, and the container is the same offline
    image QUBIT's `tests` rung needs anyway. Python is the exception only because the repository's
    own interpreter already has its dependencies.
    """

    name: str
    language: str
    #: Where the scanner is pointed. Narrower than the repo root so build output and vendored
    #: dependencies are never scanned as if they were the application.
    scan_subdir: str
    #: argv for the suite, run with the twin as the working directory.
    test_cmd: list[str]
    #: Extra `docker run` arguments — a dependency cache mount, usually.
    docker_mounts: list[str] = field(default_factory=list)
    image: str | None = None
    sandbox_image: str | None = None
    test_command_in_sandbox: str | None = None

    @property
    def root(self) -> Path:
        return TWIN_ROOT / self.name


TWINS: dict[str, Twin] = {
    "medivault-emr": Twin(
        name="medivault-emr",
        language="python",
        scan_subdir="app",
        test_cmd=[
            sys.executable,
            "-m",
            "pytest",
            "tests",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ],
        sandbox_image="qubit-eval/medivault:py312",
        test_command_in_sandbox="python -m pytest tests -q --continue-on-collection-errors",
    ),
    "paymesh-gateway": Twin(
        name="paymesh-gateway",
        language="java",
        scan_subdir="src/main",
        test_cmd=["mvn", "-B", "-o", "test"],
        image="maven:3.9-eclipse-temurin-21",
        docker_mounts=["-v", f"{Path.home() / '.m2-paymesh'}:/root/.m2"],
        sandbox_image="qubit-eval/paymesh:sandbox",
        test_command_in_sandbox="mvn -B -o test",
    ),
    "sentinel-idp": Twin(
        name="sentinel-idp",
        language="go",
        scan_subdir="internal",
        test_cmd=["go", "test", "./..."],
        image="golang:1.23-alpine",
        docker_mounts=["-v", f"{Path.home() / '.gocache-sentinel'}:/go/pkg/mod"],
        sandbox_image="qubit-eval/sentinel:sandbox",
        test_command_in_sandbox="go test ./...",
    ),
    "inkwell-esign": Twin(
        name="inkwell-esign",
        language="ruby",
        scan_subdir="lib",
        test_cmd=["ruby", "-Ilib", "-Itest", "test/crypto_contract_test.rb"],
        image="ruby:3.3-alpine",
        sandbox_image="qubit-eval/inkwell:sandbox",
        test_command_in_sandbox="ruby -Ilib -Itest test/crypto_contract_test.rb",
    ),
}

#: Copied artefacts that are build output, not source.
IGNORE = shutil.ignore_patterns(
    "__pycache__",
    "*.pyc",
    "*.db",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "MUTATION_RESULTS.json",
    "target",
    "vendor",
    ".bundle",
    "tmp",
)


def duplicate(twin: Twin, dest: Path) -> None:
    """Take a clean copy of the twin. The original is never migrated.

    `.git` is copied deliberately: QUBIT's `applies` rung runs `git apply`, and without a repository
    it skips with "no git repo to check against" — which is how that rung reported nothing on every
    patch the project has ever produced.
    """
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(twin.root, dest, ignore=IGNORE)


def run_tests(twin: Twin, app: Path) -> dict[str, Any]:
    """The twin's own suite, against whatever is on disk at `app`.

    Runs in the twin's toolchain container unless the twin is Python, whose dependencies this
    repository's interpreter already has.
    """
    started = time.perf_counter()
    if twin.image:
        argv = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{app}:/src",
            *twin.docker_mounts,
            "-w",
            "/src",
            twin.image,
            *twin.test_cmd,
        ]
        cwd = None
    else:
        argv = twin.test_cmd
        cwd = app

    # argv comes from the TWINS table above — a fixed literal in this file, never from a caller.
    proc = subprocess.run(  # noqa: S603
        argv, cwd=cwd, capture_output=True, text=True, timeout=1800
    )
    out = proc.stdout + proc.stderr

    # Each ecosystem announces its result differently; take the last line that looks like one.
    markers = ("passed", "failed", "Tests run:", " runs, ", "ok  ", "FAIL")
    summary = next(
        (ln.strip() for ln in reversed(out.splitlines()) if any(m in ln for m in markers)),
        "(no recognisable summary line)",
    )
    failed = [
        ln.strip()[:120]
        for ln in out.splitlines()
        if ln.startswith(("FAILED", "ERROR", "--- FAIL", "[ERROR] Tests run:")) or "Failure:" in ln
    ]
    return {
        "green": proc.returncode == 0,
        "summary": summary[:160],
        "seconds": round(time.perf_counter() - started, 2),
        "failed_nodes": failed[:40],
    }


def seed(twin: Twin, app: Path, db_path: Path, name: str) -> tuple[Any, list[Any]]:
    """Scan the copy and build a migration plan over it. Mirrors `scripts/seed_corpus.py`."""
    from qubit_core.db import Base, ProjectRow, ScanRow
    from qubit_core.mapping import asset_to_row
    from qubit_core.schemas import RiskAnnotation
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_scanner.api import scan_paths
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    if db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    result = scan_paths([app / twin.scan_subdir], scanners={"code"}, repo=name)
    assets = [a for a in result.assets if str(getattr(a, "asset_type", "")) == "algorithm-use"]

    with factory() as session:
        project = ProjectRow(name=name, slug=name)
        session.add(project)
        session.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        session.add(scan)
        session.flush()
        for rank, asset in enumerate(assets, start=1):
            asset.risk = RiskAnnotation(
                score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=rank
            )
            session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
        session.commit()

        orch = MigrationOrchestrator(session)
        orch.build_plan()
        session.commit()

    return factory, assets


def migrate(factory: Any, app: Path, generator: str) -> list[dict[str, Any]]:
    """Generate, approve and apply a patch for every ready task.

    Runs in one process. That is fine here and would NOT be fine for an arms comparison: several
    module-scope caches survive a fresh database, so `scripts/run_arms.py` uses one interpreter per
    finding. This is a single demonstration run, not a between-arm measurement.
    """
    from qubit_core.db import AssetRow
    from qubit_migrate.orchestrator import (
        AlreadySatisfied,
        GuidedRemediation,
        MigrationOrchestrator,
    )
    from qubit_migrate.state.models import MigrationTask

    with factory() as session:
        # Keep the UUID objects: MigrationTask.id is a UUID column, and a str primary key
        # fails in the type coercion rather than simply not matching.
        task_ids = [
            t.id
            for t in session.query(MigrationTask).order_by(MigrationTask.rank).all()
            if str(t.state) == "ready"
        ]

    outcomes: list[dict[str, Any]] = []
    for task_id in task_ids:
        with factory() as session:
            orch = MigrationOrchestrator(session)
            task = session.query(MigrationTask).filter_by(id=task_id).one()
            record: dict[str, Any] = {
                "task_id": str(task_id),
                "rule_id": str(task.rule_id or ""),
                "file": "",
                "line": None,
                "algorithm": "",
            }
            # `MigrationTask` has no `asset` relationship — it carries `asset_id` into the shared
            # assets table, whose `location` is a JSON column rather than file/line columns. An
            # earlier version used getattr on a relationship that does not exist, so every row in
            # the report had an empty file and line and the whole thing was unreadable.
            asset_row = session.get(AssetRow, task.asset_id)
            if asset_row is not None:
                location = asset_row.location or {}
                record["file"] = str(location.get("file_path") or "")
                record["line"] = location.get("line")
                record["algorithm"] = str(asset_row.algorithm or "")

            started = time.perf_counter()
            try:
                patch = orch.generate_patch(task_id, generator=generator, repo_root=app)  # type: ignore[arg-type]
                record["outcome"] = "patch"
                record["patch_status"] = str(patch.status)
                record["file"] = record["file"] or str(patch.file_path or "")
                record["validation"] = patch.validation_json or {}
                if str(patch.status) == "proposed":
                    orch.review_patch(patch.id, approve=True)
                    session.commit()
                    try:
                        orch.apply_patch(patch.id, repo_root=app)
                        session.commit()
                        record["applied"] = True
                    except Exception as exc:
                        record["applied"] = False
                        record["apply_error"] = f"{type(exc).__name__}: {exc}"
                else:
                    record["applied"] = False
            except GuidedRemediation as exc:
                record["outcome"] = "refused"
                record["advice"] = str(exc)
                record["applied"] = False
            except AlreadySatisfied as exc:
                record["outcome"] = "vacuous"
                record["detail"] = str(exc)
                record["applied"] = False
            except Exception as exc:
                record["outcome"] = "error"
                record["detail"] = f"{type(exc).__name__}: {exc}"
                record["applied"] = False
            record["seconds"] = round(time.perf_counter() - started, 2)
            session.commit()
        outcomes.append(record)
        mark = {"patch": "PATCH  ", "refused": "REFUSE ", "vacuous": "vacuous", "error": "ERROR  "}
        print(
            f"  {mark.get(record['outcome'], '?')} {Path(record['file']).name:22s}"
            f":{record['line'] or '-'!s:<5} {record['algorithm']:<12s}"
            f" {record['rule_id']:<20s} applied={record.get('applied')}"
        )
    return outcomes


def _symbol_ranges(app: Path, rel: str) -> dict[str, tuple[int, int]]:
    """`{symbol: (first_line, last_line)}` for one module, from its AST.

    The manifest names symbols; the run reports lines. Resolving one to the other by parsing beats
    recording line numbers in `GROUND_TRUTH.json`, which would go stale the first time anyone edited
    a docstring above them.

    This used `ast.parse` and nothing else until the twins stopped being Python-only. On a Ruby, Go
    or Java file that raised `SyntaxError`, returned `{}`, and left EVERY outcome `unmapped` — a
    scorer that quietly attributed nothing across three of the four twins. It surfaced only because
    `score` counts unmapped rows instead of dropping them.

    The grammars here are the same `tree_sitter_language_pack` ones the scanner itself parses with,
    so a symbol this can't find is one the scanner couldn't have flagged either.
    """
    suffix = Path(rel).suffix.lower()
    language = {
        ".py": "python", ".rb": "ruby", ".go": "go", ".java": "java",
        ".js": "javascript", ".ts": "typescript",
    }.get(suffix)
    if language is None:
        return {}
    try:
        source = (app / rel).read_bytes()
    except OSError:
        return {}

    from tree_sitter_language_pack import get_parser

    try:
        tree = get_parser(language).parse(source)
    except Exception:
        return {}

    # The node types that introduce a named callable, per grammar. Ruby's `method` covers both
    # instance methods and the `def self.x` singleton form used throughout Inkwell; Go needs
    # `method_declaration` as well as `function_declaration` or every method on a receiver is lost.
    wanted = {
        "python": {"function_definition"},
        "ruby": {"method", "singleton_method"},
        "go": {"function_declaration", "method_declaration"},
        "java": {"method_declaration", "constructor_declaration"},
        "javascript": {"function_declaration", "method_definition"},
        "typescript": {"function_declaration", "method_definition"},
    }[language]

    ranges: dict[str, tuple[int, int]] = {}
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in wanted:
            continue
        name = node.child_by_field_name("name")
        if name is None:
            continue
        # Rows are 0-based in tree-sitter and 1-based everywhere the scanner reports.
        ranges[name.text.decode("utf-8", "replace")] = (
            node.start_point[0] + 1,
            node.end_point[0] + 1,
        )
    return ranges


def score(app: Path, outcomes: list[dict[str, Any]], truth: dict[str, Any]) -> dict[str, Any]:
    """Compare what happened against what `GROUND_TRUTH.json` said should happen.

    The manifest is keyed by symbol and the run reports `(file, line)`, so each outcome is
    attributed to the function whose body contains its line. A manifest entry naming two symbols
    (`seal_note / unseal_note`) matches either.

    **A patch is scored against the finding, not against the file.** One manifest entry can receive
    several outcomes — `MV-09` covers a keygen and two call sites — and it counts as correctly
    handled only if none of them went the wrong way.

    Attribution failures are reported as `unmapped` rather than silently dropped: a finding the
    scorer cannot place is a hole in the manifest, and quietly excluding it would inflate every rate
    computed here.
    """
    # symbol -> manifest entry, per file. Negative controls are indexed alongside the findings:
    # an outcome that lands on already-correct cryptography is a false positive, and scoring only
    # the findings would make those invisible.
    by_file: dict[str, dict[str, dict[str, Any]]] = {}
    for entry in [*truth["findings"], *truth["negative_controls"]]:
        for symbol in (s.strip() for s in entry["symbol"].split("/")):
            by_file.setdefault(entry["file"], {})[symbol] = entry

    ranges_cache: dict[str, dict[str, tuple[int, int]]] = {}
    rows: list[dict[str, Any]] = []
    verdicts: dict[str, list[str]] = {}
    routed_to_guidance: dict[str, bool] = {}

    app_posix = app.as_posix().rstrip("/") + "/"
    for outcome in outcomes:
        # The scanner records an ABSOLUTE path (it was handed `app/app` as its root), while the
        # manifest is repo-relative. Without this every outcome scores as `unmapped`, which is how
        # the first run of this scorer reported 0 of 22 attributed — correctly, and uselessly.
        rel = (outcome["file"] or "").replace("\\", "/")
        if rel.startswith(app_posix):
            rel = rel[len(app_posix) :]
        line = outcome["line"]
        finding_id = None
        if rel in by_file and line:
            ranges = ranges_cache.setdefault(rel, _symbol_ranges(app, rel))
            for symbol, entry in by_file[rel].items():
                lo_hi = ranges.get(symbol)
                if lo_hi and lo_hi[0] <= line <= lo_hi[1]:
                    finding_id = entry["id"]
                    break

        # `applied` is what actually happened to the repository; everything else is a refusal in
        # one form or another (guard, failing gate, no codemod).
        acted = "migrated" if outcome.get("applied") else "not-migrated"
        rows.append(
            {
                "file": rel,
                "line": line,
                "algorithm": outcome["algorithm"],
                "rule_id": outcome["rule_id"],
                "outcome": outcome["outcome"],
                "acted": acted,
                "finding": finding_id or "unmapped",
            }
        )
        verdicts.setdefault(finding_id or "unmapped", []).append(acted)
        # `guided` is a THIRD disposition, not a failed migration. The tool decided the finding
        # needs a person and wrote the procedure; that is a correct outcome for a finding no
        # codemod and no model should attempt on its own, and it is the user's work afterwards.
        # Kept separately so the auto-migration rate below has an honest denominator.
        if "guided" in (outcome.get("outcome") or ""):
            routed_to_guidance.setdefault(finding_id or "unmapped", True)

    correct: list[str] = []
    false_migration: list[str] = []
    not_migrated: list[str] = []
    control_touched: list[str] = []

    for entry in [*truth["findings"], *truth["negative_controls"]]:
        seen = verdicts.get(entry["id"])
        if not seen:
            continue
        migrated = "migrated" in seen
        expected = entry["expected_disposition"]
        if expected == "no-finding":
            # A control that was migrated is a false positive on already-correct cryptography.
            (control_touched if migrated else correct).append(entry["id"])
        elif expected == "refuse":
            (false_migration if migrated else correct).append(entry["id"])
        elif migrated:
            correct.append(entry["id"])
        else:
            # Expected `migrate` and nothing reached disk. Not a false migration — the repository is
            # unharmed — but not a success either, so it gets its own bucket rather than being
            # folded into "correct" and flattering the result.
            not_migrated.append(entry["id"])

    # ── The auto-migration rate, on the findings the tool actually took on ──────────────────────
    #
    # `expected_migrate_but_not_migrated` counts every migratable finding that did not reach disk,
    # which lumps together two different things: findings QUBIT tried to migrate and did not, and
    # findings it deliberately routed to a written human procedure. The second is a correct outcome
    # -- `guided` exists precisely so that a finding needing a schema change, a retention policy or
    # a conversation with a counterparty is handed over rather than guessed at -- and the human does
    # that work afterwards.
    #
    # So the completion rate is reported over the AUTO-MIGRATABLE set: manifest `migrate` findings
    # that were not routed to guidance. That set is what a codemod or a model was ever going to
    # handle, and 100% of it is the target.
    #
    # `guided_count` is published beside it, always, and the two must be read together. A tool can
    # reach 100% on this metric by routing everything difficult to guidance, so the rate is only
    # meaningful next to how much it declined to attempt.
    auto_migratable = [
        e["id"]
        for e in truth["findings"]
        if e["expected_disposition"] == "migrate"
        and verdicts.get(e["id"])
        and not routed_to_guidance.get(e["id"])
    ]
    auto_migrated = [fid for fid in auto_migratable if fid in correct]
    guided = sorted(
        e["id"]
        for e in truth["findings"]
        if e["expected_disposition"] == "migrate" and routed_to_guidance.get(e["id"])
    )

    return {
        "rows": rows,
        "correct": sorted(correct),
        "false_migrations": sorted(false_migration),
        "expected_migrate_but_not_migrated": sorted(not_migrated),
        "controls_wrongly_migrated": sorted(control_touched),
        "auto_migratable": sorted(auto_migratable),
        "auto_migrated": sorted(auto_migrated),
        "routed_to_guidance": guided,
        "unmapped_outcomes": sum(1 for r in rows if r["finding"] == "unmapped"),
    }


#: The image carrying the twin's dependencies and not the twin itself.
#: Built by `qubit-v2/02-verification/Dockerfile.medivault`.
#: Fallback when a twin declares no sandbox image of its own.
DEFAULT_SANDBOX_IMAGE = "qubit-eval/medivault:py312"


def enable_the_sandbox(twin: Twin, app: Path) -> dict[str, str]:
    """Point `tests` and `behaves` at an image that can actually run this suite.

    Both stages skipped on every patch in the corpus evaluation, for two different reasons that
    look the same in the report. `tests` skipped because a bare `python:3.12-slim` cannot import
    the project's dependencies, so the baseline is red before any patch exists. `behaves` skipped
    because the harness mounts only a temp directory, so a patched module cannot import its own
    package — here, `ModuleNotFoundError: No module named 'app'`.

    Neither is a property of the repository, and reporting them as `skipped` states a fact about
    QUBIT's configuration in the grammar of a fact about the code. Configuring both is what turns
    the evidence ladder's top two rungs from decoration into gates.

    Returned as environment rather than set globally so the caller can run with and without it and
    compare — which is the only way to show the rungs made a difference.
    """
    return {
        "QUBIT_MIGRATE_TEST_SANDBOX_IMAGE": twin.sandbox_image or DEFAULT_SANDBOX_IMAGE,
        # `tests`, not the repository root: the suite lives in one directory and collecting from
        # the root picks up nothing else.
        "QUBIT_MIGRATE_TEST_COMMAND": twin.test_command_in_sandbox or "python -m pytest tests -q",
        "QUBIT_MIGRATE_ORACLE_IMAGE": twin.sandbox_image or DEFAULT_SANDBOX_IMAGE,
        # Mounted read-only on PYTHONPATH so `from app.core.keyring import ...` resolves inside the
        # oracle container. The patched file still comes from the harness's temp directory, so what
        # is under test is the patch and not whatever is on disk.
        "QUBIT_MIGRATE_ORACLE_PYPATH": str(app),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--twin", default="medivault-emr", choices=sorted(TWINS))
    ap.add_argument("--generator", default="template", choices=["template", "auto", "llm"])
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument(
        "--sandbox",
        action="store_true",
        help="run `tests` and `behaves` in the MediVault image, so the top two rungs actually gate",
    )
    args = ap.parse_args()

    # Resolved against the repository root so `--out test-output/x` and an absolute path
    # both work, and so the `relative_to` in the log line below cannot raise.
    out = (
        (REPO_ROOT / args.out)
        if args.out
        else (REPO_ROOT / "test-output" / f"{args.twin}-{args.generator}")
    )
    out = out.resolve()
    twin = TWINS[args.twin]
    app = out / twin.name

    print(f"1. duplicating {twin.name} ({twin.language}) -> {app.relative_to(REPO_ROOT)}")
    duplicate(twin, app)

    print("2. baseline: the copy's own test suite before anything is migrated")
    before = run_tests(twin, app)
    print(f"   {before['summary']}  ({before['seconds']}s)")
    if not before["green"]:
        print("   the copy is not green before migration; refusing to draw conclusions")
        return 1

    print("3. scanning the copy and building a migration plan")
    factory, assets = seed(twin, app, out / "twin.db", twin.name)
    vulnerable = [a for a in assets if a.quantum_vulnerable and a.quantum_vulnerable.vulnerable]
    print(f"   {len(assets)} algorithm-use assets, {len(vulnerable)} quantum-vulnerable")

    if args.sandbox:
        env = enable_the_sandbox(twin, app)
        os.environ.update(env)
        print(f"   sandbox: {twin.sandbox_image} for both `tests` and `behaves`")

    print(f"4. migrating with generator={args.generator}")
    outcomes = migrate(factory, app, args.generator)

    print("5. the same suite, against the migrated copy")
    after = run_tests(twin, app)
    print(f"   {after['summary']}  ({after['seconds']}s)")

    truth = json.loads((twin.root / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    scored = score(app, outcomes, truth)
    report = {
        "twin": twin.name,
        "language": twin.language,
        "generator": args.generator,
        "assets": len(assets),
        "quantum_vulnerable": len(vulnerable),
        "tests_before": before,
        "tests_after": after,
        "counts": {
            key: sum(1 for o in outcomes if o["outcome"] == key)
            for key in ("patch", "refused", "vacuous", "error")
        },
        "applied": sum(1 for o in outcomes if o.get("applied")),
        "outcomes": outcomes,
        "scored": scored,
    }
    report_path = out / "MIGRATION_REPORT.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    print("\n--- summary ---")
    print(f"  patches proposed : {report['counts']['patch']}")
    print(f"  patches applied  : {report['applied']}")
    print(f"  refused (guided) : {report['counts']['refused']}")
    print(f"  vacuous          : {report['counts']['vacuous']}")
    print(f"  errors           : {report['counts']['error']}")
    print(f"  tests before     : {before['summary']}")
    print(f"  tests after      : {after['summary']}")
    print("\n--- against GROUND_TRUTH.json ---")
    print(f"  handled correctly     : {len(scored['correct'])}  {', '.join(scored['correct'])}")
    print(
        f"  FALSE MIGRATIONS      : {len(scored['false_migrations'])}  "
        f"{', '.join(scored['false_migrations']) or '-'}"
    )
    print(
        f"  migratable, unmigrated: {len(scored['expected_migrate_but_not_migrated'])}  "
        f"{', '.join(scored['expected_migrate_but_not_migrated']) or '-'}"
    )
    print(
        f"  controls wrongly migrated: {len(scored['controls_wrongly_migrated'])}  "
        f"{', '.join(scored['controls_wrongly_migrated']) or '-'}"
    )
    print(f"  outcomes not attributed to a finding: {scored['unmapped_outcomes']}")
    print(f"\nwritten: {report_path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
