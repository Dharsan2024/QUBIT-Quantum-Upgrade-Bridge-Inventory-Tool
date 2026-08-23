"""Phase 3b: what fraction of patches the validation gate actually accepts, and does the model help.

This is the measurement the migration half has never had. The only number in the repository is a
55% in the risk register of `docs/design/03-migration-orchestrator.md`, and there it illustrates
what would still be publishable rather than reporting anything observed; nothing has ever counted
validation outcomes over real findings. Two arms, same findings, same gate:

    llm       the shipping path -- local model, with deterministic codemods where a rule has one
    template  codemods only, so the model's contribution is isolated

Paired by construction, so the comparison is not confounded by which findings each arm happened to
get. Nothing is applied: `generate_patch` runs the full gate (applies, parses, compiles, tests,
rescan) and reports its verdict, so a corpus clone is read and never written. That matters -- the
clones are pinned at commits the labels refer to.

    uv run python paper_evidence/scripts/phase3_migration.py --repos 4 --limit 40

Covers B12/B19, T08, F01/F04/F16/F18, and Limitations L3 and L5.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT, ROOT

ARMS = ("llm", "template")


@dataclass
class Outcome:
    repository: str
    rule_id: str
    algorithm: str
    file_path: str
    line: int
    arm: str
    status: str  # proposed | rejected | error
    passed: bool
    partial: bool
    stages: dict = field(default_factory=dict)
    seconds: float = 0.0
    detail: str = ""


def _corpus_repos(limit: int) -> list[tuple[str, Path]]:
    """Corpus clones that are on disk, largest strata first for a mix of languages."""
    lock = json.loads(
        (ROOT / "benchmarks" / "corpus" / "corpus.lock.json").read_text(encoding="utf-8")
    )
    found = []
    for name, meta in sorted(lock["repositories"].items()):
        path = ROOT / meta["path"]
        if path.is_dir():
            found.append((name, meta.get("primary_language") or "?", path))
    # One repository per language before a second of any, so the sample is not four C projects.
    by_language: dict[str, list] = {}
    for name, language, path in found:
        by_language.setdefault(language, []).append((name, path))
    ordered: list[tuple[str, Path]] = []
    while len(ordered) < limit and any(by_language.values()):
        for language in sorted(by_language):
            if by_language[language] and len(ordered) < limit:
                ordered.append(by_language[language].pop(0))
    return ordered[:limit]


def _seed_from_scan(session, repo_root: Path, repo_name: str, limit: int) -> list:
    """Scan a real repository and put its findings in the database as assets."""
    from qubit_core.db import ProjectRow, ScanRow
    from qubit_core.mapping import asset_to_row
    from qubit_core.schemas import RiskAnnotation
    from qubit_scanner.api import scan_paths

    result = scan_paths([repo_root], scanners={"code"}, repo=repo_name)
    assets = list(result.assets)[:limit]
    if not assets:
        return []

    project = ProjectRow(name=repo_name, slug=repo_name.replace("/", "-"))
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()

    for rank, asset in enumerate(assets, start=1):
        # The planner orders by risk, and an asset with no risk annotation is not scheduled. These
        # are placeholder ranks: this run measures the GATE, not the prioritisation.
        asset.risk = RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=rank
        )
        session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()
    return assets


def _run_arm(repo_name: str, repo_root: Path, arm: str, limit: int) -> list[Outcome]:
    """One arm over one repository, in its own in-memory database."""
    from qubit_core.db import Base
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    outcomes: list[Outcome] = []
    with Session(engine) as session:
        if not _seed_from_scan(session, repo_root, repo_name, limit):
            return outcomes

        orchestrator = MigrationOrchestrator(session)
        plan = orchestrator.build_plan()
        tasks = orchestrator.get_queue(plan.id, limit=limit)

        for task in tasks:
            asset = orchestrator._load_asset(task.asset_id)
            location = asset.location if asset else None
            started = time.monotonic()
            record = Outcome(
                repository=repo_name,
                rule_id=task.rule_id or "",
                algorithm=asset.algorithm if asset else "",
                file_path=(location.file_path if location else "") or "",
                line=(location.line if location else 0) or 0,
                arm=arm,
                status="error",
                passed=False,
                partial=False,
            )
            try:
                patch = orchestrator.generate_patch(
                    task.id,
                    generator=cast(Literal["auto", "llm", "template"], arm),
                    repo_root=repo_root,
                )
                report = patch.validation_json or {}
                record.status = patch.status
                record.passed = bool(report.get("passed"))
                record.partial = bool(report.get("partial"))
                record.stages = {
                    name: stage.get("status")
                    for name, stage in (report.get("stages") or {}).items()
                }
            except Exception as exc:
                record.detail = f"{type(exc).__name__}: {exc}".replace("\n", " ")[:300]
                # "no codemod fallback" is the template arm's ANSWER, not a malfunction: that rule
                # has no deterministic transform, so templates-only cannot attempt it at all.
                # Counting it as an error would hide the cases the arm never reached, which is the
                # opposite of what the ablation is for.
                if "no codemod fallback" in str(exc):
                    record.status = "no-codemod"
            record.seconds = round(time.monotonic() - started, 2)
            outcomes.append(record)
            print(
                f"    {arm:9} {record.rule_id:22} {record.status:9} "
                f"passed={record.passed!s:5} {record.seconds:6.1f}s {record.detail[:60]}",
                flush=True,
            )
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos", type=int, default=4, help="how many corpus repositories")
    parser.add_argument("--limit", type=int, default=10, help="tasks per repository per arm")
    parser.add_argument("--seed", type=int, default=20260822)
    args = parser.parse_args()

    random.seed(args.seed)
    repositories = _corpus_repos(args.repos)
    if not repositories:
        raise SystemExit("no corpus clones on disk; run benchmarks/corpus/build.py clone")

    print(f"migration measurement over {len(repositories)} repositories, both arms\n")
    outcomes: list[Outcome] = []
    for name, path in repositories:
        print(f"  {name}")
        for arm in ARMS:
            try:
                outcomes += _run_arm(name, path, arm, args.limit)
            except Exception:
                print(f"    {arm:9} ARM FAILED\n{traceback.format_exc()[:600]}", flush=True)

    (OUT / "data").mkdir(parents=True, exist_ok=True)
    with (OUT / "data" / "migration_outcomes.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["repository", "rule_id", "algorithm", "file_path", "line", "arm", "status",
             "passed", "partial", "stages", "seconds", "detail"]
        )  # fmt: skip
        for o in outcomes:
            writer.writerow(
                [o.repository, o.rule_id, o.algorithm, o.file_path, o.line, o.arm, o.status,
                 o.passed, o.partial, json.dumps(o.stages), o.seconds, o.detail]
            )  # fmt: skip

    for arm in ARMS:
        rows = [o for o in outcomes if o.arm == arm]
        accepted = sum(1 for o in rows if o.passed)
        fully = sum(1 for o in rows if o.passed and not o.partial)
        unreachable = sum(1 for o in rows if o.status == "no-codemod")
        errored = sum(1 for o in rows if o.status == "error")
        share = f"{accepted / len(rows):.1%}" if rows else "n/a"
        print(
            f"\n{arm:9} n={len(rows):4}  accepted={accepted} ({share})  "
            f"fully verified={fully}  no codemod={unreachable}  errors={errored}"
        )
    print(f"\nwrote {OUT / 'data' / 'migration_outcomes.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
