"""Build the seeded template database the arms are reseeded from.

`run_arms.py` takes a `--db` it copies for every isolation unit. This produces that database: scan
the corpus, annotate the assets with risk, build a migration plan, and stop. Nothing is generated
and no model is called, so the template is identical for every arm and the only thing that differs
between arms is what they do to it.

**Written to a file the arms never modify.** Each unit copies it with `sqlite3.backup()` (a WAL
database is not safe to `shutil.copy` — recent writes are in the -wal file and are silently lost),
so this database is read-only in practice and one bad seed cannot contaminate a later arm.

## Risk annotation is placeholder, and that is a design decision

The planner will not schedule an asset that has no `RiskAnnotation`, so one has to exist. This
assigns a constant score with the queue position taken from scan order.

That is deliberate: this study measures the **migration gate**, not the prioritisation. Real QARS
scores would order the queue by risk, which sounds better and would silently make `B1-fwd` and
`B1-rev` different experiments — the reverse arm would walk a risk-ordered queue backwards, and the
ordering artefact it is supposed to bound would be confounded with a risk effect. A constant score
keeps the two orders exact mirrors of one another.

It also means **no result here says anything about QARS.** That is stated rather than left for a
reader to infer from a queue that happens to look sensible.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def seed(repo: Path, db_path: Path, *, name: str, limit: int | None) -> dict[str, Any]:
    from qubit_core.db import Base, ProjectRow, ScanRow
    from qubit_core.mapping import asset_to_row
    from qubit_core.schemas import RiskAnnotation
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_scanner.api import scan_paths
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    if db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    Base.metadata.create_all(engine)

    # `scanners={"code"}` mirrors the corpus scorer. The other scanners produce certificate,
    # protocol and PII findings, which are real and are not source-level migration work.
    result = scan_paths([repo], scanners={"code"}, repo=name)
    assets = [a for a in result.assets if str(getattr(a, "asset_type", "")) == "algorithm-use"]
    if limit:
        assets = assets[:limit]

    summary: dict[str, Any] = {
        "corpus": name,
        "repo": str(repo),
        "scanned_assets_total": len(list(result.assets)),
        "algorithm_use_assets": len(assets),
    }
    if not assets:
        summary["error"] = "no algorithm-use assets; nothing to seed"
        return summary

    with Session(engine) as session:
        project = ProjectRow(name=name, slug=name.replace("/", "-"))
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
        plan = orch.build_plan()
        session.commit()
        summary["plan_id"] = str(plan.id)
        summary["plan_status"] = plan.status

        from qubit_migrate.state.models import MigrationTask

        tasks = session.query(MigrationTask).all()
        summary["tasks_total"] = len(tasks)
        by_state: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for t in tasks:
            by_state[str(t.state)] = by_state.get(str(t.state), 0) + 1
            by_rule[str(t.rule_id or "no-rule")] = by_rule.get(str(t.rule_id or "no-rule"), 0) + 1
        summary["tasks_by_state"] = dict(sorted(by_state.items()))
        summary["tasks_by_rule"] = dict(sorted(by_rule.items(), key=lambda kv: -kv[1]))
        summary["ready_tasks"] = by_state.get("ready", 0)

    engine.dispose()
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--db", type=Path, required=True)
    ap.add_argument("--name", default=None, help="corpus name; defaults to the directory name")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", type=Path, default=None, help="write the summary as JSON here")
    args = ap.parse_args()

    summary = seed(args.repo, args.db, name=args.name or args.repo.name, limit=args.limit)
    print(json.dumps(summary, indent=2))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
        )
        print(f"\nwritten: {args.out}")


if __name__ == "__main__":
    main()
