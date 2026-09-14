"""Run the evaluation arms, each in a fresh OS process, with the tripwires that make them mean it.

**The isolation unit is a fresh PROCESS, not a fresh Session or a fresh database.** Several caches
live at module scope and survive a new database entirely:

* `transform/llm.py::_REASONING_CHOICE` — which reasoning mode an engine accepted
* `transform/target_shapes.py::_cache` — the scanner's answer per (language, prefix)
* `transform/validate.py::_docker_ok` and `_verified_families` — daemon state and oracle controls
* `transform/rules.py` — the parsed rule catalog
* `bandit` posteriors, once they are persisted

An arm that reuses the interpreter inherits every one of those from the arm before it, and the
comparison silently becomes "arm B, warmed up by arm A". Each unit therefore gets its own
`subprocess.run`.

## The arms

* **Pilot** - 10 findings at B1 settings. Confirms the controls, `from_cache == 0`, no
  unexpected external routing, and gives per-finding wall clock for budgeting.
* **B0** - codemods only, no model. The deterministic floor, reported as "codemods cover X% of
  findings" and **never as a competitor**.
* **A1** - **one finding per database.** The only arm whose findings are genuinely exchangeable:
  `learn.lookup` cannot hit, `experience_for` is always empty, `reliability` is always `(0, 0)`.
  The reference for every paired test.
* **B1-fwd** - one database, findings in queue order. The shipped configuration.
* **B1-rev** - the same, reversed. `abs(B1-fwd - B1-rev)` bounds how much of `B1 - A1` is an
  ordering artefact rather than an effect.
* **A2** - B1 without plan-first. An ablation.
* **B2** - routed, three replicates, and only if the pilot shows the reliability gate firing or
  oversize files present. Otherwise B2 is B1, and the report says so.

## Tripwires

Each is a way a result could be wrong without looking wrong, so each is asserted rather than hoped
for:

* `from_cache` must be **0** in A1. A cache hit there means the "experience-free" arm had
  experience, and the reference for every comparison is void.
* the count of findings refused by the reliability gate — if it never fires, B2 collapses into B1
  and the report must say so rather than presenting two arms.
* the count routed to an external engine — "routed" that never routed is not an arm.
* `migration_plans.config_json`, the full `MigrateConfig` snapshot, as the provenance record.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Per-arm configuration, as environment overrides on `MigrateConfig`.
#:
#: Expressed as env rather than as a config file so each arm's settings are visible in the process
#: table and in `config_json`, and cannot be edited between arms without leaving a trace.
ARMS: dict[str, dict[str, str]] = {
    "pilot": {"QUBIT_MIGRATE_LLM_PLAN_FIRST": "true"},
    "B0": {"QUBIT_MIGRATE_GENERATOR": "template"},
    "A1": {"QUBIT_MIGRATE_LLM_PLAN_FIRST": "true"},
    "B1-fwd": {"QUBIT_MIGRATE_LLM_PLAN_FIRST": "true"},
    "B1-rev": {"QUBIT_MIGRATE_LLM_PLAN_FIRST": "true"},
    "A2": {"QUBIT_MIGRATE_LLM_PLAN_FIRST": "false"},
    "B2": {"QUBIT_MIGRATE_LLM_PLAN_FIRST": "true"},
}

#: Arms whose findings must each get their own database.
#:
#: A1 is the experience-free reference and is the whole reason the paired tests mean anything: with
#: one finding per database, `learn.lookup` cannot hit and no finding's treatment can depend on an
#: earlier one's outcome.
PER_FINDING_DB = frozenset({"A1"})

#: Arms that walk the queue backwards.
REVERSED_ORDER = frozenset({"B1-rev"})


@dataclass
class ArmResult:
    arm: str
    findings: int = 0
    processes: int = 0
    #: Patches actually written. The denominator of everything, and the thing whose absence the
    #: runner used to be blind to.
    patches: int = 0
    #: Findings the pipeline deliberately declined to patch, with advice recorded instead. A
    #: refusal is an outcome, not a gap — distinguishing it from silence is what stops the
    #: no-patches tripwire firing on a correctly cautious arm.
    refused: int = 0
    from_cache: int = 0
    reliability_skips: int = 0
    routed_external: int = 0
    failures: list[str] = field(default_factory=list)
    config_json: dict[str, Any] = field(default_factory=dict)

    def tripwires(self) -> list[str]:
        """Violations that invalidate this arm, named rather than merely logged."""
        broken = []
        # An arm that produced nothing is not a result, and it used to look like one. The worker
        # command was wrong for long enough to run a full arm as 32 no-ops and report "0 failures",
        # because the runner only ever asked whether the process exited badly — never whether it
        # did anything. Exit status is not evidence of work.
        #
        # But "no patches" is not by itself a fault. Once the protocol-contract guard landed, B0 on
        # `pyload` correctly produced ZERO patches and seven pieces of advice, because every
        # codemod-reachable finding turned out to be a credential digest. Refusing is work. So the
        # tripwire fires only when the arm produced neither a patch nor a refusal — nothing at all.
        if self.findings and not self.patches and not self.refused:
            broken.append(
                f"{self.arm} ran {self.processes} processes over {self.findings} findings and "
                f"produced 0 patches AND 0 refusals — it did nothing. Check the worker command: "
                f"`python -m qubit_migrate.cli` has no entry point and exits 0 silently"
            )
        if self.arm in PER_FINDING_DB and self.from_cache:
            broken.append(
                f"{self.from_cache} findings answered from the learned-patch cache in {self.arm}, "
                "which is supposed to have no experience at all — every paired test against it "
                "is void"
            )
        if self.arm == "B2" and self.routed_external == 0:
            broken.append(
                "B2 routed nothing to an external engine, so it is not a different arm from B1. "
                "Report that, do not present two arms"
            )
        return broken

    def as_dict(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "findings": self.findings,
            "processes": self.processes,
            "patches": self.patches,
            "refused": self.refused,
            "from_cache": self.from_cache,
            "reliability_skips": self.reliability_skips,
            "routed_external": self.routed_external,
            "tripwires": self.tripwires(),
            "failures": self.failures[:20],
            "config_json": self.config_json,
        }


def _worker_argv(task_id: str, repo: Path, generator: str) -> list[str]:
    """One isolation unit: a fresh interpreter that prepares exactly one finding.

    `generate` takes the task id POSITIONALLY (`generate <task_id> --repo-root ...`); an earlier
    version passed `--task`, which typer rejects.

    **The app is invoked explicitly, not as `-m qubit_migrate.cli`.** That module defines
    `migrate_app` and has no `if __name__ == "__main__"` block and no `__main__.py`, so
    `python -m qubit_migrate.cli generate ...` imports it, runs nothing, and **exits 0**. An entire
    arm ran that way: 32 processes, 0 failures, 0 patches, every task still `ready` — a clean bill
    of health for work that never happened. `qubit_cli.main:app` is the real entry point, and it is
    reached through `-c` rather than `-m` because `-m qubit_cli.main` re-imports an
    already-imported module and warns about it.
    """
    return [
        sys.executable,
        "-c",
        "from qubit_cli.main import app; app()",
        "migrate",
        "generate",
        task_id,
        "--repo-root",
        str(repo),
        "--generator",
        generator,
    ]


def run_arm(
    arm: str,
    *,
    db_template: Path,
    repo: Path,
    workdir: Path,
    limit: int | None = None,
) -> ArmResult:
    """Run one arm. Every isolation unit is a separate `subprocess.run`."""
    result = ArmResult(arm=arm)
    overrides = dict(ARMS.get(arm, {}))
    # B0 is the deterministic floor: codemods only, no model call at all.
    generator = overrides.pop("QUBIT_MIGRATE_GENERATOR", "auto")
    env = {**os.environ, **overrides}
    workdir.mkdir(parents=True, exist_ok=True)

    tasks = _tasks_for(db_template)
    if arm in REVERSED_ORDER:
        tasks = list(reversed(tasks))
    if limit:
        tasks = tasks[:limit]
    result.findings = len(tasks)

    if arm in PER_FINDING_DB:
        # One database per finding. Reseeded from the cached scan each time, so `learn.lookup`
        # cannot hit and `reliability` is always (0, 0).
        for i, task_id in enumerate(tasks):
            db = workdir / f"{arm}-{i:04d}.db"
            _reseed(db_template, db)
            result.processes += 1
            _run_unit(_worker_argv(task_id, repo, generator), env, db, result)
    else:
        db = workdir / f"{arm}.db"
        _reseed(db_template, db)
        for task_id in tasks:
            # Still one process per finding: the caches listed in the module docstring would
            # otherwise carry the first finding's warm-up into every later one.
            result.processes += 1
            _run_unit(_worker_argv(task_id, repo, generator), env, db, result)

    result.patches = _count_patches(workdir)
    result.refused = _count_refusals(workdir)
    return result


def _count_refusals(workdir: Path) -> int:
    """Findings the pipeline declined to patch and advised on instead."""
    import sqlite3

    total = 0
    for db in sorted(workdir.glob("*.db")):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            total += con.execute(
                "SELECT COUNT(*) FROM migration_tasks "
                "WHERE advice_text IS NOT NULL AND advice_text != ''"
            ).fetchone()[0]
            con.close()
        except sqlite3.Error:
            continue
    return total


def _count_patches(workdir: Path) -> int:
    """Patches written across every database this arm used.

    Counted from the databases rather than from the workers' output, because a worker that does
    nothing prints nothing and exits 0 — which is precisely the failure this exists to catch.
    """
    import sqlite3

    total = 0
    for db in sorted(workdir.glob("*.db")):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            total += con.execute("SELECT COUNT(*) FROM migration_patches").fetchone()[0]
            con.close()
        except sqlite3.Error:
            continue
    return total


def _run_unit(argv: list[str], env: dict[str, str], db: Path, result: ArmResult) -> None:
    env = {**env, "QUBIT_DB_URL": f"sqlite:///{db.as_posix()}"}
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=3600, check=False)
    if proc.returncode not in (0, 2, 3):
        result.failures.append(f"{argv[-1]}: exit {proc.returncode}: {proc.stderr[-200:]}")


def _reseed(template: Path, target: Path) -> None:
    """A fresh database from the cached scan, WAL-safely.

    `shutil.copy` on a WAL database silently drops recent writes, which here would mean an arm
    starting from a partially seeded corpus and reporting a smaller denominator than it ran.
    """
    import sqlite3

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    src = sqlite3.connect(f"file:{template}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    with dst:
        src.backup(dst)
    src.close()
    dst.close()


def _tasks_for(db: Path) -> list[str]:
    """Ready task ids in queue order."""
    import sqlite3

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT id FROM migration_tasks WHERE state = 'ready' ORDER BY rank, id"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        con.close()
    return [str(r[0]) for r in rows]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=Path, required=True, help="seeded template database")
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--workdir", type=Path, default=Path("output/arms"))
    ap.add_argument("--arms", nargs="*", default=["pilot"])
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", type=Path, default=Path("qubit-v2/08-evaluation"))
    args = ap.parse_args()

    results = []
    for arm in args.arms:
        if arm not in ARMS:
            raise SystemExit(f"unknown arm {arm!r}; known: {sorted(ARMS)}")
        print(f"=== {arm} ===", flush=True)
        r = run_arm(
            arm,
            db_template=args.db,
            repo=args.repo,
            workdir=args.workdir / arm,
            limit=args.limit,
        )
        for violation in r.tripwires():
            print(f"  TRIPWIRE: {violation}", flush=True)
        print(
            f"  {r.findings} findings, {r.processes} processes, "
            f"{r.patches} patches, {r.refused} refused, {len(r.failures)} failures"
        )
        results.append(r.as_dict())

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "arms.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    print(f"\nwritten: {args.out / 'arms.json'}")


if __name__ == "__main__":
    main()
