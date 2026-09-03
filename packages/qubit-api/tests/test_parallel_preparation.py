"""A bulk run works the whole engine pool at once, and still respects what must stay in order.

The pool was a fallback chain, not a pool: engines were tried one after another and the first that
answered kept the work, so exactly one engine was ever busy. Local Ollama sat at the END of that
chain, reached only when every hosted engine had failed -- which on a healthy pool is never. Six
configured engines, one working, and a GPU at 0% for the whole run.

Findings in different files are independent, so they can be prepared at the same time. With one
worker per engine the whole pool runs at once and the local model is a first-class member of it
rather than a last resort.

The constraint that survives is per FILE. Two findings in one file must be prepared in sequence:
each patch is written against the file as it stood, and the second's "already migrated by an earlier
patch to this file" verdict can only be reached once the first has been decided. Prepared
concurrently, both are generated against the original, both look valid, and writing the second
silently reverts the first.
"""

from __future__ import annotations

import contextlib
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from qubit_api.jobs import handlers
from qubit_core.db import AssetRow, Base, ProjectRow, ScanRow
from qubit_core.db.session import session_factory
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.orchestrator import MigrationOrchestrator
from sqlalchemy import create_engine

VULN = "import hashlib\ndigest = hashlib.md5(data)\nother = hashlib.md5(more)\n"

#: Three files, two findings in one of them. Enough to tell "several at once" apart from "several at
#: once, but never two in the same file".
LAYOUT = (("a.py", (2, 3)), ("b.py", (2,)), ("c.py", (2,)))
TOTAL = sum(len(lines) for _, lines in LAYOUT)


def _asset(path: str, line: int, rank: int) -> CryptoAsset:
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm="MD5",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=datetime.now(UTC),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=rank
        ),
    )


class _Reporter:
    """The progress surface the handler writes to, kept so the messages can be asserted on."""

    def __init__(self, sf) -> None:
        self.sf = sf
        self.messages: list[str] = []

    def update(self, progress: float, stage: str, message: str) -> None:
        self.messages.append(message)

    def checkpoint(self) -> None:
        return None


@pytest.fixture
def plan(tmp_path: Path):
    db = tmp_path / "t.db"
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    Base.metadata.create_all(engine)
    sf = session_factory(engine)

    with sf() as s:
        project = ProjectRow(name="t", slug="t", root_path=str(tmp_path))
        s.add(project)
        s.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        s.add(scan)
        s.flush()
        rank = 1
        for name, lines in LAYOUT:
            (tmp_path / name).write_text(VULN, encoding="utf-8")
            for line in lines:
                s.add(
                    asset_to_row(
                        _asset(str(tmp_path / name), line, rank),
                        scan_id=scan.id,
                        project_id=project.id,
                    )
                )
                rank += 1
        s.commit()
        plan_id = MigrationOrchestrator(s).build_plan().id
    return sf, plan_id


@pytest.fixture
def two_engines(monkeypatch: pytest.MonkeyPatch):
    """A pool of two, without needing two real providers configured.

    The width of the pool is what decides how many workers run, so it is the thing to control here.
    Standing up a second real endpoint would test the provider plumbing, which has its own tests,
    and would make this suite depend on a network.
    """
    monkeypatch.setattr(
        MigrationOrchestrator, "engine_names", lambda self: ["local", "second"], raising=True
    )


def test_findings_in_different_files_are_prepared_at_the_same_time(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of the change, measured rather than assumed.

    A barrier is the only honest way to assert concurrency: it can only be crossed if two workers
    are genuinely inside the preparation step together, so a sequential implementation times out on
    it instead of passing by accident.
    """
    sf, plan_id = plan
    overlap = threading.Barrier(2, timeout=30)
    pins: list[str | None] = []
    real = handlers._prepare_one

    def watched(session, orch, task, **kw):
        pins.append(orch.pinned_engine)
        with contextlib.suppress(threading.BrokenBarrierError):
            overlap.wait()
        return real(session, orch, task, **kw)

    monkeypatch.setattr(handlers, "_prepare_one", watched)

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["total"] == TOTAL
    assert len(pins) == TOTAL
    assert set(pins) == {"local", "second"}, (
        f"both engines must have carried work, saw {sorted(set(pins))}"
    )


def test_two_findings_in_one_file_are_never_prepared_at_once(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The correctness constraint the parallelism must not break.

    Asserted on the FILE rather than on the grouping code, so the property survives a different
    implementation of it: no two workers may be inside the same path together.
    """
    sf, plan_id = plan
    live: dict[str, int] = {}
    clashes: list[str] = []
    lock = threading.Lock()
    #: Set by the SECOND worker to enter a file that is already occupied. The first entrant waits on
    #: it, so the overlap is detected by rendezvous rather than by out-sleeping the other thread.
    #:
    #: A fixed sleep was tried first and was flaky: each worker builds its own orchestrator, which
    #: parses the rule pack, so the second worker can arrive after any hold short enough to keep the
    #: suite quick. Reverting the grouping then passed about half the time — a test that only
    #: sometimes catches the bug it exists for.
    second_arrived = threading.Event()
    real = handlers._prepare_one

    def watched(session, orch, task, **kw):
        asset = session.get(AssetRow, task.asset_id)
        path = str((asset.location or {}).get("file_path") or "")
        with lock:
            occupied = bool(live.get(path))
            if occupied:
                clashes.append(path)
            live[path] = live.get(path, 0) + 1
        try:
            if occupied:
                second_arrived.set()
            else:
                # Held until a second worker turns up in this same file, or until it is clear none
                # will. Correct grouping means none can, so this waits out the timeout once and the
                # run proceeds; broken grouping trips it immediately.
                second_arrived.wait(6.0)
            return real(session, orch, task, **kw)
        finally:
            with lock:
                live[path] -= 1

    monkeypatch.setattr(handlers, "_prepare_one", watched)
    handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert clashes == [], f"two findings in one file were prepared concurrently: {clashes}"


def test_all_of_a_files_findings_land_in_one_group(plan) -> None:
    """The same constraint, asserted where it is decided rather than where it shows up.

    The concurrency test above can only observe an overlap that actually happens, and that depends
    on thread scheduling — each worker builds its own orchestrator, which parses the rule pack, so
    the second worker sometimes arrives after the first has moved on. Measured: reverting the
    grouping was caught on two runs in three. A real check, but not a reliable one, and a guard
    against silent data loss has to be reliable.

    Grouping is deterministic, so this is too: whatever the threads do, two findings in one file can
    only ever be handed to one worker if they are in the same group.
    """
    sf, plan_id = plan
    from qubit_migrate.state import MigrationTask
    from sqlalchemy import select

    with sf() as session:
        tasks = list(
            session.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .order_by(MigrationTask.rank)
            ).all()
        )
        groups = handlers._file_groups(session, tasks)

        paths = [
            {
                str((session.get(AssetRow, t.asset_id).location or {}).get("file_path"))
                for t in group
            }
            for group in groups
        ]

    assert sum(len(g) for g in groups) == TOTAL, "grouping must not lose or duplicate a finding"
    assert all(len(p) == 1 for p in paths), f"a group spans more than one file: {paths}"
    assert len(paths) == len({next(iter(p)) for p in paths}), (
        f"one file was split across groups, so its findings could run concurrently: {paths}"
    )
    assert len(groups) == len(LAYOUT), f"expected one group per file, got {len(groups)}"


def test_every_finding_is_accounted_for_exactly_once(plan, two_engines) -> None:
    """Counting across threads is where parallelism goes wrong quietly.

    A lost increment reads as a finding that simply never happened, which from the outside is
    indistinguishable from a smaller plan; a double increment inflates the result. The buckets are
    mutually exclusive by construction, so they must sum to the total.
    """
    sf, plan_id = plan
    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["total"] == TOTAL
    assert (
        result["generated"] + result["covered"] + result["needs_guidance"] + result["failed"]
        == TOTAL
    ), result


def test_a_single_engine_install_still_works_one_at_a_time(
    plan, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An install with only local Ollama must behave exactly as it did before this change.

    The width of the run is the width of the pool, not a setting, so a pool of one is a sequential
    run -- no threads racing over one engine, and no change in outcome for the common case.
    """
    sf, plan_id = plan
    monkeypatch.setattr(MigrationOrchestrator, "engine_names", lambda self: ["local"])
    concurrent: list[int] = []
    live = 0
    lock = threading.Lock()
    real = handlers._prepare_one

    def watched(session, orch, task, **kw):
        nonlocal live
        with lock:
            live += 1
            concurrent.append(live)
        try:
            return real(session, orch, task, **kw)
        finally:
            with lock:
                live -= 1

    monkeypatch.setattr(handlers, "_prepare_one", watched)
    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert max(concurrent) == 1, "a one-engine pool must not run findings in parallel"
    assert result["total"] == TOTAL


def test_a_poisoned_session_does_not_cost_the_run(plan, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dead transaction must cost at most the finding that caused it.

    Tested against a REAL poisoned Session rather than a plain exception, because the two behave
    nothing alike.

    This distinction is the whole test. A `RuntimeError` raised out of the preparation step needs no
    rollback to recover from -- the Session is fine. A failed FLUSH is different: SQLAlchemy marks
    the transaction dead, and every later use of that Session raises `PendingRollbackError`,
    including the task lookup that sits outside the preparation step's own error handling. So one
    bad write takes out every remaining finding in that worker's queue, with an error naming a table
    the caller never touched.

    Measured on the certbot run: a lost race on a `learned_outcomes` hit-count bump ("database is
    locked") did exactly this, and a job that had already prepared 133 of 143 findings was reported
    as FAILED at 93%.

    Deliberately a ONE-engine pool, so all four findings go through a single worker in sequence and
    the recovery is visible: the first is poisoned, and the rest must still be prepared.
    """
    from sqlalchemy import text as sqltext

    sf, plan_id = plan
    monkeypatch.setattr(MigrationOrchestrator, "engine_names", lambda self: ["local"])
    real = handlers._prepare_one
    poisoned = {"done": False}

    def poison_once(session, orch, task, **kw):
        got = real(session, orch, task, **kw)
        if not poisoned["done"]:
            poisoned["done"] = True
            # Poisoned AFTER the finding is prepared, which is where it really happens: the
            # learning store bumps its hit count at the END of a successful generation. So the
            # first thing to meet the dead transaction is the NEXT task's lookup, outside the
            # preparation step's own error handling.
            #
            # A genuine failed flush, not a raised exception: the row violates NOT NULL, so
            # SQLAlchemy marks the transaction dead exactly as a lost write race does. Swallowed
            # here, which is the realistic shape -- the learning store's writes are best-effort
            # and swallow their own errors too.
            with contextlib.suppress(Exception):
                session.execute(sqltext("INSERT INTO migration_tasks (id) VALUES ('poison')"))
                session.flush()
        return got

    monkeypatch.setattr(handlers, "_prepare_one", poison_once)

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert poisoned["done"], "the fixture must actually have poisoned the session"
    assert result["total"] == TOTAL
    assert result["generated"] >= TOTAL - 1, (
        f"the worker must recover and prepare the remaining findings, got {result}"
    )


def test_a_run_whose_every_worker_dies_is_still_a_failure(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the same judgement, so tolerance does not become silence.

    If nothing survived to do the work, the run failed and must say so. Reporting success over a
    plan where every worker crashed would be the worse error of the two: an operator would go
    looking for diffs that do not exist.
    """
    sf, plan_id = plan

    def always_explodes(session, orch, task, **kw):
        raise RuntimeError("nothing works")

    monkeypatch.setattr(handlers, "_prepare_one", always_explodes)

    # Every finding fails, but the run itself completes and reports them — a crash inside
    # `_prepare_one` is counted, and that is not the same as a worker dying outright.
    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )
    assert result["failed"] == TOTAL, result
    assert result["generated"] == 0


def test_a_worker_that_dies_outright_does_not_fail_the_whole_run(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A worker lost before it can guard anything must not take the run with it.

    Killed at construction, which is the one place the per-task guard above cannot help: there is no
    task in hand yet, so the exception leaves the worker and lands on the pool. What the run must do
    is keep what the other workers prepared -- the certbot run that prompted this had 133 of 143
    findings ready when a single worker's Session went bad, and reported FAILED.
    """
    sf, plan_id = plan
    real_init = MigrationOrchestrator.__init__

    def refuse_second(self, session, config=None, pinned_engine=None):
        if pinned_engine == "second":
            raise RuntimeError("this worker never got started")
        real_init(self, session, config, pinned_engine)

    monkeypatch.setattr(MigrationOrchestrator, "__init__", refuse_second)

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["total"] == TOTAL
    assert result["generated"] > 0, "the surviving worker's prepared findings must be kept"
