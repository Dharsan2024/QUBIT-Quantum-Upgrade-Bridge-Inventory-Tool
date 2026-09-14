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
from types import SimpleNamespace

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
from qubit_migrate.state import MigrationTask
from sqlalchemy import create_engine, select

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
        result["generated"]
        + result["refused"]
        + result["needs_guidance"]
        + result["rejected"]
        + result["failed"]
        == TOTAL
    ), result
    # `covered` is the `AlreadySatisfied` share of `refused`, not a bucket of its own -- adding it
    # to the sum above would double-count every finding an earlier patch had already fixed.
    assert result["covered"] <= result["refused"], result


# ── What the run says it did ─────────────────────────────────────────────────
#
# One word, "failed", used to cover three outcomes that mean opposite things: a refusal (QUBIT
# decided no edit is correct, which is the answer), a rejection (a gate caught a bad patch, which
# is the gate working) and a genuine failure (nothing usable was produced). Measured on
# medivault-emr: "Migrating 24/24 (0 ready, 5 guided, 18 failed)" for a run whose 18 were 6
# ownership refusals, 1 already-satisfied file, 7 gate rejections and 2 real failures.


def _rejected_patch(stage: str = "tests", detail: str = "3 tests regressed under the patch"):
    """What `generate_patch` returns when the validator turned its candidate down.

    A stand-in rather than a real rejection because producing one needs a model to write a patch
    the gates then refuse -- which is a model call per finding, and an outcome that depends on
    which engines this machine happens to have running. The handler's whole share of this is
    reading `status` and `validation_json`, so that is what the double provides.
    """
    return SimpleNamespace(
        id=uuid.uuid4(),
        status="failed",
        model_name=None,
        validation_json={
            "stages": {
                "applies": {"status": "pass", "detail": ""},
                stage: {"status": "fail", "detail": detail},
            },
            "passed": False,
            "evidence_level": -1,
        },
    )


def test_a_gate_rejecting_a_patch_is_not_the_same_as_producing_none(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A patch the validator refused is the gate working, and must not read as QUBIT failing.

    These are the two ends of the tool. `failed` means nothing usable came out at all -- the model
    exhausted its attempts, the transport died. `rejected` means a patch WAS written and the
    project's own test suite, or the symbol resolver, caught something wrong with it before a byte
    reached the disk. Reporting the second as the first describes the single most valuable thing
    QUBIT does as a defect in it: 7 of the 18 findings medivault-emr called failures were
    rejections, 5 by `tests` and 2 by `symbols`.

    The stage is carried through to the failure list, because "rejected" without "by which gate"
    sends a reviewer to read four diffs to find out.
    """
    sf, plan_id = plan
    monkeypatch.setattr(
        MigrationOrchestrator,
        "generate_patch",
        lambda self, task_id, **kw: _rejected_patch(),
        raising=True,
    )

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["rejected"] == TOTAL, result
    assert result["failed"] == 0, "a gate rejecting a patch is not a failure to produce one"
    assert result["generated"] == 0, "a rejected patch was never proposed"
    details = [f["detail"] for f in result["failures"]]
    assert all("tests" in d for d in details), f"the rejecting stage must be named: {details}"
    assert {f.get("bucket") for f in result["failures"]} == {"rejected"}, result["failures"]


def test_a_rejected_patch_is_still_left_retryable(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counting it apart from a failure must not stop it being retried like one.

    A rejection and a failure differ in what they SAY about the run; they owe the finding the same
    follow-up, because the next run has a different engine pool and whatever the learning store
    picked up in between. Parking a rejected finding as resolved would quietly retire it -- the
    bulk run's retry query selects only `unresolved` -- so the honest count would have been bought
    by losing the work.
    """
    sf, plan_id = plan
    monkeypatch.setattr(
        MigrationOrchestrator,
        "generate_patch",
        lambda self, task_id, **kw: _rejected_patch(stage="symbols", detail="mldsa65 not imported"),
        raising=True,
    )

    first = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )
    assert first["rejected"] == TOTAL, first

    with sf() as session:
        from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED

        parked = list(
            session.scalars(select(MigrationTask).where(MigrationTask.plan_id == plan_id)).all()
        )
        assert {t.resolution for t in parked} == {RESOLUTION_UNRESOLVED}, (
            f"a rejected finding must stay unresolved so a later run picks it up: {parked}"
        )

    second = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )
    assert second["total"] == TOTAL, "the rejected findings were not selected again"


def test_an_algorithm_this_repository_does_not_own_is_refused_not_failed(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal is a verdict QUBIT reached, and it belongs in its own column.

    `GuidedRemediation` is raised for two unrelated reasons and the handler used to count both as
    "guided": no patch was available (no rule matches, the target primitive is not installable
    here), and a patch WAS available and writing it would be wrong. The second is the interesting
    one -- eleven patches on `pyload` passed every gate while breaking authentication against three
    services, and this check is what stops that -- and it was invisible in the report.
    """
    from qubit_migrate.orchestrator import GuidedRemediation

    sf, plan_id = plan

    def refuse(self, task_id, **kw):
        raise GuidedRemediation(task_id, "MD5 here is fixed by Gravatar", refusal=True)

    monkeypatch.setattr(MigrationOrchestrator, "generate_patch", refuse, raising=True)

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["refused"] == TOTAL, result
    assert result["failed"] == 0, "refusing to break a remote party's format is not a failure"
    assert result["needs_guidance"] == 0, (
        "a refusal is a decision about the finding, not an admission that no patch was available"
    )


def test_a_finding_with_no_patch_available_is_still_counted_as_guided(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the same split, so the new bucket does not swallow the old one.

    `guided` keeps meaning exactly what it meant: QUBIT had no patch to offer, so it produced a
    written procedure instead. Only the ownership verdicts moved.
    """
    from qubit_migrate.orchestrator import GuidedRemediation

    sf, plan_id = plan

    def no_rule(self, task_id, **kw):
        raise GuidedRemediation(task_id, "no migration rule covers this finding")

    monkeypatch.setattr(MigrationOrchestrator, "generate_patch", no_rule, raising=True)

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["needs_guidance"] == TOTAL, result
    assert result["refused"] == 0, result
    assert result["failed"] == 0, result


def test_finished_work_is_counted_as_refused_and_still_reported_as_covered(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`AlreadySatisfied` is a refusal too, and `covered` is the dashboard's sub-count of it.

    The finding is real and there is nothing to write, because an earlier patch already made the
    file right -- "billing.py already meets what py-signature-01 asks for" is the measured wording.
    Both numbers have to hold: `refused` so the headline is honest, `covered` under its original
    name and original meaning so the run banner keeps working.
    """
    from qubit_migrate.orchestrator import AlreadySatisfied

    sf, plan_id = plan

    def satisfied(self, task_id, **kw):
        raise AlreadySatisfied("already remediated by an earlier task in this plan")

    monkeypatch.setattr(MigrationOrchestrator, "generate_patch", satisfied, raising=True)

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["refused"] == TOTAL, result
    assert result["covered"] == TOTAL, "the dashboard's own key must keep its meaning"
    assert result["failed"] == 0, result


def test_the_progress_line_names_each_outcome_separately(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sentence an operator actually reads, pinned end to end.

    Four findings, one of each outcome, so the final line has to spell all four out. This is the
    regression that matters: the old builder had three slots ("ready", "guided", "failed") and
    everything that did not fit the first two was added to the third, which is how a run that
    refused 6, rejected 7 and failed 2 reported "18 failed".

    Which worker gets which outcome is up to the thread pool, so the outcomes are handed out from a
    shared list rather than pinned to a task. The COUNTS are what the message states, and one of
    each makes them deterministic however the four are dealt.
    """
    from qubit_migrate.orchestrator import GuidedRemediation

    sf, plan_id = plan
    outcomes = ["guided", "refused", "rejected", "failed"]
    lock = threading.Lock()

    def one_of_each(self, task_id, **kw):
        with lock:
            outcome = outcomes.pop(0)
        if outcome == "guided":
            raise GuidedRemediation(task_id, "no migration rule covers this finding")
        if outcome == "refused":
            raise GuidedRemediation(task_id, "fixed by a remote party", refusal=True)
        if outcome == "rejected":
            return _rejected_patch()
        raise RuntimeError("LLM rewrite rejected after 3 attempt(s)")

    monkeypatch.setattr(MigrationOrchestrator, "generate_patch", one_of_each, raising=True)
    assert TOTAL == len(outcomes), "this test deals exactly one outcome per finding"

    reporter = _Reporter(sf)
    handlers.migrate_handler({"plan_id": str(plan_id), "apply": False, "generate": True}, reporter)

    final = next(m for m in reversed(reporter.messages) if m.startswith("Preparing 4/4"))
    assert final.startswith("Preparing 4/4 (1 guided, 1 refused, 1 rejected, 1 failed)"), final
    # A run that prepared nothing must not lead with "0 ready" either: an empty bucket is dropped,
    # so the line says what happened rather than what did not.
    assert "0 ready" not in final, final


def test_covered_is_a_sub_count_of_refused_and_is_never_summed_beside_it() -> None:
    """`AlreadySatisfied` is the ONLY thing `covered` counts, so the two can never disagree.

    Asserted at the tally rather than through a run, because the property is about the bookkeeping:
    every path that increments `covered` must also increment `refused`, or the invariant the result
    dict documents (`generated + refused + needs_guidance + rejected + failed == total`) quietly
    stops holding for exactly the findings that were already finished.
    """
    tally = handlers._Tally()
    tally.merge(handlers._Tally(done=1, refused=1, covered=1))
    tally.merge(handlers._Tally(done=1, refused=1))
    assert tally.refused == 2 and tally.covered == 1
    assert tally.done == tally.refused, "covered must not be summed alongside refused"


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


def test_when_generation_and_its_own_recovery_both_fail_the_task_is_not_silently_orphaned(
    plan, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    """The gap `_prepare_one`'s own exception handler had: two failures in a row, not one.

    `generate_patch` failing is the ordinary case -- caught, tallied, and the task is parked via
    `resolve_guided(force=True, claim_resolved=False)` so a later run can retry it. But if THAT
    recovery write also raises, the old code swallowed it with a bare `contextlib.suppress`: the
    tally still reported the task as accounted for, the job still finished as "succeeded", and the
    task's own row was left in whatever state `generate_patch` set before it failed -- silently.

    Measured live: a paymesh-gateway migration finished at progress 1.0 with two tasks still sitting
    in `generating`/`ready`, dropped from a run the UI reported as done, with no error anywhere
    that named them.

    This does not assert the task reaches any particular state -- that depends on exactly where the
    double failure lands, which is not this test's concern. What has to be true is narrower and
    checkable: the failure is no longer INVISIBLE. It must be logged with the task's id, so the
    next person looking at a "succeeded" job with fewer applied patches than findings has somewhere
    to start.
    """
    import logging

    sf, plan_id = plan
    real = handlers._prepare_one

    def fail_generation_and_its_recovery(session, orch, task, **kw):
        # Force the ordinary failure path...
        monkeypatch.setattr(
            orch, "generate_patch", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        # ...and make the recovery write it falls back to fail too.
        monkeypatch.setattr(
            orch,
            "resolve_guided",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("resolve_guided also boom")),
        )
        return real(session, orch, task, **kw)

    monkeypatch.setattr(handlers, "_prepare_one", fail_generation_and_its_recovery)

    with caplog.at_level(logging.ERROR, logger="qubit_api.jobs.handlers"):
        result = handlers.migrate_handler(
            {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
        )

    # The run itself must not crash or lose the OTHER findings over this one task's double failure.
    assert result["total"] == TOTAL

    messages = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("resolve_guided also failed" in m for m in messages), (
        f"the double failure must be logged, not silently swallowed; got: {messages}"
    )
    assert any("boom" in m and "resolve_guided also boom" in m for m in messages), (
        "the log must carry BOTH exceptions -- the original failure and the recovery's own -- "
        "or a reader cannot tell which one actually left the task stuck"
    )


# ── The idle pool, after the patches are done ────────────────────────────────


def test_findings_that_got_no_patch_are_read_by_the_pool(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A finding that ends a run without a patch gets a model's reading of its own file.

    Such a finding carries the deterministic plan and nothing else -- `advice_model` is
    `qubit-guided`, meaning no model was ever asked to read the file. That plan is the same text
    for every finding of its shape, and for a guided finding it is the ONLY output. Measured on
    `medivault-emr` before this pass existed: 24 findings, 17 ending that way, zero model calls
    spent reading any of them, on an install with nine configured engines.

    Generation is failed deliberately rather than left to chance. Whether a real engine on THIS
    machine can patch an MD5 call decides how many findings end unpatched, and a test whose
    subject only exists when the local model happens to be stopped tests nothing on the machines
    where it is running.

    The mock raises `GuidedRemediation`, not a bare exception, and that is load-bearing here: a
    generic failure now correctly parks `RESOLUTION_UNRESOLVED` (retryable -- see
    `test_a_run_retries_what_an_earlier_run_failed`), which `_advise_unpatched` must NOT touch.
    Only a genuinely guided outcome (`RESOLUTION_GUIDED`) is this pass's subject.
    """
    from qubit_migrate.orchestrator import GuidedRemediation

    sf, plan_id = plan
    advised: list[tuple[str, str | None]] = []
    lock = threading.Lock()
    real = handlers._prepare_one

    def fail_generation(session, orch, task, **kw):
        monkeypatch.setattr(
            orch,
            "generate_patch",
            lambda *a, **k: (_ for _ in ()).throw(
                GuidedRemediation(task.id, "no engine could take it")
            ),
        )
        return real(session, orch, task, **kw)

    def fake_advise(self, task_id, *, force: bool = False):
        with lock:
            advised.append((str(task_id), self.pinned_engine))
        return None

    monkeypatch.setattr(handlers, "_prepare_one", fail_generation)
    monkeypatch.setattr(MigrationOrchestrator, "advise_task", fake_advise, raising=True)

    handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    # Read back from the database rather than assumed: the pass's subject is defined by the rows
    # the run left behind, so that is what it has to be checked against.
    with sf() as s:
        unpatched = {
            str(t.id)
            for t in s.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .where(MigrationTask.state == "deferred")
                .where(MigrationTask.advice_model == "qubit-guided")
            ).all()
        }

    assert len(unpatched) == TOTAL, f"every finding should be unpatched here, got {unpatched}"
    assert {task_id for task_id, _ in advised} == unpatched, (
        "every finding that ended without a patch must have been read, and nothing else"
    )
    assert {pin for _, pin in advised} <= {"local", "second"}


def test_a_failing_advice_pass_never_fails_the_run(
    plan, two_engines, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tally is complete before the pass runs; advice is an addition to it, not part of it."""
    sf, plan_id = plan

    def boom(self, task_id, *, force: bool = False):
        raise RuntimeError("every engine is down")

    monkeypatch.setattr(MigrationOrchestrator, "advise_task", boom, raising=True)

    result = handlers.migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generate": True}, _Reporter(sf)
    )

    assert result["total"] == TOTAL, "the run's own verdict must be untouched by the advice pass"
