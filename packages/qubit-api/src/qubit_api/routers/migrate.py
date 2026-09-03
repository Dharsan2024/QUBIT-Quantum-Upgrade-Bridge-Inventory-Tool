"""Migration workflow endpoints (doc 03 §5.1 exposed over REST — M2).

Wraps :class:`qubit_migrate.MigrationOrchestrator`; plan → queue → generate → review → apply.
Importing the state models here also registers the migration tables on the shared ``Base`` so
``create_schema_on_startup`` creates them.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from qubit_core.db import AssetRow, commit_with_retry, retry_write_on_lock
from qubit_migrate.orchestrator import (
    RESOLUTION_UNRESOLVED,
    GuidedRemediation,
    MigrationOrchestrator,
)
from qubit_migrate.state import MigrationPlan, MigrationTask, PatchProposal
from qubit_migrate.state.machine import InvalidTransition
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from ..auth import get_current_tenant
from ..deps import get_session
from ..schemas import UtcDateTime
from ..services import require_plan, require_project, require_task

logger = logging.getLogger(__name__)

router = APIRouter(tags=["migrate"])


# ── Schemas ──────────────────────────────────────────────────────────────────


class PlanCreate(BaseModel):
    min_risk: float = Field(0.0, ge=0.0, le=1.0)
    # Optional so the pre-scoping call shape (`{"min_risk": 0}`) still means what it always meant:
    # a plan across everything. The app always sends a project.
    project_id: UUID | None = None
    scan_id: UUID | None = None
    #: Build a NEW plan even when this scan already has one. Off by default, because planning the
    #: same scan twice produces two plans holding the same findings and the reader has no way to
    #: tell which one to work. Set it deliberately to re-plan at a different `min_risk`.
    force: bool = False


class PlanOut(BaseModel):
    id: UUID
    status: str
    stats: dict
    # `UtcDateTime`, not a hand-rolled `.isoformat()` string. SQLite has no timezone type, so the
    # value comes back naive and `.isoformat()` emitted `2026-08-20T15:51:25.853134` with no
    # offset — which JavaScript parses as LOCAL time. On this UTC+5:30 machine a plan built two
    # seconds ago looked 5.5 hours OLDER than the scan it was built from, so the Migration Hub
    # showed "this plan is outdated, rebuild it" on every freshly built plan. `schemas._ensure_utc`
    # already existed for exactly this failure (it was fixed for scans); this router had simply
    # never adopted it.
    created_at: UtcDateTime
    project_id: UUID | None = None
    scan_id: UUID | None = None
    scope: dict = Field(default_factory=dict)
    #: The regulatory regime this plan was built under, or None if none was configured.
    #:
    #: Surfaced because the targets in a plan are otherwise unexplainable. `ML-KEM-1024` and
    #: `X25519MLKEM768` are each required by one regulator and rejected by another, so a reviewer
    #: cannot tell a deliberate choice from a mistake without knowing which one the plan was
    #: answering. None is shown as "no regime", never as the default regime's name — that would
    #: attribute a decision to an operator who never made it.
    regime: str | None = None


class TaskOut(BaseModel):
    id: UUID
    plan_id: UUID
    unit_id: UUID
    asset_id: UUID
    state: str
    rule_id: str | None
    #: True when `rule_id` names a rule with a deterministic codemod. Without it the app cannot
    #: know that picking the "template" generator will 422, so it offered the option anyway.
    has_codemod: bool = False
    #: True when this finding's rule says the right answer is a guided path, not an edit — a
    #: certificate that must be re-issued, an ecosystem with no provider trustworthy enough to
    #: install automatically, a shell script whose post-quantum answer lives in configuration.
    #: The queue reads it to offer the guidance directly instead of a Generate button that would
    #: only come back saying the same thing.
    is_guided: bool = False
    priority: float
    rank: int
    effort_points: int
    last_error: str | None
    #: Why a `deferred` task is parked: "satisfied" (an earlier patch covered it, or the pin already
    #: meets the PQC floor) vs "unresolved" (QUBIT could not migrate it). Both share one FSM state,
    #: so without this the queue shows finished work as failed and sends the operator to fix
    #: something already correct. NULL for tasks that never parked.
    resolution: str | None = None
    # denormalized asset context for the UI
    algorithm: str | None = None
    key_size: int | None = None
    file_path: str | None = None
    line: int | None = None
    risk_score: float | None = None
    # The remaining asset context the queue table had no way to show. Without these a row read
    # "AES-128 · 0.412" with no way to tell a config finding from a certificate or to know whether
    # the number is a signing key or a hash, which is most of what decides how a task is handled.
    asset_type: str | None = None
    source_scanner: str | None = None
    usage_context: str | None = None
    sensitivity: str | None = None
    mosca_margin_years: float | None = None
    effort_hours_low: float | None = None
    effort_hours_high: float | None = None
    effort_drivers: list[str] = Field(default_factory=list)
    #: Migration advice, when it has been generated. Present on the task so the queue can show
    #: which entries already have guidance without a request per row.
    advice_text: str | None = None
    advice_model: str | None = None


class GenerateRequest(BaseModel):
    repo_root: str | None = None
    generator: Literal["auto", "llm", "template"] = "auto"


class PatchOut(BaseModel):
    id: UUID
    task_id: UUID
    generator: str
    model_name: str | None = None
    file_path: str
    diff_text: str
    validation: dict
    status: str
    review_note: str | None
    applied_branch: str | None
    applied_commit: str | None


class LearnedRuleStat(BaseModel):
    """How this rule has fared, per language, across every run on this machine."""

    rule_id: str
    language: str
    passed: int
    failed: int
    #: Verified rewrites retained for this rule, hunks included - the grounding a fresh call gets.
    proven: int
    #: Distinct rejections retained, replayed as warnings so an attempt is not repeated blind.
    warnings: int


class LearningOut(BaseModel):
    """What QUBIT has learned from its own migrations.

    Reported because a system that claims to improve with use has to be able to show it. The line
    cache and the experience base are counted separately: the first answers an identical line
    without a model call, the second grounds a fresh call on structurally similar work.
    """

    #: Exact line replacements available for instant replay.
    cached_lines: int
    #: How many times a cached line has answered a finding instead of the model.
    cache_hits: int
    #: Verified rewrites retained WITH their reasoning, including the multi-line ones the cache
    #: cannot hold.
    proven_rewrites: int
    #: Rejections retained, so the same dead end is not walked into twice.
    retained_failures: int
    #: How many times stored experience has been replayed into a prompt.
    grounding_uses: int
    by_rule: list[LearnedRuleStat]


class ReviewRequest(BaseModel):
    approve: bool
    note: str = ""


class ApplyRequest(BaseModel):
    repo_root: str
    branch: str | None = None


# ── Helpers ──────────────────────────────────────────────────────────────────


def _plan_split(plan: MigrationPlan) -> dict[str, int]:
    """The automatic / LLM-assisted / manual counts for a plan.

    Stored on the plan when it was built. Plans built before the split existed carry only
    `automatable` (a count of tasks with a rule of ANY kind), and rendering those as
    "0 automatic, 0 LLM-assisted" is wrong — measured on the live installation, 2 of 7 plans. The
    counts are derived from the plan's own tasks in that case, so an old plan reads correctly
    without having to be rebuilt.
    """
    stats = plan.stats_json or {}
    if "with_codemod" in stats:
        return {
            "with_codemod": int(stats.get("with_codemod", 0)),
            "with_llm_rule": int(stats.get("with_llm_rule", 0)),
            "manual": int(stats.get("manual", 0)),
        }
    codemod_rules = _codemod_rule_ids()
    guided_rules = _guided_rule_ids()
    with_codemod = sum(1 for t in plan.tasks if t.rule_id in codemod_rules)
    with_rule = sum(1 for t in plan.tasks if t.rule_id)
    # See `MigrationOrchestrator.build_plan`: guided is its own category, and leaving it inside
    # the LLM count made the tiles claim work the model is never asked to do.
    guided = sum(1 for t in plan.tasks if t.rule_id is None or t.rule_id in guided_rules)
    return {
        "with_codemod": with_codemod,
        "with_llm_rule": max(0, with_rule - with_codemod - guided),
        "manual": guided,
    }


def _plan_out(plan: MigrationPlan) -> PlanOut:
    return PlanOut(
        id=plan.id,
        status=plan.status,
        stats={**(plan.stats_json or {}), **_plan_split(plan)},
        created_at=plan.created_at,
        project_id=plan.project_id,
        scan_id=plan.scan_id,
        scope=plan.scope_json or {},
        regime=plan.regime,
    )


@lru_cache(maxsize=1)
def _codemod_rule_ids() -> frozenset[str]:
    """Ids of the rules that carry a deterministic codemod.

    Cached because the rule pack is read-only at runtime and this is consulted once per task in a
    queue that can be several hundred rows long.
    """
    from qubit_migrate.transform import load_rules

    return frozenset(r.id for r in load_rules() if r.codemod)


@lru_cache(maxsize=1)
def _guided_rule_ids() -> frozenset[str]:
    """Ids of the rules whose answer is a guided path rather than a patch.

    The queue needs this BEFORE the user clicks anything. Offering Generate on a certificate
    finding and then answering "this resolves to a guided path" wastes a round trip to say
    something the rule pack already knew.
    """
    from qubit_migrate.transform import load_rules

    return frozenset(r.id for r in load_rules() if r.remediation == "guided")


def _task_out(task: MigrationTask, row: AssetRow | None) -> TaskOut:
    loc = (row.location or {}) if row else {}
    effort = task.effort_json or {}
    drivers = effort.get("drivers") or []
    return TaskOut(
        id=task.id,
        plan_id=task.plan_id,
        unit_id=task.unit_id,
        asset_id=task.asset_id,
        state=task.state,
        rule_id=task.rule_id,
        has_codemod=task.rule_id in _codemod_rule_ids(),
        is_guided=task.rule_id in _guided_rule_ids() or task.rule_id is None,
        priority=task.priority,
        rank=task.rank,
        effort_points=task.effort_points,
        last_error=task.last_error,
        resolution=task.resolution,
        algorithm=row.algorithm if row else None,
        key_size=row.key_size if row else None,
        file_path=loc.get("file_path"),
        line=loc.get("line"),
        risk_score=row.risk_score if row else None,
        asset_type=row.asset_type if row else None,
        source_scanner=row.source_scanner if row else None,
        usage_context=row.usage_context if row else None,
        sensitivity=row.sensitivity if row else None,
        mosca_margin_years=row.mosca_margin_years if row else None,
        effort_hours_low=effort.get("hours_low"),
        effort_hours_high=effort.get("hours_high"),
        effort_drivers=[str(d) for d in drivers],
        advice_text=task.advice_text,
        advice_model=task.advice_model,
    )


def _patch_out(patch: PatchProposal) -> PatchOut:
    return PatchOut(
        id=patch.id,
        task_id=patch.task_id,
        generator=patch.generator,
        model_name=patch.model_name,
        file_path=patch.file_path,
        diff_text=patch.diff_text,
        validation=patch.validation_json or {},
        status=patch.status,
        review_note=patch.review_note,
        applied_branch=patch.applied_branch,
        applied_commit=patch.applied_commit,
    )


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/migrate/plans", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
def create_plan(
    payload: PlanCreate,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> PlanOut:
    if payload.project_id is not None:
        require_project(session, payload.project_id, tenant_id)

    # Planning the same scan twice is a duplicate, not a second opinion. Measured against the
    # running app: one scan of demo-lab/vulnapp-python ended up with THREE plans -- one built
    # automatically when the scan finished, plus one for each explicit request -- each holding the
    # same findings, with nothing to say which was the real one. On the polyglot corpus that is two
    # plans of 127 tasks each.
    #
    # `generate_patch` already guards the same double-click for a single task (it answers 409 and
    # points at the existing patch). This is that protection one level up, except that returning
    # the existing plan is friendlier than refusing: "plan this scan" is a request for THE plan,
    # and the caller wants a usable id back either way.
    if payload.scan_id is not None and not payload.force:
        existing = (
            session.query(MigrationPlan)
            .filter(
                MigrationPlan.scan_id == payload.scan_id,
                MigrationPlan.tenant_id == tenant_id,
            )
            .order_by(MigrationPlan.created_at.desc())
            .first()
        )
        if existing is not None:
            return _plan_out(existing)

    orch = MigrationOrchestrator(session)
    # `build_plan` adds a plan, its units and every task across a loop with several of its OWN
    # intermediate `flush()` calls before its final commit -- any one of which can be where a
    # concurrent writer's lock is hit. Measured live, driving the app against five real
    # repositories scanned and migrated at once: this call got a genuine `sqlite3.OperationalError:
    # database is locked` and a bare 500, no plan created. `retry_write_on_lock` redoes the WHOLE
    # call on that error rather than patching up a partial write -- see its docstring for why that
    # is the correct unit of retry here, unlike `commit_with_retry`'s fixed-object-list shape.
    plan = retry_write_on_lock(
        session,
        lambda: orch.build_plan(
            min_risk=payload.min_risk,
            project_id=payload.project_id,
            scan_id=payload.scan_id,
            tenant_id=tenant_id,
        ),
    )
    return _plan_out(plan)


@router.get("/migrate/learning", response_model=LearningOut)
def get_learning(session: Annotated[Session, Depends(get_session)]) -> LearningOut:
    """What this installation has learned from its own validated migrations.

    Everything here is local and was written by the validation gate, not by the model: a rewrite
    only becomes "proven" after it passed, and a rejection is only retained after the gate refused
    it. Nothing in this endpoint reaches the network.
    """
    from qubit_core.db.models import LearnedOutcome, LearnedPatch

    cached_lines = session.scalar(select(func.count()).select_from(LearnedPatch)) or 0
    cache_hits = session.scalar(select(func.coalesce(func.sum(LearnedPatch.hit_count), 0))) or 0

    rows = session.execute(
        select(
            LearnedOutcome.rule_id,
            LearnedOutcome.language,
            LearnedOutcome.outcome,
            func.count().label("n"),
            func.coalesce(func.sum(LearnedOutcome.hit_count), 0).label("uses"),
        ).group_by(LearnedOutcome.rule_id, LearnedOutcome.language, LearnedOutcome.outcome)
    ).all()

    per: dict[tuple[str, str], dict[str, int]] = {}
    proven = failures = uses = 0
    for rule_id, language, outcome, n, row_uses in rows:
        entry = per.setdefault((rule_id, language), {"proven": 0, "warnings": 0})
        uses += int(row_uses)
        if outcome == "passed":
            entry["proven"] += int(n)
            proven += int(n)
        else:
            entry["warnings"] += int(n)
            failures += int(n)

    by_rule = [
        LearnedRuleStat(
            rule_id=rule_id,
            language=language,
            passed=counts["proven"],
            failed=counts["warnings"],
            proven=counts["proven"],
            warnings=counts["warnings"],
        )
        for (rule_id, language), counts in sorted(
            per.items(), key=lambda kv: -(kv[1]["proven"] + kv[1]["warnings"])
        )
    ]
    return LearningOut(
        cached_lines=int(cached_lines),
        cache_hits=int(cache_hits),
        proven_rewrites=proven,
        retained_failures=failures,
        grounding_uses=int(uses),
        by_rule=by_rule,
    )


@router.get("/migrate/plans", response_model=list[PlanOut])
def list_plans(
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
    project_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> list[PlanOut]:
    """Plans, newest first.

    `project_id` filters to one project. Without it every plan is returned, including the
    unscoped ones built before plans carried a project — the caller can tell them apart by
    `project_id` being null rather than having them silently folded into some project's list.
    """
    stmt = (
        select(MigrationPlan)
        .where(MigrationPlan.tenant_id == tenant_id)
        .order_by(MigrationPlan.created_at.desc())
        .limit(limit)
    )
    if project_id is not None:
        stmt = stmt.where(MigrationPlan.project_id == project_id)
    plans = session.scalars(stmt).all()
    return [_plan_out(p) for p in plans]


@router.delete("/migrate/plans")
def delete_all_plans(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict[str, int]:
    """Clear every migration plan of THIS team, keeping the scans and assets they were built from.

    The middle rung of the three the app offers, and the one that did not exist: `DELETE /scans`
    throws away the findings as well, and `DELETE /projects` throws away everything. Rebuilding a
    plan is cheap -- it is derived entirely from assets that are still here -- so "start the
    migration over" should not cost a rescan of the corpus that produced them.

    The `migration_plans.id` -> CASCADE chain already reaches units, tasks, dependency edges,
    patches and events, so deleting the plan rows is the whole operation.

    What deliberately SURVIVES this: `learned_patches` and `learned_outcomes`. They carry only a
    `tenant_id`, never a plan or scan id, so no cascade reaches them and none should -- they are
    what this installation has learned about migrating THIS code, and re-deriving them costs the
    model calls that produced them. Clearing plans is "run it again", not "forget what you know".

    Tenant-filtered for the same reason as the other two bulk deletes: unscoped, one team's
    cleanup button would destroy every other team's plans.
    """
    plans = session.scalars(select(MigrationPlan).where(MigrationPlan.tenant_id == tenant_id)).all()
    logger.warning(
        "DELETE /migrate/plans (bulk, %d plan(s), tenant=%s) from %s",
        len(plans),
        tenant_id,
        request.client.host if request.client else "unknown",
    )
    for plan in plans:
        session.delete(plan)
    session.commit()
    return {"deleted": len(plans)}


class RunPlanRequest(BaseModel):
    #: Write the resulting patches into the working tree.
    apply: bool = True
    #: Produce the patches. Off means "write what is already prepared" — the app's "Initiate
    #: migration" button, which runs no model and decides nothing, it only makes the edits real.
    #: Both default to on, so every existing caller keeps the single-shot behaviour it had.
    generate: bool = True
    generator: Literal["auto", "llm", "template"] = "auto"


@router.post("/migrate/plans/{plan_id}/run", status_code=status.HTTP_202_ACCEPTED)
def run_plan(
    plan_id: UUID,
    payload: RunPlanRequest,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict[str, object]:
    """Run one or both halves of this plan's migration.

    `generate` writes the patches and leaves them to be read; `apply` writes those patches into
    the files. The app drives them separately — "Build plan" prepares, "Initiate migration"
    writes — and a caller that asks for neither flag gets both, which is what it always got.

    Dispatched to the job runner rather than run here: a plan of twenty findings can hold the
    request open for minutes while the local model works, and the caller needs progress, not a
    timeout. Poll `GET /jobs/{id}` for status and the per-task result.
    """
    plan = require_plan(session, plan_id, tenant_id)

    # What this run can actually work on, which is not the same question for the two halves: a
    # generating run needs READY tasks, a writing run needs PREPARED PATCHES. Asking the wrong one
    # would refuse "Initiate migration" on a plan whose every finding is generated and waiting,
    # because generating had already moved all of them out of `ready`.
    if payload.generate:
        # `ready` alone undercounted what this run will actually do: `migrate_handler` resumes
        # every `deferred`/`unresolved` task before generating (that is the whole point of the
        # resume mechanism bug #10 added — "the engine learns between runs"), but this check did
        # not know that, so it 409'd "no ready tasks" the moment a plan's last `ready` task was
        # consumed, even with genuinely retryable work still sitting in `unresolved`. Found live
        # on OpenSSL: 1912/1912 tasks settled into terminal states (1734 guided, 80 satisfied, 98
        # unresolved, 0 ready) — from that point on, "Rebuild Plan" 409'd forever, and the 98
        # findings a code fix had just made retryable were permanently unreachable from the UI.
        pending = session.scalar(
            select(func.count())
            .select_from(MigrationTask)
            .where(MigrationTask.plan_id == plan_id)
            .where(
                or_(
                    MigrationTask.state == "ready",
                    and_(
                        MigrationTask.state == "deferred",
                        MigrationTask.resolution == RESOLUTION_UNRESOLVED,
                    ),
                )
            )
        )
        if not pending:
            raise HTTPException(
                status_code=409,
                detail=(
                    "This plan has no ready tasks — every finding is already migrated or parked."
                ),
            )
    else:
        pending = session.scalar(
            select(func.count())
            .select_from(PatchProposal)
            .join(MigrationTask, PatchProposal.task_id == MigrationTask.id)
            .where(MigrationTask.plan_id == plan_id)
            .where(PatchProposal.status.in_(("proposed", "approved")))
        )
        if not pending:
            raise HTTPException(
                status_code=409,
                detail=(
                    "There are no prepared changes to write. Build the plan first — that is what "
                    "generates the patches this step applies."
                ),
            )
    ready = pending

    runner = getattr(request.app.state, "job_runner", None)
    if runner is None:
        raise HTTPException(
            status_code=503,
            detail="The job runner is not available, so a bulk migration cannot be dispatched.",
        )

    from qubit_core.db import Job

    job = Job(
        kind="migrate",
        project_id=plan.project_id,
        ref_id=plan.id,
        payload={
            "plan_id": str(plan_id),
            "apply": payload.apply,
            "generate": payload.generate,
            "generator": payload.generator,
        },
    )
    # Retried, not a bare commit: measured live, driving the app against five real repositories
    # scanned and migrated at once, a click here while another project's bulk migration was mid-run
    # (committing once per task, in a loop that can run for minutes) got a genuine
    # `sqlite3.OperationalError: database is locked` on this exact INSERT — a bare 500, no job
    # created. `commit_with_retry` re-adds `job` on every attempt; see its docstring for why a
    # naive rollback-then-recommit would have silently dropped it instead of raising.
    commit_with_retry(session, job)
    session.refresh(job)
    runner.submit(job.id)
    return {
        "job": {"id": str(job.id), "kind": "migrate"},
        "tasks": int(ready),
        "warning": (
            f"{'Preparing changes for' if not payload.apply else 'Migrating'} {ready} "
            f"finding(s) in the background. Poll GET /api/v1/jobs/{job.id} for progress; "
            "the result carries per-task outcomes."
        ),
    }


@router.get("/migrate/plans/{plan_id}/queue", response_model=list[TaskOut])
def get_queue(
    plan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> list[TaskOut]:
    require_plan(session, plan_id, tenant_id)
    tasks = session.scalars(
        select(MigrationTask).where(MigrationTask.plan_id == plan_id).order_by(MigrationTask.rank)
    ).all()
    return [_task_out(t, session.get(AssetRow, t.asset_id)) for t in tasks]


@router.post("/migrate/tasks/{task_id}/generate", response_model=PatchOut)
def generate_patch(
    task_id: UUID,
    payload: GenerateRequest,
    session: Annotated[Session, Depends(get_session)],
) -> PatchOut:
    orch = MigrationOrchestrator(session)
    try:
        patch = orch.generate_patch(
            task_id,
            generator=payload.generator,
            repo_root=Path(payload.repo_root) if payload.repo_root else None,
        )
    except OperationalError as e:
        # Backstop, not the fix. Every write on this path is already wrapped in
        # `retry_write_on_lock` (see the orchestrator), but SQLite has exactly one writer and a
        # long enough pile-up can still exhaust the retry budget. What must never happen again is
        # this reaching the user as a bare "500 Internal Server Error" with nothing to act on --
        # measured, that is precisely what a queue of overlapping generations produced, and it
        # read as the model failing when the database was simply busy.
        if "database is locked" not in str(e).lower():
            raise
        raise HTTPException(
            status_code=503,
            detail=(
                "The database was busy with another migration and this request could not get a "
                "turn to write. Nothing was changed — try this finding again in a moment."
            ),
            headers={"Retry-After": "5"},
        ) from e
    except InvalidTransition as e:
        # Generating twice for the same task. The task FSM only allows `generate` from `ready`, and
        # a second call arrives with the task already in `proposed` — which is reachable from the
        # app by double-clicking Generate before the queue refetches, and was an uncaught 500 with
        # a stack trace. 409 is the accurate answer: the request conflicts with the task's current
        # state, and the existing patch is the thing to look at.
        #
        # "already has a generated patch" is only true for SOME of the states that land here, and
        # saying it unconditionally was actively misleading for the one users actually hit: a task
        # still at `generating` has no patch at all, and telling someone to "review or reject it"
        # sends them looking for something that does not exist. `resume_task` reclaims a genuinely
        # stranded `generating` task, so reaching here in that state means the generation really is
        # still running — which is a wait, not a conflict to resolve.
        state = session.get(MigrationTask, task_id)
        if state is not None and state.state == "generating":
            raise HTTPException(
                status_code=409,
                detail=(
                    "This task is still generating — a patch is being produced for it right now. "
                    "Wait for it to finish; the queue updates on its own when it does."
                ),
            ) from e
        raise HTTPException(
            status_code=409,
            detail=(
                f"{e} — this task already has a generated patch. Review or reject it before "
                "generating another."
            ),
        ) from e
    except GuidedRemediation as e:
        # Not an error. The rule says no edit QUBIT can correctly make is the right answer for this
        # finding — a certificate is a signed object, an unverified-publisher package should not be
        # installed on the user's behalf — and the remediation plan is already stored on the task.
        # 409 was tempting and wrong: nothing conflicts, the request succeeded and the answer is a
        # different shape. 303 points the caller at the resource that now holds it.
        raise HTTPException(
            status_code=303,
            detail=str(e),
            headers={"Location": f"/migrate/tasks/{task_id}"},
        ) from e
    except (ValueError, NotImplementedError) as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return _patch_out(patch)


class AdviseRequest(BaseModel):
    force: bool = False


@router.post("/migrate/tasks/{task_id}/advise", response_model=TaskOut)
def advise_task(
    task_id: UUID,
    payload: AdviseRequest,
    session: Annotated[Session, Depends(get_session)],
) -> TaskOut:
    """Ask the local model how to migrate this finding by hand.

    For the tasks QUBIT cannot patch — a structural protocol change, a language with no codemod, a
    SQL dialect the token swap cannot express — the queue otherwise says "manual change" and stops.
    This is the other half: what the code does, why it is a problem, what to change in THIS file,
    what it breaks, and how to prove it is gone.

    Needs Ollama. Cached on the task; `force` regenerates.
    """
    orch = MigrationOrchestrator(session)
    try:
        task = orch.advise_task(task_id, force=payload.force)
    except ValueError as e:
        # The model is optional; an answer is not. Ollama being down, or the file being unreadable,
        # used to make this a 422 and the guidance panel stayed empty — the app's answer to "what
        # do I do about this?" depended on a side-car the user may not be running. The deterministic
        # plan is built from shipped data and always exists, so fall back to it and say so.
        try:
            task = orch.resolve_guided(task_id, force=payload.force)
        except ValueError as inner:
            raise HTTPException(status_code=422, detail=str(inner)) from e
    return _task_out(task, session.get(AssetRow, task.asset_id))


@router.get("/migrate/tasks/{task_id}/patches", response_model=list[PatchOut])
def list_task_patches(
    task_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> list[PatchOut]:
    patches = session.scalars(
        select(PatchProposal)
        .where(PatchProposal.task_id == task_id)
        .order_by(PatchProposal.created_at.desc())
    ).all()
    return [_patch_out(p) for p in patches]


@router.get("/migrate/plans/{plan_id}/graph")
def get_plan_graph(
    plan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict:
    from qubit_core import row_to_asset
    from qubit_core.db import AssetRow
    from qubit_migrate.graph.builder import build_dependency_graph
    from qubit_migrate.graph.export import serialize_graph
    from qubit_migrate.graph.order import migration_order

    plan = require_plan(session, plan_id, tenant_id)

    asset_ids = [t.asset_id for t in plan.tasks]
    if not asset_ids:
        return {"nodes": [], "edges": [], "units": []}

    asset_rows = session.scalars(select(AssetRow).where(AssetRow.id.in_(asset_ids))).all()
    assets = [row_to_asset(row) for row in asset_rows]
    id_to_asset = {a.id: a for a in assets}

    g = build_dependency_graph(assets)
    units = migration_order(g, id_to_asset=id_to_asset)

    return serialize_graph(g, units)


@router.get("/migrate/tasks/{task_id}/governance")
def get_task_governance(
    task_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict:
    from qubit_migrate.governance import evaluate_gate

    task = require_task(session, task_id, tenant_id)

    return evaluate_gate(task, session)


@router.post("/migrate/patches/{patch_id}/review", response_model=PatchOut)
def review_patch(
    patch_id: UUID,
    payload: ReviewRequest,
    session: Annotated[Session, Depends(get_session)],
) -> PatchOut:
    orch = MigrationOrchestrator(session)
    try:
        patch = orch.review_patch(patch_id, approve=payload.approve, note=payload.note, actor="api")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return _patch_out(patch)


@router.post("/migrate/patches/{patch_id}/apply", response_model=PatchOut)
def apply_patch(
    patch_id: UUID,
    payload: ApplyRequest,
    session: Annotated[Session, Depends(get_session)],
) -> PatchOut:
    repo_root = Path(payload.repo_root)
    if not repo_root.is_dir():
        raise HTTPException(status_code=422, detail=f"repo_root {payload.repo_root} not found")
    orch = MigrationOrchestrator(session)
    try:
        patch = orch.apply_patch(patch_id, repo_root=repo_root, branch=payload.branch, actor="api")
    except Exception as e:  # EditApplyError / ValueError / subprocess errors
        msg = str(e)
        if "Governance gate blocked" in msg:
            raise HTTPException(status_code=409, detail=msg) from e
        raise HTTPException(status_code=422, detail=msg) from e
    return _patch_out(patch)
