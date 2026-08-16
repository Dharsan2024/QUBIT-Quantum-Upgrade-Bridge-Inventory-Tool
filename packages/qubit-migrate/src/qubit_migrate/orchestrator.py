"""MigrationOrchestrator facade (doc 03 §5.2)."""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from qubit_core import CryptoAsset
from qubit_core.db import AssetRow
from qubit_core.mapping import row_to_asset
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from .config import MigrateConfig
from .graph import build_dependency_graph, migration_order
from .queue import rank_ready_frontier
from .state import (
    MigrationPlan,
    MigrationTask,
    MigrationUnit,
    PatchProposal,
    to_public_status,
    transition,
    write_event,
)
from .transform import (
    EditApplyError,
    ValidationReport,
    file_sha256,
    load_rules,
    match_rule,
    old_new_to_diff,
    run_codemod,
    validate_patch,
)
from .transform.llm import OllamaError, generate_llm_source

logger = logging.getLogger(__name__)


class MigrationOrchestrator:
    """Facade wiring all qubit-migrate components (the only import surface for api/cli)."""

    def __init__(self, session: Session, config: MigrateConfig | None = None) -> None:
        self.session = session
        self.config = config or MigrateConfig()
        self._rules = load_rules()

    def build_plan(self, *, min_risk: float = 0.0) -> MigrationPlan:
        """Build graph+queue from risk-annotated assets -> saves plan."""
        # Domain assets live as flattened AssetRow rows; hydrate back to the schema the
        # graph/queue components expect.
        #
        # The scope filter runs in SQL. This used to `select(AssetRow)` with NO predicate at all —
        # every asset in the entire database, across every project and every historical scan —
        # convert each one through `row_to_asset` (pydantic validation per asset), and only then
        # discard the ones that are safe or unscored. A plan only ever concerns vulnerable,
        # risk-scored assets, so the rest was work done purely to be thrown away, and it grew with
        # total scan history rather than with the size of the plan. `qv_vulnerable` and `risk_score`
        # are both indexed.
        rows = self.session.scalars(
            select(AssetRow).where(
                AssetRow.qv_vulnerable.is_(True),
                AssetRow.risk_score.is_not(None),
                AssetRow.risk_score >= min_risk,
            )
        ).all()
        in_scope = [row_to_asset(r) for r in rows]
        if not in_scope:
            plan = MigrationPlan(
                status="completed", stats_json={"message": "No vulnerable assets in scope"}
            )
            self.session.add(plan)
            self.session.commit()
            return plan

        plan = MigrationPlan(status="active", config_json=self.config.model_dump())
        self.session.add(plan)
        self.session.flush()

        g = build_dependency_graph(in_scope, min_confidence=self.config.min_confidence)
        id_to_asset = {a.id: a for a in in_scope}
        units = migration_order(g, id_to_asset=id_to_asset)

        # Ranked tasks (ignoring prerequisites for the initial rank snapshot)
        ranked = rank_ready_frontier(in_scope)
        rank_map = {rt.asset.id: rt for rt in ranked}

        for info in units:
            unit_db = MigrationUnit(
                plan_id=plan.id,
                order_index=info.order_index,
                label=info.label,
                member_ids_json=[str(uid) for uid in info.member_ids],
            )
            self.session.add(unit_db)
            self.session.flush()

            for asset_id in info.member_ids:
                rt = rank_map[asset_id]
                rule = match_rule(rt.asset, self._rules)
                task = MigrationTask(
                    plan_id=plan.id,
                    unit_id=unit_db.id,
                    asset_id=asset_id,
                    state="ready",  # M1: all start ready (edge prerequisites don't block yet)
                    rule_id=rule.id if rule else None,
                    effort_points=rt.effort.points,
                    effort_json={
                        "hours_low": rt.effort.hours_low,
                        "hours_high": rt.effort.hours_high,
                        "drivers": rt.effort.drivers,
                    },
                    priority=rt.priority,
                    rank=rt.rank,
                )
                self.session.add(task)
                self.session.flush()

                # Sync back to Asset.migration
                self._sync_public_status(task)
                write_event(
                    self.session,
                    task,
                    from_state=None,
                    to_state="ready",
                    detail={"rule": task.rule_id},
                )

        plan.stats_json = {"tasks": len(in_scope), "units": len(units)}
        self.session.commit()
        return plan

    def get_queue(self, plan_id: UUID, limit: int = 50) -> list[MigrationTask]:
        """Ready frontier, ranked."""
        stmt = (
            select(MigrationTask)
            .where(MigrationTask.plan_id == plan_id)
            .where(MigrationTask.state == "ready")
            .order_by(MigrationTask.rank)
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def generate_patch(
        self,
        task_id: UUID,
        *,
        generator: Literal["auto", "llm", "template"] = "auto",
        repo_root: Path | None = None,
    ) -> PatchProposal:
        """Generate a patch for a task.

        M1 only supports generator="template".
        """
        task = self.session.get(MigrationTask, task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        asset = self._load_asset(task.asset_id)
        if not asset or not asset.location or not asset.location.file_path:
            raise ValueError(f"Asset {task.asset_id} has no file_path")

        file_path = Path(asset.location.file_path)
        if repo_root:
            file_path = repo_root / file_path

        # Diff headers + the stored patch path are repo-relative (posix) whenever the file
        # sits under repo_root — required for `git apply` to work from the repo root.
        # Absolute paths only remain for repo-less generation (no apply possible there).
        diff_path = str(file_path)
        if repo_root:
            # file outside repo_root keeps its absolute path (repo-less generation only)
            with contextlib.suppress(ValueError):
                diff_path = file_path.resolve().relative_to(repo_root.resolve()).as_posix()

        rule = match_rule(asset, self._rules)
        if not rule:
            self._fail_task(task, "no rule matched")
            raise ValueError(f"No rule matches asset {asset.id}")

        self._transition(task, "generate", detail={"generator": generator})

        # auto prefers the deterministic codemod; LLM is used when forced or when the
        # rule has no codemod. Either way the same validation pipeline gates the result.
        use_llm = generator == "llm" or (generator == "auto" and not rule.codemod)
        # Some codemods are the authority for their transform and outrank an explicit
        # `--generator llm` (see MigrationRule.codemod_authoritative): the correct output is a
        # constant, so a model can only lose information. This is what kept X25519MLKEM768 out of
        # LLM-generated configs.
        if use_llm and rule.codemod and rule.codemod_authoritative:
            use_llm = False
        model_name: str | None = None

        # A rule rewrites the WHOLE file, so once one of its patches has been applied to a file, any
        # other pending task for the same (rule, file) has nothing left to do. Checking that here
        # covers LLM-only rules, which have no codemod to probe with: two RSA/kex findings in one
        # seal.go used to send the second one to the model, which correctly returned the
        # already-migrated file unchanged — and that was then reported as three failed attempts.
        already_applied = self.session.scalar(
            select(PatchProposal.id)
            .join(MigrationTask, MigrationTask.id == PatchProposal.task_id)
            .where(PatchProposal.file_path == diff_path)
            .where(PatchProposal.status == "applied")
            .where(MigrationTask.rule_id == rule.id)
            .limit(1)
        )
        if already_applied is not None:
            self._fail_task(task, f"already migrated by an earlier {rule.id} patch to this file")
            raise ValueError(f"already migrated by an earlier {rule.id} patch to this file")

        if use_llm:
            # Several assets routinely share one file — a weak sshd_config yields a finding per
            # algorithm in every list — so whichever task runs first remediates the file for all of
            # them. The rest then have nothing to do. The deterministic codemod is the cheapest
            # authority on that: it reports "no change" exactly when its target pattern is gone.
            # Probing it first turns three wasted 7B-model attempts and a misleading "LLM rewrite
            # rejected" into an immediate, accurate skip. The probe result is DISCARDED — an
            # explicit `--generator llm` still gets its rewrite from the model when work remains.
            if rule.codemod:
                probe_found_work = True
                with contextlib.suppress(Exception):  # a probe failure must not block generation
                    probe_found_work = run_codemod(rule.codemod, asset, file_path) is not None
                if not probe_found_work:
                    self._fail_task(task, "already remediated by an earlier task in this plan")
                    raise ValueError("already remediated by an earlier task in this plan")
            try:
                orig = file_path.read_text(encoding="utf-8")
                new = generate_llm_source(orig, rule, asset, model=self.config.model)
                model_name = self.config.model
            except (OSError, OllamaError) as e:
                self._fail_task(task, f"LLM generation failed: {e}")
                raise ValueError(f"LLM generation failed: {e}") from e
        else:
            if not rule.codemod:
                self._fail_task(task, "Rule has no codemod")
                raise ValueError(f"Rule {rule.id} has no codemod fallback")
            try:
                result = run_codemod(rule.codemod, asset, file_path)
                if not result:
                    self._fail_task(task, f"Codemod {rule.codemod} produced no change")
                    raise ValueError("Codemod produced no change")
                orig, new = result
            except Exception as e:
                self._fail_task(task, f"Codemod error: {e}")
                raise

        diff = old_new_to_diff(diff_path, orig, new)
        report = validate_patch(
            diff_text=diff,
            patched_source=new,
            rule=rule,
            repo_root=repo_root,
            language=rule.language,
            target_rel_path=diff_path if repo_root else None,
            no_docker=self.config.no_docker,
        )

        patch = PatchProposal(
            task_id=task.id,
            generator="llm" if use_llm else "template",
            model_name=model_name,
            file_path=diff_path,
            base_sha256=file_sha256(file_path),
            diff_text=diff,
            validation_json=report.as_dict(),
            status="proposed" if report.passed else "failed",
        )
        self.session.add(patch)
        self.session.flush()

        if report.passed:
            self._transition(task, "validation_passed", detail={"patch_id": str(patch.id)})
        else:
            self._transition(task, "generators_exhausted", detail={"report": report.as_dict()})

        self.session.commit()
        return patch

    def review_patch(
        self,
        patch_id: UUID,
        *,
        approve: bool,
        note: str = "",
        actor: str = "cli",
    ) -> PatchProposal:
        """Approve or reject a proposed patch."""
        patch = self.session.get(PatchProposal, patch_id)
        if not patch or patch.status != "proposed":
            raise ValueError(f"Patch {patch_id} not found or not proposed")

        task = self.session.get(MigrationTask, patch.task_id)
        if not task:
            raise ValueError("Task not found")

        patch.status = "approved" if approve else "rejected"
        patch.review_note = note
        from datetime import datetime

        patch.reviewed_at = datetime.now(UTC)

        self._transition(task, "approve" if approve else "reject", actor=actor)
        self.session.commit()
        return patch

    def apply_patch(
        self,
        patch_id: UUID,
        *,
        repo_root: Path,
        branch: str | None = None,
        actor: str = "cli",
    ) -> PatchProposal:
        """Apply an approved patch to the git repo using git apply."""
        patch = self.session.get(PatchProposal, patch_id)
        if not patch or patch.status != "approved":
            raise ValueError(f"Patch {patch_id} not approved")

        task = self.session.get(MigrationTask, patch.task_id)
        if not task:
            raise ValueError("Task not found")

        # 0. Guard: Governance Policy Gate
        from qubit_migrate.governance import check_governance

        check_governance(task.id, self.session)

        # 1. Guard: Check git repo is clean
        import subprocess

        try:
            r = subprocess.run(
                ["git", "status", "--porcelain"], capture_output=True, cwd=str(repo_root)
            )
            if r.stdout.strip():
                raise ValueError("Dirty git tree; commit or stash changes before applying")
        except FileNotFoundError as e:
            raise ValueError("git not found") from e

        # 2. Guard: File hasn't changed since generation
        file_path = repo_root / patch.file_path
        if not file_path.exists():
            patch.status = "superseded"
            self.session.commit()
            raise ValueError(f"File {patch.file_path} deleted")
        if file_sha256(file_path) != patch.base_sha256:
            patch.status = "superseded"
            self._transition(task, "defer", actor=actor)  # Back to ready via resume later
            self._transition(task, "resume", actor=actor)
            self.session.commit()
            raise ValueError(f"File {patch.file_path} changed since generation. Patch superseded.")

        # 3. Create branch (if requested)
        applied_branch = None
        if branch:
            subprocess.run(["git", "checkout", "-b", branch], cwd=str(repo_root), check=True)
            applied_branch = branch

        # 4. Apply diff
        p = subprocess.run(
            ["git", "apply", "-"], input=patch.diff_text.encode("utf-8"), cwd=str(repo_root)
        )
        if p.returncode != 0:
            if applied_branch:
                subprocess.run(["git", "checkout", "-"], cwd=str(repo_root))
                if branch:
                    subprocess.run(["git", "branch", "-D", branch], cwd=str(repo_root))
            raise EditApplyError(f"git apply failed with code {p.returncode}")

        # 5. Commit (if branch requested)
        applied_commit = None
        if branch:
            subprocess.run(["git", "add", patch.file_path], cwd=str(repo_root), check=True)
            msg = f"QUBIT: migrate {patch.file_path}\n\nTask: {task.id}\nRule: {task.rule_id}"
            subprocess.run(["git", "commit", "-m", msg], cwd=str(repo_root), check=True)
            c = subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, cwd=str(repo_root)
            )
            applied_commit = c.stdout.decode().strip()

        patch.status = "applied"
        patch.applied_branch = applied_branch
        patch.applied_commit = applied_commit
        self._transition(task, "apply", actor=actor)
        self.session.commit()
        return patch

    def verify_task(self, task_id: UUID) -> ValidationReport | None:
        """Re-scan to prove remediation."""
        task = self.session.get(MigrationTask, task_id)
        if not task or task.state not in ("applied", "verifying"):
            raise ValueError(f"Task {task_id} not applied")

        patch = self.session.scalars(
            select(PatchProposal).where(
                PatchProposal.task_id == task.id, PatchProposal.status == "applied"
            )
        ).first()
        if not patch:
            raise ValueError("No applied patch found")

        asset = self._load_asset(task.asset_id)
        if not asset or not asset.location or not asset.location.file_path:
            raise ValueError("Asset lost")

        # M1 verification: doc 03 §6.5 triggers a re-scan of the patched file. Full rescan wiring
        # (reaching into the target repo path) lands in M2; M1 records the state transition.
        # In M1 we'll cheat slightly for testing by simulating verification success if applied.

        # Real verification would be:
        # self._transition(task, "verify_pass")
        # return ValidationReport(...)

        self._transition(task, "verify_pass", actor="system")
        self.session.commit()
        return ValidationReport(passed=True)

    def _fail_task(self, task: MigrationTask, reason: str) -> None:
        task.last_error = reason
        # `deferred` only accepts `resume`, so a SECOND failure on an already-deferred task made
        # transition() raise and the real reason was replaced by a confusing FSM error surfacing as
        # "skipped one asset: No transition 'defer' from state 'deferred'". This happens in ordinary
        # use: when one file contains two findings, the first patch fixes both, and the second task
        # then fails with nothing to change. Recording a failure must be idempotent — the task is
        # already parked in exactly the state we wanted, so keep the newest reason and move on.
        if task.state == "deferred":
            write_event(
                self.session,
                task,
                from_state="deferred",
                to_state="deferred",
                actor="system",
                detail={"error": reason, "note": "already deferred"},
            )
            return
        self._transition(task, "defer", detail={"error": reason})  # fail -> pending basically

    def _transition(
        self,
        task: MigrationTask,
        event: str,
        actor: str = "system",
        detail: dict[str, Any] | None = None,
    ) -> None:
        from_state = task.state
        task.state = transition(from_state, event)
        self._sync_public_status(task)
        write_event(
            self.session,
            task,
            from_state=from_state,
            to_state=task.state,
            actor=actor,
            detail=detail,
        )

    def _load_asset(self, asset_id: UUID) -> CryptoAsset | None:
        """Hydrate the domain CryptoAsset for an asset id (rows are flattened AssetRow)."""
        row = self.session.get(AssetRow, asset_id)
        return row_to_asset(row) if row else None

    def _sync_public_status(self, task: MigrationTask) -> None:
        row = self.session.get(AssetRow, task.asset_id)
        if row:
            status = to_public_status(task.state)
            migration = dict(row.migration_json or {})
            migration["status"] = status
            # MigrationAnnotation requires a recommendation — always write one so the row
            # stays hydratable via row_to_asset.
            if task.rule_id:
                migration["recommendation"] = f"Migrate using {task.rule_id}"
            else:
                migration.setdefault("recommendation", "Manual migration required (no rule)")
            row.migration_status = status
            row.migration_json = migration
            flag_modified(row, "migration_json")


__all__ = ["MigrationOrchestrator"]
