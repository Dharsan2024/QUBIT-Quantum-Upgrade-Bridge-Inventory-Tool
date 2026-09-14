""" "Already migrated" is a claim about a LINE, not about a file.

The pre-flight probe that parks a task as `satisfied` used to ask: has an earlier patch for the same
(rule, file) been applied in this plan? That was correct while codemods rewrote whole files -- one
applied patch really did remediate every occurrence. It stopped being correct the moment codemods
became line-scoped, and nothing failed to say so.

Measured on `inkwell-esign` through the desktop app: `lib/inkwell/crypto/internal.rb` holds five
`code-weakhash-02` findings. The first was migrated; lines 52, 61, 83 and 88 were then parked
`satisfied` without a codemod or a model ever running on them. Five of the seven skipped findings in
that run came from here -- and the change that caused it was the fix that narrowed the codemod.

The failure is silent by construction: the tasks park, the plan completes, and the only symptom is a
migration that quietly does four fifths less work than it reports.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from qubit_core import CryptoAsset
from qubit_core.db import AssetRow, Base, ProjectRow, ScanRow
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.state import MigrationPlan, MigrationTask, MigrationUnit
from qubit_migrate.state.models import PatchProposal
from qubit_migrate.orchestrator import _relocate_finding_line
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

RULE_ID = "code-weakhash-02"
FILE = "lib/inkwell/crypto/internal.rb"


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _plan(session: Session):
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    plan = MigrationPlan(project_id=project.id, scan_id=scan.id)
    session.add(plan)
    session.flush()
    unit = MigrationUnit(plan_id=plan.id, label=FILE)
    session.add(unit)
    session.flush()
    return project, scan, plan, unit


def _task_at(session: Session, project, scan, plan, unit, line: int) -> MigrationTask:
    """One finding in `FILE`, at `line`."""
    asset = CryptoAsset(
        id=uuid.uuid4(),
        algorithm="SHA-1",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=FILE, line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=datetime.now(UTC),
        risk=RiskAnnotation(
            score=0.4, ci_low=0.4, ci_high=0.4, mosca_margin_years=10.0, priority_rank=1
        ),
    )
    row: AssetRow = asset_to_row(asset, project_id=project.id, scan_id=scan.id)
    session.add(row)
    session.flush()
    task = MigrationTask(
        plan_id=plan.id, unit_id=unit.id, asset_id=row.id, state="ready", rule_id=RULE_ID
    )
    session.add(task)
    session.flush()
    return task


def _applied_patch(session: Session, task: MigrationTask) -> None:
    session.add(
        PatchProposal(
            task_id=task.id,
            file_path=FILE,
            generator="template",
            base_sha256="0" * 64,
            diff_text="--- a\n+++ b\n",
            status="applied",
        )
    )
    session.flush()


def _lines_already_migrated(session: Session, task: MigrationTask, rule_id: str) -> set[int]:
    """The query the probe makes, in isolation.

    Mirrors the block in `MigrationOrchestrator._generate_patch`; testing it directly keeps the test
    about the SCOPE decision rather than about assembling a whole generation run.
    """
    lines: set[int] = set()
    for other_task, other_asset in session.execute(
        select(MigrationTask, AssetRow)
        .join(PatchProposal, PatchProposal.task_id == MigrationTask.id)
        .join(AssetRow, AssetRow.id == MigrationTask.asset_id)
        .where(PatchProposal.file_path == FILE)
        .where(PatchProposal.status == "applied")
        .where(MigrationTask.rule_id == rule_id)
        .where(MigrationTask.plan_id == task.plan_id)
    ).all():
        if other_task.id == task.id:
            continue
        line = (other_asset.location or {}).get("line")
        if isinstance(line, int):
            lines.add(line)
    return lines


class TestSiblingFindingsAreNotSatisfied:
    def test_a_sibling_on_another_line_still_has_work(self, session: Session) -> None:
        """The inkwell case: one applied patch must not park the other four."""
        project, scan, plan, unit = _plan(session)
        migrated = _task_at(session, project, scan, plan, unit, line=33)
        _applied_patch(session, migrated)
        session.commit()

        for line in (52, 61, 83, 88):
            sibling = _task_at(session, project, scan, plan, unit, line=line)
            session.commit()
            done = _lines_already_migrated(session, sibling, RULE_ID)
            assert line not in done, f"line {line} was wrongly reported as already migrated"

    def test_the_same_line_is_genuinely_satisfied(self, session: Session) -> None:
        """Two tasks on one line -- two rules matching the same call -- is the real duplicate."""
        project, scan, plan, unit = _plan(session)
        first = _task_at(session, project, scan, plan, unit, line=33)
        _applied_patch(session, first)
        second = _task_at(session, project, scan, plan, unit, line=33)
        session.commit()

        assert 33 in _lines_already_migrated(session, second, RULE_ID)

    def test_a_task_does_not_satisfy_itself(self, session: Session) -> None:
        """Its own applied patch must be excluded, or a retry can never proceed."""
        project, scan, plan, unit = _plan(session)
        task = _task_at(session, project, scan, plan, unit, line=33)
        _applied_patch(session, task)
        session.commit()

        assert _lines_already_migrated(session, task, RULE_ID) == set()

    def test_a_different_rule_does_not_satisfy_this_one(self, session: Session) -> None:
        project, scan, plan, unit = _plan(session)
        other = _task_at(session, project, scan, plan, unit, line=33)
        other.rule_id = "code-signature-01"
        _applied_patch(session, other)
        mine = _task_at(session, project, scan, plan, unit, line=33)
        session.commit()

        assert _lines_already_migrated(session, mine, RULE_ID) == set()

    def test_an_unapplied_patch_satisfies_nothing(self, session: Session) -> None:
        """A proposed patch is not a migration; only `applied` counts."""
        project, scan, plan, unit = _plan(session)
        first = _task_at(session, project, scan, plan, unit, line=33)
        session.add(
            PatchProposal(
                task_id=first.id,
                file_path=FILE,
                generator="template",
                base_sha256="0" * 64,
                diff_text="--- a\n+++ b\n",
                status="proposed",
            )
        )
        second = _task_at(session, project, scan, plan, unit, line=33)
        session.commit()

        assert _lines_already_migrated(session, second, RULE_ID) == set()


class TestLineShiftReanchoring:
    def test_an_earlier_edit_above_the_finding_moves_its_anchor(self) -> None:
        """A current line number must not be compared with an old task's stored line.

        This is the Sentinel shape: an import removal shifted the next finding onto the prior
        task's scan-time line.  The scan evidence still uniquely identifies the later call, and
        relocation finds its new line rather than treating that numeric collision as completion.
        """
        original = """package cryptox
import \"crypto/md5\"

func keep() {}
func cache(data []byte) string {
    return md5.Sum(data).String()
}
"""
        asset = CryptoAsset(
            algorithm="MD5",
            usage_context=UsageContext.hash,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path="internal/cryptox/internal.go", line=6),
            # The scanner records two surrounding lines when they exist.  Retaining that exact
            # shape matters: the anchor is the finding's offset within this window.
            evidence={
                "snippet": (
                    "func keep() {}\nfunc cache(data []byte) string {\n"
                    "    return md5.Sum(data).String()\n}"
                )
            },
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
            discovered_at=datetime.now(UTC),
            risk=RiskAnnotation(
                score=0.4, ci_low=0.4, ci_high=0.4, mosca_margin_years=10.0, priority_rank=1
            ),
        )

        current = original.replace('import "crypto/md5"\n', "")

        assert _relocate_finding_line(asset, current) == 5
