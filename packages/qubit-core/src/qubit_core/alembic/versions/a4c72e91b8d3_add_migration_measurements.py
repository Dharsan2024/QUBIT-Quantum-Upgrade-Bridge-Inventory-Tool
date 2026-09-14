"""add_migration_measurements

Revision ID: a4c72e91b8d3
Revises: f3b91d5e08a7
Create Date: 2026-09-02 00:00:00.000000

One row per finding attempt: the dataset that turns Mosca's `Y` from an estimate into a
measurement.

`Y` -- time to complete a migration -- is an input to every quantum risk model in the literature,
and every one of them ESTIMATES it, because completed migrations do not exist to measure. The QARS
authors (Electronics 2025, 14, 3338) name the collection of real-world migration times as their own
future work. QUBIT performs migrations with timestamps, per finding, and was discarding that as a
log line.

Three properties are in the schema rather than left to reporting code, because each has a direction
of error and all three err toward flattering the tool:

* A row is written for EVERY terminal path, not only successes. A finding that consumed four repair
  attempts and was then routed to a human took real time; dropping it biases `Y` downward.
* The path is recorded, because the pooled mean is wrong rather than merely imprecise. Measured on
  certbot: 155 codemod, 102 guided, 2 model. A mean over 272 findings averages three unrelated
  distributions and describes none of them.
* Time is conditioned on evidence level. "Median 4.2 s to an L2 patch" and "median 96 s to an L3
  patch" are different claims.

`task_id` is ON DELETE SET NULL, not CASCADE. A measurement outlives the task it describes: the
task is working state and can be pruned, while the measurement is the published record, and losing
rows when a plan is cleaned up would silently shrink the dataset -- again in the flattering
direction, since the runs most likely to be pruned are the failed ones.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a4c72e91b8d3"
down_revision: str | Sequence[str] | None = "f3b91d5e08a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    if "migration_measurements" in inspector.get_table_names():
        return
    op.create_table(
        "migration_measurements",
        sa.Column("id", sa.Uuid(), primary_key=True),
        # identity
        sa.Column(
            "task_id",
            sa.Uuid(),
            sa.ForeignKey("migration_tasks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("plan_id", sa.Uuid(), nullable=True),
        sa.Column("corpus", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("rule_id", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("synthesised", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("language", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("algorithm", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("usage_context", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("regime", sa.String(length=32), nullable=True),
        sa.Column("construction", sa.String(length=16), nullable=False, server_default="pure"),
        # path
        sa.Column("path", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("engine", sa.String(length=64), nullable=True),
        sa.Column("windowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("from_cache", sa.Boolean(), nullable=False, server_default=sa.false()),
        # time
        sa.Column("queued_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("first_candidate_s", sa.Float(), nullable=True),
        sa.Column("total_s", sa.Float(), nullable=False, server_default="0"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("model_seconds", sa.Float(), nullable=False, server_default="0"),
        sa.Column("gate_seconds", sa.Float(), nullable=False, server_default="0"),
        sa.Column("apply_seconds", sa.Float(), nullable=False, server_default="0"),
        # outcome
        sa.Column("outcome", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("evidence_level", sa.Integer(), nullable=True),
        sa.Column("stage_outcomes", sa.JSON(), nullable=True),
        sa.Column("vacuous", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("human_needed", sa.Boolean(), nullable=False, server_default=sa.false()),
        # size
        sa.Column("file_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("file_lines", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("diff_changed_lines", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("diff_noise_lines", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_migration_measurements_task_id", "migration_measurements", ["task_id"])
    op.create_index("ix_migration_measurements_plan_id", "migration_measurements", ["plan_id"])
    # The two columns every report groups by. Without them the per-path breakdown -- which is the
    # whole point of the schema -- is a full scan on every query.
    op.create_index("ix_migration_measurements_path", "migration_measurements", ["path"])
    op.create_index("ix_migration_measurements_outcome", "migration_measurements", ["outcome"])


def downgrade() -> None:
    """Downgrade schema."""
    inspector = sa.inspect(op.get_bind())
    if "migration_measurements" in inspector.get_table_names():
        op.drop_table("migration_measurements")
