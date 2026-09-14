"""add_patch_approved_by

Closes a governance gate loophole: `evaluate_gate` (E4, `governance_policy.yaml`) requires 2
approvals for PHI/financial-sensitivity findings before a patch can be applied, but counted
`PatchProposal` rows with `status == "approved"`, not distinct approvers. `review_patch` already
took an `actor` parameter and forwarded it to the audit log (`MigrationEvent.actor`), but never
stored it on the patch itself -- so ONE person could satisfy a 2-approval gate alone: approve,
defer, regenerate, approve again. Two "approved" rows, one real approver.

`approved_by` records who approved THIS patch. `evaluate_gate` now counts `{p.approved_by for p in
task.patches if p.status == "approved" and p.approved_by}` -- distinct values, `None` excluded so
an approval from before this column existed is not counted as a second real approver of its own.

NULL for every existing row (no backfill: nothing recorded the approver before now, and a guess
would be worse than an honest unknown that the gate's own exclusion already treats safely).

Revision ID: a4c9f2e6b813
Revises: e7a3c02f1b48
Create Date: 2026-08-26 02:35:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a4c9f2e6b813"
down_revision: str | None = "e7a3c02f1b48"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "migration_patches",
        sa.Column("approved_by", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("migration_patches", "approved_by")
