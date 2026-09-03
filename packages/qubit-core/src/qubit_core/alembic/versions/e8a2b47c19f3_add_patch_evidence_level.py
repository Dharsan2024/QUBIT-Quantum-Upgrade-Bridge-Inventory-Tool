"""add_patch_evidence_level

Revision ID: e8a2b47c19f3
Revises: d7b3f1c68a42
Create Date: 2026-09-02 00:00:00.000000

How much was actually established about a patch, on a ladder, instead of a boolean.

`status='proposed'` (i.e. `passed`) collapsed six very different states into one word, and that is
why QUBIT's headline number could not be defended. Measured on the live database at 292 patches:

    applies   146 pass    19 fail   127 skipped (43.5%)
    parses    247 pass     0 fail    45 skipped
    symbols    27 pass    37 fail     6 skipped
    compiles   76 pass     1 fail   215 skipped (73.6%)
    tests       0 pass     0 fail   292 skipped (100%)
    rescan    258 pass     0 fail    34 skipped

Every accepted patch was flagged `partial`. Twenty were accepted with EVERY stage skipped. The
project's own suites had never run on a single one. "74% passed validation" was a statement about
a gate, not about a migration.

The ladder each rung is a strictly stronger claim than the one below it:

    -1  nothing established
     0  the diff applies and the result parses
     1  every name resolves and the module loads
     2  the SCANNER's opinion changed -- and note this is compatible with a reused nonce, a
        dropped auth tag, or every caller broken, because it is a syntactic statement
     3  the primitive demonstrably WORKS and demonstrably FAILS when it should (metamorphic)
     4  behaviour preserved on lines the project's own suite executes

Two rules make the number honest, both enforced in `transform/validate.py`:

* a `skipped` gate awards nothing. Treating a gate that did not run as a pass is the single
  assumption behind every figure this project has had to retract.
* a `vacuous` gate awards nothing either. A rule lists every algorithm it can migrate; when none
  of them describes the asset in hand, the `gone` check asks whether some unrelated algorithm is
  absent from the file, and it always is. That pass could not have been a fail.

Stored as a column rather than left inside `validation_json` because the distribution of this is
the reported result, and a `GROUP BY evidence_level` should not require parsing 292 JSON blobs.

Nullable with no default. Existing rows read as "not assessed under the ladder", which is what
they are -- backfilling them from stored stages would be inventing a measurement, and rows written
before `behaves` existed could never have reached rung 3 anyway.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e8a2b47c19f3"
down_revision: str | Sequence[str] | None = "d7b3f1c68a42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("migration_patches")}
    if "evidence_level" not in columns:
        op.add_column(
            "migration_patches",
            sa.Column("evidence_level", sa.Integer(), nullable=True),
        )


def downgrade() -> None:
    """Downgrade schema."""
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("migration_patches")}
    if "evidence_level" in columns:
        with op.batch_alter_table("migration_patches") as batch:
            batch.drop_column("evidence_level")
