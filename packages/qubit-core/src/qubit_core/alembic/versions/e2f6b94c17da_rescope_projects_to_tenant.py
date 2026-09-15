"""rescope_projects_to_tenant

Revision ID: e2f6b94c17da
Revises: d4b7c25e8f19
Create Date: 2026-08-27 00:30:00.000000

`projects` gets its NOT NULL `tenant_id` like every other scoped table, and its name/slug
uniqueness moves from global to per-tenant.

The uniqueness change is the point. Two teams sharing one engine both wanting a project called
"backend" is ordinary, and a global UNIQUE made the second one fail with a 409 — which is not just
inconvenient, it leaks the first team's naming to the second through the error.

A full table rebuild, in raw SQL, rather than batch mode. Batch mode reflects the existing table and
faithfully reproduces what it finds, which is exactly wrong here: the constraint that has to
disappear is SQLite's unnamed ``UNIQUE (name)`` (it appears as `sqlite_autoindex_projects_1`, with
no name `drop_constraint` can target), and `ix_projects_slug` has to go from UNIQUE to plain.
Verified against a copy of a real database — row counts, data, indexes, and the cascade from
`projects` to `scans`/`assets`/`jobs` — before being applied anywhere real.
"""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import sqlalchemy as sa
from alembic import op
from qubit_core.db.models import DEFAULT_TENANT_ID

# revision identifiers, used by Alembic.
revision: str = "e2f6b94c17da"
down_revision: str | Sequence[str] | None = "d4b7c25e8f19"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_COLUMNS = "id, name, slug, root_path, description, settings, created_at, updated_at"


@contextmanager
def _sqlite_rebuild() -> Iterator[None]:
    """Toggle FK enforcement outside a transaction; rebuild atomically inside one.

    Explicit BEGIN is required even with SQLite's legacy DDL transaction behavior. A failed
    downgrade (for example duplicate names across tenants) must leave the original schema/data
    intact. Alembic's autocommit block commits preceding migration work, not this rebuild.
    """
    with op.get_context().autocommit_block():
        bind = op.get_bind()
        was_enabled = bind.exec_driver_sql("PRAGMA foreign_keys").scalar()
        bind.exec_driver_sql("PRAGMA foreign_keys=OFF")
        try:
            bind.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield
                if bind.exec_driver_sql("PRAGMA foreign_key_check").first() is not None:
                    raise RuntimeError("Project rebuild would violate foreign keys")
                bind.exec_driver_sql("COMMIT")
            except BaseException:
                bind.exec_driver_sql("ROLLBACK")
                raise
        finally:
            bind.exec_driver_sql(
                "PRAGMA foreign_keys=ON" if was_enabled else "PRAGMA foreign_keys=OFF"
            )


def _sqlite_rebuild_with_tenant() -> None:
    """Rebuild `projects` with tenant_id and per-tenant uniqueness, preserving every row."""
    with _sqlite_rebuild():
        op.execute(
            """
            CREATE TABLE projects_new (
                id CHAR(32) NOT NULL,
                tenant_id CHAR(32) NOT NULL,
                name VARCHAR(120) NOT NULL,
                slug VARCHAR(64) NOT NULL,
                root_path VARCHAR,
                description VARCHAR,
                settings JSON NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                CONSTRAINT uq_project_tenant_name UNIQUE (tenant_id, name),
                CONSTRAINT uq_project_tenant_slug UNIQUE (tenant_id, slug),
                FOREIGN KEY(tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )
            """
        )
        # _OLD_COLUMNS and DEFAULT_TENANT_ID are fixed module-level constants, not user input.
        copy_rows = (
            f"INSERT INTO projects_new (tenant_id, {_OLD_COLUMNS}) "  # noqa: S608
            f"SELECT '{DEFAULT_TENANT_ID.hex}', {_OLD_COLUMNS} FROM projects"
        )
        op.execute(copy_rows)
        op.execute("DROP TABLE projects")
        op.execute("ALTER TABLE projects_new RENAME TO projects")
        # Plain index, not UNIQUE: the composite uq_project_tenant_slug carries uniqueness now,
        # and this one only exists to keep slug lookups fast.
        op.execute("CREATE INDEX ix_projects_slug ON projects (slug)")
        op.execute("CREATE INDEX ix_projects_tenant_id ON projects (tenant_id)")


def _generic_rescope() -> None:
    """PostgreSQL and friends: named constraints are addressable, so no rebuild is needed."""
    op.add_column("projects", sa.Column("tenant_id", sa.Uuid(), nullable=True))
    target = sa.table("projects", sa.column("tenant_id", sa.Uuid()))
    op.execute(target.update().values(tenant_id=DEFAULT_TENANT_ID))
    op.alter_column("projects", "tenant_id", existing_type=sa.Uuid(), nullable=False)
    op.create_foreign_key(
        "fk_projects_tenant_id", "projects", "tenants", ["tenant_id"], ["id"], ondelete="CASCADE"
    )
    op.create_index("ix_projects_tenant_id", "projects", ["tenant_id"])

    inspector = sa.inspect(op.get_bind())
    for constraint in inspector.get_unique_constraints("projects"):
        if constraint["column_names"] in (["name"], ["slug"]) and constraint["name"]:
            op.drop_constraint(constraint["name"], "projects", type_="unique")
    existing_indexes = {idx["name"] for idx in inspector.get_indexes("projects")}
    if "ix_projects_slug" in existing_indexes:
        op.drop_index("ix_projects_slug", table_name="projects")
    op.create_index("ix_projects_slug", "projects", ["slug"])
    op.create_unique_constraint("uq_project_tenant_name", "projects", ["tenant_id", "name"])
    op.create_unique_constraint("uq_project_tenant_slug", "projects", ["tenant_id", "slug"])


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("projects"):
        return
    if "tenant_id" in {col["name"] for col in inspector.get_columns("projects")}:
        return  # already present via Base.metadata.create_all()

    if bind.dialect.name == "sqlite":
        _sqlite_rebuild_with_tenant()
    else:
        _generic_rescope()


def downgrade() -> None:
    """Downgrade schema: back to global name/slug uniqueness, dropping tenant_id."""
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with _sqlite_rebuild():
            op.execute(
                """
                CREATE TABLE projects_old (
                    id CHAR(32) NOT NULL,
                    name VARCHAR(120) NOT NULL,
                    slug VARCHAR(64) NOT NULL,
                    root_path VARCHAR,
                    description VARCHAR,
                    settings JSON NOT NULL,
                    created_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL,
                    PRIMARY KEY (id),
                    UNIQUE (name)
                )
                """
            )
            restore_rows = (
                f"INSERT INTO projects_old ({_OLD_COLUMNS}) "  # noqa: S608
                f"SELECT {_OLD_COLUMNS} FROM projects"
            )
            op.execute(restore_rows)
            op.execute("DROP TABLE projects")
            op.execute("ALTER TABLE projects_old RENAME TO projects")
            op.execute("CREATE UNIQUE INDEX ix_projects_slug ON projects (slug)")
        return

    op.drop_constraint("uq_project_tenant_slug", "projects", type_="unique")
    op.drop_constraint("uq_project_tenant_name", "projects", type_="unique")
    op.drop_index("ix_projects_slug", table_name="projects")
    op.create_index("ix_projects_slug", "projects", ["slug"], unique=True)
    op.create_unique_constraint("uq_projects_name", "projects", ["name"])
    op.drop_index("ix_projects_tenant_id", table_name="projects")
    op.drop_constraint("fk_projects_tenant_id", "projects", type_="foreignkey")
    op.drop_column("projects", "tenant_id")
