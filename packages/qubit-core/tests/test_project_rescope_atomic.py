"""Exercise the actual migration with populated foreign-key dependants."""

import importlib

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from qubit_core.db.models import DEFAULT_TENANT_ID
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError

migration = importlib.import_module(
    "qubit_core.alembic.versions.e2f6b94c17da_rescope_projects_to_tenant"
)


@pytest.fixture
def connection(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        conn.exec_driver_sql("CREATE TABLE tenants (id CHAR(32) PRIMARY KEY)")
        conn.exec_driver_sql("INSERT INTO tenants VALUES (?)", (DEFAULT_TENANT_ID.hex,))
        conn.exec_driver_sql("""CREATE TABLE projects (
            id CHAR(32) PRIMARY KEY, name TEXT NOT NULL UNIQUE, slug TEXT NOT NULL,
            root_path TEXT, description TEXT, settings JSON NOT NULL,
            created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)""")
        conn.exec_driver_sql("CREATE UNIQUE INDEX ix_projects_slug ON projects(slug)")
        conn.exec_driver_sql("""INSERT INTO projects VALUES
            ('p', 'backend', 'backend', '/work', 'preserve', '{}', '2026-01-01', '2026-01-01')""")
        for table in ("scans", "jobs"):
            conn.exec_driver_sql(
                f"CREATE TABLE {table} (id TEXT PRIMARY KEY, project_id TEXT "
                "REFERENCES projects(id) ON DELETE CASCADE)"
            )
            conn.exec_driver_sql(f"INSERT INTO {table} VALUES ('dependent', 'p')")
        conn.commit()
        yield conn
    engine.dispose()


def run(conn, operation):
    conn.commit()
    context = MigrationContext.configure(conn, opts={"transactional_ddl": True})
    with context.begin_transaction(), Operations.context(context):
        operation()


def assert_dependants(conn):
    assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    assert conn.exec_driver_sql("PRAGMA foreign_key_check").all() == []
    for table in ("scans", "jobs"):
        assert conn.exec_driver_sql(f"SELECT project_id FROM {table}").all() == [("p",)]
    assert (
        conn.exec_driver_sql("SELECT description FROM projects WHERE id='p'").scalar() == "preserve"
    )


def test_populated_upgrade_and_downgrade_preserve_rows_and_foreign_keys(connection):
    run(connection, migration.upgrade)
    assert (
        connection.exec_driver_sql("SELECT tenant_id FROM projects").scalar()
        == DEFAULT_TENANT_ID.hex
    )
    assert_dependants(connection)
    run(connection, migration.downgrade)
    assert "tenant_id" not in {c["name"] for c in inspect(connection).get_columns("projects")}
    assert_dependants(connection)


def test_failed_downgrade_rolls_back_ddl_and_restores_enforcement(connection):
    run(connection, migration.upgrade)
    connection.exec_driver_sql("INSERT INTO tenants VALUES ('team-b')")
    connection.exec_driver_sql("""INSERT INTO projects
        SELECT 'other', 'team-b', name, slug, root_path, description,
               settings, created_at, updated_at
        FROM projects WHERE id='p'""")
    connection.commit()
    with pytest.raises(IntegrityError):
        run(connection, migration.downgrade)
    assert_dependants(connection)
    assert connection.exec_driver_sql("SELECT count(*) FROM projects").scalar() == 2
    assert "projects_old" not in inspect(connection).get_table_names()
