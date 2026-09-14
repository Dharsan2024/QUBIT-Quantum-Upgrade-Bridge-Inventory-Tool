"""Repo-wide pytest isolation. Session-scoped process state that any package's tests can leak
into any other package's tests, when the whole suite runs together, belongs here rather than in a
single package's tests/conftest.py.
"""

from __future__ import annotations

import logging
from typing import Iterator

import pytest


@pytest.fixture(autouse=True)
def _isolate_root_logging_state() -> Iterator[None]:
    """Undo any process-global logging reconfiguration a test performs, so it cannot leak into
    later tests that share this same pytest process.

    Concretely, this guards against Alembic's ``env.py``: it calls
    ``logging.config.fileConfig(config.config_file_name)`` whenever the ``Config`` it is given is
    file-backed (as ``qubit db upgrade``/``current`` build it, to match a real CLI invocation --
    see ``qubit_cli.main._alembic_cfg``). That is correct, desired behaviour for a real
    ``qubit db upgrade`` run, which is its own short-lived process. But ``fileConfig`` is stdlib
    behaviour that (a) unconditionally strips every handler off the root logger and (b), via its
    default ``disable_existing_loggers=True``, permanently sets ``.disabled = True`` on every
    already-created logger not named in alembic.ini's ``[loggers]`` section (just ``root``,
    ``sqlalchemy``, ``alembic``). Loggers are cached for the life of the process
    (``logging.Logger.manager.loggerDict``), so once a test exercises that path -- e.g.
    ``qubit-cli``'s ``test_db_upgrade_and_current`` -- every other logger in the process is
    silently disabled for the rest of the pytest session, and the root logger loses whatever
    handler pytest's own ``caplog`` fixture relied on. A later, unrelated test asserting on
    ``caplog.text`` then sees `''` no matter what it logs, even though the code under test behaves
    correctly. Confirmed by direct repro: `pytest test_cli.py::test_db_upgrade_and_current
    test_rate_budget_persistence.py::test_an_hours_long_reset_retires_the_engine_with_an_honest_reason`
    fails the second test every time; either test alone passes.
    """
    root = logging.root
    original_handlers = list(root.handlers)
    original_level = root.level
    original_disabled = {
        name: logger.disabled
        for name, logger in root.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    try:
        yield
    finally:
        root.handlers[:] = original_handlers
        root.setLevel(original_level)
        for name, logger in root.manager.loggerDict.items():
            if isinstance(logger, logging.Logger):
                logger.disabled = original_disabled.get(name, False)
