"""Regression checks for test isolation and optional evaluation prerequisites."""

import importlib.util
import logging
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_logging_fixture_restores_full_named_logger_state():
    spec = importlib.util.spec_from_file_location("root_isolation", ROOT / "conftest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    logger = logging.getLogger("qubit.isolation.regression")
    original = (
        list(logger.handlers),
        logger.level,
        logger.disabled,
        logger.propagate,
        list(logger.filters),
    )
    fixture = module._isolate_root_logging_state.__wrapped__()
    next(fixture)
    try:
        logger.handlers = [logging.NullHandler()]
        logger.setLevel(logging.CRITICAL)
        logger.disabled = not original[2]
        logger.propagate = not original[3]
        logger.filters = [logging.Filter("changed")]
        logging.disable(logging.CRITICAL)
    finally:
        fixture.close()
    assert (
        logger.handlers,
        logger.level,
        logger.disabled,
        logger.propagate,
        logger.filters,
    ) == original
    assert logging.root.manager.disable == 0


def test_missing_sonar_corpus_fails_actionably_before_scan(tmp_path):
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/sonar_agreement.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "Sonar corpus is missing or empty" in result.stderr
    assert "IndexError" not in result.stderr
    assert not (tmp_path / "qubit-v2/05-detection/detection_agreement.csv").exists()
