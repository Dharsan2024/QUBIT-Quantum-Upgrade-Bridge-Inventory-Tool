"""A slow generation must not hold SQLite's write lock while it runs.

SQLite allows exactly one writer at a time, even under WAL. `_transition` writes the task's new
state and an event row WITHOUT committing, so the write lock was taken at the next autoflush and
then held for the whole of `generate_patch` -- including the model call, which for a structural
rewrite is three attempts at up to `llm_timeout` (180s default) each.

Measured during a five-repository stress run: 3 of 5 "Build plan" clicks produced no job at all,
each failing on `INSERT INTO jobs` with `database is locked`. `commit_with_retry` was added first
and did not fix it, because no retry budget outlasts a five-minute lock -- the fix has to be
releasing the lock, not waiting longer for it.

This test reproduces exactly that shape: begin a generation whose model call blocks, and assert a
SECOND connection can still write meanwhile.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from qubit_core.db import Base, Job, ProjectRow, ScanRow, session_factory
from qubit_core.db.session import _apply_sqlite_pragmas
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.orchestrator import MigrationOrchestrator
from sqlalchemy import create_engine, event

VULN = "import hashlib\ndigest = hashlib.md5(data)\n"
REWRITTEN = "import hashlib\ndigest = hashlib.sha256(data)\n"


def test_a_slow_model_call_does_not_block_another_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "app.py"
    src.write_text(VULN, encoding="utf-8")

    engine = create_engine(
        f"sqlite:///{(tmp_path / 'lock.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    event.listen(engine, "connect", _apply_sqlite_pragmas)
    Base.metadata.create_all(engine)
    sf = session_factory(engine)

    with sf() as setup:
        project = ProjectRow(name="t", slug="t")
        setup.add(project)
        setup.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        setup.add(scan)
        setup.flush()
        setup.add(
            asset_to_row(
                CryptoAsset(
                    algorithm="MD5",
                    usage_context=UsageContext.hash,
                    source_scanner=SourceScanner.code,
                    asset_type=AssetType.algorithm_use,
                    location=Location(file_path=str(src), line=2),
                    quantum_vulnerable=QuantumVulnerability(
                        vulnerable=True, attack=QuantumAttack.grover
                    ),
                    discovered_at=utcnow(),
                    risk=RiskAnnotation(
                        score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
                    ),
                ),
                scan_id=scan.id,
                project_id=project.id,
            )
        )
        setup.commit()
        orch_setup = MigrationOrchestrator(setup)
        plan = orch_setup.build_plan(project_id=project.id, scan_id=scan.id)
        task_id = orch_setup.get_queue(plan.id)[0].id

    generation_started = threading.Event()
    release_model = threading.Event()

    def slow_model(prompt, *, model, base_url="x", timeout=0, **_):
        """Stands in for a real structural rewrite: slow, and holding nothing of its own."""
        generation_started.set()
        release_model.wait(timeout=30)
        return "```python\n" + REWRITTEN + "```"

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", slow_model)

    errors: list[BaseException] = []

    def generate() -> None:
        try:
            with sf() as session:
                MigrationOrchestrator(session).generate_patch(task_id, generator="llm")
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=generate)
    worker.start()
    try:
        assert generation_started.wait(timeout=30), "the stand-in model was never reached"
        # The generation is now mid-flight with its model call blocked. This is exactly the window
        # in which a "Build plan" click for another project inserts its job row.
        time.sleep(0.2)
        started = time.time()
        with sf() as other:
            other.add(Job(kind="migrate", status="queued", payload={"plan_id": "other"}))
            other.commit()
        elapsed = time.time() - started
    finally:
        release_model.set()
        worker.join(timeout=60)

    assert not errors, f"the generation itself failed: {errors[0]!r}"
    # Generous, because the point is "did not wait on a lock held for the model's lifetime", not
    # a latency benchmark. Before the fix this raised `database is locked` after busy_timeout.
    assert elapsed < 10, (
        f"writing while a generation was in flight took {elapsed:.1f}s — the write lock is still "
        "being held across the model call"
    )
