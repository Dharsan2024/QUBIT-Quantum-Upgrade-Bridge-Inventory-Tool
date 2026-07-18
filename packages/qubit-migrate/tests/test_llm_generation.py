"""LLM generation path (doc 03 §6.3.2) — Ollama HTTP mocked so the suite stays offline.

The live model is exercised manually / in demos; these tests pin the contract:
prompt building, fenced-block extraction, orchestrator wiring, and failure handling.
"""

from __future__ import annotations

import pytest
from qubit_core.db import Base, ProjectRow, ScanRow
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
from qubit_migrate.transform.llm import OllamaError, extract_code_block
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

REWRITTEN = "import hashlib\ndigest = hashlib.sha256(data)\n"


def test_extract_code_block_picks_largest_fence() -> None:
    text = "Sure!\n```python\n" + REWRITTEN + "```\nand also ```x = 1```"
    assert extract_code_block(text) == REWRITTEN


def test_extract_code_block_no_fence_raises() -> None:
    with pytest.raises(OllamaError):
        extract_code_block("no code here")


def _seeded_orchestrator(tmp_path) -> tuple[MigrationOrchestrator, object]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    src = tmp_path / "app.py"
    src.write_text("import hashlib\ndigest = hashlib.md5(data)\n", encoding="utf-8")
    asset = CryptoAsset(
        algorithm="MD5",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=str(src), line=2),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
        ),
    )
    session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    task = orch.get_queue(plan.id)[0]
    return orch, task


def test_llm_generator_produces_validated_patch(tmp_path, monkeypatch) -> None:
    orch, task = _seeded_orchestrator(tmp_path)
    monkeypatch.setattr(
        "qubit_migrate.transform.llm._ollama_generate",
        lambda prompt, *, model, base_url="x", timeout=0: "```python\n" + REWRITTEN + "```",
    )
    patch = orch.generate_patch(task.id, generator="llm")
    assert patch.generator == "llm"
    assert patch.model_name == orch.config.model
    assert "sha256" in patch.diff_text
    assert patch.status == "proposed", patch.validation_json


def test_llm_failure_fails_task_cleanly(tmp_path, monkeypatch) -> None:
    orch, task = _seeded_orchestrator(tmp_path)

    def boom(prompt, *, model, base_url="x", timeout=0):
        raise OllamaError("server down")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", boom)
    with pytest.raises(ValueError, match="LLM generation failed"):
        orch.generate_patch(task.id, generator="llm")


def test_auto_prefers_template_when_codemod_exists(tmp_path, monkeypatch) -> None:
    orch, task = _seeded_orchestrator(tmp_path)

    def never(prompt, **kw):  # pragma: no cover - would fail the test if called
        raise AssertionError("LLM must not be called when a codemod exists (auto)")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", never)
    patch = orch.generate_patch(task.id, generator="auto")
    assert patch.generator == "template"
    assert patch.model_name is None
