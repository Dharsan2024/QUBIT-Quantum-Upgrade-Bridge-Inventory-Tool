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


def test_rsa_kex_rule_matches_and_routes_to_llm() -> None:
    """py-rsa-kex-01 has no codemod, so auto generation routes RSA kex assets to the LLM.

    The asset carries a real ``.py`` path. It previously carried none at all, which passed only
    because the two Python rules had no ``file_suffix`` guard and therefore matched a code asset in
    any language — see ``test_python_rules_do_not_claim_other_languages`` for what that cost. Every
    ``source_scanner=code`` asset the scanner produces has a file path, so requiring one here makes
    the fixture match reality rather than the bug.
    """
    from qubit_migrate.transform import match_rule

    rsa = CryptoAsset(
        algorithm="RSA-2048",
        usage_context=UsageContext.kex,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="app/crypto.py", line=12),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        discovered_at=utcnow(),
    )
    rule = match_rule(rsa)
    assert rule is not None and rule.id == "py-rsa-kex-01"
    assert rule.codemod is None  # forces the LLM path under auto

    md5 = rsa.model_copy(update={"algorithm": "MD5", "usage_context": UsageContext.hash})
    weak = match_rule(md5)
    assert weak is not None and weak.id == "py-weakhash-01"  # rule order stays correct


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        # Languages with a real token-swap table get the multi-language rule.
        ("svc/hash.go", "code-weakhash-02"),
        ("src/Main.java", "code-weakhash-02"),
        ("web/util.js", "code-weakhash-02"),
        ("web/util.ts", "code-weakhash-02"),
        # .tsx and .cjs were in every other code-* rule's suffix list but not this one, so a React
        # component fell through to the Python rule despite the JS/TS swap covering it.
        ("web/Component.tsx", "code-weakhash-02"),
        ("web/legacy.cjs", "code-weakhash-02"),
        ("lib/digest.c", "code-weakhash-02"),
        ("lib/digest.cpp", "code-weakhash-02"),
        # Python keeps its own precise libcst codemod.
        ("app/hash.py", "py-weakhash-01"),
        # Everything the scanner learned to read in the language expansion has NO weak-hash
        # codemod. The honest answer is None: the app then says "manual change" instead of
        # offering a libcst Python transform for a Ruby or SQL file.
        ("app/billing.rb", None),
        ("app/legacy.php", None),
        ("src/Vault.cs", None),
        ("src/seal.rs", None),
        ("src/Crypto.kt", None),
        ("src/Wallet.swift", None),
        ("src/Ledger.scala", None),
        ("lib/fleet.dart", None),
        ("bin/provision.sh", None),
        ("bin/Provision.ps1", None),
        ("migrations/V3__hash.sql", None),
    ],
)
def test_python_rules_do_not_claim_other_languages(path: str, expected: str | None) -> None:
    """A ``language: python`` rule must not claim a file in another language.

    ``py-rsa-kex-01`` and ``py-weakhash-01`` were the only rules naming a language without also
    constraining the file suffix, so they matched ``source_scanner=code`` assets in every language
    the scanner can read. Once code scanning grew from 6 languages to 19 that meant 34 of the 127
    tasks in the polyglot demo project were offered a libcst **Python** codemod for a .rb, .php,
    .cs, .rs, .kt, .swift, .scala, .dart, .sh, .ps1 or .sql file. The template generator refused
    with a 422 after the click; the LLM generator would have used Python-specific prompt
    constraints and produced a plausible, wrong patch.
    """
    from qubit_migrate.transform import match_rule

    asset = CryptoAsset(
        algorithm="MD5",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=3),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
    )
    rule = match_rule(asset)
    assert (rule.id if rule else None) == expected


def test_rsa_rule_does_not_claim_other_languages() -> None:
    """Same guard, on the other unguarded rule — RSA key transport outside Python."""
    from qubit_migrate.transform import match_rule

    def rsa_at(path: str) -> str | None:
        asset = CryptoAsset(
            algorithm="RSA-1024",
            usage_context=UsageContext.kex,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path=path, line=7),
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
            discovered_at=utcnow(),
        )
        rule = match_rule(asset)
        return rule.id if rule else None

    assert rsa_at("app/keys.py") == "py-rsa-kex-01"
    # .go/.java/.js/.c have their own multi-language kex rule.
    assert rsa_at("svc/keys.go") == "code-kex-01"
    # These have neither, and must resolve to nothing rather than to the Python rule.
    for path in ("app/billing.rb", "src/seal.rs", "src/Wallet.swift", "bin/provision.sh"):
        assert rsa_at(path) is None, path


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
