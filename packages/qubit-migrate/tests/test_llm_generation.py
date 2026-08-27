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
from qubit_migrate.transform.validate import StageResult, ValidationReport
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
        # Python keeps its own precise libcst rules — a token swap cannot take the argon2id
        # password path, which py-weakhash-01 can.
        ("app/hash.py", "py-weakhash-01"),
        # The six original languages.
        ("svc/hash.go", "code-weakhash-02"),
        ("src/Main.java", "code-weakhash-02"),
        ("web/util.js", "code-weakhash-02"),
        ("web/util.ts", "code-weakhash-02"),
        ("lib/digest.c", "code-weakhash-02"),
        ("lib/digest.cpp", "code-weakhash-02"),
        # .tsx and .cjs were in every other code-* rule's suffix list but not this one, so a React
        # component fell through to the Python rule despite the JS/TS swap covering it.
        ("web/Component.tsx", "code-weakhash-02"),
        ("web/legacy.cjs", "code-weakhash-02"),
        # The thirteen languages added when code scanning grew from 6 grammars to 19. Each now has
        # a real swap table (codemods._HASH_SWAPS), so each resolves to the cross-language rule.
        ("app/billing.rb", "code-weakhash-02"),
        ("app/legacy.php", "code-weakhash-02"),
        ("src/Vault.cs", "code-weakhash-02"),
        ("src/seal.rs", "code-weakhash-02"),
        ("src/Crypto.kt", "code-weakhash-02"),
        ("src/Wallet.swift", "code-weakhash-02"),
        ("src/Ledger.scala", "code-weakhash-02"),
        ("lib/fleet.dart", "code-weakhash-02"),
        ("bin/provision.sh", "code-weakhash-02"),
        ("bin/Provision.ps1", "code-weakhash-02"),
        ("migrations/V3__hash.sql", "code-weakhash-02"),
    ],
)
def test_weak_hash_resolves_to_a_language_appropriate_rule(path: str, expected: str) -> None:
    """Every language the scanner reads must resolve to a rule, and never to another language's.

    Two things are pinned here at once, because they failed in opposite directions.

    ``py-rsa-kex-01`` and ``py-weakhash-01`` were the only rules naming a language without also
    constraining the file suffix, so they matched ``source_scanner=code`` assets in every language.
    Once code scanning grew from 6 grammars to 19 that meant 34 of the 127 tasks in the polyglot
    demo project were offered a libcst **Python** codemod for a .rb, .php, .cs, .rs, .kt, .swift,
    .scala, .dart, .sh, .ps1 or .sql file. The template generator refused with a 422 after the
    click; the LLM generator would have used Python-specific prompt constraints and produced a
    plausible, wrong patch.

    The opposite failure is a language resolving to **nothing**, which is what adding the ``.py``
    guard produced until the cross-language rule and its swap tables were extended to cover the
    thirteen new languages. A finding with no rule cannot be migrated from the app at all.
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
    assert rule is not None, f"{path} resolves to no rule, so it cannot be migrated from the app"
    assert rule.id == expected
    if not path.endswith(".py"):
        assert not rule.id.startswith("py-"), f"a Python rule claimed {path}"


def test_rsa_kex_resolves_per_language() -> None:
    """The same guard on the other rule that was missing it — RSA key transport outside Python."""
    from qubit_migrate.transform import match_rule
    from qubit_migrate.transform.rules import load_rules

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
    for path in (
        "svc/keys.go",
        "app/billing.rb",
        "src/seal.rs",
        "src/Wallet.swift",
        "src/Vault.cs",
    ):
        assert rsa_at(path) == "code-kex-01", path

    # Shell, PowerShell and SQL must never reach the MODEL. `openssl genrsa` and
    # `ssh-keygen -t rsa` have no ML-KEM equivalent to be rewritten into: the post-quantum answer
    # for SSH is a KexAlgorithms config change, which cfg-ssh-01 makes against sshd_config.
    # Claiming them for an LLM rewrite spent three local-model attempts per finding on something
    # the tooling cannot express; measured on the polyglot corpus, the model correctly returned
    # the file unchanged every time.
    #
    # They used to match NO rule at all, which kept them away from the model at the cost of
    # leaving them with no answer either. `code-shell-01` gives the same protection with a
    # result: a guided path naming the config change. So the property under test is "never
    # generated", not "never matched".
    for path in ("bin/provision.sh", "bin/Provision.ps1", "migrations/V3__keys.sql"):
        matched_id = rsa_at(path)
        if matched_id is not None:
            rule = next(r for r in load_rules() if r.id == matched_id)
            assert rule.remediation == "guided", (
                f"{path} must never be sent to the model; it matched {matched_id}"
            )


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
        lambda prompt, *, model, base_url="x", timeout=0, **_: "```python\n" + REWRITTEN + "```",
    )
    patch = orch.generate_patch(task.id, generator="llm")
    assert patch.generator == "llm"
    assert patch.model_name == orch.config.model
    assert "sha256" in patch.diff_text
    assert patch.status == "proposed", patch.validation_json


def test_llm_failure_fails_task_cleanly(tmp_path, monkeypatch) -> None:
    orch, task = _seeded_orchestrator(tmp_path)

    def boom(prompt, *, model, base_url="x", timeout=0, **_):
        raise OllamaError("server down")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", boom)
    with pytest.raises(ValueError, match="LLM generation failed"):
        orch.generate_patch(task.id, generator="llm")


def test_llm_validation_failure_fails_task_cleanly(tmp_path, monkeypatch) -> None:
    """A patch that the MODEL returns successfully but that fails the validation gate must still
    park the task as `deferred`/`unresolved` with a `last_error`, exactly like a transport failure
    does above — not silently leave both fields `None` forever.

    Found live on a real OpenSSL migration: a `code-weakhash-02` patch's ``applies`` stage failed
    because an earlier task had already rewritten the same file, shifting the context lines this
    diff was built against. `generate_patch`'s ``else`` branch (patch produced, validation failed)
    called bare `_transition(task, "generators_exhausted", ...)` instead of `_fail_task`, so
    `task.resolution` stayed NULL — neither retryable (the bulk-retry query selects only
    `unresolved`) nor countable as handled (the Migration Hub's progress split reads the same
    field). This reproduces that exact shape without needing a second colliding task: the LLM call
    succeeds and returns real content, but `validate_patch` is patched to report a failing
    ``applies`` stage, which is what any genuinely-failing validation looks like from
    `generate_patch`'s point of view.
    """
    orch, task = _seeded_orchestrator(tmp_path)

    monkeypatch.setattr(
        "qubit_migrate.transform.llm._ollama_generate",
        lambda prompt, *, model, base_url="x", timeout=0, **_: "```python\n" + REWRITTEN + "```",
    )

    failing_report = ValidationReport(
        stages={
            "applies": StageResult(
                "fail", "patch does not apply: context lines already changed by an earlier task"
            )
        },
        passed=False,
    )
    monkeypatch.setattr(
        "qubit_migrate.orchestrator.validate_patch", lambda *args, **kwargs: failing_report
    )

    patch = orch.generate_patch(task.id, generator="llm")

    assert patch.status == "failed"
    orch.session.refresh(task)
    assert task.state == "deferred"
    assert task.resolution == "unresolved"
    assert task.last_error is not None
    assert "applies failed" in task.last_error
    assert "context lines already changed" in task.last_error


def test_a_failed_task_can_be_generated_for_again_without_a_manual_resume(
    tmp_path, monkeypatch
) -> None:
    """A single retry click must not require the caller to know about `resume_task`.

    `generate_patch`'s own FSM transition (`ready -> generating`) has no `generate` event from
    `deferred`, the state a failed task parks in - so calling it again on the SAME task, exactly
    as a user clicking "Retry" on that row does, used to raise `InvalidTransition`. The API mapped
    that to a 409 saying "this task already has a generated patch, review or reject it", which is
    false: the task has no patch at all, only a rejection. `generate_patch` now resumes a
    `deferred`/`unresolved` task itself before generating, so the exact same call that starts a
    fresh migration also retries a failed one.
    """
    orch, task = _seeded_orchestrator(tmp_path)

    def boom(prompt, *, model, base_url="x", timeout=0, **_):
        raise OllamaError("server down")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", boom)
    with pytest.raises(ValueError, match="LLM generation failed"):
        orch.generate_patch(task.id, generator="llm")

    from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED

    orch.session.refresh(task)
    assert task.state == "deferred"
    assert task.resolution == RESOLUTION_UNRESOLVED

    # The engine (or the code) has since improved - the retry now succeeds. No InvalidTransition,
    # and no manual `resume_task` call in this test: the retry path handles that itself.
    monkeypatch.setattr(
        "qubit_migrate.transform.llm._ollama_generate",
        lambda prompt, *, model, base_url="x", timeout=0, **_: "```python\n" + REWRITTEN + "```",
    )
    patch = orch.generate_patch(task.id, generator="llm")
    assert patch.status == "proposed", patch.validation_json
    assert "sha256" in patch.diff_text


def test_auto_prefers_template_when_codemod_exists(tmp_path, monkeypatch) -> None:
    orch, task = _seeded_orchestrator(tmp_path)

    def never(prompt, **kw):  # pragma: no cover - would fail the test if called
        raise AssertionError("LLM must not be called when a codemod exists (auto)")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", never)
    patch = orch.generate_patch(task.id, generator="auto")
    assert patch.generator == "template"
    assert patch.model_name is None


# ── security reasoning ────────────────────────────────────────────────────────
# A diff alone does not tell a reviewer whether the model understood the migration or
# pattern-matched it. The prompt asks for the reasoning; these pin that it is captured from the
# ACCEPTED attempt, never fabricated, and never fatal when absent.

REWRITE_WITH_NOTES = (
    "```python\n" + REWRITTEN + "```\n"
    "SECURITY NOTES:\n"
    "- Replaced MD5 with SHA-256; MD5 offers no collision resistance.\n"
    "- Callers storing a 32-char digest must widen to 64.\n"
)


def test_security_notes_are_extracted_from_after_the_fence() -> None:
    from qubit_migrate.transform.llm import extract_security_notes

    notes = extract_security_notes(REWRITE_WITH_NOTES)
    assert "Replaced MD5 with SHA-256" in notes
    assert "widen to 64" in notes
    assert "```" not in notes, "the code fence must never leak into the reasoning"


def test_security_notes_absent_is_not_an_error() -> None:
    """A perfect rewrite that forgets the heading is still a good patch."""
    from qubit_migrate.transform.llm import extract_security_notes

    assert extract_security_notes("```python\n" + REWRITTEN + "```") == ""


def test_security_notes_inside_the_fence_are_ignored() -> None:
    """Prose inside the fence is a defect the rewrite guards catch, not reasoning to display."""
    from qubit_migrate.transform.llm import extract_security_notes

    assert extract_security_notes("```\nSECURITY NOTES: this is code, not commentary\n```") == ""


def test_orchestrator_stores_the_reasoning_beside_the_validation_record(tmp_path, monkeypatch):
    orch, task = _seeded_orchestrator(tmp_path)
    monkeypatch.setattr(
        "qubit_migrate.transform.llm._ollama_generate",
        lambda prompt, *, model, base_url="x", timeout=0, **_: REWRITE_WITH_NOTES,
    )
    patch = orch.generate_patch(task.id, generator="llm")
    assert patch.status == "proposed", patch.validation_json
    assert "Replaced MD5 with SHA-256" in patch.validation_json["security_notes"]


def test_prompt_asks_for_reasoning_after_the_fence(tmp_path, monkeypatch) -> None:
    """The instruction has to survive prompt edits, or the reasoning silently stops arriving."""
    orch, task = _seeded_orchestrator(tmp_path)
    prompts: list[str] = []

    def capture(prompt, *, model, base_url="x", timeout=0, **_):
        prompts.append(prompt)
        return REWRITE_WITH_NOTES

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", capture)
    orch.generate_patch(task.id, generator="llm")
    # The first prompt is now the PLAN for a structural rule, which asks for prose and not
    # for a file. The generation prompt is the one that has to demand the reasoning.
    generation = next(p for p in prompts if "Rewrite the file below" in p)
    assert "SECURITY NOTES:" in generation
    assert "AFTER the closing fence" in generation
