"""Learned-patch store (transform/learn.py + its orchestrator wiring).

Two behaviours are pinned here, and they are different:

* **exact reuse** — an identical flagged line is answered from the store with NO model call;
* **experience grounding** — a *different* line under the same rule still gets the earlier,
  already-validated fix replayed into its prompt.

The second matters more in practice. Measured on the 21-app demo corpus, exact reuse fired 0 times
across 250 findings — real code in 11 languages almost never repeats a line byte-for-byte — while
17 validated fixes were recorded and were available as grounding. A test suite that only covered
the cache would have reported a working feature that never fires.
"""

from __future__ import annotations

from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.db.models import LearnedPatch
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
from qubit_migrate.transform import learn
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

REWRITTEN = "import hashlib\ndigest = hashlib.sha256(data)\n"


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_lookup_returns_none_when_nothing_learned_yet() -> None:
    s = _session()
    assert learn.lookup(s, rule_id="py-weakhash-01", orig="x = 1\n", line=1) is None


def test_record_then_lookup_then_apply_round_trips() -> None:
    s = _session()
    orig = "a = 1\ndigest = hashlib.md5(data)\nb = 2\n"
    new = "a = 1\ndigest = hashlib.sha256(data)\nb = 2\n"
    learn.record(
        s,
        rule_id="py-weakhash-01",
        language="python",
        algorithm="MD5",
        orig=orig,
        new=new,
        line=2,
        model_name="qwen2.5-coder:7b-instruct-q4_K_M",
    )
    s.commit()

    found = learn.lookup(s, rule_id="py-weakhash-01", orig=orig, line=2)
    assert found is not None
    assert found.hit_count == 0

    result = learn.apply(orig, 2, found)
    assert result is not None
    assert result.new_source == new

    learn.touch(s, found)
    s.commit()
    assert found.hit_count == 1
    assert found.last_used_at is not None


def test_apply_preserves_the_new_files_own_indentation() -> None:
    """A fix learned at column 0 must not flatten the indentation of the file it lands in."""
    s = _session()
    learn.record(
        s,
        rule_id="py-weakhash-01",
        language="python",
        algorithm="MD5",
        orig="digest = hashlib.md5(data)\n",
        new="digest = hashlib.sha256(data)\n",
        line=1,
        model_name="m",
    )
    s.commit()
    learned = learn.lookup(s, rule_id="py-weakhash-01", orig="digest = hashlib.md5(data)\n", line=1)
    assert learned is not None

    indented = "if True:\n    digest = hashlib.md5(data)\n"
    result = learn.apply(indented, 2, learned)
    assert result is not None
    assert result.new_source == "if True:\n    digest = hashlib.sha256(data)\n"


def test_apply_returns_none_when_the_line_has_drifted() -> None:
    """A near-miss must fall through to a real generation, not be force-fitted."""
    s = _session()
    learn.record(
        s,
        rule_id="py-weakhash-01",
        language="python",
        algorithm="MD5",
        orig="digest = hashlib.md5(data)\n",
        new="digest = hashlib.sha256(data)\n",
        line=1,
        model_name="m",
    )
    s.commit()
    learned = learn.lookup(s, rule_id="py-weakhash-01", orig="digest = hashlib.md5(data)\n", line=1)
    assert learned is not None
    assert learn.apply("digest = hashlib.md5(other_data)\n", 1, learned) is None


def test_record_is_idempotent_for_the_same_rule_and_line() -> None:
    s = _session()
    kwargs = {
        "rule_id": "py-weakhash-01",
        "language": "python",
        "algorithm": "MD5",
        "orig": "digest = hashlib.md5(data)\n",
        "new": "digest = hashlib.sha256(data)\n",
        "line": 1,
        "model_name": "m",
    }
    learn.record(s, **kwargs)  # type: ignore[arg-type]
    learn.record(s, **kwargs)  # type: ignore[arg-type]
    s.commit()
    assert s.query(LearnedPatch).count() == 1


def test_record_skips_a_whole_file_restructure() -> None:
    """No safe single-line snippet exists when the line count changed, so nothing is stored.

    Storing one anyway would produce an entry that corrupts the next file it is replayed onto.
    """
    s = _session()
    learn.record(
        s,
        rule_id="py-rsa-kex-01",
        language="python",
        algorithm="RSA-2048",
        orig="a = 1\nrsa_encrypt(x)\n",
        new="a = 1\nss = mlkem_encapsulate(pk)\naes_gcm_seal(ss, x)\n",
        line=2,
        model_name="m",
    )
    s.commit()
    assert s.query(LearnedPatch).count() == 0


def test_experience_is_scoped_to_the_files_language() -> None:
    """A cross-language rule must not ground a Rust file in a Go fix.

    `llm._worked_examples` documents the measured cost of exactly this: the 7B model returned the
    example's language verbatim for 3 of 4 files.
    """
    s = _session()
    for lang, before, after in (
        ("go", "h := md5.New()", "h := sha256.New()"),
        ("rust", "let mut h = Md5::new();", "let mut h = Sha256::new();"),
    ):
        learn.record(
            s,
            rule_id="code-weakhash-02",
            language=lang,
            algorithm="MD5",
            orig=f"x\n{before}\n",
            new=f"x\n{after}\n",
            line=2,
            model_name="m",
        )
    s.commit()

    rust = learn.get_experience_for_rule(s, "code-weakhash-02", "rust")
    assert rust == [("let mut h = Md5::new();", "let mut h = Sha256::new();")]
    go = learn.get_experience_for_rule(s, "code-weakhash-02", "go")
    assert go == [("h := md5.New()", "h := sha256.New()")]


def test_experience_ranks_proven_fixes_first() -> None:
    s = _session()
    for i in (1, 2):
        learn.record(
            s,
            rule_id="code-weakhash-02",
            language="go",
            algorithm="MD5",
            orig=f"x\nvar{i} := md5.New()\n",
            new=f"x\nvar{i} := sha256.New()\n",
            line=2,
            model_name="m",
        )
    s.commit()
    rows = s.query(LearnedPatch).order_by(LearnedPatch.snippet_before).all()
    learn.touch(s, rows[1])  # var2 has now been reused once
    s.commit()

    ranked = learn.get_experience_for_rule(s, "code-weakhash-02", "go", limit=2)
    assert ranked[0][0] == rows[1].snippet_before, "the reused fix should rank first"


# --------------------------------------------------------------------------------------------
# Orchestrator wiring
# --------------------------------------------------------------------------------------------


def _seed(tmp_path, files: dict[str, str]) -> tuple:
    """One project, one plan, one task per file, each flagged on line 2."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()

    paths = []
    for filename, content in files.items():
        src = tmp_path / filename
        src.write_text(content, encoding="utf-8")
        paths.append(str(src))
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
    queue = orch.get_queue(plan.id)
    assert len(queue) == len(files)
    by_path = {}
    for t in queue:
        loaded = orch._load_asset(t.asset_id)
        assert loaded is not None and loaded.location is not None
        by_path[loaded.location.file_path] = t
    return (orch, *[by_path[p] for p in paths])


def test_second_identical_finding_skips_the_model(tmp_path, monkeypatch) -> None:
    body = "import hashlib\ndigest = hashlib.md5(data)\n"
    orch, task1, task2 = _seed(tmp_path, {"app1.py": body, "app2.py": body})

    calls = {"n": 0}

    def fake(prompt, *, model, base_url="x", timeout=0, **_):
        if "Before writing any code, plan the change" in prompt:
            return "1. Swap the digest.\n2. Nothing new.\n3. Nothing.\n4. Nothing.\n5. Names."
        # The self-review pass calls the same server a second time. It is not a
        # GENERATION, and counting it here would assert something this test does
        # not care about.
        if "You are reviewing a cryptographic migration patch" in prompt:
            return "VERDICT: OK"
        calls["n"] += 1
        return "```python\n" + REWRITTEN + "```"

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", fake)

    patch1 = orch.generate_patch(task1.id, generator="llm")
    assert patch1.status == "proposed", patch1.validation_json
    assert patch1.model_name == orch.config.model
    assert calls["n"] == 1

    rows = orch.session.query(LearnedPatch).all()
    assert len(rows) == 1 and rows[0].hit_count == 0

    def must_not_be_called(prompt, *, model, base_url="x", timeout=0, **_):
        if "Before writing any code, plan the change" in prompt:
            return "1. Swap the digest.\n2. Nothing new.\n3. Nothing.\n4. Nothing.\n5. Names."
        if "You are reviewing a cryptographic migration patch" in prompt:
            return "VERDICT: OK"
        raise AssertionError("an identical finding must be served from the store")

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", must_not_be_called)

    patch2 = orch.generate_patch(task2.id, generator="llm")
    assert patch2.status == "proposed", patch2.validation_json
    assert patch2.model_name is not None and patch2.model_name.startswith("cache:")
    assert calls["n"] == 1  # still just the one real model call

    orch.session.refresh(rows[0])
    assert rows[0].hit_count == 1


def test_a_different_finding_is_grounded_in_the_earlier_fix(tmp_path, monkeypatch) -> None:
    """The path that actually fires on real code: no exact match, but real grounding."""
    orch, task1, task2 = _seed(
        tmp_path,
        {
            "app1.py": "import hashlib\ndigest = hashlib.md5(data)\n",
            "app2.py": "import hashlib\nchecksum = hashlib.md5(payload)\n",
        },
    )

    prompts: list[str] = []
    outputs = iter(
        [
            "```python\nimport hashlib\ndigest = hashlib.sha256(data)\n```",
            "```python\nimport hashlib\nchecksum = hashlib.sha256(payload)\n```",
        ]
    )

    def fake(prompt, *, model, base_url="x", timeout=0, **_):
        if "Before writing any code, plan the change" in prompt:
            return "1. Swap the digest.\n2. Nothing new.\n3. Nothing.\n4. Nothing.\n5. Names."
        if "You are reviewing a cryptographic migration patch" in prompt:
            return "VERDICT: OK"
        prompts.append(prompt)
        return next(outputs)

    monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", fake)

    assert orch.generate_patch(task1.id, generator="llm").status == "proposed"
    patch2 = orch.generate_patch(task2.id, generator="llm")
    assert patch2.status == "proposed", patch2.validation_json
    # A genuine second generation, NOT a cache hit — the flagged lines differ.
    assert patch2.model_name == orch.config.model

    assert len(prompts) == 2
    # The two findings differ only in their variable names, so the SHAPE key matches even though
    # the exact-line cache does not - which is the whole reason the experience base exists. The
    # second prompt is grounded in a rewrite QUBIT has already had validated.
    assert "Verified patch 1" not in prompts[0], "nothing was learned yet on the first call"
    assert "Verified patch 1" in prompts[1], "the second call must be grounded in the first fix"
    assert "already migrated code of EXACTLY this shape" in prompts[1], (
        "a structurally identical rewrite is the strongest grounding there is and must say so"
    )
    assert "digest = hashlib.md5(data)" in prompts[1]
    assert "digest = hashlib.sha256(data)" in prompts[1]
