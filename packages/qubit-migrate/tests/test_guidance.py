"""Guided remediation: the outcome that replaced the dead end.

Before this, a finding QUBIT could not patch reached the queue as "manual change" or "no migration
rule matches this asset", and the only way to get anything more was a model call that failed
outright when Ollama was not running. Three properties matter and are asserted here:

* the plan is built from SHIPPED DATA, so it exists offline;
* it says what to do, not that QUBIT will not do it;
* where automation is genuinely impossible, it says so and names what is possible instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_core import (
    AssetType,
    CryptoAsset,
    Evidence,
    EvidenceContext,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.playbook import load_playbook
from qubit_migrate.transform.guidance import build_guided_plan
from qubit_migrate.transform.rules import load_rules, match_rule


def _asset(
    algorithm: str,
    usage: UsageContext,
    path: str,
    *,
    scanner: SourceScanner = SourceScanner.code,
    asset_type: AssetType = AssetType.algorithm_use,
    attack: QuantumAttack = QuantumAttack.shor,
    key_size: int | None = None,
    weaknesses: list[dict] | None = None,
    library: str | None = None,
) -> CryptoAsset:
    from qubit_core import LibraryRef

    return CryptoAsset(
        algorithm=algorithm,
        key_size=key_size,
        usage_context=usage,
        source_scanner=scanner,
        asset_type=asset_type,
        location=Location(file_path=path, line=12),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=attack),
        discovered_at=utcnow(),
        library=LibraryRef(name=library) if library else None,
        evidence=Evidence(
            snippet="",
            context=EvidenceContext(extra={"weaknesses": weaknesses} if weaknesses else {}),
        ),
    )


def _plan_for(asset: CryptoAsset):
    return build_guided_plan(asset, match_rule(asset, load_rules()))


# --- the plan is always substantive -----------------------------------------------------------


@pytest.mark.parametrize(
    ("algorithm", "usage", "path", "scanner"),
    [
        ("RSA-2048", UsageContext.signature, "certs/edge.pem", SourceScanner.cert),
        ("ECDSA-P256", UsageContext.signature, "Package.swift", SourceScanner.config),
        ("RSA", UsageContext.kex, "pubspec.yaml", SourceScanner.config),
        ("RSA-1024", UsageContext.kex, "bin/provision.sh", SourceScanner.code),
        ("MD5", UsageContext.hash, "requirements.txt", SourceScanner.config),
        ("RSA-2048", UsageContext.kex, "app/handler.erl", SourceScanner.code),
    ],
)
def test_every_finding_gets_steps_and_never_a_shrug(
    algorithm: str, usage: UsageContext, path: str, scanner: SourceScanner
) -> None:
    plan = _plan_for(_asset(algorithm, usage, path, scanner=scanner))
    assert plan.headline, "a plan with no headline is a blank panel"
    assert plan.steps, f"{path} produced a plan with no steps"
    assert all(s.title for s in plan.steps)
    rendered = plan.to_markdown()
    assert "### Steps" in rendered
    # The words the product must never fall back to.
    for phrase in ("manual change", "nothing we can do", "not supported"):
        assert phrase not in rendered.lower(), f"{path} guidance still says {phrase!r}"


def test_the_plan_needs_no_model_and_no_network() -> None:
    """Built from the rule pack, knowledge base and playbook - all shipped files.

    Asserted by construction: `build_guided_plan` takes no model, no base URL and no session, so
    there is nothing for it to call. This pins that signature.
    """
    import inspect

    params = set(inspect.signature(build_guided_plan).parameters)
    assert params == {"asset", "rule", "failure_reason", "playbook"}, params


# --- certificates -----------------------------------------------------------------------------


def test_a_certificate_gets_re_issuance_steps_not_an_edit() -> None:
    plan = _plan_for(
        _asset("RSA-2048", UsageContext.signature, "certs/edge.pem", scanner=SourceScanner.cert)
    )
    assert "signed object" in plan.honest_note, "the reason no patch exists must be stated"
    text = plan.to_markdown()
    assert "openssl genpkey -algorithm ML-DSA-65" in text, "no concrete command to run"
    assert "X25519MLKEM768" in text, (
        "the certificate is the less urgent half; the KEX change is what protects recorded traffic"
    )
    assert any("Confirm" in s.title for s in plan.steps)


# --- ecosystems with and without a provider ----------------------------------------------------


def test_swift_now_resolves_to_apples_own_package() -> None:
    """An earlier pass of this project concluded Swift had no PQC provider. It was wrong.

    swift-crypto's released 4.5.1 tag carries MLKEM.swift, MLDSA.swift and XWing.swift; the 4.5.x
    release notes do not mention post-quantum at all, which is why a changelog search says
    otherwise. The guided path has to carry the fact AND the reason the fact is easy to miss.
    """
    plan = _plan_for(
        _asset("ECDSA-P256", UsageContext.signature, "Package.swift", scanner=SourceScanner.config)
    )
    text = plan.to_markdown()
    assert "swift-crypto" in text
    assert "4.5.1" in text
    assert "release notes" in text, "the reason this provider is easy to miss must be stated"


def test_dart_says_no_and_says_what_is_possible_instead() -> None:
    plan = _plan_for(_asset("RSA", UsageContext.kex, "pubspec.yaml", scanner=SourceScanner.config))
    assert plan.honest_note, "an ecosystem with no provider must say so"
    assert "unverified" in plan.honest_note.lower()
    options = [s for s in plan.steps if s.title.startswith("Option")]
    assert len(options) >= 2, "refusing to install something is only half an answer"
    assert any("FFI" in s.detail for s in options)
    # The refusal must be checkable, not an assertion of taste.
    assert any("pub.dev" in s for s in plan.sources)


def test_a_non_pqc_target_does_not_raise_a_pqc_provider_blocker() -> None:
    """An MD5 finding in a pubspec.yaml was answered with Dart's missing-ML-KEM notice.

    Three options about FFI and platform crypto, for a digest that migrates to SHA3-256 using
    facilities the language has shipped for years. Naming a blocker that does not apply is its own
    kind of dead end.
    """
    plan = _plan_for(
        _asset(
            "MD5",
            UsageContext.hash,
            "pubspec.yaml",
            scanner=SourceScanner.config,
            attack=QuantumAttack.grover,
            library="crypto",
        )
    )
    assert "unverified" not in plan.honest_note.lower()
    assert not [s for s in plan.steps if s.title.startswith("Option")]
    assert any("call sites" in s.detail for s in plan.steps), (
        "a manifest records a capability, not a call - the plan has to say where the fix lives"
    )


# --- sourcing ---------------------------------------------------------------------------------


def test_sources_are_scoped_to_the_target() -> None:
    """Citing FIPS 203 under an MD5-to-SHA3 recommendation is noise.

    The reader checks the source, finds it says nothing about hashes, and trusts the next citation
    less. This is the guard against exactly that.
    """
    hashes = _plan_for(
        _asset(
            "MD5",
            UsageContext.hash,
            "requirements.txt",
            scanner=SourceScanner.config,
            attack=QuantumAttack.grover,
        )
    )
    assert not any("FIPS 203" in s for s in hashes.sources), hashes.sources

    kex = _plan_for(_asset("RSA", UsageContext.kex, "Cargo.toml", scanner=SourceScanner.config))
    assert any("IR 8547" in s for s in kex.sources), kex.sources


def test_shor_findings_carry_the_deprecation_timeline() -> None:
    plan = _plan_for(_asset("RSA-2048", UsageContext.kex, "svc/seal.go"))
    assert "2030" in plan.why and "2035" in plan.why
    assert "harvest-now-decrypt-later" in plan.why, (
        "a key-exchange finding is exposed today, not in 2030, and the plan has to say why"
    )


def test_a_weakness_brings_its_authority_into_the_sources() -> None:
    plan = _plan_for(
        _asset(
            "AES-256",
            UsageContext.encryption_at_rest,
            "hr/vault.py",
            attack=QuantumAttack.none,
            key_size=256,
            weaknesses=[
                {
                    "id": "ecb-mode",
                    "title": "Block cipher used in ECB mode",
                    "cwe": "CWE-327",
                    "authority": "NIST SP 800-38A Appendix A",
                    "remedy": "Encrypt with an AEAD mode.",
                }
            ],
        )
    )
    assert any("800-38A" in s for s in plan.sources)
    assert "CWE-327" in plan.why


# --- the playbook itself ----------------------------------------------------------------------


def test_every_provider_records_how_and_when_it_was_verified() -> None:
    """A version floor with no provenance is a number somebody remembered.

    This project has already shipped one of those: an npm package called `ml-kem` that does not
    exist, carried forward from a note whose real subject was the crates.io crate of that name.
    """
    for key, provider in load_playbook().providers.items():
        assert provider.verified_on, f"{key} has no verification date"
        assert provider.source, f"{key} does not say which registry answered"
        assert provider.adoption, f"{key} has no adoption figure"
        assert provider.constraint, f"{key} has no version constraint"


def test_every_unavailable_ecosystem_offers_options_and_cites_its_refusal() -> None:
    for key, entry in load_playbook().unavailable.items():
        assert entry.options, f"{key} refuses without offering an alternative"
        assert entry.sources, f"{key} refuses without evidence"
        assert len(entry.reason.split()) >= 25, f"{key} reason is too thin to act on"


def test_the_playbook_ships_inside_the_package() -> None:
    """It is data the installed app reads, not a document in the repository root."""
    from qubit_migrate.playbook import PLAYBOOK_PATH

    assert PLAYBOOK_PATH.is_file()
    assert PLAYBOOK_PATH.parent.name == "params"
    assert Path(PLAYBOOK_PATH).read_text(encoding="utf-8").startswith("schema: qubit-playbook/v1")


def test_a_hardcoded_secret_gets_the_rotation_procedure() -> None:
    """The most urgent finding in any inventory, and it had no entry in the queue at all.

    A key committed to a repository is compromised today by anyone with read access - it is not
    quantum-vulnerable in any interesting sense, which is exactly why the plan's
    `qv_vulnerable` filter excluded it. Removing the literal is the smallest part of the fix.
    """
    plan = _plan_for(
        _asset(
            "Hardcoded password/secret",
            UsageContext.unknown,
            "atlas/settings.py",
            asset_type=AssetType.secret,
            attack=QuantumAttack.none,
        )
    )
    text = plan.to_markdown()
    assert "Rotate at the issuer first" in text, "deleting the line is not the remediation"
    assert "git filter-repo" in text, "the value survives in history until it is rewritten"
    assert "live credential" in plan.honest_note


def test_every_rule_reaches_a_defined_outcome() -> None:
    """No rule may exist that can neither produce a patch nor explain itself.

    The three legitimate shapes are: a deterministic codemod, an LLM rewrite with worked examples
    and constraints, or a guided path with a written remediation. A rule that is none of those is
    a finding that matches something and then stops - which is the dead end this whole change set
    exists to remove, reintroduced one rule at a time.
    """
    load_rules.cache_clear()
    broken = []
    for rule in load_rules():
        if rule.remediation == "guided":
            if len(rule.semantic_note.split()) < 40:
                broken.append(f"{rule.id}: guided with no substantive explanation")
        elif rule.codemod:
            continue
        elif not rule.example:
            broken.append(f"{rule.id}: LLM rule with no worked example")
    assert not broken, broken


def test_a_file_that_already_meets_the_rule_is_not_sent_to_the_model(tmp_path, monkeypatch) -> None:
    """The rescan verifier is the rule's own definition of "migrated". Ask it first.

    On a partially-migrated codebase the model was handed files that were already correct:
    `code-weakcipher-01` matches bare `AES`, and a file rewritten to AES-256-GCM still reports
    bare `AES`, because the key length lives in the key variable and not in the call. The model
    returned the file unchanged - which was right - and the engine called that a rejection, tried
    twice more, and recorded a failure. Three model calls to arrive at "already done".
    """
    from qubit_core.db import Base, ProjectRow, ScanRow, session_factory
    from qubit_core.mapping import asset_to_row
    from qubit_migrate.orchestrator import (
        RESOLUTION_SATISFIED,
        AlreadySatisfied,
        MigrationOrchestrator,
    )
    from qubit_migrate.state import MigrationTask
    from qubit_migrate.transform import llm
    from sqlalchemy import create_engine

    def must_not_be_called(*args: object, **kwargs: object) -> str:
        raise AssertionError("a file that already meets the rule must not reach the model")

    monkeypatch.setattr(llm, "_ollama_generate", must_not_be_called)

    src = tmp_path / "seal.go"
    src.write_text(
        "package main\n\n"
        'import (\n\t"crypto/aes"\n\t"crypto/cipher"\n\t"crypto/rand"\n)\n\n'
        "func seal(key, pt []byte) ([]byte, error) {\n"
        "\tblock, err := aes.NewCipher(key)\n"
        "\tif err != nil {\n\t\treturn nil, err\n\t}\n"
        "\taead, err := cipher.NewGCM(block)\n"
        "\tif err != nil {\n\t\treturn nil, err\n\t}\n"
        "\tnonce := make([]byte, aead.NonceSize())\n"
        "\tif _, err := rand.Read(nonce); err != nil {\n\t\treturn nil, err\n\t}\n"
        "\treturn aead.Seal(nonce, nonce, pt, nil), nil\n}\n",
        encoding="utf-8",
    )

    engine = create_engine(f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    Base.metadata.create_all(engine)
    sf = session_factory(engine)
    with sf() as session:
        project = ProjectRow(name="t", slug="t")
        session.add(project)
        session.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        session.add(scan)
        session.flush()
        asset = _asset(
            "AES",
            UsageContext.encryption_at_rest,
            str(src),
            attack=QuantumAttack.grover,
        )
        from qubit_core.schemas import RiskAnnotation

        asset.risk = RiskAnnotation(
            score=0.4, ci_low=0.3, ci_high=0.5, mosca_margin_years=1.0, priority_rank=1
        )
        session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
        session.commit()

        orch = MigrationOrchestrator(session)
        plan = orch.build_plan()
        queue = orch.get_queue(plan.id)
        assert queue, "fixture must produce a task"
        task_id = queue[0].id

        with pytest.raises(AlreadySatisfied) as excinfo:
            orch.generate_patch(task_id, generator="llm")
        assert "already meets" in str(excinfo.value)

        task = session.get(MigrationTask, task_id)
        assert task is not None and task.resolution == RESOLUTION_SATISFIED
