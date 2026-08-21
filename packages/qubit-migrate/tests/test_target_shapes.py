"""The generator must be told what the checker will accept — in the right language.

A patch is kept only if the rescan DETECTS the rule's target algorithm in the rewritten file, and
nothing told the generator what that looked like. It was read as the local model being too small
for a structural post-quantum rewrite. It was not:

    `code-kex-01` carries per-language API guidance ("Go: use crypto/mlkem ... GenerateKey768()")
    and claims 21 file suffixes. Nothing scoped those lines to their language, so a `.rs` file's
    only concrete instruction was Go's. The model followed it exactly and emitted
    `mlkem::GenerateKey768(&mut rng)` in Rust, where no such crate exists — undetectable, so the
    rescan reported the target missing and the task failed all three attempts.

Measured after the fix, same model and machine: that case is accepted on the first attempt. These
tests pin the behaviours that made it possible — constraints scoped to the file's language, a
target shape taken from the scanner's own rules, and feedback that matches which expectation
actually failed rather than assuming.

The last class pins a correction: inferring "this language is unwinnable" from the absence of a
shipped shape was wrong, and gating on it cost two tasks that had been passing.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.transform import target_shapes as ts
from qubit_migrate.transform.llm import (
    _build_prompt,
    _scoped_constraints,
    present_prefixes,
    unverifiable_reason,
)
from qubit_migrate.transform.rules import load_rules, match_rule
from qubit_migrate.transform.validate import _stage_rescan

RUST_SOURCE = (
    "use openssl::rsa::Rsa;\n"
    "use rsa::RsaPrivateKey;\n"
    "\n"
    "pub fn issue() {\n"
    "    let a = Rsa::generate(1024).unwrap();\n"
    "    let _ = a;\n"
    "}\n"
)


def _asset(path: str, algorithm: str = "RSA-1024") -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=UsageContext.kex,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=5),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        evidence=Evidence(),
        discovered_at=utcnow(),
    )


def _kex_rule(path: str = "seal.rs"):  # type: ignore[no-untyped-def]
    rule = match_rule(_asset(path), load_rules())
    assert rule is not None, f"no migration rule matches {path}"
    return rule


class TestConstraintsAreScopedToTheFilesLanguage:
    """The exact defect: a Rust file was handed Go's API and nothing else."""

    def test_rust_is_not_given_the_go_api_when_a_verified_shape_exists(self) -> None:
        """Rust has a verified ML-KEM shape, so no other language's API should appear at all."""
        rendered = _scoped_constraints(_kex_rule(), "rust", have_target_shape=True)
        assert "crypto/mlkem" not in rendered, (
            "a .rs file is being told to use Go's crypto/mlkem — this is the instruction the "
            "model transliterated into `mlkem::GenerateKey768(&mut rng)`"
        )
        assert "@noble/post-quantum" not in rendered
        assert "liboqs" not in rendered

    def test_a_language_with_nothing_better_still_gets_the_shape_of_it(self) -> None:
        """Dropping foreign lines outright cost `Wallet.swift`'s 3DES migration, which was passing.

        With no guidance of its own and no verified shape, the rule's other-language lines are the
        only semantics available — so they are kept, explicitly labelled as another language's API.
        """
        rendered = _scoped_constraints(_kex_rule(), "swift", have_target_shape=False)
        assert "no guidance written for swift" in rendered
        assert "not for API names" in rendered
        assert "crypto/mlkem" in rendered, "the semantics were thrown out with the misdirection"

    def test_go_still_gets_its_own_api(self) -> None:
        rendered = _scoped_constraints(_kex_rule("seal.go"), "go", have_target_shape=True)
        assert "crypto/mlkem" in rendered, "scoping must not strip a language's own guidance"

    def test_tsx_inherits_typescript_guidance(self) -> None:
        """`.tsx` is a separate grammar but the same crypto APIs, so "TypeScript:" applies."""
        rendered = _scoped_constraints(_kex_rule("app.tsx"), "tsx", have_target_shape=True)
        assert "@noble/post-quantum" in rendered

    def test_universal_lines_are_kept_for_every_language(self) -> None:
        for language in ("rust", "go", "swift", "python"):
            rendered = _scoped_constraints(_kex_rule(), language, have_target_shape=True)
            assert "Never send or store the shared secret" in rendered, language

    def test_an_ordinary_sentence_with_a_colon_is_not_a_language(self) -> None:
        """Guarding the guard: "Note: ..." must not be mistaken for language-scoped guidance."""

        class _FakeRule:
            prompt_constraints: ClassVar[list[str]] = [
                "Note: keep the old decrypt path.",
                "Go: use crypto/mlkem.",
                "Rotate the key: then re-encrypt.",
            ]

        rendered = _scoped_constraints(
            _FakeRule(),  # type: ignore[arg-type]
            "rust",
            have_target_shape=True,
        )
        assert "Note: keep the old decrypt path." in rendered
        assert "Rotate the key: then re-encrypt." in rendered
        assert "crypto/mlkem" not in rendered


class TestVerifiedTargetShapes:
    """The shapes come from the scanner, so the instruction and the check share one source."""

    def test_rust_shape_is_the_scanners_own_rule_example(self) -> None:
        shapes = ts.verified_target_shapes("rust", "ML-KEM")
        assert shapes, "the scanner detects ML-KEM in Rust; the lookup must surface it"
        assert any("MlKem768" in s.source for s in shapes)
        assert all(any(a.startswith("ML-KEM") for a in s.algorithms) for s in shapes)

    def test_the_shape_actually_passes_the_check_it_is_offered_for(self) -> None:
        """Not merely 'a rule mentions ML-KEM' — the shape is run through the real rescan stage.

        This is what makes the hint trustworthy: if the scanner stopped recognising it, this fails.
        """
        shapes = ts.verified_target_shapes("rust", "ML-KEM")
        assert shapes, "the scanner CLI must be answerable for this test to mean anything"
        result = _stage_rescan(shapes[0].source, _kex_rule(), "rust", "RSA-1024")
        assert result.status != "fail", result.detail

    def test_a_language_the_scanner_cannot_verify_returns_nothing(self) -> None:
        assert ts.verified_target_shapes("swift", "ML-KEM") == ()

    def test_lookup_is_cached_so_a_plan_does_not_re_ask_per_task(self) -> None:
        ts._cache.clear()
        first = ts.verified_target_shapes("rust", "ML-KEM")
        assert ("rust", "ML-KEM") in ts._cache
        assert ts.verified_target_shapes("rust", "ML-KEM") is first

    def test_the_prompt_carries_the_shape(self) -> None:
        rule = _kex_rule()
        prompt = _build_prompt(RUST_SOURCE, rule, _asset("seal.rs"))
        assert "MlKem768" in prompt, "the generator is still not told what the checker accepts"
        assert "crypto/mlkem" not in prompt


class TestUnverifiableIsADiagnosisNotAGate:
    """It was briefly a gate. Measurement said no.

    Refusing every task in a language QUBIT ships no verified shape for cost two tasks that had
    previously passed their rescan — `Wallet.swift` 3DES and `Crypto.kt` RSA. A rule can detect an
    algorithm without shipping an example that resolves to it, so "no example" never proved "no
    rule". It now only sharpens the message after generation has already failed.
    """

    def test_rust_is_winnable(self) -> None:
        assert unverifiable_reason(_kex_rule(), "rust") is None

    @pytest.mark.parametrize("language", ["php", "ruby", "dart"])
    def test_a_language_with_no_shipped_shape_is_named(self, language: str) -> None:
        reason = unverifiable_reason(_kex_rule(), language)
        assert reason is not None
        assert "ML-KEM" in reason
        assert language in reason
        assert "candidate for migration advice" in reason

    def test_it_never_blocks_generation(self) -> None:
        """The regression guard: a language with no shipped shape must still be attempted.

        `Wallet.swift` 3DES passed its rescan before this helper existed, and was refused outright
        once it became a gate. Generation must reach the model regardless of what this returns.
        """
        import qubit_migrate.transform.llm as llm

        calls: list[str] = []

        def fake_generate(prompt: str, **kwargs: object) -> str:
            calls.append(prompt)
            return "```swift\nlet x = 1\n```"

        original = llm._ollama_generate
        original_installed = llm.installed_models
        llm._ollama_generate = fake_generate  # type: ignore[assignment]
        # An empty list means "cannot ask Ollama", which skips the model-availability check —
        # otherwise this test would fail for that reason and prove nothing about the gate.
        llm.installed_models = lambda *a, **k: []  # type: ignore[assignment]
        try:
            llm.generate_llm_source(
                "let x = 0\n",
                _kex_rule("Wallet.swift"),
                _asset("Wallet.swift"),
                model="unused",
                max_attempts=1,
                verify=None,
            )
        except Exception:
            pass
        finally:
            llm._ollama_generate = original  # type: ignore[assignment]
            llm.installed_models = original_installed  # type: ignore[assignment]

        assert calls, (
            "generation never reached the model — the unverifiable diagnosis is gating again, "
            "which is what cost two previously-passing tasks"
        )

    def test_a_rule_with_no_present_expectation_is_never_blocked(self) -> None:
        class _FakeRule:
            rescan_expect: ClassVar[dict] = {"gone": {"algorithm_prefix": "MD5"}}
            prompt_constraints: ClassVar[list[str]] = []

        assert unverifiable_reason(_FakeRule(), "swift") is None  # type: ignore[arg-type]

    def test_present_prefixes_reads_the_rule(self) -> None:
        assert present_prefixes(_kex_rule()) == ["ML-KEM"]

    def test_an_unreachable_scanner_does_not_look_like_an_unwinnable_task(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ "The scanner says none" and "the scanner could not be asked" are different answers.

        Collapsing them would refuse every LLM task the moment the CLI became unreachable — a
        packaging problem presenting as a silent, total capability loss.
        """
        ts._cache.clear()
        monkeypatch.setattr(ts, "run_cli_json", lambda *a, **k: None)
        assert ts.verified_target_shapes("rust", "ML-KEM") is None
        assert unverifiable_reason(_kex_rule(), "swift") is None, (
            "with no answer available, the attempt must be allowed to run rather than refused"
        )
        assert ts._cache == {}, "a failed lookup must not be cached as an authoritative 'none'"
        ts._cache.clear()


class TestRescanSaysWhichExpectationFailed:
    """Two failures need opposite corrections; one fixed sentence gave the wrong one."""

    def test_leftover_algorithm_is_reported_as_gone(self) -> None:
        result = _stage_rescan(RUST_SOURCE, _kex_rule(), "rust", "RSA-1024")
        assert result.status == "fail"
        assert result.expectation == "gone"
        assert result.expected == "RSA"

    def test_missing_replacement_is_reported_as_present(self) -> None:
        """RSA removed, but the replacement is one the scanner cannot see — the real failure."""
        migrated_but_undetectable = (
            "use crypto::mlkem;\n\npub fn issue() {\n"
            "    let (dk, ek) = mlkem::GenerateKey768(&mut rng);\n    let _ = (dk, ek);\n}\n"
        )
        result = _stage_rescan(migrated_but_undetectable, _kex_rule(), "rust", "RSA-1024")
        assert result.status == "fail"
        assert result.expectation == "present", (
            "this rewrite removed RSA entirely; calling it a leftover-RSA failure is what sent "
            "the repair loop after a problem that did not exist"
        )
        assert result.expected == "ML-KEM"
