"""The passes that were missing between "the model answered" and "this patch is good".

Generation used to be: ask once, check the output parses and the finding is gone, ship. Both of
those pass for a rewrite that swaps the algorithm name and gets the semantics wrong - a nonce that
never changes, an auth tag computed and dropped, a stored format that silently orphans every
existing record. The two passes here are what look at that:

* `self_review` - the model reads its own draft against the rule's stated requirements;
* `check_reasoning` - the model's account of the patch is checked against the file it returned.

Neither calls a real model in these tests; both are exercised against fixed strings, which is the
only way to assert their behaviour deterministically.
"""

from __future__ import annotations

import pytest
from qubit_core import (
    AssetType,
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.transform import llm
from qubit_migrate.transform.rules import load_rules


def _asset() -> CryptoAsset:
    return CryptoAsset(
        algorithm="3DES",
        usage_context=UsageContext.encryption_at_rest,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="svc/seal.go", line=9),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
    )


def _rule():
    return next(r for r in load_rules() if r.id == "code-weakcipher-01")


# --- check_reasoning --------------------------------------------------------------------------


def test_a_claim_the_file_does_not_support_is_rejected() -> None:
    """The failure no other stage sees.

    The file parses, the old algorithm is gone, the rescan is satisfied — and the reasoning shown
    to the reviewer describes a migration that is not in the diff. Read together, the two actively
    mislead, which is worse than a patch that fails cleanly.
    """
    reason, caveats = llm.check_reasoning(
        "- Replaced the RSA key exchange with ML-KEM-768 per FIPS 203.",
        "package main\n\nfunc seal() {}\n",
    )
    assert reason is not None
    assert "ML-KEM" in reason
    assert caveats == []


def test_a_supported_claim_passes() -> None:
    reason, _ = llm.check_reasoning(
        "- Replaced the RSA key exchange with ML-KEM-768 per FIPS 203.",
        'import { ml_kem768 } from "@noble/post-quantum/ml-kem";\n',
    )
    assert reason is None


def test_spelling_variants_of_the_same_claim_are_not_treated_as_lies() -> None:
    """`AES-GCM` and `AES-256-GCM` are one claim written two ways."""
    reason, _ = llm.check_reasoning(
        "- Switched to AES-256-GCM with a fresh nonce per message.",
        'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n',
    )
    assert reason is None

    reason, _ = llm.check_reasoning(
        "- Switched to AES-GCM.", "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
    )
    assert reason is None


def test_an_admission_is_a_caveat_and_never_a_rejection() -> None:
    """Honesty must not be the losing strategy.

    A patch whose notes admit a gap is strictly more useful than an identical patch that stays
    quiet about the same gap. If admissions were rejected, the prompt would be selecting for
    silence — so claims are checked strictly and admissions are surfaced.
    """
    reason, caveats = llm.check_reasoning(
        "- Migrated the cipher to AES-256-GCM.\n"
        "- I could not update the two callers in report.go; they still pass the old IV.\n"
        "- Existing ciphertext must be re-encrypted; this patch does not do that.",
        "cipher.NewGCM(block)  // aes-256-gcm\n",
    )
    assert reason is None, "an honest note must never fail a patch"
    assert len(caveats) == 2
    assert any("report.go" in c for c in caveats)


def test_empty_notes_are_not_an_error() -> None:
    """A model that returns a perfect file and forgets the heading has still done the work."""
    assert llm.check_reasoning("", "anything") == (None, [])


# --- self_review ------------------------------------------------------------------------------


def test_review_keeps_the_draft_when_the_model_says_it_is_fine(monkeypatch) -> None:
    monkeypatch.setattr(llm, "_ollama_generate", lambda *a, **k: "VERDICT: OK")
    draft = "package main\n\nfunc seal() {}\n"
    result, notes = llm.self_review("orig\n", draft, _rule(), _asset(), model="m", language="go")
    assert result == draft
    assert notes == ""


def test_review_adopts_a_correction_that_clears_the_same_bar(monkeypatch) -> None:
    original = "package main\n\nfunc seal(k, p []byte) []byte {\n\treturn p\n}\n"
    draft = "package main\n\nfunc seal(k, p []byte) []byte {\n\treturn nil\n}\n"
    fixed = (
        "package main\n\nfunc seal(k, p []byte) ([]byte, error) {\n"
        "\taead, err := cipher.NewGCM(block)\n\treturn aead.Seal(nil, nonce, p, nil), err\n}\n"
    )
    monkeypatch.setattr(
        llm,
        "_ollama_generate",
        lambda *a, **k: f"```go\n{fixed}```\n\nSECURITY NOTES:\n- Added the missing GCM seal.",
    )
    result, notes = llm.self_review(original, draft, _rule(), _asset(), model="m", language="go")
    assert result.strip() == fixed.strip()
    assert "GCM" in notes


def test_review_never_returns_something_worse_than_the_draft(monkeypatch) -> None:
    """A review that "fixes" a file into a truncated one is worse than the draft it replaced.

    The correction is put through the same cheap checks the draft passed, and the draft wins on a
    tie. That is what makes running this pass before validation safe rather than a gamble.
    """
    original = "\n".join(f"line{i} = {i}" for i in range(40)) + "\n"
    draft = original.replace("line0 = 0", "line0 = 999")
    truncated = "package main\n"
    monkeypatch.setattr(llm, "_ollama_generate", lambda *a, **k: f"```go\n{truncated}```")
    result, _ = llm.self_review(original, draft, _rule(), _asset(), model="m", language="go")
    assert result == draft


def test_review_failure_is_not_a_generation_failure(monkeypatch) -> None:
    """Ollama dying between the draft and the review must cost the review, not the patch."""

    def boom(*a, **k):
        raise llm.OllamaError("connection refused")

    monkeypatch.setattr(llm, "_ollama_generate", boom)
    draft = "package main\n"
    result, notes = llm.self_review("orig\n", draft, _rule(), _asset(), model="m", language="go")
    assert result == draft
    assert notes == ""


def test_the_review_prompt_asks_checkable_questions(monkeypatch) -> None:
    """ "Is this good?" gets a yes. The prompt has to name the specific things to check."""
    captured: dict[str, str] = {}

    def capture(prompt: str, **kwargs: object) -> str:
        captured["prompt"] = prompt
        return "VERDICT: OK"

    monkeypatch.setattr(llm, "_ollama_generate", capture)
    llm.self_review("orig\n", "draft\n", _rule(), _asset(), model="m", language="go")
    prompt = captured["prompt"]
    for probe in ("nonce", "authentication tag", "still be read", "call site"):
        assert probe in prompt.lower(), f"the review prompt never asks about {probe}"
    # The rule's own constraints, not a generic checklist.
    assert "12-byte nonce" in prompt


# --- integration through generate_llm_source ---------------------------------------------------


def test_generation_runs_draft_review_and_reasoning_in_order(monkeypatch) -> None:
    """One accepted patch should cost a draft call and a review call, in that order."""
    calls: list[str] = []
    good = 'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n' * 5

    def fake(prompt: str, **kwargs: object) -> str:
        if "Before writing any code, plan the change" in prompt:
            return "1. seal changes to AES-256-GCM.\n"
            "2. A fresh 12-byte nonce per message, stored with the ciphertext.\n"
            "3. Existing ciphertext needs the old decrypt path until re-encrypted.\n"
            "4. Callers reading the old layout.\n5. The public function names."
        if "You are reviewing a cryptographic migration patch" in prompt:
            calls.append("review")
            return "VERDICT: OK"
        calls.append("draft")
        return f"```go\n{good}```\n\nSECURITY NOTES:\n- Uses AES-256-GCM with a fresh nonce."

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    seen: list[str] = []
    out = llm.generate_llm_source(
        good.replace("aes-256-gcm", "des-ede3-cbc"),
        _rule(),
        _asset(),
        model="m",
        on_notes=seen.append,
        max_attempts=1,
    )
    assert calls == ["draft", "review"]
    assert "aes-256-gcm" in out
    assert seen and "AES-256-GCM" in seen[0]


def test_the_review_pass_can_be_switched_off(monkeypatch) -> None:
    calls: list[str] = []
    good = 'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n' * 5

    def fake(prompt: str, **kwargs: object) -> str:
        if "Before writing any code, plan the change" in prompt:
            return "1. Swap it. 2. A nonce. 3. Old data. 4. Callers. 5. Names."
        calls.append("review" if "You are reviewing" in prompt else "draft")
        return f"```go\n{good}```"

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    llm.generate_llm_source(
        good.replace("aes-256-gcm", "des-ede3-cbc"),
        _rule(),
        _asset(),
        model="m",
        max_attempts=1,
        self_review_pass=False,
    )
    assert calls == ["draft"]


def test_an_unsupported_claim_is_fed_back_as_repair_feedback(monkeypatch) -> None:
    """The reasoning check has to reach the repair loop, not just fail at the end."""
    good = 'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n' * 5
    prompts: list[str] = []
    attempt = {"n": 0}

    def fake(prompt: str, **kwargs: object) -> str:
        if "Before writing any code, plan the change" in prompt:
            return "1. seal changes to AES-256-GCM.\n"
            "2. A fresh 12-byte nonce per message, stored with the ciphertext.\n"
            "3. Existing ciphertext needs the old decrypt path until re-encrypted.\n"
            "4. Callers reading the old layout.\n5. The public function names."
        if "You are reviewing" in prompt:
            return "VERDICT: OK"
        prompts.append(prompt)
        attempt["n"] += 1
        if attempt["n"] == 1:
            # Claims a primitive the file does not contain.
            return f"```go\n{good}```\n\nSECURITY NOTES:\n- Migrated to ML-KEM-768."
        return f"```go\n{good}```\n\nSECURITY NOTES:\n- Migrated to AES-256-GCM."

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    llm.generate_llm_source(
        good.replace("aes-256-gcm", "des-ede3-cbc"),
        _rule(),
        _asset(),
        model="m",
        max_attempts=2,
    )
    assert len(prompts) == 2, "the reasoning failure did not trigger a repair attempt"
    assert "REJECTED" in prompts[1]
    assert "ML-KEM" in prompts[1]


@pytest.mark.parametrize("marker", ["could not", "TODO", "requires manual"])
def test_caveats_reach_the_caller(monkeypatch, marker: str) -> None:
    good = 'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n' * 5

    def fake(prompt: str, **kwargs: object) -> str:
        if "Before writing any code, plan the change" in prompt:
            return "1. seal changes to AES-256-GCM.\n"
            "2. A fresh 12-byte nonce per message, stored with the ciphertext.\n"
            "3. Existing ciphertext needs the old decrypt path until re-encrypted.\n"
            "4. Callers reading the old layout.\n5. The public function names."
        if "You are reviewing" in prompt:
            return "VERDICT: OK"
        return (
            f"```go\n{good}```\n\nSECURITY NOTES:\n"
            f"- Uses AES-256-GCM.\n- Callers {marker} be updated here."
        )

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    got: list[list[str]] = []
    llm.generate_llm_source(
        good.replace("aes-256-gcm", "des-ede3-cbc"),
        _rule(),
        _asset(),
        model="m",
        max_attempts=1,
        on_caveats=got.append,
    )
    assert got and any(marker.lower() in c.lower() for c in got[0])


def test_the_review_is_not_spent_on_a_draft_the_rescan_rejects(monkeypatch) -> None:
    """Ordering, and it is a cost decision measured on a real run.

    On `code-kex-01` the draft routinely passes the cheap checks and then fails the rescan. With
    the review running first, every one of those attempts paid for a full model call on a file
    about to be discarded - three per task, on the tasks least likely to succeed, and a 163-task
    run crawled. A rescan is a one-second subprocess.
    """
    calls: list[str] = []
    good = 'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n' * 5

    def fake(prompt: str, **kwargs: object) -> str:
        if "Before writing any code, plan the change" in prompt:
            return "1. seal changes to AES-256-GCM.\n"
            "2. A fresh 12-byte nonce per message, stored with the ciphertext.\n"
            "3. Existing ciphertext needs the old decrypt path until re-encrypted.\n"
            "4. Callers reading the old layout.\n5. The public function names."
        calls.append("review" if "You are reviewing" in prompt else "draft")
        return f"```go\n{good}```"

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    with pytest.raises(llm.OllamaError):
        llm.generate_llm_source(
            good.replace("aes-256-gcm", "des-ede3-cbc"),
            _rule(),
            _asset(),
            model="m",
            max_attempts=3,
            verify=lambda _src: "the finding is still present",
        )
    assert calls == ["draft", "draft", "draft"], (
        f"the review must not run on a draft the rescan rejects; got {calls}"
    )


def test_a_review_correction_that_breaks_the_rescan_is_discarded(monkeypatch) -> None:
    """The review runs AFTER the rescan, so its correction has to face the rescan too.

    Without the re-check, a review could turn a patch the rescan accepted into one it does not,
    and that patch would ship - the stage that would have caught it had already run.
    """
    good = 'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n' * 5
    broken = "const c = nothing();\n" * 5

    def fake(prompt: str, **kwargs: object) -> str:
        if "You are reviewing" in prompt:
            return f"```go\n{broken}```\n\nSECURITY NOTES:\n- Rewrote it."
        return f"```go\n{good}```\n\nSECURITY NOTES:\n- Uses AES-256-GCM."

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    out = llm.generate_llm_source(
        good.replace("aes-256-gcm", "des-ede3-cbc"),
        _rule(),
        _asset(),
        model="m",
        max_attempts=1,
        verify=lambda src: None if "aes-256-gcm" in src else "the target is not present",
    )
    assert "aes-256-gcm" in out, "the rejected correction replaced a patch that had passed"


def test_the_prompt_states_what_the_scanner_saw_at_the_call(monkeypatch) -> None:
    """The specific fact, not a general warning.

    "Migrate this AES call" and "this AES call runs in ECB mode; encrypt with an AEAD mode
    instead" are different instructions, and only the second one names the defect. The observed
    mode, iteration count and floor are all things the scanner READ, so the model should be
    applying them rather than inferring them.
    """
    from qubit_core import Evidence, EvidenceContext

    captured: dict[str, str] = {}

    def capture(prompt: str, **kwargs: object) -> str:
        captured.setdefault("prompt", prompt)
        return "```go\npackage main\n```"

    monkeypatch.setattr(llm, "_ollama_generate", capture)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])

    asset = _asset().model_copy(
        update={
            "evidence": Evidence(
                snippet="",
                context=EvidenceContext(
                    extra={
                        "weaknesses": [
                            {
                                "id": "ecb-mode",
                                "title": "Block cipher used in ECB mode",
                                "cwe": "CWE-327",
                                "authority": "NIST SP 800-38A Appendix A",
                                "remedy": "Encrypt with an AEAD mode - AES-256-GCM.",
                                "detail": {"mode": "ECB", "family": "AES"},
                            }
                        ]
                    }
                ),
            )
        }
    )
    llm.generate_llm_source("x = 1\n", _rule(), asset, model="m", max_attempts=1)

    prompt = captured["prompt"]
    assert "observed AT THIS CALL" in prompt
    assert "ECB mode" in prompt
    assert "mode=ECB" in prompt
    assert "AEAD" in prompt


def test_a_finding_with_no_weakness_adds_nothing_to_the_prompt(monkeypatch) -> None:
    """Context costs a 7B model output budget; an empty section is not free."""
    captured: dict[str, str] = {}

    def capture(prompt: str, **kwargs: object) -> str:
        captured.setdefault("prompt", prompt)
        return "```go\npackage main\n```"

    monkeypatch.setattr(llm, "_ollama_generate", capture)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    llm.generate_llm_source("x = 1\n", _rule(), _asset(), model="m", max_attempts=1)
    assert "observed AT THIS CALL" not in captured["prompt"]


def test_a_patch_validated_only_by_parse_and_rescan_is_marked_partial() -> None:
    """`passed` and `passed with most checks skipped` must not look the same.

    Measured on a real accepted patch: an RSA-to-ML-KEM rewrite in Rust parsed, satisfied the
    rescan, and would not have compiled - it returned a tuple from a function declared to return
    one value. `compiles` was skipped because the sandbox carries no Rust toolchain, and a
    tree-sitter parse is not a type-check. The flag was already computed and shown nowhere; the
    reviewer now sees which checks did not run.
    """
    from qubit_migrate.transform.validate import validate_patch

    report = validate_patch(
        diff_text="",
        patched_source="package main\n",
        rule=None,
        repo_root=None,
        language="go",
        target_rel_path="svc/seal.go",
        no_docker=True,
    )
    assert report.partial, "skipped stages must mark the report partial"
    skipped = {name for name, stage in report.stages.items() if stage.status == "skipped"}
    assert "compiles" in skipped and "tests" in skipped
    payload = report.as_dict()
    assert payload["partial"] is True, "the flag has to survive into the stored record"


# --- plan before writing ------------------------------------------------------------------------


def test_only_structural_rules_are_planned() -> None:
    """A one-token substitution does not need a plan and should not pay for one.

    Judged from the rule rather than a hand-kept list, so a rule added later is classified without
    anyone remembering to update a constant.
    """
    rules = {r.id: r for r in load_rules()}
    assert llm.needs_planning(rules["code-weakcipher-01"]), (
        "the key length changes, a nonce appears, a tag appears and stored data stops being "
        "readable - that is four moving parts"
    )
    assert llm.needs_planning(rules["code-ecb-01"])
    assert llm.needs_planning(rules["code-kdf-01"])
    assert not llm.needs_planning(rules["code-weakhash-02"]), (
        "a digest swap has two constraints and a deterministic codemod behind it"
    )
    assert not llm.needs_planning(rules["code-tls-01"]), (
        "six constraints but in_place, and already the highest-scoring rule measured - planning "
        "it could only slow it down"
    )
    assert not llm.needs_planning(rules["dep-pqc-03"]), "a manifest edit has one moving part"


def test_the_plan_asks_about_consequences_not_syntax(monkeypatch) -> None:
    """The questions are chosen because these are the ones the model gets wrong.

    Measured across two runs: it swaps the cipher correctly and forgets the nonce must be fresh,
    or that existing ciphertext is now unreadable. Asking about those BEFORE it writes puts its
    own answers in its context while it does.
    """
    captured: dict[str, str] = {}

    def capture(prompt: str, **kwargs: object) -> str:
        captured["prompt"] = prompt
        return (
            "1. seal() becomes AES-256-GCM. 2. A fresh nonce. "
            "3. Old ciphertext. 4. Callers. 5. Names."
        )

    monkeypatch.setattr(llm, "_ollama_generate", capture)
    plan = llm.plan_rewrite("x = 1\n", _rule(), _asset(), model="m", language="go")
    assert plan
    prompt = captured["prompt"].lower()
    for probe in (
        "which function",
        "new values",
        "no longer be read",
        "outside this file",
        "not change",
    ):
        assert probe in prompt, f"the plan never asks about {probe!r}"
    assert "plan only" in prompt


def test_a_plan_that_came_back_as_code_is_discarded(monkeypatch) -> None:
    """The model skipped ahead and wrote the file.

    Nothing has validated that rewrite, and pasting it into the generation prompt as "your plan"
    invites it to be copied through unchecked.
    """
    monkeypatch.setattr(
        llm, "_ollama_generate", lambda *a, **k: "```go\npackage main\nfunc x() {}\n```"
    )
    assert llm.plan_rewrite("x = 1\n", _rule(), _asset(), model="m", language="go") == ""


def test_a_planning_failure_does_not_fail_the_generation(monkeypatch) -> None:
    def boom(*a, **k):
        raise llm.OllamaError("connection refused")

    monkeypatch.setattr(llm, "_ollama_generate", boom)
    assert llm.plan_rewrite("x = 1\n", _rule(), _asset(), model="m", language="go") == ""


def test_the_plan_reaches_the_generation_prompt_and_is_made_once(monkeypatch) -> None:
    """Carried across every repair attempt rather than re-planned each time.

    A plan does not become wrong because the first draft of it was truncated, and re-planning on
    each retry would triple the cost of the tasks that already cost the most.
    """
    plans = 0
    prompts: list[str] = []

    def fake(prompt: str, **kwargs: object) -> str:
        nonlocal plans
        if "Before writing any code, plan the change" in prompt:
            plans += 1
            return "1. seal becomes GCM. 2. A fresh nonce. 3. Old data. 4. Callers. 5. Names."
        if "You are reviewing" in prompt:
            return "VERDICT: OK"
        prompts.append(prompt)
        return "```go\nstill des-ede3-cbc\n```"

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    with pytest.raises(llm.OllamaError):
        llm.generate_llm_source(
            'const c = crypto.createCipheriv("des-ede3-cbc", key, iv);\n' * 5,
            _rule(),
            _asset(),
            model="m",
            max_attempts=3,
            verify=lambda _s: "the finding is still present",
        )
    assert plans == 1, f"the plan must be made once, not per attempt (made {plans})"
    assert len(prompts) == 3
    assert "This is YOUR plan for this change" in prompts[0]
    assert "A fresh nonce" in prompts[2], "the plan has to survive into the repair attempts"


def test_planning_can_be_switched_off(monkeypatch) -> None:
    calls: list[str] = []
    good = 'const c = crypto.createCipheriv("aes-256-gcm", key, nonce);\n' * 5

    def fake(prompt: str, **kwargs: object) -> str:
        calls.append("plan" if "plan the change" in prompt else "draft")
        return f"```go\n{good}```"

    monkeypatch.setattr(llm, "_ollama_generate", fake)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])
    llm.generate_llm_source(
        good.replace("aes-256-gcm", "des-ede3-cbc"),
        _rule(),
        _asset(),
        model="m",
        max_attempts=1,
        plan_first=False,
        self_review_pass=False,
    )
    assert "plan" not in calls
