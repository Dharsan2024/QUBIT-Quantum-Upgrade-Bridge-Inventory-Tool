"""Migration advice for findings that cannot be patched.

A queue entry reading "manual change" and nothing else is where the work stops. These cover the
half that replaces it — and, more importantly, the guard that stops the advice being confidently
wrong.

The failure that made the guard necessary, measured on the first real run. Asked about
`openssl genrsa -out server.key 1024` in a shell script — a finding with no migration rule — the
local model answered:

    "Replace the RSA-1024 key generation with RSA-2048 or RSA-3072. Update the encryption and
     signing operations to use NIST-recommended algorithms like AES-256 and ECDSA with a
     256-bit curve."

Every one of those is Shor-breakable. It is the right answer to "this key is too short" and the
wrong answer to "this key is quantum-vulnerable", and a post-quantum migration tool that prints it
is worse than one that prints nothing.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    Sensitivity,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.transform.advise import (
    build_advice_prompt,
    generate_migration_advice,
    recommended_vulnerable_algorithms,
)
from qubit_migrate.transform.rules import load_rules, match_rule

MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"

SHELL_SOURCE = (
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "\n"
    "openssl genrsa -out server.key 1024\n"
    "ssh-keygen -t rsa -b 1024 -f deploy_key -N ''\n"
)


def _ollama_up() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as r:
            return bool(r.status == 200)
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


needs_ollama = pytest.mark.skipif(not _ollama_up(), reason="no Ollama server on 127.0.0.1:11434")


def _asset(algorithm: str, usage: UsageContext, path: str, line: int = 4) -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=usage,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        sensitivity=Sensitivity.credentials,
        evidence=Evidence(),
        discovered_at=utcnow(),
    )


# ── The guard (no model needed) ──────────────────────────────────────────────


def test_guard_rejects_a_quantum_vulnerable_recommendation() -> None:
    """The exact answer the model gave, which must never be shipped as advice."""
    advice = (
        "WHAT TO CHANGE\n"
        "Replace the RSA-1024 key generation with RSA-2048 or RSA-3072, and use ECDSA with a "
        "256-bit curve.\n\n"
        "WHAT THIS BREAKS\nExisting ciphertext.\n"
    )
    flagged = recommended_vulnerable_algorithms(advice, "RSA-1024")
    assert "RSA-2048" in flagged
    assert "ECDSA" in flagged


def test_guard_accepts_a_post_quantum_recommendation() -> None:
    """And must not fire on correct advice, or it blocks every answer.

    Naming the OLD algorithm is not a recommendation — "Replace RSA-1024…" and "the RSA key" are
    both describing what is there now, so the exact name and the bare family are excluded. A
    different member of the same family is not: RSA-2048 in place of RSA-1024 is the failure above.
    """
    advice = (
        "WHAT TO CHANGE\n"
        "Replace the RSA-1024 key generation with ML-KEM-768, using the hybrid X25519MLKEM768 "
        "group during the transition. The RSA key material can then be retired.\n\n"
        "WHAT THIS BREAKS\nExisting ciphertext.\n"
    )
    assert recommended_vulnerable_algorithms(advice, "RSA-1024") == []


def test_guard_only_reads_the_recommendation_section() -> None:
    """The earlier sections name the broken algorithm because describing it is their job."""
    advice = (
        "WHAT THIS CODE DOES\nIt signs with ECDSA-P256 and encrypts with 3DES.\n\n"
        "WHY IT IS A PROBLEM\nECDSA-P256 is Shor-breakable.\n\n"
        "WHAT TO CHANGE\nUse ML-DSA-65.\n\n"
        "WHAT THIS BREAKS\nSignatures.\n"
    )
    assert recommended_vulnerable_algorithms(advice, "ECDSA-P256") == []


# ── The prompt (no model needed) ─────────────────────────────────────────────


def test_prompt_states_the_knowledge_base_target_when_no_rule_matches() -> None:
    """A finding with no codemod rule still has a known target.

    `params/migration_kb.yaml` is the project's single source of truth for
    vulnerable-family + usage-context -> PQC target, and the advice path was not consulting it, so
    the model was asked to invent one. It invented RSA-2048.
    """
    asset = _asset("RSA-1024", UsageContext.kex, "bin/provision.sh")
    rule = match_rule(asset, load_rules())
    assert rule is None, "this fixture is only meaningful for a finding with no rule"

    prompt = build_advice_prompt(SHELL_SOURCE, asset, rule)
    assert "ML-KEM-768" in prompt, "the knowledge base's target never reached the model"
    assert "provision.sh" in prompt
    assert "openssl genrsa" in prompt, (
        "the real code must be in the prompt, not a description of it"
    )


def test_prompt_carries_the_reason_a_patch_was_rejected() -> None:
    """The rejection reason is the most useful single fact available: it says what the automated
    attempt could not do, which is exactly what the person now has to."""
    asset = _asset("MD5", UsageContext.hash, "migrations/V3__hash.sql", line=1)
    prompt = build_advice_prompt(
        "SELECT MD5(password) FROM users;\n",
        asset,
        match_rule(asset, load_rules()),
        failure_reason="nothing left for weakhash_to_sha256 to change",
    )
    assert "nothing left for weakhash_to_sha256 to change" in prompt
    assert "rejected" in prompt.lower()


def test_advice_is_specific_to_the_file_not_the_algorithm() -> None:
    """Two findings of the same algorithm in different files must not get the same prompt.

    This is what "not a template" means concretely: the file, the line, the surrounding code and the
    language all reach the model, so the answer can refer to the actual call sites.
    """
    shell = _asset("RSA-1024", UsageContext.kex, "bin/provision.sh")
    rust = _asset("RSA-1024", UsageContext.kex, "src/seal.rs")
    rust_source = (
        "use rsa::RsaPrivateKey;\n\nfn issue() {\n    RsaPrivateKey::new(&mut r, 1024);\n}\n"
    )

    a = build_advice_prompt(SHELL_SOURCE, shell, match_rule(shell, load_rules()))
    b = build_advice_prompt(rust_source, rust, match_rule(rust, load_rules()))
    assert a != b
    assert "openssl genrsa" in a and "openssl genrsa" not in b
    assert "RsaPrivateKey" in b and "RsaPrivateKey" not in a
    assert "```bash" in a and "```rust" in b


# ── Against the real local model ─────────────────────────────────────────────


@pytest.mark.llm
@needs_ollama
def test_live_advice_never_recommends_a_broken_algorithm() -> None:
    """End to end. This is the test that would have caught the original defect.

    The guard runs inside the generator, so reaching a returned answer at all means no
    quantum-vulnerable target survived — but it is asserted again here, because the whole point is
    that this specific output can never ship.
    """
    asset = _asset("RSA-1024", UsageContext.kex, "bin/provision.sh")
    advice = generate_migration_advice(
        SHELL_SOURCE, asset, match_rule(asset, load_rules()), model=MODEL
    )

    assert recommended_vulnerable_algorithms(advice, asset.algorithm) == [], advice
    for heading in ("WHAT TO CHANGE", "WHAT THIS BREAKS", "HOW TO VERIFY"):
        assert heading.lower() in advice.lower(), f"missing section {heading}:\n{advice}"
    # The knowledge base's target, not one the model recalled.
    assert "ml-kem" in advice.lower()
