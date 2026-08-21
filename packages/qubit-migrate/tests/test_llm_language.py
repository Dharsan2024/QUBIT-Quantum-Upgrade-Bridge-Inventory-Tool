"""The LLM tier must produce code in the language of the file it was given.

Nine of the fourteen migration rules have no deterministic codemod — cipher swaps, key exchange,
signatures, TLS versions — so this path owns most of a real queue. Every test it had used a mocked
HTTP response, which is why the following went unnoticed until the local model was actually asked:

    asked to migrate 3DES in a **Ruby** file, qwen2.5-coder returned **Go**
    asked for the same in **C#**, it returned the *same* Go
    asked to raise a TLS version in **Kotlin**, it returned **Python**

1 of 4 cases came back in the right language. The model was echoing the rule's worked example, and
three faults compounded to make that the likeliest output — a private suffix map that did not know
the newer languages, a primary example attached to files it did not demonstrate, and a rewrite guard
that was handed `rule.language` ("multi") so its language check never ran.

The first two classes below need no Ollama and always run. The live ones are marked `llm` and skip
only when no model server is reachable.
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
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.transform.llm import (
    _build_prompt,
    _worked_examples,
    check_rewrite,
    generate_llm_source,
)
from qubit_migrate.transform.rules import load_rules, match_rule

MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"


def _ollama_up() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as r:
            return bool(r.status == 200)
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


needs_ollama = pytest.mark.skipif(not _ollama_up(), reason="no Ollama server on 127.0.0.1:11434")


def _asset(path: str, algorithm: str, usage: UsageContext) -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=usage,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=3),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        evidence=Evidence(),
        discovered_at=utcnow(),
    )


# ── Prompt construction (no model needed) ────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "expected_language"),
    [
        ("app/seal.rb", "ruby"),
        ("src/Vault.cs", "csharp"),
        ("src/Crypto.kt", "kotlin"),
        ("lib/fleet.dart", "dart"),
        ("src/seal.rs", "rust"),
        ("web/Component.tsx", "tsx"),
        ("svc/seal.go", "go"),
    ],
)
def test_prompt_labels_the_file_with_its_real_language(path: str, expected_language: str) -> None:
    """The fence label is the model's clearest signal about what to return.

    A cross-language rule declares `language: multi`, and `llm.py` kept its own suffix map that
    listed only the original languages — so for every language added since, the fence was labelled
    ```multi```, which is not a language at all.
    """
    asset = _asset(path, "3DES", UsageContext.encryption_at_rest)
    rule = match_rule(asset, load_rules())
    assert rule is not None, f"{path} matched no rule"
    prompt = _build_prompt("x = 1\n", rule, asset)
    assert f"```{expected_language}\n" in prompt, (
        f"the prompt does not label the source fence as {expected_language}"
    )
    assert "```multi" not in prompt


def test_no_worked_example_is_shown_in_another_language() -> None:
    """An example in the wrong language is worse than no example at all.

    `code-weakcipher-01`'s primary example is Go. It was attached to files in every language that
    had no example of its own, and the model returned Go.
    """
    by_id = {r.id: r for r in load_rules()}
    rule = by_id["code-weakcipher-01"]
    assert rule.example_language == "go"

    go_marker = "package main"
    assert go_marker in _worked_examples(rule, "go"), (
        "a Go file should still get the Go example — this test would otherwise pass vacuously"
    )
    for language in ("ruby", "csharp", "kotlin", "dart", "swift", "php", "rust"):
        rendered = _worked_examples(rule, language)
        assert go_marker not in rendered, f"a {language} file is being shown a Go worked example"


def test_rewrite_guard_rejects_the_wrong_language() -> None:
    """The repair loop can only correct a mistake it is told about.

    `check_rewrite` was called with `rule.language`, which for a cross-language rule is "multi" —
    matching no grammar, so the one language-aware check never ran and all three attempts were
    spent re-prompting with the same misleading context.
    """
    ruby_before = (
        "require 'openssl'\n\ndef seal(d, k)\n  OpenSSL::Cipher.new('des-ede3-cbc')\nend\n"
    )
    go_rewrite = (
        "package main\n\n"
        'import "crypto/aes"\n\n'
        "func seal(key []byte) {\n"
        "    block, _ := aes.NewCipher(key)\n"
        "    _ = block\n"
        "}\n"
    )
    reason = check_rewrite(ruby_before, go_rewrite, "ruby")
    assert reason is not None, "Go returned for a Ruby file was accepted"
    assert "ruby" in reason.lower()

    # And it must not reject a genuine Ruby rewrite — otherwise the guard blocks every patch.
    ruby_after = "require 'openssl'\n\ndef seal(d, k)\n  OpenSSL::Cipher.new('aes-256-gcm')\nend\n"
    assert check_rewrite(ruby_before, ruby_after, "ruby") is None


# ── Against the real local model ─────────────────────────────────────────────

_LIVE_CASES = [
    (
        "seal.rb",
        "require 'openssl'\n\ndef seal(data, key)\n  c = OpenSSL::Cipher.new('des-ede3-cbc')\n"
        "  c.encrypt\n  c.key = key\n  c.update(data) + c.final\nend\n",
        "3DES",
        UsageContext.encryption_at_rest,
        "ruby",
    ),
    (
        "Vault.cs",
        "using System.Security.Cryptography;\n\nclass Vault {\n"
        "  byte[] Seal(byte[] d, byte[] k) {\n"
        "    var c = new TripleDESCryptoServiceProvider();\n    c.Key = k;\n"
        "    return c.CreateEncryptor().TransformFinalBlock(d, 0, d.Length);\n  }\n}\n",
        "3DES",
        UsageContext.encryption_at_rest,
        "csharp",
    ),
    (
        "Client.kt",
        "import javax.net.ssl.SSLContext\n\nfun client(): SSLContext {\n"
        '    return SSLContext.getInstance("TLSv1")\n}\n',
        "TLSv1.0",
        UsageContext.tls,
        "kotlin",
    ),
]


@pytest.mark.llm
@needs_ollama
@pytest.mark.parametrize(
    ("filename", "source", "algorithm", "usage", "language"),
    _LIVE_CASES,
    ids=[c[4] for c in _LIVE_CASES],
)
def test_live_model_returns_the_file_s_own_language(
    filename: str, source: str, algorithm: str, usage: UsageContext, language: str
) -> None:
    """End to end against the local model, for languages that have no worked example.

    This is the test that would have caught the original defect. Everything else in this file
    reasons about the prompt; only this one asks the model.
    """
    from qubit_migrate.transform.validate import _stage_parses

    asset = _asset(filename, algorithm, usage)
    rule = match_rule(asset, load_rules())
    assert rule is not None

    rewritten = generate_llm_source(source, rule, asset, model=MODEL)

    assert rewritten.strip() != source.strip(), "the model returned the file unchanged"
    parsed = _stage_parses(rewritten, language)
    assert parsed.status == "pass", (
        f"the model did not return valid {language} — {parsed.detail}\n{rewritten[:400]}"
    )
    # The weak algorithm's own spelling must be gone from the rewrite.
    for token in ("des-ede3", "TripleDES", 'TLSv1"'):
        assert token not in rewritten, f"{token!r} survived the rewrite"
