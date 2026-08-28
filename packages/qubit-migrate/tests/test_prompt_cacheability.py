"""The prompt's static half must stay an unbroken PREFIX, because that is what providers cache.

Prompt caching bills a repeated prefix at a fraction of the normal rate -- 50% off on OpenAI,
up to 90% on Anthropic -- but only for an unbroken prefix. One dynamic token early in the prompt
strands everything after it.

Measured on this rule pack before the sections were reordered: 95.7% of a `code-signature-01`
prompt is identical between two findings, yet only **10.8%** was reachable as a prefix, because
the flagged asset's line number sat at character 723. 85% of every prompt was cacheable content
that could never be cached -- and QUBIT re-sends it on each of the up-to-seven model calls a single
patch makes, for every finding of that rule.

These tests pin the ordering. They are cheap to keep passing and the regression they prevent is
invisible: moving one interpolated value up would quietly multiply the token bill with no
functional symptom at all.
"""

from __future__ import annotations

import pytest
from qubit_core.schemas import (
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

#: Below this, the reordering has regressed. Well under the ~86% measured so the test tracks the
#: property (a large static prefix) rather than an exact figure that shifts with rule wording.
_MIN_PREFIX_FRACTION = 0.60


def _asset(path: str, line: int, algorithm: str = "ECDSA-P256") -> CryptoAsset:
    return CryptoAsset(
        fingerprint=f"fp-{line}",
        source_scanner=SourceScanner("code"),
        asset_type=AssetType("algorithm-use"),
        algorithm=algorithm,
        usage_context=UsageContext("signature"),
        discovered_at=utcnow(),
        location=Location(file_path=path, line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack("shor")),
    )


def _shared_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n


@pytest.mark.parametrize("rule_id", ["code-signature-01", "code-kex-01", "code-weakcipher-01"])
def test_two_findings_of_one_rule_share_a_large_cacheable_prefix(rule_id: str) -> None:
    rule = next(r for r in load_rules() if r.id == rule_id)
    first = llm._build_prompt(
        "package main\n" + "\n".join(f"var x{i} = {i}" for i in range(40)),
        rule,
        _asset("a/one.go", 12),
    )
    second = llm._build_prompt(
        "package main\n" + "\n".join(f"var y{i} = {i * 2}" for i in range(60)),
        rule,
        _asset("b/two.go", 88),
    )

    fraction = _shared_prefix(first, second) / len(first)

    assert fraction >= _MIN_PREFIX_FRACTION, (
        f"{rule_id}: only {fraction:.1%} of the prompt is a shared prefix. Something dynamic moved "
        f"ahead of the rule's static guidance, which strands the rest from any provider cache."
    )


def test_the_finding_specific_half_comes_last() -> None:
    """The ordering rule stated positively: rule guidance, then the finding, then the file."""
    rule = next(r for r in load_rules() if r.id == "code-kex-01")
    prompt = llm._build_prompt(
        "package w\nfunc UNIQUEMARKER() {}\n", rule, _asset("w/wallet.go", 42, "RSA-2048")
    )

    assert prompt.index("Hard constraints:") < prompt.index("Flagged asset:")
    assert prompt.index("Flagged asset:") < prompt.rindex("UNIQUEMARKER")
    # The file being migrated is the very last thing the model reads.
    assert prompt.rstrip().endswith("```")


def test_reordering_did_not_drop_anything() -> None:
    """Order may change; content may not. Each of these earns its place from a real defect --
    see `_build_prompt`'s own comments for the failure each one prevents.
    """
    rule = next(r for r in load_rules() if r.id == "code-kex-01")
    prompt = llm._build_prompt(
        "package w\nfunc f() {}\n", rule, _asset("w/wallet.go", 42, "RSA-2048")
    )

    for required in (
        "cryptographic migration engineer",
        "SECURITY NOTES",
        "Migration rule:",
        "Guidance:",
        "Hard constraints:",
        "Flagged asset: algorithm=RSA-2048",
        "usage_context=signature",
        "line=42",
        "Shor's algorithm",
        "REMOVE any import",
        "Preserve all unrelated code",
        "The file below has",
    ):
        assert required in prompt, f"reordering dropped {required!r}"
