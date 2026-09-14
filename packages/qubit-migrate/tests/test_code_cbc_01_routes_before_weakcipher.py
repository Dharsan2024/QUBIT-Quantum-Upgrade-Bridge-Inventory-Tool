"""`code-cbc-01` must exist and must win routing for a bare-`AES`/CBC finding, the way
`code-ecb-01` already wins for ECB -- same precedence trick (alphabetical rule-id ordering,
`weakness:` as the discriminating match clause). See RESUME.md "BUG 7/8" and
`scratchpad/PLAN_task4_bugs_7_8.md` for the full design.

Two things this file exists specifically to pin, because getting either wrong reintroduces a
bug this fix is meant to close:

* `AES-128`/`AES-192` findings must NOT be caught by `code-cbc-01` -- they still need a KEY
  LENGTH change (Grover halves effective security; 128 bits is not the post-quantum floor this
  corpus uses), which is `code-weakcipher-01`'s job, and inkwell's IE-14 already reaches it
  correctly via `_names_a_parameter`. `code-cbc-01` only matches bare `AES`.
* the weakness clause is the ONLY thing that should separate the two rules for a bare-`AES`
  finding -- without `cbc-unauthenticated` present, a bare-`AES` finding must still fall through
  to `code-weakcipher-01` exactly as it does today.
"""

from __future__ import annotations

from qubit_core.schemas import (
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
from qubit_migrate.transform.rules import load_rules, match_rule


def _asset(
    algorithm: str,
    *,
    weaknesses: list[dict] | None = None,
    path: str = "src/Vault.java",
) -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=UsageContext.encryption_at_rest,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=12),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
        library=None,
        evidence=Evidence(
            snippet="",
            context=EvidenceContext(extra={"weaknesses": weaknesses} if weaknesses else {}),
        ),
    )


def test_the_rule_exists() -> None:
    rules = load_rules()
    rule = next((r for r in rules if r.id == "code-cbc-01"), None)

    assert rule is not None, "code-cbc-01 has not been added yet"


def test_bare_aes_with_cbc_unauthenticated_routes_to_the_new_rule() -> None:
    rules = load_rules()
    asset = _asset("AES", weaknesses=[{"id": "cbc-unauthenticated"}])

    rule = match_rule(asset, rules)

    assert rule is not None
    assert rule.id == "code-cbc-01", (
        f"expected code-cbc-01 for a bare-AES/CBC finding, got {rule.id}"
    )


def test_bare_aes_without_the_weakness_still_routes_to_weakcipher() -> None:
    """Regression guard: an ordinary bare-AES finding with no CBC weakness present must be
    completely unaffected by this change."""
    rules = load_rules()
    asset = _asset("AES", weaknesses=None)

    rule = match_rule(asset, rules)

    assert rule is not None
    assert rule.id == "code-weakcipher-01"


def test_aes_128_cbc_still_routes_to_weakcipher_not_the_new_rule() -> None:
    """The regression this test exists to prevent: AES-128 needs a KEY LENGTH change, not just a
    mode change, so it must stay on code-weakcipher-01's path even when the CBC weakness fires."""
    rules = load_rules()
    asset = _asset("AES-128", weaknesses=[{"id": "cbc-unauthenticated"}])

    rule = match_rule(asset, rules)

    assert rule is not None
    assert rule.id == "code-weakcipher-01", (
        f"AES-128/CBC must stay on code-weakcipher-01 (key-length migration), got {rule.id}"
    )
