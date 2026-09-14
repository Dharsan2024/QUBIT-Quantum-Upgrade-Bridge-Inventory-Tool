"""A previous patch may move a later finding's scanned line number.

Line-scoped transforms must never use the stale coordinate to edit whatever now happens to live
there.  The scanner's evidence window is the stable anchor; an ambiguous or absent anchor is a
rescan requirement, not an invitation to guess.
"""

from __future__ import annotations

from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.orchestrator import _relocate_finding_line


def _asset(line: int, snippet: str) -> CryptoAsset:
    return CryptoAsset(
        algorithm="SHA-1",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="internal.go", line=line),
        evidence=Evidence(snippet=snippet),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
    )


def test_reanchors_after_an_earlier_import_is_removed() -> None:
    scanned = """package internal

import \"crypto/sha1\"

func DiscoveryETag(body []byte) string {
    return sha1.Sum(body)
}
"""
    # The scanner's +/-2-line window around the call on source line 6.
    asset = _asset(6, "\nfunc DiscoveryETag(body []byte) string {\n    return sha1.Sum(body)\n}")
    # An earlier task removed a now-unused import.  The SHA-1 call moved up one line but did not
    # become safe; using the old line 6 would instead hit the closing brace.
    current = scanned.replace('import "crypto/sha1"\n\n', "")

    assert _relocate_finding_line(asset, current) == 4


def test_does_not_guess_between_identical_evidence_windows() -> None:
    snippet = "func digest(body []byte) string {\n    return sha1.Sum(body)\n}"
    current = f"{snippet}\n\n{snippet}\n"
    assert _relocate_finding_line(_asset(2, snippet), current) is None


def test_missing_evidence_requires_a_rescan_instead_of_using_old_line() -> None:
    assert _relocate_finding_line(_asset(7, ""), "one\ntwo\nthree\n") is None
