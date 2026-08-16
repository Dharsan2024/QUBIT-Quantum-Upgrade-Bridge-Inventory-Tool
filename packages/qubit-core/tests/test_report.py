"""Report outputs: SARIF 2.1.0 for analyst tooling, PDF for compliance and leadership.

These assert on what a CONSUMER would receive, not on our own data structures, because every failure
mode worth catching here lives at the boundary: a SARIF file that uploads and then annotates
nothing, or a PDF that is a valid document containing none of the content it claims to.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_core.report import export_sarif, validate_sarif_structure
from qubit_core.schemas import (
    AssetType,
    Confidence,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)


def _asset(
    algorithm: str = "RSA-2048",
    *,
    attack: QuantumAttack = QuantumAttack.shor,
    vulnerable: bool = True,
    usage: UsageContext = UsageContext.kex,
    file_path: str | None = "src/app.py",
    line: int | None = 42,
    host: str | None = None,
    rule_id: str = "PY-CRYPTOGRAPHY-RSA-KEYGEN",
    risk: RiskAnnotation | None = None,
    fingerprint: str = "fp-deadbeef",
) -> CryptoAsset:
    location = (
        Location(file_path=file_path, line=line)
        if file_path
        else Location(host=host or "example.test", service="tcp/443")
    )
    asset = CryptoAsset(
        source_scanner=SourceScanner.code if file_path else SourceScanner.network,
        asset_type=AssetType.algorithm_use,
        algorithm=algorithm,
        usage_context=usage,
        quantum_vulnerable=QuantumVulnerability(vulnerable=vulnerable, attack=attack),
        location=location,
        evidence=Evidence(),
        rule_id=rule_id,
        confidence=Confidence.high,
        risk=risk,
    )
    asset.fingerprint = fingerprint
    return asset


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def test_sarif_document_is_structurally_valid() -> None:
    doc = export_sarif([_asset(), _asset("MD5", attack=QuantumAttack.grover)])
    assert doc["version"] == "2.1.0"
    assert validate_sarif_structure(doc) == []
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "QUBIT"
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_level_reflects_the_attack_not_an_arbitrary_score() -> None:
    """`error` is reserved for Shor-breakable public key: that is the only class whose compromise is
    RETROACTIVE, because recorded traffic becomes readable. Grover-affected symmetric material is a
    real problem but does not hand an adversary past traffic, so it is `warning`."""
    doc = export_sarif(
        [
            _asset("RSA-2048", attack=QuantumAttack.shor),
            _asset("MD5", attack=QuantumAttack.grover, rule_id="PY-HASHLIB-MD5"),
            _asset("AES-256", attack=QuantumAttack.none, vulnerable=False, rule_id="PY-AES"),
        ],
        include_safe=True,
    )
    levels = {r["properties"]["algorithm"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels == {"RSA-2048": "error", "MD5": "warning", "AES-256": "note"}


def test_sarif_omits_safe_assets_by_default() -> None:
    """An analyst opening code-scanning alerts wants the problems. A `note` for every healthy
    SHA-256 call would bury them, and the complete inventory is the CBOM's job."""
    doc = export_sarif([_asset("AES-256", attack=QuantumAttack.none, vulnerable=False)])
    assert doc["runs"][0]["results"] == []


def test_sarif_uri_is_relative_when_a_repo_root_is_given(tmp_path: Path) -> None:
    """The regression this guards: an ABSOLUTE uri tagged with `uriBaseId: SRCROOT` uploads happily
    and then annotates nothing, because the platform cannot match it to a file in the repository.
    When a base id is claimed, the uri must be relative to it."""
    (tmp_path / "src").mkdir()
    target = tmp_path / "src" / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    doc = export_sarif([_asset(file_path=str(target))], repo_root=str(tmp_path))
    artifact = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact["uri"] == "src/app.py"
    assert artifact["uriBaseId"] == "SRCROOT"
    assert not Path(artifact["uri"]).is_absolute()
    assert doc["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"].endswith("/")


def test_sarif_path_outside_the_repo_root_keeps_no_base_id(tmp_path: Path) -> None:
    """A system config or absolute include is genuinely outside the tree. Emitting a `../..` chain
    or claiming SRCROOT for it would both be wrong, so it stays absolute and unbased."""
    doc = export_sarif([_asset(file_path="/etc/nginx/nginx.conf")], repo_root=str(tmp_path))
    artifact = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "uriBaseId" not in artifact


def test_sarif_uses_forward_slashes() -> None:
    doc = export_sarif([_asset(file_path="src\\pkg\\app.py")])
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert "\\" not in uri


def test_sarif_carries_the_asset_fingerprint_for_alert_identity() -> None:
    """GitHub matches results across commits on `partialFingerprints`. Without it the platform falls
    back to line numbers, so an unrelated edit above a finding closes the alert and opens a new one.
    QUBIT already computes a stable fingerprint, so it is passed straight through."""
    doc = export_sarif([_asset(fingerprint="stable-fp-123")])
    assert doc["runs"][0]["results"][0]["partialFingerprints"] == {
        "qubitAssetFingerprint": "stable-fp-123"
    }


def test_sarif_network_finding_still_has_a_location() -> None:
    """A network, cert or Vault asset has no file. Omitting `locations` makes GitHub reject the
    whole RUN, so a logical location carries the host/service, not a fabricated file path."""
    doc = export_sarif([_asset(file_path=None, host="tls.example.test")])
    location = doc["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" not in location
    assert "tls.example.test" in location["logicalLocations"][0]["name"]
    assert validate_sarif_structure(doc) == []


def test_sarif_rule_indexes_stay_in_range_when_rules_repeat() -> None:
    """`ruleIndex` must point into `driver.rules`; findings are grouped per DETECTION rule so a
    platform can show "N alerts from this rule" and dismiss a class at once."""
    doc = export_sarif([_asset(), _asset(), _asset("MD5", rule_id="PY-HASHLIB-MD5")])
    run = doc["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert {r["ruleIndex"] for r in run["results"]} == {0, 1}
    assert validate_sarif_structure(doc) == []


def test_sarif_message_states_the_hndl_consequence() -> None:
    """The message is what an analyst reads in the alert, so it has to say why this matters rather
    than only naming the algorithm."""
    risk = RiskAnnotation(
        score=0.42, ci_low=0.3, ci_high=0.5, mosca_margin_years=-2.5, priority_rank=1
    )
    doc = export_sarif([_asset(risk=risk)])
    text = doc["runs"][0]["results"][0]["message"]["text"]
    assert "harvest-now-decrypt-later" in text
    assert "0.42" in text and "-2.5" in text
    assert "past due" in text  # negative Mosca margin must be called out, not just printed


def test_validate_sarif_catches_a_result_with_no_location() -> None:
    """The validator exists to fail at export time rather than in someone's CI log."""
    doc = export_sarif([_asset()])
    del doc["runs"][0]["results"][0]["locations"]
    assert any("no locations" in e for e in validate_sarif_structure(doc))


def test_validate_sarif_catches_a_wrong_version() -> None:
    doc = export_sarif([_asset()])
    doc["version"] = "2.0.0"
    assert any("version" in e for e in validate_sarif_structure(doc))


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def test_pdf_report_is_a_real_readable_document(tmp_path: Path) -> None:
    """Asserts on RENDERED TEXT via a real parser, not on file size. A hand-rolled zlib/regex
    extraction reported zero content for a perfectly valid document during development — the sort of
    false negative that would have hidden an actually empty report."""
    from qubit_core.report import build_pdf_report

    pypdf = pytest.importorskip("pypdf")

    risk = RiskAnnotation(
        score=0.42, ci_low=0.3, ci_high=0.5, mosca_margin_years=-2.5, priority_rank=1
    )
    assets = [
        _asset(risk=risk),
        _asset("MD5", attack=QuantumAttack.grover, rule_id="PY-HASHLIB-MD5"),
        _asset("AES-256", attack=QuantumAttack.none, vulnerable=False, rule_id="PY-AES"),
    ]
    out = build_pdf_report(assets, tmp_path / "report.pdf", target="/srv/app")

    assert out.exists() and out.stat().st_size > 2000
    reader = pypdf.PdfReader(str(out))
    assert len(reader.pages) >= 1
    assert "QUBIT" in (reader.metadata.get("/Title") or "")

    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    # The verdict, the regulatory anchor, the urgency, and the remediation must all be present —
    # these are the four things the document exists to communicate.
    assert "Executive summary" in text
    assert "quantum-vulnerable" in text
    assert "Executive Order 14412" in text
    assert "ML-KEM-768" in text
    assert "Recommended migration targets" in text
    # 2 of 3 vulnerable, and the negative Mosca margin has to be surfaced as past due.
    assert "2 of 3" in text
    assert "Mosca margin" in text


def test_pdf_report_caps_the_findings_table_and_says_so(tmp_path: Path) -> None:
    """A 100k-asset monorepo must produce a usable document, and the truncation has to be stated —
    a silently shortened report is worse than a long one."""
    from qubit_core.report import build_pdf_report

    pypdf = pytest.importorskip("pypdf")

    assets = [_asset(f"RSA-{1024 + i}", fingerprint=f"fp-{i}") for i in range(30)]
    out = build_pdf_report(assets, tmp_path / "big.pdf", max_findings=5)
    text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(str(out)).pages)
    assert "Showing the 5 highest-risk of 30" in text
    assert "CBOM contains all of them" in text


def test_pdf_report_handles_an_all_safe_inventory(tmp_path: Path) -> None:
    """ "Nothing is vulnerable" is a reportable result, not an error — and it must not divide by
    zero or emit an empty findings table with no explanation."""
    from qubit_core.report import build_pdf_report

    pypdf = pytest.importorskip("pypdf")

    out = build_pdf_report(
        [_asset("ML-KEM-768", attack=QuantumAttack.none, vulnerable=False, rule_id="PY-PQC")],
        tmp_path / "clean.pdf",
    )
    text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(str(out)).pages)
    assert "0 of 1" in text
