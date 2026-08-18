"""The three capabilities that existed but were unreachable from the app.

CNSA 2.0 evaluation, the paginated PDF report, and the SARIF log were all real, tested code — and
none of them had an API route. CNSA 2.0 had no caller at all outside its own unit tests; PDF and
SARIF were reachable only through `qubit report` on the CLI, so the dashboard's "Save as PDF" was
`window.print()` — a browser rendering of the page, not the composed report. These tests cover the
routes that close that gap.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'reports.db').as_posix()}",
        create_schema_on_startup=True,
    )
    return TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
    )


def _repo(tmp_path: Path) -> Path:
    """A target with a known mix: Shor-broken RSA, Grover-tier SHA-1, and quantum-safe SHA-256.

    The mix matters — CNSA 2.0 milestones key off which algorithm *classes* are present, so a
    single-algorithm fixture could not distinguish "partial" from "non-compliant", and the SARIF
    `include_safe` test needs at least one asset that is genuinely rated safe. SHA-256 is that
    asset: a bare `algorithms.AES(...)` call carries no key size, so it resolves to `AES` and is
    rated Grover-vulnerable rather than safe — using it here made the include_safe test pass
    vacuously (3 results either way) until the fixture was checked against a real scan.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "\n".join(
            [
                "import hashlib",
                "from cryptography.hazmat.primitives.asymmetric import rsa",
                "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms",
                "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
                "digest = hashlib.sha1(data)",
                "cipher = Cipher(algorithms.AES(key_256), None)",
                "safe = hashlib.sha256(data)",  # the quantum-safe asset include_safe must add
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return repo


def _scan(client: TestClient, repo: Path) -> str:
    project_id = client.post("/api/v1/projects", json={"name": "reports"}).json()["id"]
    resp = client.post(
        f"/api/v1/projects/{project_id}/scans",
        json={"targets": [str(repo)], "run_risk": True},
    )
    assert resp.status_code in (200, 202), resp.text
    scan_id = resp.json()["scan"]["id"]
    for _ in range(200):
        status = client.get(f"/api/v1/scans/{scan_id}").json()["status"]
        if status not in ("queued", "running"):
            assert status == "succeeded", f"seed scan failed: {status}"
            return scan_id
        time.sleep(0.1)
    raise TimeoutError("seed scan did not finish")


@pytest.fixture
def scanned(tmp_path: Path):
    with _client(tmp_path) as client:
        yield client, _scan(client, _repo(tmp_path))


# ── CNSA 2.0 ─────────────────────────────────────────────────────────────────────────────────────


def test_cnsa2_reports_every_milestone_with_a_deadline_and_a_verdict(scanned) -> None:
    client, scan_id = scanned
    resp = client.get(f"/api/v1/scans/{scan_id}/cnsa2")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["assets_evaluated"] > 0, "the fixture must produce assets or this proves nothing"
    assert len(body["milestones"]) == 5
    assert body["current_phase"]
    assert body["next_action"]
    for m in body["milestones"]:
        assert m["status"] in {"compliant", "partial", "in-progress", "non-compliant"}
        assert m["deadline"].startswith("20")  # ISO date, 2025-01-01 .. 2035-01-01
        assert isinstance(m["is_due"], bool)
        assert m["weight"] > 0
        assert m["evidence"], "a verdict with no evidence string is not actionable"


def test_cnsa2_score_is_schedule_adherence_not_readiness(scanned) -> None:
    """Pins the semantics the UI depends on, because the two are easy to conflate.

    A milestone that is not yet due scores full marks — you are not late yet — so `overall_score`
    can be high while most milestones are unmet. The dashboard therefore shows readiness (how many
    milestones are actually satisfied) beside the score rather than the score alone. If this
    behavior ever changes, the Compliance page's two headline numbers become wrong, so it is pinned
    here rather than left implicit.
    """
    client, scan_id = scanned
    body = client.get(f"/api/v1/scans/{scan_id}/cnsa2").json()

    not_due = [m for m in body["milestones"] if not m["is_due"]]
    assert not_due, "fixture assumes at least one future milestone"
    assert all(m["score_contribution"] == 100.0 for m in not_due)

    # And the readiness figure the UI computes is genuinely independent of the score.
    satisfied = sum(1 for m in body["milestones"] if m["status"] == "compliant")
    assert satisfied < len(body["milestones"]), (
        "a fixture with RSA-2048 and SHA-1 must not be fully CNSA 2.0 compliant"
    )


def test_cnsa2_404s_for_an_unknown_scan(scanned) -> None:
    client, _ = scanned
    resp = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/cnsa2")
    assert resp.status_code == 404


# ── SARIF ────────────────────────────────────────────────────────────────────────────────────────


def test_sarif_is_a_valid_2_1_0_log_with_stable_fingerprints(scanned) -> None:
    client, scan_id = scanned
    resp = client.get(f"/api/v1/scans/{scan_id}/sarif")
    assert resp.status_code == 200, resp.text
    doc = resp.json()

    assert doc["version"] == "2.1.0"
    assert doc["$schema"]
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"]
    assert run["results"], (
        "the fixture is deliberately vulnerable; an empty log means a broken join"
    )
    for result in run["results"]:
        assert result["ruleId"]
        # partialFingerprints are what keep a GitHub code-scanning alert identical across runs;
        # without them every re-scan opens duplicate alerts.
        assert result["partialFingerprints"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    # Every referenced rule must be declared, or the upload is rejected.
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= declared


def test_sarif_omits_safe_assets_by_default_and_includes_them_on_request(scanned) -> None:
    client, scan_id = scanned
    default = client.get(f"/api/v1/scans/{scan_id}/sarif").json()
    everything = client.get(f"/api/v1/scans/{scan_id}/sarif?include_safe=true").json()
    assert len(everything["runs"][0]["results"]) > len(default["runs"][0]["results"]), (
        "the fixture includes SHA-256, so include_safe must add at least one result"
    )


# ── PDF ──────────────────────────────────────────────────────────────────────────────────────────


def test_pdf_endpoint_returns_a_real_pdf_document(scanned) -> None:
    client, scan_id = scanned
    resp = client.get(f"/api/v1/scans/{scan_id}/report.pdf")
    if resp.status_code == 503:
        pytest.fail(
            "reportlab is missing from the environment — the PDF report is a shipped feature, "
            "so this is a packaging failure rather than a reason to skip"
        )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/pdf"
    assert f"qubit-report-{scan_id}.pdf" in resp.headers["content-disposition"]
    # Checked as bytes, not by length: a JSON error page would also be "some bytes".
    assert resp.content.startswith(b"%PDF-")
    assert resp.content.rstrip().endswith(b"%%EOF")


def test_pdf_endpoint_explains_itself_when_a_scan_found_nothing(tmp_path: Path) -> None:
    """An empty scan must not produce a zero-finding PDF that looks like a clean bill of health."""
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "notes.txt").write_text("no crypto here\n", encoding="utf-8")
    with _client(tmp_path) as client:
        scan_id = _scan(client, empty)
        resp = client.get(f"/api/v1/scans/{scan_id}/report.pdf")
        assert resp.status_code == 409
        assert "nothing to report" in resp.json()["detail"]
