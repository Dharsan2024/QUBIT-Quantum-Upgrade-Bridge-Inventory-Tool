from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings


def _make_client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        create_schema_on_startup=True,
    )
    return TestClient(
        create_app(settings),
        headers={"Authorization": f"Bearer {settings.api_token}"},
    )


def _write_repo(repo: Path, *, include_md5: bool = True, include_rsa: bool = True) -> None:
    parts = ["import hashlib", "from cryptography.hazmat.primitives.asymmetric import rsa"]
    if include_md5:
        parts.append("digest = hashlib.md5(data)")
    if include_rsa:
        parts.append("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)")
    (repo / "app.py").write_text("\n".join(parts) + "\n", encoding="utf-8")


def _wait_for_scan(client: TestClient, scan_id: str, timeout: int = 15) -> dict:
    import time

    for _ in range(timeout * 10):
        resp = client.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 200
        scan = resp.json()
        if scan["status"] not in ("queued", "running"):
            return scan
        time.sleep(0.1)
    raise TimeoutError("Scan did not complete")


def test_project_crud_and_scan_asset_flow(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    with _make_client(tmp_path) as client:
        create_resp = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "root_path": str(repo)},
        )
        assert create_resp.status_code == 201
        project_id = create_resp.json()["id"]

        scan_resp = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)]},
        )
        assert scan_resp.status_code == 202
        scan_payload = scan_resp.json()
        scan_id = scan_payload["scan"]["id"]
        scan = _wait_for_scan(client, scan_id)
        assert scan["status"] == "succeeded"

        assets_resp = client.get(f"/api/v1/scans/{scan_id}/assets")
        assert assets_resp.status_code == 200
        body = assets_resp.json()
        assert body["total"] == 2
        assert {item["algorithm"] for item in body["items"]} == {"MD5", "RSA-2048"}

        summary_resp = client.get(f"/api/v1/scans/{scan_id}/summary")
        assert summary_resp.status_code == 200
        assert summary_resp.json()["total_assets"] == 2

        cbom_resp = client.get(f"/api/v1/scans/{scan_id}/cbom")
        assert cbom_resp.status_code == 200
        assert cbom_resp.json()["specVersion"] == "1.7"


def test_delete_project_cascades_through_job_history(tmp_path: Path) -> None:
    """Regression test: DELETE /projects/{id} 500ed (FOREIGN KEY constraint failed) for any
    project with a job history, because jobs.project_id's ondelete=CASCADE fix (see
    qubit_core.db.models.Job) was only ever applied to the model source — Base.metadata
    .create_all() cannot retroactively alter an existing table's constraints, and there was no
    Alembic migration for it either. Every scan creates a Job row, so this hit every real
    project. Fixed by migration 29c500adeb13 + running pending migrations at API startup
    (qubit_api.app.create_app). A brand-new test database always goes through create_all(), which
    already has today's schema, so this test only proves the endpoint itself now succeeds
    end-to-end — the migration-application path is exercised separately against a real,
    pre-existing database (verified manually; the migration predates any app code that could
    assert it in a hermetic test without shipping a stale fixture database)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    with _make_client(tmp_path) as client:
        project_id = client.post(
            "/api/v1/projects",
            json={"name": "Delete Me", "root_path": str(repo)},
        ).json()["id"]

        scan_id = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)]},
        ).json()["scan"]["id"]
        _wait_for_scan(client, scan_id)

        # The scan above created at least one Job row referencing this project — the exact
        # shape that used to trip the FK constraint on delete.
        delete_resp = client.delete(f"/api/v1/projects/{project_id}")
        assert delete_resp.status_code == 204

        assert client.get(f"/api/v1/projects/{project_id}").status_code == 404
        assert client.get(f"/api/v1/scans/{scan_id}").status_code == 404


def test_trends_and_scan_diff(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with _make_client(tmp_path) as client:
        project = client.post(
            "/api/v1/projects",
            json={"name": "Trend Project", "root_path": str(repo)},
        ).json()
        project_id = project["id"]

        _write_repo(repo, include_md5=True, include_rsa=False)
        scan_1 = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)]},
        ).json()["scan"]["id"]
        _wait_for_scan(client, scan_1)

        _write_repo(repo, include_md5=True, include_rsa=True)
        scan_2 = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)]},
        ).json()["scan"]["id"]
        _wait_for_scan(client, scan_2)

        trends = client.get(f"/api/v1/projects/{project_id}/trends")
        assert trends.status_code == 200
        trend_items = trends.json()
        assert len(trend_items) == 2
        assert trend_items[0]["total"] == 1
        assert trend_items[1]["total"] == 2

        diff_resp = client.get(f"/api/v1/scans/{scan_2}/diff", params={"against": scan_1})
        assert diff_resp.status_code == 200
        diff = diff_resp.json()
        assert len(diff["added"]) == 1
        assert len(diff["removed"]) == 0
        assert len(diff["persisting"]) == 1


def test_scan_rejects_target_outside_project_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write_repo(outside)
    with _make_client(tmp_path) as client:
        project_id = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "root_path": str(repo)},
        ).json()["id"]
        response = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(outside)]},
        )
        assert response.status_code == 400
        payload = response.json()
        assert "outside project root" in payload["detail"]


def test_auth_missing_token(tmp_path: Path) -> None:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
    # No headers injected
    client = TestClient(create_app(settings))
    response = client.get("/api/v1/projects")
    assert response.status_code == 401


def test_auth_invalid_token(tmp_path: Path) -> None:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer bad-token"})
    response = client.get("/api/v1/projects")
    assert response.status_code == 401


def test_auth_whoami(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        response = client.get("/api/v1/auth/whoami")
        assert response.status_code == 200
        assert response.json()["scopes"] == "rw"


def test_migrate_workflow_plan_generate_review(tmp_path: Path) -> None:
    """Full REST migration workflow: scan -> plan -> queue -> generate -> review (doc 03 §5.1)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo, include_rsa=False)  # md5 asset matches rule py-weakhash-01
    with _make_client(tmp_path) as client:
        project_id = client.post("/api/v1/projects", json={"name": "Mig"}).json()["id"]
        scan_id = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)], "run_risk": True},
        ).json()["scan"]["id"]
        assert _wait_for_scan(client, scan_id)["status"] == "succeeded"

        # plan
        plan_resp = client.post("/api/v1/migrate/plans", json={"min_risk": 0.0})
        assert plan_resp.status_code == 201
        plan = plan_resp.json()
        assert plan["status"] == "active"
        assert plan["stats"]["tasks"] >= 1

        # listed
        assert any(p["id"] == plan["id"] for p in client.get("/api/v1/migrate/plans").json())

        # queue carries asset context + matched rule
        queue = client.get(f"/api/v1/migrate/plans/{plan['id']}/queue").json()
        assert len(queue) >= 1
        task = next(t for t in queue if t["algorithm"] == "MD5")
        assert task["state"] == "ready"
        assert task["rule_id"] == "py-weakhash-01"
        assert task["file_path"]

        # generate a real codemod patch
        gen = client.post(f"/api/v1/migrate/tasks/{task['id']}/generate", json={})
        assert gen.status_code == 200, gen.text
        patch = gen.json()
        assert patch["diff_text"].startswith("---")
        assert "sha256" in patch["diff_text"] or "argon2" in patch["diff_text"]
        assert patch["status"] == "proposed"

        # review -> approve
        rev = client.post(
            f"/api/v1/migrate/patches/{patch['id']}/review",
            json={"approve": True, "note": "lgtm"},
        )
        assert rev.status_code == 200
        assert rev.json()["status"] == "approved"

        # double-review is rejected
        again = client.post(
            f"/api/v1/migrate/patches/{patch['id']}/review", json={"approve": False}
        )
        assert again.status_code == 422


def test_algorithm_timeline_returns_real_curve(tmp_path: Path) -> None:
    # GET /risk/timeline?algorithm= runs the real Monte-Carlo simulator on demand (no scan needed).
    with _make_client(tmp_path) as client:
        r = client.get("/api/v1/risk/timeline", params={"algorithm": "RSA-2048"})
        assert r.status_code == 200
        body = r.json()
        assert body["algorithm"] == "RSA-2048"
        assert len(body["years"]) == len(body["cdf"]) > 0
        # A real CDF is monotonically non-decreasing and bounded in [0, 1].
        assert body["cdf"] == sorted(body["cdf"])
        assert 0.0 <= body["cdf"][0] and body["cdf"][-1] <= 1.0
        assert body["p05_year"] <= body["median_year"] <= body["p95_year"]
        assert body["n_trials"] > 0


def test_algorithm_timeline_unknown_algorithm_404(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        r = client.get("/api/v1/risk/timeline", params={"algorithm": "ML-KEM-768"})
        assert r.status_code == 404


def test_asset_hndl_explanation(tmp_path: Path) -> None:
    """Per-asset HNDL factor decomposition with BN/closed-form agreement (doc 02 §6.2)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo, include_md5=False)  # RSA-2048 (Shor) asset present
    with _make_client(tmp_path) as client:
        pid = client.post("/api/v1/projects", json={"name": "H"}).json()["id"]
        sid = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"targets": [str(repo)], "run_risk": True},
        ).json()["scan"]["id"]
        assert _wait_for_scan(client, sid)["status"] == "succeeded"

        assets = client.get(f"/api/v1/scans/{sid}/assets").json()["items"]
        rsa = next(a for a in assets if a["algorithm"] == "RSA-2048")

        r = client.get(f"/api/v1/assets/{rsa['id']}/hndl")
        assert r.status_code == 200
        body = r.json()
        assert body["vulnerable"] is True and body["shor"] is True
        assert 0.0 <= body["harvest_prob"] <= 1.0
        assert 0.0 <= body["p_decrypt"] <= 1.0
        # closed-form ≈ harvest · p_decrypt, and the BN agrees to <0.02
        assert abs(body["p_hndl_closed_form"] - body["harvest_prob"] * body["p_decrypt"]) < 1e-3
        assert body["bn_closed_form_agreement"] < 0.02
        assert "score_source" in body  # always present (closed-form when no regressor)

        # If the shipped XGBoost model + xgboost are available, the regressor tier is surfaced.
        if body.get("regressor") is not None:
            reg = body["regressor"]
            assert body["score_source"] == "xgb"
            assert 0.0 <= reg["ci_low"] <= reg["score"] <= reg["ci_high"] <= 1.0
            assert len(reg["shap_top"]) == 8
            assert all("feature" in s and "contribution" in s for s in reg["shap_top"])


def test_asset_hndl_missing_404(tmp_path: Path) -> None:
    import uuid

    with _make_client(tmp_path) as client:
        r = client.get(f"/api/v1/assets/{uuid.uuid4()}/hndl")
        assert r.status_code == 404


def test_algorithm_timeline_survey_blend(tmp_path: Path) -> None:
    # blend=true fuses the expert-survey CDF (doc 02 §6.1.5) and reports the weight used.
    with _make_client(tmp_path) as client:
        r = client.get(
            "/api/v1/risk/timeline",
            params={"algorithm": "RSA-2048", "blend": "true", "weight": "0.3"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["blended"] is True
        assert body["survey_weight"] == 0.3
        assert body["cdf"] == sorted(body["cdf"])
        assert body["p05_year"] <= body["median_year"] <= body["p95_year"]


def test_custom_api_token_is_honored(tmp_path: Path) -> None:
    # regression: create_app(settings) must thread the token into auth (not a fresh Settings()).
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'q.db').as_posix()}",
        api_token="a-custom-token",
        create_schema_on_startup=True,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/api/v1/projects").status_code == 401  # no token
        ok = client.get("/api/v1/projects", headers={"Authorization": "Bearer a-custom-token"})
        assert ok.status_code == 200
        wrong = client.get("/api/v1/projects", headers={"Authorization": "Bearer default-token"})
        assert wrong.status_code == 401


# ---------------------------------------------------------------------------
# E5 — Migration Knowledge Base endpoint
# ---------------------------------------------------------------------------


def test_meta_migration_kb_structure(tmp_path: Path) -> None:
    """GET /meta/migration-kb returns versioned KB with at least 6 entries (no auth needed)."""
    client = _make_client(tmp_path)
    resp = client.get("/api/v1/meta/migration-kb")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "version" in body
    assert body["version"].startswith("20")  # e.g. "2026.08"
    assert "file_hash_sha256" in body
    assert len(body["file_hash_sha256"]) == 64
    assert body["entry_count"] >= 6
    assert len(body["entries"]) == body["entry_count"]


def test_meta_migration_kb_rsa_kex_entry(tmp_path: Path) -> None:
    """The RSA kex entry maps to ML-KEM-768 hybrid."""
    client = _make_client(tmp_path)
    body = client.get("/api/v1/meta/migration-kb").json()
    rsa_kex = next(
        (
            e
            for e in body["entries"]
            if e["vuln"]["family"] == "RSA" and e["vuln"]["usage_context"] == "kex"
        ),
        None,
    )
    assert rsa_kex is not None, "RSA kex entry must exist in KB"
    assert rsa_kex["target"]["algorithm"] == "ML-KEM-768"
    assert rsa_kex["target"]["mode"] == "hybrid"


# ---------------------------------------------------------------------------
# E2 — Agility Policy endpoint
# ---------------------------------------------------------------------------


def test_meta_agility_policy_structure(tmp_path: Path) -> None:
    """GET /meta/agility-policy returns versioned policy with kex/signature defaults."""
    client = _make_client(tmp_path)
    resp = client.get("/api/v1/meta/agility-policy")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["version"].startswith("20")
    assert "kex" in body["defaults"]
    assert "signature" in body["defaults"]
    assert body["defaults"]["kex"]["target"] == "ML-KEM-768"
    assert body["defaults"]["kex"]["mode"] == "hybrid"
    assert body["defaults"]["signature"]["target"] == "ML-DSA-65"
    assert body["defaults"]["signature"]["mode"] == "pure"


def test_meta_agility_policy_no_auth_required(tmp_path: Path) -> None:
    """Agility policy is public meta info — no bearer token required."""
    db_path = tmp_path / "q.db"
    settings = Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        create_schema_on_startup=True,
    )
    with TestClient(create_app(settings)) as client:
        resp = client.get("/api/v1/meta/agility-policy")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# E1 — Per-asset Recommendation endpoint
# ---------------------------------------------------------------------------


def test_asset_recommendation_rsa_kex(tmp_path: Path) -> None:
    """A scanned RSA-2048 asset returns a rule-matched or KB-matched recommendation."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo, include_rsa=True, include_md5=False)

    with _make_client(tmp_path) as client:
        # Create project + scan
        proj_resp = client.post(
            "/api/v1/projects",
            json={"name": "rec-test", "root_path": str(repo)},
        )
        assert proj_resp.status_code == 201
        pid = proj_resp.json()["id"]
        scan_resp = client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"targets": [str(repo)]},
        )
        assert scan_resp.status_code == 202
        scan_id = scan_resp.json()["scan"]["id"]
        scan = _wait_for_scan(client, scan_id)
        assert scan["status"] == "succeeded"

        # Get assets for this scan
        assets_resp = client.get(f"/api/v1/scans/{scan_id}/assets")
        assert assets_resp.status_code == 200
        assets = assets_resp.json()["items"]
        rsa_asset = next((a for a in assets if "RSA" in a["algorithm"]), None)
        assert rsa_asset is not None, "RSA asset must be detected"

        # Get recommendation
        rec_resp = client.get(f"/api/v1/assets/{rsa_asset['id']}/recommendation")
        assert rec_resp.status_code == 200, rec_resp.text
        rec = rec_resp.json()
        assert rec["asset_id"] == rsa_asset["id"]
        assert rec["current"]["algorithm"] == rsa_asset["algorithm"]
        assert "ML-KEM" in rec["target"]["algorithm"] or "ML-DSA" in rec["target"]["algorithm"]
        assert rec["source"] in {"rule", "kb", "agility-policy"}
        assert 0.0 <= rec["confidence"] <= 1.0


def test_asset_recommendation_non_vulnerable_404(tmp_path: Path) -> None:
    """A non-vulnerable asset (e.g. AES-256) returns 404 — no action needed."""
    import uuid

    from qubit_core import CryptoAsset, asset_to_row
    from qubit_core.db import get_engine, session_factory
    from qubit_core.schemas import (
        AssetType,
        Confidence,
        Evidence,
        QuantumAttack,
        QuantumVulnerability,
        Sensitivity,
        SourceScanner,
        UsageContext,
    )

    db_path = tmp_path / "q2.db"
    settings = Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        create_schema_on_startup=True,
        api_token="tok",
    )
    engine = get_engine(settings.db_url)
    sf = session_factory(engine)

    # Build a non-vulnerable asset and write it to DB
    scan_id = uuid.uuid4()
    project_id = uuid.uuid4()
    asset = CryptoAsset(
        id=uuid.uuid4(),
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="AES-256",
        key_size=256,
        usage_context=UsageContext.encryption_at_rest,
        sensitivity=Sensitivity.unknown,
        quantum_vulnerable=QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none),
        evidence=Evidence(snippet="AES256 = True"),
        confidence=Confidence.high,
    )
    from qubit_core.db import Base

    Base.metadata.create_all(engine)
    with sf() as session:
        from qubit_core.db import ProjectRow, ScanRow

        proj_row = ProjectRow(id=project_id, name="p", slug="p")
        session.add(proj_row)
        session.flush()  # flush project first to satisfy scan FK

        scan_row = ScanRow(
            id=scan_id,
            project_id=project_id,
            seq=1,
            targets=[],
            status="succeeded",
        )
        session.add(scan_row)
        session.flush()  # flush scan before asset

        row = asset_to_row(asset, scan_id=scan_id, project_id=project_id)
        session.add(row)
        session.commit()

    with TestClient(create_app(settings), headers={"Authorization": "Bearer tok"}) as client:
        resp = client.get(f"/api/v1/assets/{asset.id}/recommendation")
        assert resp.status_code == 404


def test_asset_recommendation_missing_asset_404(tmp_path: Path) -> None:
    """A completely unknown asset ID returns 404."""
    import uuid

    with _make_client(tmp_path) as client:
        resp = client.get(f"/api/v1/assets/{uuid.uuid4()}/recommendation")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# E3 — Dependency Graph API endpoint
# ---------------------------------------------------------------------------


def test_migrate_plan_graph(tmp_path: Path) -> None:
    """GET /migrate/plans/{plan_id}/graph returns the dependency graph."""
    client = _make_client(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo, include_rsa=True, include_md5=False)

    # 1. Project + Scan
    proj_resp = client.post("/api/v1/projects", json={"name": "graph-test", "root_path": str(repo)})
    pid = proj_resp.json()["id"]
    scan_resp = client.post(f"/api/v1/projects/{pid}/scans", json={"targets": [str(repo)]})
    scan_id = scan_resp.json()["scan"]["id"]
    scan = _wait_for_scan(client, scan_id)
    assert scan["status"] == "succeeded"

    # 2. Plan
    plan_resp = client.post("/api/v1/migrate/plans", json={"project_id": pid})
    assert plan_resp.status_code == 201
    plan_id = plan_resp.json()["id"]

    # 3. Graph
    response = client.get(f"/api/v1/migrate/plans/{plan_id}/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "units" in data
    assert len(data["nodes"]) > 0


def test_governance_endpoint(tmp_path: Path):
    # Setup asset and task
    client = _make_client(tmp_path)
    from uuid import uuid4

    from qubit_core.db import AssetRow, ProjectRow, ScanRow
    from qubit_migrate.state.models import MigrationPlan, MigrationTask, MigrationUnit
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    db_path = tmp_path / "qubit-api.db"
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    with Session(engine) as db_session:
        project = ProjectRow(id=uuid4(), name="t", slug="t")
        db_session.add(project)
        db_session.flush()
        scan = ScanRow(id=uuid4(), project_id=project.id, seq=1, status="succeeded")
        db_session.add(scan)
        db_session.flush()

        asset_id = uuid4()
        db_session.add(
            AssetRow(
                id=asset_id,
                project_id=project.id,
                scan_id=scan.id,
                fingerprint="abc",
                source_scanner="code",
                asset_type="key",
                algorithm="RSA",
                sensitivity="public",
            )
        )
        plan = MigrationPlan(id=uuid4())
        db_session.add(plan)
        db_session.flush()
        unit = MigrationUnit(id=uuid4(), plan_id=plan.id)
        db_session.add(unit)
        db_session.flush()
        task = MigrationTask(
            id=uuid4(), plan_id=plan.id, unit_id=unit.id, asset_id=asset_id, state="pending"
        )
        db_session.add(task)
        db_session.commit()
        task_id = task.id

    response = client.get(f"/api/v1/migrate/tasks/{task_id}/governance")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "blocked"
    assert data["required"] == 1
    assert data["current"] == 0


def test_list_jobs_with_a_real_job_row(tmp_path: Path) -> None:
    """Regression: `JobOut` declared created_at/started_at/finished_at as `str` while the ORM stores
    `datetime`, so Pydantic v2 response validation failed and BOTH /jobs and /jobs/{id} returned 500
    for any non-empty jobs table. The previous tests only ever hit an EMPTY jobs list, which
    validates trivially — hence this asserts against a real persisted row.
    """
    from uuid import uuid4

    from qubit_core.db import Job

    client = _make_client(tmp_path)
    app = client.app

    with app.state.session_factory() as db_session:  # type: ignore[attr-defined]
        job = Job(id=uuid4(), kind="scan", status="succeeded", payload={"x": 1})
        db_session.add(job)
        db_session.commit()
        job_id = job.id

    listed = client.get("/api/v1/jobs")
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert any(r["id"] == str(job_id) for r in rows)
    # ISO-8601 on the wire, not a Python repr
    row = next(r for r in rows if r["id"] == str(job_id))
    assert row["created_at"].startswith("20") and "T" in row["created_at"]

    single = client.get(f"/api/v1/jobs/{job_id}")
    assert single.status_code == 200, single.text
    assert single.json()["kind"] == "scan"


# ---------------------------------------------------------------------------
# Scanner selection actually reaches the scanner
# ---------------------------------------------------------------------------


def test_scanner_name_enum_matches_the_scanner_dispatch_vocabulary() -> None:
    """`ScannerName` and `qubit_scanner.SCANNER_NAMES` must not drift: the scanner is what
    dispatches on these strings, so a name the API accepts but the scanner does not know would raise
    at scan time, and a scanner the API cannot name is unreachable through the REST surface."""
    from qubit_api.schemas import ScannerName
    from qubit_scanner import SCANNER_NAMES

    assert {s.value for s in ScannerName} == set(SCANNER_NAMES)


def test_requested_scanners_are_honored_not_just_recorded(tmp_path: Path) -> None:
    """The defect this covers: the requested scanner list was stored on the scan row and then
    never passed to `scan_paths`, so selection was recorded and silently ignored. A code-only scan
    of a tree whose ONLY crypto lives in a config file must therefore find nothing, and a
    config-only scan of the same tree must find something."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "nginx.conf").write_text(
        "server {\n    ssl_protocols TLSv1 TLSv1.1;\n}\n", encoding="utf-8"
    )

    with _make_client(tmp_path) as client:
        project_id = client.post(
            "/api/v1/projects", json={"name": "sel", "root_path": str(repo)}
        ).json()["id"]

        def scan_with(names: list[str]) -> int:
            resp = client.post(
                f"/api/v1/projects/{project_id}/scans",
                json={"targets": [str(repo)], "scanners": names, "run_risk": False},
            )
            assert resp.status_code == 202, resp.text
            scan_id = resp.json()["scan"]["id"]
            assert _wait_for_scan(client, scan_id)["status"] == "succeeded"
            return int(client.get(f"/api/v1/scans/{scan_id}/assets").json()["total"])

        assert scan_with(["code"]) == 0, (
            "a code-only scan returned config findings, so the scanner selection was ignored"
        )
        assert scan_with(["config"]) > 0, "config scanner found nothing in a weak nginx.conf"


def test_unknown_scanner_name_is_rejected_not_ignored(tmp_path: Path) -> None:
    """A typo must not present as a clean scan of zero findings (NFR-7: fail loudly)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    with _make_client(tmp_path) as client:
        project_id = client.post(
            "/api/v1/projects", json={"name": "bad-sel", "root_path": str(repo)}
        ).json()["id"]
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)], "scanners": ["cod"], "run_risk": False},
        )
        assert resp.status_code == 422, resp.text


def test_scan_creation_hands_back_the_job_handle_and_says_to_poll(tmp_path: Path) -> None:
    """`POST /projects/{id}/scans` is genuinely asynchronous — a JobRunner executes the scan off the
    request path — so returning `status: "running"` with 0 assets is correct. What was wrong was the
    response never saying so: `job` was hardcoded to `None`, and the warning claimed "Synchronous
    scan execution is enabled in M1; JobRunner lands in M2", which is untrue. A client that believed
    it would read through and conclude the scan found nothing."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    with _make_client(tmp_path) as client:
        project_id = client.post(
            "/api/v1/projects", json={"name": "async", "root_path": str(repo)}
        ).json()["id"]
        resp = client.post(f"/api/v1/projects/{project_id}/scans", json={"targets": [str(repo)]})
        assert resp.status_code == 202
        body = resp.json()

        assert body["job"] is not None, "async scan returned no job handle to poll"
        assert body["job"]["kind"] == "scan"
        UUID(body["job"]["id"])  # a real job id, not a placeholder

        assert "poll" in body["warning"].lower()
        assert "synchronous" not in body["warning"].lower()

        # And the handle is honest: polling really does settle on a finished scan.
        assert _wait_for_scan(client, body["scan"]["id"])["status"] == "succeeded"


def test_asset_batch_ingest_lands_bridge_findings_in_the_inventory(tmp_path: Path) -> None:
    """`qubit bridge probe --push` and `qubit demo run --all` have always POSTed to
    /api/v1/assets/batch, but the endpoint did not exist — so the push 404ed on every run and the
    demo reported "Assets not pushed (API unreachable)", blaming reachability for a missing route.

    The bridge probe is what proves a deployment negotiated X25519MLKEM768, so its findings belong
    in
    the same inventory and CBOM as a filesystem scan rather than being printed and discarded."""
    with _make_client(tmp_path) as client:
        payload = {
            "project": "bridge",
            "label": "bridge probe localhost:8443",
            "targets": ["localhost:8443"],
            "assets": [
                {
                    "source_scanner": "network",
                    "asset_type": "protocol",
                    "algorithm": "X25519MLKEM768",
                    "usage_context": "kex",
                    "quantum_vulnerable": {"vulnerable": False, "attack": "none"},
                    "location": {"host": "localhost", "service": "tcp/8443"},
                    "evidence": {},
                },
                {
                    "source_scanner": "cert",
                    "asset_type": "certificate",
                    "algorithm": "RSA-2048",
                    "usage_context": "signature",
                    "quantum_vulnerable": {"vulnerable": True, "attack": "shor"},
                    "location": {"host": "localhost", "service": "tcp/8443"},
                    "evidence": {},
                },
            ],
        }
        resp = client.post("/api/v1/assets/batch", json=payload)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["ingested"] == 2
        scan_id = body["scan_id"]

        # The scan row must describe where the findings came from, not masquerade as a file scan.
        scan = client.get(f"/api/v1/scans/{scan_id}").json()
        assert scan["status"] == "succeeded"
        assert scan["scanners"] == ["network"]
        assert scan["targets"] == ["localhost:8443"]

        assets = client.get(f"/api/v1/scans/{scan_id}/assets").json()
        assert {a["algorithm"] for a in assets["items"]} == {"X25519MLKEM768", "RSA-2048"}

        # And they must be exportable through the same CBOM path as everything else — that is the
        # whole point of ingesting them rather than printing them.
        cbom = client.get(f"/api/v1/scans/{scan_id}/cbom").json()
        assert cbom["specVersion"] == "1.7"
        assert len(cbom["components"]) == 2


def test_asset_batch_requires_auth_and_rejects_an_empty_batch(tmp_path: Path) -> None:
    """The bridge client sent no Authorization header, so this would have been 401 even once the
    route existed — worth pinning that the route really is protected."""
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
    with TestClient(create_app(settings)) as anon:
        assert anon.post("/api/v1/assets/batch", json={"assets": []}).status_code == 401

    with _make_client(tmp_path) as client:
        assert client.post("/api/v1/assets/batch", json={"assets": []}).status_code == 422
