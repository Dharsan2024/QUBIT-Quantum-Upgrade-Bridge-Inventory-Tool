"""The SQL-aggregated summary/trends/diff must equal the row-hydrating versions they replaced.

`scan_trends`, `scan_summary` and `scan_diff` each used to `select(AssetRow)` and build a full ORM
object per asset — JSON `location`/`evidence` parsed for every one — to compute a handful of counts.
Profiled against 20,000 assets that was 470 ms for one trends call. They now aggregate in SQL.

An optimization that changes the numbers is a bug, not an optimization, so these tests hold the new
implementations against the old logic transcribed literally. The median is the delicate one: there
is no portable SQL median, so it is computed with a window-function idiom, and an early version got
the
even-count case wrong (float division made the middle-rank predicate select one row instead of two,
returning 0.3 where the answer was 0.25). That is exactly what `median` cases below pin down.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from statistics import median

import pytest
from qubit_api.services import _median_risk_by_scan, scan_diff, scan_summary, scan_trends
from qubit_core.db import AssetRow, Base, ProjectRow, ScanRow
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

_ALGS = ["RSA-2048", "ECDSA-P256", "MD5", "AES-128", "TLSv1.0", "X25519"]
_USAGE = ["kex", "signature", "hash", "tls", "encryption-at-rest"]


def _asset(
    scan_id, project_id, i: int, *, score: float | None, vulnerable: bool = True
) -> AssetRow:
    return AssetRow(
        id=uuid.uuid4(),
        scan_id=scan_id,
        project_id=project_id,
        fingerprint=f"fp-{scan_id}-{i}",
        source_scanner="code",
        asset_type="algorithm-use",
        algorithm=_ALGS[i % len(_ALGS)],
        usage_context=_USAGE[i % len(_USAGE)],
        sensitivity="unknown",
        qv_vulnerable=vulnerable,
        qv_attack="shor",
        confidence="high",
        stale=False,
        # `line` is 1-based: the frozen Location schema requires >= 1, and a 0 here makes every
        # endpoint that hydrates the row raise a validation error.
        location={"file_path": f"src/mod{i % 7}.py", "line": (i % 50) + 1},
        evidence={},
        discovered_at=datetime.now(UTC),
        last_seen_at=datetime.now(UTC),
        risk_score=score,
        mosca_margin_years=float((i % 10) - 5),
        priority_rank=(i % 9) + 1,
        migration_status="not-started",
    )


@pytest.fixture
def seeded() -> Session:
    """Two scans with overlapping fingerprints, some unscored assets, some non-vulnerable ones."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="agg", slug="agg")
    session.add(project)
    session.flush()

    for seq in (1, 2):
        scan = ScanRow(
            project_id=project.id,
            seq=seq,
            status="succeeded",
            targets=["/srv/app"],
            scanners=["code"],
            stats={},
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        session.add(scan)
        session.flush()
        for i in range(37):  # odd count, so the median hits the single-middle-rank branch
            session.add(
                _asset(
                    scan.id,
                    project.id,
                    i,
                    # every 5th asset is unscored, so the None-handling paths are exercised
                    score=None if i % 5 == 0 else (i % 100) / 100.0,
                    vulnerable=(i % 6 != 0),
                )
            )
    session.commit()
    return session


# --- literal transcriptions of the implementations that were replaced --------------------------


def _old_trends(session: Session, project_id) -> list[dict]:
    scans = session.scalars(
        select(ScanRow).where(ScanRow.project_id == project_id).order_by(ScanRow.seq.asc())
    ).all()
    ids = [s.id for s in scans]
    rows = session.scalars(select(AssetRow).where(AssetRow.scan_id.in_(ids))).all()
    by_scan: dict = {i: [] for i in ids}
    for r in rows:
        by_scan[r.scan_id].append(r)
    out = []
    for scan in scans:
        group = by_scan[scan.id]
        scores = [r.risk_score for r in group if r.risk_score is not None]
        out.append(
            {
                "scan_id": scan.id,
                "seq": scan.seq,
                "total": len(group),
                "vulnerable": sum(1 for r in group if r.qv_vulnerable),
                "median_risk": median(scores) if scores else None,
                "negative_mosca": sum(1 for r in group if (r.mosca_margin_years or 0.0) < 0.0),
            }
        )
    return out


def _old_summary(session: Session, scan_id) -> dict:
    rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan_id)).all()
    by_algorithm: dict[str, dict[str, int]] = {}
    by_usage: dict[str, int] = {}
    for row in rows:
        algo = by_algorithm.setdefault(row.algorithm, {"count": 0, "vulnerable": 0})
        algo["count"] += 1
        if row.qv_vulnerable:
            algo["vulnerable"] += 1
        by_usage[row.usage_context] = by_usage.get(row.usage_context, 0) + 1
    return {
        "total_assets": len(rows),
        "by_algorithm": by_algorithm,
        "by_usage_context": by_usage,
        "risk_scores": sorted(r.risk_score for r in rows if r.risk_score is not None),
    }


# --- equivalence -------------------------------------------------------------------------------


def test_trends_match_the_row_hydrating_implementation(seeded: Session) -> None:
    project_id = seeded.scalar(select(ProjectRow.id))
    old = _old_trends(seeded, project_id)
    new = scan_trends(seeded, project_id)
    assert len(new) == len(old)
    for want, got in zip(old, new, strict=True):
        assert got.scan_id == want["scan_id"]
        assert got.total == want["total"]
        assert got.vulnerable == want["vulnerable"]
        assert got.negative_mosca == want["negative_mosca"]
        assert got.median_risk == pytest.approx(want["median_risk"])


def test_summary_matches_the_row_hydrating_implementation(seeded: Session) -> None:
    scan_id = seeded.scalar(select(ScanRow.id).order_by(ScanRow.seq))
    old = _old_summary(seeded, scan_id)
    new = scan_summary(seeded, scan_id)
    assert new["total_assets"] == old["total_assets"]
    assert new["by_algorithm"] == old["by_algorithm"]
    assert new["by_usage_context"] == old["by_usage_context"]
    assert new["risk_scores"] == old["risk_scores"]


def test_summary_top_10_is_ordered_by_risk_with_nulls_last(seeded: Session) -> None:
    """`coalesce(risk_score, 0.0)` reproduces the previous Python `r.risk_score or 0.0` ordering.
    Without it the backend's own NULL ordering decides, and SQLite puts NULLs FIRST on a DESC sort —
    which would put the unscored assets at the top of a "highest risk" list."""
    scan_id = seeded.scalar(select(ScanRow.id).order_by(ScanRow.seq))
    top = scan_summary(seeded, scan_id)["top_10_risk"]
    assert len(top) == 10
    scores = [entry["risk_score"] or 0.0 for entry in top]
    assert scores == sorted(scores, reverse=True)
    assert scores[0] > 0.0  # a real finding leads, not a NULL


def test_diff_reports_the_same_sets_and_deltas(seeded: Session) -> None:
    ids = list(seeded.scalars(select(ScanRow.id).order_by(ScanRow.seq)).all())
    result = scan_diff(seeded, ids[0], ids[1])
    # Fingerprints embed the scan id in this fixture, so the two scans share none — which is exactly
    # the shape that proves added/removed are computed from both sides rather than from one.
    assert len(result["added"]) == 37
    assert len(result["removed"]) == 37
    assert result["persisting"] == []
    assert result["risk_deltas"] == []


# --- the median idiom, which is where the subtle bug was ---------------------------------------


@pytest.mark.parametrize(
    "scores",
    [
        [0.1, 0.2, 0.3],  # odd
        [0.1, 0.2, 0.3, 0.4],  # even — the case a float-division rank got wrong (0.3 vs 0.25)
        [0.5],  # single
        [],  # none scored
        [0.2, 0.2, 0.2, 0.9],  # duplicates
        [0.0, 1.0],  # two, wide apart
        [0.7, 0.1, 0.4, 0.9, 0.2, 0.6],  # unsorted input
    ],
)
def test_median_in_sql_equals_statistics_median(scores: list[float]) -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        project = ProjectRow(name="m", slug="m")
        session.add(project)
        session.flush()
        scan = ScanRow(
            project_id=project.id, seq=1, status="succeeded", targets=[], scanners=[], stats={}
        )
        session.add(scan)
        session.flush()
        for i, score in enumerate(scores):
            session.add(_asset(scan.id, project.id, i, score=score))
        session.commit()

        got = _median_risk_by_scan(session, [scan.id]).get(scan.id)
        want = median(scores) if scores else None
        if want is None:
            assert got is None
        else:
            assert got == pytest.approx(want)


def test_median_helper_handles_an_empty_scan_list() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        assert _median_risk_by_scan(session, []) == {}
