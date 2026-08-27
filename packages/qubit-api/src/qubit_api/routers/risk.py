from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from qubit_core.db import Job, RiskRun
from qubit_core.mapping import row_to_asset
from qubit_risk import CRQCTimelineSimulator
from qubit_risk.config import load_config
from qubit_risk.hndl import harvest_prob, hndl_bayes_net, p_decrypt_integral
from qubit_risk.score import exposure_of
from qubit_risk.timeline.survey import BlendedTimeline
from sqlalchemy.orm import Session

from ..auth import get_current_tenant
from ..deps import get_session
from ..jobs.runner import JobRunner
from ..services import require_asset, require_risk_run, require_scan

router = APIRouter(tags=["risk"])
logger = logging.getLogger(__name__)


class RiskRunOut(BaseModel):
    id: UUID
    scan_id: UUID
    status: str
    params: dict
    timeline: list | None = None
    percentiles: dict | None = None
    summary: dict | None = None
    started_at: str | None = None
    finished_at: str | None = None

    model_config = ConfigDict(from_attributes=True)


class RiskRunRequest(BaseModel):
    params: dict = {}


@router.post("/scans/{scan_id}/risk/run", status_code=status.HTTP_202_ACCEPTED)
async def run_risk_for_scan(
    scan_id: UUID,
    request: Request,
    payload: RiskRunRequest,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict[str, str]:
    scan = require_scan(session, scan_id, tenant_id)

    # Check for concurrent running risk jobs on this scan
    existing = (
        session.query(RiskRun)
        .filter(RiskRun.scan_id == scan_id, RiskRun.status.in_(["queued", "running"]))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409, detail=f"Risk run already in progress (run id: {existing.id})"
        )

    job = Job(
        kind="risk",
        tenant_id=tenant_id,
        project_id=scan.project_id,
        ref_id=scan_id,
        payload={
            "scan_id": str(scan_id),
            "params": payload.params,
        },
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    runner: JobRunner = request.app.state.job_runner
    runner.submit(job.id)  # sync: schedules the async job; do not await

    return {"job_id": str(job.id), "status": "queued"}


@router.get("/risk/runs/{risk_run_id}", response_model=RiskRunOut)
def get_risk_run(
    risk_run_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> RiskRun:
    return require_risk_run(session, risk_run_id, tenant_id)


@router.get("/scans/{scan_id}/risk/summary")
def get_risk_summary(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict:
    # The scan check is what scopes this: a run is only reachable through a scan the caller owns.
    require_scan(session, scan_id, tenant_id)
    risk_run = (
        session.query(RiskRun)
        .filter(RiskRun.scan_id == scan_id)
        .order_by(RiskRun.finished_at.desc())
        .first()
    )
    if not risk_run or risk_run.status != "succeeded":
        raise HTTPException(status_code=404, detail="Completed risk run not found for this scan")
    return risk_run.summary or {}


@router.get("/scans/{scan_id}/risk/timeline")
def get_risk_timeline(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict:
    require_scan(session, scan_id, tenant_id)
    risk_run = (
        session.query(RiskRun)
        .filter(RiskRun.scan_id == scan_id)
        .order_by(RiskRun.finished_at.desc())
        .first()
    )
    if not risk_run or risk_run.status != "succeeded":
        raise HTTPException(status_code=404, detail="Completed risk run not found for this scan")
    return {"timeline": risk_run.timeline or [], "percentiles": risk_run.percentiles or {}}


# On-demand CRQC timeline for a single algorithm — runs the real Monte-Carlo simulator (doc 02 §5.3
# `GET /risk/timeline?algorithm=`). No scan required; used by the dashboard's CRQC Timeline page.
# blend=true additionally fuses the expert-survey CDF (doc 02 §6.1.5); weight overrides w.
_SIM = CRQCTimelineSimulator()
_BLEND = BlendedTimeline()

# Optional XGBoost regressor (doc 02 §6.4): loaded once from QUBIT_RISK_XGB_DIR (default the shipped
# models/risk-xgboost). If xgboost/model is missing, endpoints degrade to closed-form/BN only.
_REGRESSOR: object | None = None
_REGRESSOR_TRIED = False


def _get_regressor():
    global _REGRESSOR, _REGRESSOR_TRIED
    if not _REGRESSOR_TRIED:
        import os
        from pathlib import Path

        _REGRESSOR_TRIED = True
        model_dir = Path(os.getenv("QUBIT_RISK_XGB_DIR", "models/risk-xgboost"))
        try:
            from qubit_risk.regressor.predict import RiskRegressor

            if RiskRegressor.available(model_dir):
                _REGRESSOR = RiskRegressor.load(model_dir)
        except Exception:  # xgboost missing / load error -> graceful degradation (NFR2)
            _REGRESSOR = None
    return _REGRESSOR


@router.get("/risk/timeline")
def get_algorithm_timeline(
    algorithm: str = "RSA-2048",
    blend: bool = False,
    weight: float | None = None,
) -> dict:
    curve = _BLEND.blend(algorithm, weight=weight) if blend else _SIM.simulate(algorithm)
    if curve is None:
        raise HTTPException(
            status_code=404,
            detail=f"No CRQC timeline for '{algorithm}' (not Shor-vulnerable / unknown)",
        )
    used_weight = (_BLEND.cfg.survey_weight if weight is None else weight) if blend else None
    return {
        "algorithm": curve.algorithm,
        "blended": blend,
        "survey_weight": used_weight,
        "years": curve.years,
        "cdf": curve.cdf,
        "cdf_stderr": curve.cdf_stderr,
        "median_year": curve.median_year,
        "p05_year": curve.p05_year,
        "p95_year": curve.p95_year,
        "n_trials": curve.n_trials,
    }


# Per-asset HNDL explanation: the factor decomposition behind the risk score, with the closed-form
# integral and its Bayesian-network agreement (doc 02 §6.2). Powers the dashboard "why this score".
@router.get("/assets/{asset_id}/hndl")
def get_asset_hndl(
    asset_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict:
    row = require_asset(session, asset_id, tenant_id)
    asset = row_to_asset(row)

    if not asset.quantum_vulnerable.vulnerable:
        return {"asset_id": str(asset_id), "algorithm": asset.algorithm, "vulnerable": False}

    curve = _SIM.simulate(asset.algorithm)
    if curve is None:
        # Grover-tier / symmetric: no CRQC arrival curve, so no HNDL factor decomposition
        return {
            "asset_id": str(asset_id),
            "algorithm": asset.algorithm,
            "vulnerable": True,
            "shor": False,
            "note": "Symmetric/Grover-tier — no CRQC timeline; scored with a fixed marginal.",
        }

    cfg = load_config()
    now = cfg.hardware_priors["reference_year"]
    sensitivity = asset.sensitivity.value if asset.sensitivity else "unknown"
    exposure = exposure_of(asset)
    shelf_spec = cfg.shelf_life_priors["classes"].get(sensitivity, {})

    harvest = harvest_prob(cfg, exposure, sensitivity)
    p_dec = p_decrypt_integral(curve, shelf_spec, now)
    closed_form = harvest * p_dec
    bn_p, factors = hndl_bayes_net(cfg).p_hndl(curve, exposure, sensitivity, shelf_spec, now)

    result = {
        "asset_id": str(asset_id),
        "algorithm": asset.algorithm,
        "vulnerable": True,
        "shor": True,
        "exposure": exposure,
        "sensitivity": sensitivity,
        "tier": factors.tier,
        "harvest_prob": round(harvest, 4),
        "p_decrypt": round(p_dec, 4),
        "p_hndl_closed_form": round(closed_form, 4),
        "p_hndl_bayes_net": round(bn_p, 4),
        "bn_closed_form_agreement": round(abs(closed_form - bn_p), 4),
        "crqc_median_year": curve.median_year,
        "persisted_score": row.risk_score,
        "score_source": "closed-form",
    }

    # XGBoost distillation tier (doc 02 §6.4): calibrated score + conformal CI + TreeSHAP top-8.
    reg = _get_regressor()
    if reg is not None:
        try:
            from qubit_risk.regressor.asset_features import build_asset_features
            from qubit_risk.sensitivity import classify_sensitivity

            sens = classify_sensitivity(asset, cfg)
            feats = build_asset_features(asset, sens, curve, cfg, now)
            pred = reg.predict(feats)  # type: ignore[attr-defined]
            result["score_source"] = pred.score_source
            result["regressor"] = {
                "score": pred.score,
                "ci_low": pred.ci_low,
                "ci_high": pred.ci_high,
                "shap_top": [{"feature": f, "contribution": c} for f, c in pred.shap_top],
            }
        except Exception:  # never let the regressor path break the explanation (NFR2)
            logger.exception("regressor explanation failed; returning closed-form/BN only")

    return result
