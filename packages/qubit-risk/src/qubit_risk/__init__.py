"""qubit-risk — HNDL risk quantification.

M1: Monte-Carlo CRQC timeline + heuristic sensitivity + Mosca
margin + static, explainable risk score, composed by RiskPipeline
over CryptoAssets. (Survey blend, BN, DistilBERT, XGBoost = M2.)
"""

from __future__ import annotations

from .cnsa2 import CNSA2Report, MilestoneResult, evaluate_cnsa2
from .config import RiskConfig, load_config
from .mosca import MoscaResult, mosca
from .pipeline import RiskPipeline
from .score import ScoreResult, score_asset
from .sensitivity import SensitivityResult, classify_sensitivity
from .timeline import CRQCTimelineSimulator, TimelineCurve

__version__ = "0.1.0"

__all__ = [
    "CNSA2Report",
    "CRQCTimelineSimulator",
    "MilestoneResult",
    "MoscaResult",
    "RiskConfig",
    "RiskPipeline",
    "ScoreResult",
    "SensitivityResult",
    "TimelineCurve",
    "__version__",
    "classify_sensitivity",
    "evaluate_cnsa2",
    "load_config",
    "mosca",
    "score_asset",
]
