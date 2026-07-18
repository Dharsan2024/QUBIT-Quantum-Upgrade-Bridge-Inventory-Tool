"""Heuristic data-sensitivity classifier + shelf-life prior (doc 02 6.3.2 / 6.3.5).

Reads the evidence snippet + file path an asset carries, scores
sensitivity-class rules, and returns the class plus its shelf-life
prior (Mosca X). Transparent and deterministic — DistilBERT is M2.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from qubit_core import CryptoAsset

from .config import RiskConfig

_Z90 = 1.2815515594  # standard-normal 90th percentile

_IDENTIFIER_WHERES = {"identifier", "comment"}  # M1: both searched against the snippet text


@dataclass(frozen=True)
class SensitivityResult:
    sensitivity: str
    shelf_life_years: float  # E[L]
    shelf_life_p90: float  # P90 (Mosca X)
    matched: list[str]  # rule classes that fired (trace)


def _shelf(cfg: RiskConfig, cls: str) -> tuple[float, float]:
    spec = cfg.shelf_life_priors["classes"].get(cls, {})
    if "fixed" in spec:
        return float(spec["fixed"]), float(spec["fixed"])
    mu, sigma = float(spec["mu_ln"]), float(spec["sigma_ln"])
    mean = math.exp(mu + sigma * sigma / 2.0)
    p90 = math.exp(mu + sigma * _Z90)
    return mean, p90


def classify_sensitivity(asset: CryptoAsset, cfg: RiskConfig) -> SensitivityResult:
    snippet = asset.evidence.snippet or ""
    file_path = asset.location.file_path or ""
    rules = cfg.sensitivity_rules

    scores: dict[str, float] = {}
    matched: list[str] = []
    for rule in rules["rules"]:
        wheres = set(rule["where"])
        text = ""
        if wheres & _IDENTIFIER_WHERES:
            text += snippet + "\n"
        if "file_path" in wheres:
            text += file_path
        if text and re.search(rule["regex"], text):
            scores[rule["class"]] = scores.get(rule["class"], 0.0) + float(rule["weight"])
            matched.append(rule["class"])

    threshold = float(rules["score_threshold"])
    cls = "unknown"
    if scores:
        top = max(scores.values())
        if top >= threshold:
            winners = [c for c, s in scores.items() if s == top]
            order = rules["tie_break_order"]
            cls = min(winners, key=lambda c: order.index(c) if c in order else len(order))

    if cls == "unknown":
        cls = rules.get("usage_defaults", {}).get(asset.usage_context.value, "unknown")

    mean, p90 = _shelf(cfg, cls)
    return SensitivityResult(
        sensitivity=cls,
        shelf_life_years=mean,
        shelf_life_p90=p90,
        matched=matched,
    )


__all__ = ["SensitivityResult", "classify_sensitivity"]
