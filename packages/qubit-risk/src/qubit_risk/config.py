"""Load and hash the versioned parameter files under ``params/``.

All model parameters live in YAML so results are reproducible (a run records the params hash). This
module reads them once and exposes typed accessors.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PARAMS_DIR = Path(__file__).parent / "params"
_FILES = (
    "hardware_priors",
    "resource_estimates",
    "sensitivity_rules",
    "shelf_life_priors",
    "mosca",
)


@dataclass(frozen=True)
class RiskConfig:
    hardware_priors: dict[str, Any]
    resource_estimates: dict[str, Any]
    sensitivity_rules: dict[str, Any]
    shelf_life_priors: dict[str, Any]
    mosca: dict[str, Any]
    params_hash: str = field(default="")

    @property
    def seed(self) -> int:
        return int(self.hardware_priors.get("seed", 42))

    @property
    def n_trials(self) -> int:
        return int(self.hardware_priors.get("n_trials", 10000))

    def resource_for(self, algorithm: str) -> dict[str, Any] | None:
        """Return the resource estimate for an algorithm, following one level of ``alias``."""
        algos = self.resource_estimates["algorithms"]
        entry = algos.get(algorithm)
        if entry is None:
            return None
        if "alias" in entry:
            return algos.get(entry["alias"])
        return entry


@lru_cache(maxsize=1)
def load_config(params_dir: str | None = None) -> RiskConfig:
    base = Path(params_dir) if params_dir else PARAMS_DIR
    data: dict[str, dict[str, Any]] = {}
    for name in _FILES:
        data[name] = yaml.safe_load((base / f"{name}.yaml").read_text(encoding="utf-8"))
    canonical = json.dumps(data, sort_keys=True).encode("utf-8")
    params_hash = hashlib.sha256(canonical).hexdigest()[:16]
    return RiskConfig(params_hash=params_hash, **data)


__all__ = ["PARAMS_DIR", "RiskConfig", "load_config"]
