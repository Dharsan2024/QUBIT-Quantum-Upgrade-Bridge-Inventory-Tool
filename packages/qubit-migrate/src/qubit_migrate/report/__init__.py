"""Reporting artefacts released with the benchmark.

Kept out of `state/` and out of the orchestrator on purpose: what is measured and what is published
are different concerns, and mixing them is how a reporting convenience quietly becomes a
measurement decision.
"""

from .analysis import (
    BOOTSTRAP_DRAWS,
    COMPARISONS,
    DenominatorLadder,
    Interval,
    McNemarResult,
    bootstrap_rate,
    denominator_ladder,
    exact_mcnemar,
    holm,
    verified_accept,
    widest,
)
from .measurements import (
    NO_POOLED_AGGREGATE,
    SCHEMA_VERSION,
    PathSummary,
    RoutingCost,
    export,
    format_table,
    routing_cost,
    run_manifest,
    summarise_by_evidence,
    summarise_by_path,
    to_csv,
)

__all__ = [
    "BOOTSTRAP_DRAWS",
    "COMPARISONS",
    "NO_POOLED_AGGREGATE",
    "SCHEMA_VERSION",
    "DenominatorLadder",
    "Interval",
    "McNemarResult",
    "PathSummary",
    "RoutingCost",
    "bootstrap_rate",
    "denominator_ladder",
    "exact_mcnemar",
    "export",
    "format_table",
    "holm",
    "routing_cost",
    "run_manifest",
    "summarise_by_evidence",
    "summarise_by_path",
    "to_csv",
    "verified_accept",
    "widest",
]
