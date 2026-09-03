"""Export and summarise the migration-time dataset.

Two jobs, both with a single constraint running through them: **the artefact must be reproducible
and the summary must not lie by aggregation.**

Reproducible means byte-identical from identical data. That rules out a surprising number of
ordinary choices — mapper introspection order, `dict` iteration, locale-dependent number
formatting, platform line endings, and `datetime.isoformat()` on a naive datetime (which emits no
offset, so a reader in another timezone parses a different instant). Each is pinned below. An
unreproducible measurement artefact is uncitable, and an uncitable one is not worth releasing.

Not lying by aggregation means refusing to emit the number a reader will ask for. `Y` as a single
figure is malformed: measured on certbot the plan is 155 codemod, 102 guided, 2 model, so a mean
over 272 findings averages three unrelated distributions and describes none of them. The codemod
path is milliseconds; one `py-rsa-kex-01` finding on the model path ran fifteen minutes. This
module therefore has no function that returns a pooled mean, and `format_table` prints the refusal
explicitly rather than omitting the row — saying why the question is malformed is more useful than
answering it badly, and silence would read as an oversight.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..state.measurement import PATHS, MigrationMeasurement

#: Written as-is into every artefact. A reader comparing two exports needs to know whether a
#: difference is in the data or in the exporter.
SCHEMA_VERSION = "1.0.0"


def _iso(value: datetime | None) -> str:
    """UTC ISO-8601 with an explicit offset, or "".

    SQLite has no timezone type, so datetimes come back NAIVE. `isoformat()` on a naive value emits
    `2026-09-02T15:51:25` with no offset, which JavaScript and pandas both read as LOCAL time — on
    this UTC+5:30 machine that shifts every timestamp by five and a half hours. The same defect
    already reached production once in the migration-plan API, where a freshly built plan looked
    older than the scan it came from.
    """
    if value is None:
        return ""
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


def _cell(value: Any) -> str:
    """One CSV cell, formatted deterministically.

    Floats are fixed to 6 decimal places rather than left to `repr`, which switches to scientific
    notation below 1e-4: a 0.00008 s codemod would export as `8e-05` while a 0.4 s one exports as
    `0.4`, and a reader parsing the column gets two formats for one quantity.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        # Before the int branch: bool IS an int in Python, so `True` would export as `1`.
        return "true" if value else "false"
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def to_csv(rows: Sequence[MigrationMeasurement]) -> str:
    """The measurements table, byte-reproducible.

    Sorted by a stable key rather than left in query order: SQLite does not promise an order
    without `ORDER BY`, and two exports of the same database could otherwise differ.
    """
    ordered = sorted(
        rows,
        # `id` last, as the tiebreaker. Without it two findings on the same file and rule with
        # identical timings could swap places between exports.
        key=lambda r: (r.corpus, r.rule_id, _iso(r.queued_at), str(r.id)),
    )
    # `io.StringIO` + explicit `\n`: csv's default terminator is `\r\n`, so the same data exported
    # on Windows and Linux would differ byte for byte.
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(MigrationMeasurement.CSV_COLUMNS)
    for row in ordered:
        writer.writerow(
            [_cell(getattr(row, name, None)) for name in MigrationMeasurement.CSV_COLUMNS]
        )
    return buffer.getvalue()


def _percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile.

    Nearest-rank rather than interpolated, deliberately: with n=2 on the model path an interpolated
    p95 invents a value between the two observations and presents it with the authority of a
    measurement. The nearest-rank definition can only ever return a number that was actually
    observed.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(-(-q * len(ordered) // 1))))
    return ordered[rank - 1]


def _median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


#: Below this many observations a p95 is not reported. Nearest-rank on n<5 returns the maximum,
#: which is an order statistic dressed up as a tail estimate.
_P95_FLOOR = 5


@dataclass(frozen=True)
class PathSummary:
    """One row of the published table. One path, never a pool."""

    path: str
    n: int
    median_s: float
    #: None when n is too small for a tail estimate to mean anything.
    p95_s: float | None
    accepted: int
    l3_plus: int
    vacuous: int
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "n": self.n,
            "median_s": round(self.median_s, 6),
            "p95_s": None if self.p95_s is None else round(self.p95_s, 6),
            "accepted": self.accepted,
            "l3_plus": self.l3_plus,
            "vacuous": self.vacuous,
            "note": self.note,
        }


def summarise_by_path(rows: Iterable[MigrationMeasurement]) -> list[PathSummary]:
    """Median and p95 per path, with failures INSIDE the distribution.

    A finding that consumed four repair attempts and was then routed to guidance took real time.
    Excluding it biases `Y` downward — the direction that flatters the tool, and therefore the
    direction to be most careful about — so every row is counted wherever it ended up.
    """
    grouped: dict[str, list[MigrationMeasurement]] = {}
    for row in rows:
        grouped.setdefault(row.path or "unknown", []).append(row)

    summaries: list[PathSummary] = []
    # Declared order first, then anything unexpected alphabetically, so the table is stable across
    # runs that happened to exercise different paths.
    for path in [p for p in PATHS if p in grouped] + sorted(set(grouped) - set(PATHS)):
        group = grouped[path]
        times = [r.total_s for r in group]
        enough = len(times) >= _P95_FLOOR
        summaries.append(
            PathSummary(
                path=path,
                n=len(group),
                median_s=_median(times),
                p95_s=_percentile(times, 0.95) if enough else None,
                accepted=sum(1 for r in group if r.outcome == "accepted"),
                l3_plus=sum(1 for r in group if (r.evidence_level or -1) >= 3),
                vacuous=sum(1 for r in group if r.vacuous),
                note="" if enough else f"n={len(group)}; too small to report a p95",
            )
        )
    return summaries


def summarise_by_evidence(rows: Iterable[MigrationMeasurement]) -> dict[str, dict[str, Any]]:
    """Time conditioned on how much was actually established.

    "Median 4.2 s to an L2 patch" and "median 96 s to an L3 patch" are different claims. Reporting
    the first while implying the second is the inflation the evidence ladder exists to remove, and
    the two can only be told apart if the times are split this way.
    """
    grouped: dict[int, list[float]] = {}
    for row in rows:
        grouped.setdefault(row.evidence_level if row.evidence_level is not None else -1, []).append(
            row.total_s
        )
    return {
        (f"L{level}" if level >= 0 else "none"): {
            "n": len(times),
            "median_s": round(_median(times), 6),
        }
        for level, times in sorted(grouped.items())
    }


#: Printed in place of a pooled figure. Deliberately in the artefact and in the paper: a reader who
#: wants one number for `Y` is asking a question the data says is malformed, and saying so is more
#: useful than answering it badly. Omitting the line would read as an oversight rather than a
#: finding.
NO_POOLED_AGGREGATE = (
    "Aggregate Y for this corpus: NOT REPORTED as a single figure. The paths above are "
    "unrelated distributions — a mean over them describes none of them. See per-path rows."
)


def format_table(summaries: Sequence[PathSummary], corpus: str, regime: str | None) -> str:
    """The published table, as it appears in the paper."""
    header = (
        f"Migration time per finding, {corpus or '(corpus unset)'}, regime = {regime or 'none'}"
    )
    lines = [
        header,
        "",
        f"{'path':<10}{'n':>6}{'median':>12}{'p95':>12}{'accepted':>10}{'L3+':>6}"
        f"{'vacuous':>9}  notes",
    ]
    for s in summaries:
        p95 = "—" if s.p95_s is None else f"{s.p95_s:.3f} s"
        lines.append(
            f"{s.path:<10}{s.n:>6}{f'{s.median_s:.3f} s':>12}{p95:>12}"
            f"{s.accepted:>10}{s.l3_plus:>6}{s.vacuous:>9}  {s.note}"
        )
    lines += ["", NO_POOLED_AGGREGATE]
    return "\n".join(lines)


def run_manifest(
    *,
    corpus: str,
    regime: str | None,
    config: dict[str, Any] | None = None,
    engines: Sequence[str] = (),
    images: dict[str, str] | None = None,
    qubit_commit: str = "",
    row_count: int = 0,
) -> str:
    """`run.json` — what produced these measurements.

    Without it the numbers are unreproducible and therefore uncitable. `config` is the same
    `MigrateConfig` snapshot already written to `migration_plans.config_json`, so this is a copy
    rather than new instrumentation.
    """
    payload = {
        "schema_version": SCHEMA_VERSION,
        "corpus": corpus,
        "regime": regime,
        "qubit_commit": qubit_commit,
        "row_count": row_count,
        "engines": sorted(engines),
        "images": dict(sorted((images or {}).items())),
        "config": config or {},
        "reporting_rules": [
            "No pooled mean over paths is reported; see NO_POOLED_AGGREGATE.",
            "Failed and guided attempts are inside the distribution, not excluded.",
            "Times are conditioned on evidence level.",
            "started_at - queued_at is scheduling, not migration time.",
        ],
    }
    # `sort_keys` and a trailing newline: the artefact must be byte-identical across runs and
    # diffable in git.
    return json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"


def export(
    rows: Sequence[MigrationMeasurement],
    out_dir: Path,
    *,
    corpus: str,
    regime: str | None,
    config: dict[str, Any] | None = None,
    engines: Sequence[str] = (),
    images: dict[str, str] | None = None,
    qubit_commit: str = "",
    controls: dict[str, Any] | None = None,
) -> dict[str, Path]:
    """Write `measurements.csv`, `run.json` and `controls.json` under `out_dir`.

    `controls.json` is not optional in spirit even though the parameter is: without the oracle's
    admission controls a reader cannot tell a gate that discriminates from one that says yes to
    everything, and every evidence level in the CSV becomes unfalsifiable. When no controls were
    run the file records exactly that, rather than being absent — an absent file reads as an
    oversight, a file saying `"ran": false` is a finding.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    csv_path = out_dir / "measurements.csv"
    csv_path.write_text(to_csv(rows), encoding="utf-8", newline="")
    written["measurements"] = csv_path

    run_path = out_dir / "run.json"
    run_path.write_text(
        run_manifest(
            corpus=corpus,
            regime=regime,
            config=config,
            engines=engines,
            images=images,
            qubit_commit=qubit_commit,
            row_count=len(rows),
        ),
        encoding="utf-8",
        newline="",
    )
    written["run"] = run_path

    controls_path = out_dir / "controls.json"
    controls_path.write_text(
        json.dumps(
            controls if controls is not None else {"ran": False, "controls": []},
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n",
        encoding="utf-8",
        newline="",
    )
    written["controls"] = controls_path
    return written


__all__ = [
    "NO_POOLED_AGGREGATE",
    "SCHEMA_VERSION",
    "PathSummary",
    "RoutingCost",
    "export",
    "format_table",
    "routing_cost",
    "run_manifest",
    "summarise_by_evidence",
    "summarise_by_path",
    "to_csv",
]


# ------------------------------------------------------------------- what exploration cost


@dataclass(frozen=True)
class RoutingCost:
    """What Thompson sampling cost, against the best fixed engine chosen with hindsight.

    Reported per corpus, never pooled: engine availability, quota and latency differ per run, and a
    regret figure averaged across corpora describes no run that actually happened.
    """

    #: Engine with the best mean reward over this corpus, identified AFTER the fact. Not a policy
    #: anything could have followed — it is the yardstick, and saying so matters because a reader
    #: will otherwise take it for an achievable baseline.
    best_engine: str
    best_mean_reward: float
    #: Total reward the best fixed engine would have collected, minus what was actually collected.
    #: Zero is unattainable in practice: some exploration is the price of not being stuck.
    cumulative_regret: float
    #: Attempts routed to an engine that was NOT the hindsight-best one.
    exploration_requests: int
    total_requests: int

    @property
    def exploration_share(self) -> float:
        return self.exploration_requests / self.total_requests if self.total_requests else 0.0

    @property
    def regret_per_request(self) -> float:
        return self.cumulative_regret / self.total_requests if self.total_requests else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "best_engine": self.best_engine,
            "best_mean_reward": round(self.best_mean_reward, 4),
            "cumulative_regret": round(self.cumulative_regret, 4),
            "regret_per_request": round(self.regret_per_request, 4),
            "exploration_requests": self.exploration_requests,
            "total_requests": self.total_requests,
            "exploration_share": round(self.exploration_share, 4),
        }


def routing_cost(rows: Iterable[MigrationMeasurement]) -> RoutingCost | None:
    """Cumulative regret and exploration cost over the attempts that reached an engine.

    `None` when fewer than two engines were used — with one engine there is no choice to regret,
    and reporting a regret of 0.0 would read as "the policy was optimal" rather than "the question
    did not arise".

    Only rows with an engine count. A codemod took no routing decision, and folding those in would
    dilute the figure with attempts the policy never saw.
    """
    from ..bandit import reward_for

    attempts = [(r.engine, reward_for(r.evidence_level)) for r in rows if r.engine]
    if not attempts:
        return None

    by_engine: dict[str, list[float]] = {}
    for engine, reward in attempts:
        by_engine.setdefault(str(engine), []).append(reward)
    if len(by_engine) < 2:
        return None

    means = {name: sum(v) / len(v) for name, v in by_engine.items()}
    # Ties broken by name so the yardstick is reproducible across runs.
    best = min(means, key=lambda n: (-means[n], n))
    best_mean = means[best]

    # Regret is measured against the best engine's MEAN, not against a perfect score: the
    # comparison is "the best fixed choice available", which is itself imperfect.
    collected = sum(reward for _, reward in attempts)
    return RoutingCost(
        best_engine=best,
        best_mean_reward=best_mean,
        cumulative_regret=max(0.0, best_mean * len(attempts) - collected),
        exploration_requests=sum(1 for engine, _ in attempts if engine != best),
        total_requests=len(attempts),
    )
