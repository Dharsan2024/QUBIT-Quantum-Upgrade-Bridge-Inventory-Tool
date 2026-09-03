"""The migration-time dataset: reproducible artefacts, and a summary that refuses to pool.

Two properties carry the whole module, and both are easy to lose silently:

* byte-identical output from identical data, or the artefact is uncitable
* no pooled mean over paths, because that number is wrong rather than merely imprecise
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from qubit_migrate.report.measurements import (
    NO_POOLED_AGGREGATE,
    export,
    format_table,
    routing_cost,
    run_manifest,
    summarise_by_evidence,
    summarise_by_path,
    to_csv,
)
from qubit_migrate.state.measurement import MigrationMeasurement

_T0 = datetime(2026, 9, 2, 12, 0, 0, tzinfo=UTC)


def _row(
    path: str = "codemod",
    total_s: float = 1.0,
    outcome: str = "accepted",
    evidence_level: int | None = 2,
    *,
    vacuous: bool = False,
    offset: int = 0,
    **kw: object,
) -> MigrationMeasurement:
    return MigrationMeasurement(
        id=uuid.UUID(int=offset + 1),
        corpus="certbot/certbot@2b817be",
        rule_id=kw.pop("rule_id", "py-weakhash-01"),  # type: ignore[arg-type]
        path=path,
        total_s=total_s,
        outcome=outcome,
        evidence_level=evidence_level,
        vacuous=vacuous,
        queued_at=_T0 + timedelta(seconds=offset),
        started_at=_T0 + timedelta(seconds=offset),
        **kw,  # type: ignore[arg-type]
    )


class TestByteReproducibility:
    """An artefact that differs between two exports of the same data cannot be cited."""

    def test_the_same_rows_produce_the_same_bytes(self) -> None:
        rows = [_row(offset=i, total_s=i / 3) for i in range(8)]
        assert to_csv(rows) == to_csv(rows)

    def test_input_order_does_not_change_the_output(self) -> None:
        """SQLite promises no order without ORDER BY, so query order must not reach the file."""
        rows = [_row(offset=i, total_s=i / 3) for i in range(8)]
        assert to_csv(rows) == to_csv(list(reversed(rows)))

    def test_rows_sharing_a_sort_key_are_ordered_by_id(self) -> None:
        """Two findings on the same file and rule at the same instant must not swap places.

        The rows must differ in an EXPORTED column, or the assertion is unfalsifiable: `id` is not
        in `CSV_COLUMNS`, so two otherwise-identical rows produce byte-identical lines and the
        comparison holds no matter what the sort does. `total_s` differs here so row order is
        visible in the output, while corpus, rule_id and queued_at — the rest of the key — are
        deliberately equal.
        """
        a = _row(offset=0, total_s=1.0)
        a.id = uuid.UUID(int=1)
        b = _row(offset=0, total_s=2.0)
        b.id = uuid.UUID(int=999)
        forward, reverse = to_csv([a, b]), to_csv([b, a])
        assert forward == reverse
        # And the id decides which way round: 1 < 999, so a's row comes first in both.
        assert "1.000000" in forward.splitlines()[1]
        assert "2.000000" in forward.splitlines()[2]

    def test_line_endings_are_lf(self) -> None:
        """csv's default terminator is CRLF, so the same data would differ across platforms."""
        text = to_csv([_row()])
        assert "\r\n" not in text
        assert text.endswith("\n")

    def test_small_floats_do_not_switch_to_scientific_notation(self) -> None:
        """A 0.00008 s codemod would export as `8e-05` beside a `0.4` — two formats, one column."""
        text = to_csv([_row(total_s=0.00008)])
        cell = next(r for r in csv.DictReader(io.StringIO(text)))["total_s"]
        assert "e" not in cell.lower(), cell
        assert float(cell) == pytest.approx(0.00008)

    def test_booleans_are_not_exported_as_integers(self) -> None:
        """`bool` IS an `int` in Python, so an unguarded int branch turns True into 1."""
        text = to_csv([_row(vacuous=True)])
        assert next(r for r in csv.DictReader(io.StringIO(text)))["vacuous"] == "true"

    def test_timestamps_carry_an_explicit_offset(self) -> None:
        """SQLite returns naive datetimes; an offset-less ISO string is read as LOCAL time.

        The same defect already shipped once in the plan API, where a plan built two seconds ago
        appeared 5.5 hours older than the scan it came from.
        """
        text = to_csv([_row()])
        queued = next(r for r in csv.DictReader(io.StringIO(text)))["queued_at"]
        assert queued.endswith("+00:00"), queued

    def test_a_naive_timestamp_is_treated_as_utc_not_as_local(self) -> None:
        """Asserted on the queued_at CELL, not on the whole text.

        `started_at` is timezone-aware in the fixture and renders the very string this test looks
        for, so a substring search over the file passes even when the naive value is emitted with
        no offset at all.
        """
        row = _row()
        row.queued_at = datetime(2026, 9, 2, 12, 0, 0)
        row.started_at = None
        cell = next(r for r in csv.DictReader(io.StringIO(to_csv([row]))))["queued_at"]
        assert cell == "2026-09-02T12:00:00+00:00", cell

    def test_the_column_order_is_declared_not_introspected(self) -> None:
        """Mapper order changes with SQLAlchemy versions; the header must not."""
        header = to_csv([]).splitlines()[0]
        assert header.split(",")[:4] == ["corpus", "plan_id", "task_id", "rule_id"]


class TestNoPooledMean:
    def test_the_module_exposes_no_pooled_aggregate(self) -> None:
        """Not an oversight — a deliberate refusal, asserted so nobody helpfully adds one."""
        import qubit_migrate.report.measurements as module

        assert not [n for n in dir(module) if "mean" in n.lower() and not n.startswith("_")]

    def test_the_table_states_the_refusal(self) -> None:
        """A reader wanting one number for Y is asking a malformed question; silence reads as an
        oversight, so the table says so."""
        table = format_table(summarise_by_path([_row()]), "certbot@2b817be", "anssi")
        assert NO_POOLED_AGGREGATE in table


class TestPerPathSummary:
    def test_paths_are_summarised_separately(self) -> None:
        """Certbot's real shape: three unrelated distributions under one plan."""
        rows = (
            [_row("codemod", 0.4, offset=i) for i in range(155)]
            + [
                _row("guided", 1.9, outcome="guided", evidence_level=None, offset=200 + i)
                for i in range(102)
            ]
            + [_row("model", 312.0, offset=400 + i) for i in range(2)]
        )
        by_path = {s.path: s for s in summarise_by_path(rows)}
        assert by_path["codemod"].n == 155
        assert by_path["guided"].n == 102
        assert by_path["model"].n == 2
        assert by_path["codemod"].median_s == pytest.approx(0.4)
        assert by_path["model"].median_s == pytest.approx(312.0)

    def test_a_tiny_path_reports_no_p95(self) -> None:
        """Nearest-rank on n=2 returns the maximum, which is an order statistic dressed as a
        tail estimate."""
        summary = summarise_by_path([_row("model", 312.0, offset=i) for i in range(2)])[0]
        assert summary.p95_s is None
        assert "too small" in summary.note

    def test_failures_stay_inside_the_distribution(self) -> None:
        """Excluding them biases Y downward — the direction that flatters the tool."""
        rows = [
            _row("model", 1.0, offset=0),
            _row("model", 900.0, outcome="failed", evidence_level=None, offset=1),
        ]
        summary = summarise_by_path(rows)[0]
        assert summary.n == 2
        assert summary.median_s == pytest.approx(450.5)
        assert summary.accepted == 1

    def test_the_declared_path_order_is_stable(self) -> None:
        """Runs exercising different paths must still produce comparable tables."""
        rows = [_row("guided", offset=0), _row("codemod", offset=1), _row("model", offset=2)]
        assert [s.path for s in summarise_by_path(rows)] == ["codemod", "model", "guided"]

    def test_vacuous_passes_are_counted_per_path(self) -> None:
        rows = [_row(vacuous=True, offset=0), _row(offset=1)]
        assert summarise_by_path(rows)[0].vacuous == 1


class TestTimeConditionedOnEvidence:
    def test_evidence_levels_are_reported_separately(self) -> None:
        """ "Median 4.2 s to an L2 patch" and "median 96 s to an L3 patch" are different claims."""
        rows = [
            _row(total_s=4.2, evidence_level=2, offset=0),
            _row(total_s=96.0, evidence_level=3, offset=1),
        ]
        summary = summarise_by_evidence(rows)
        assert summary["L2"]["median_s"] == pytest.approx(4.2)
        assert summary["L3"]["median_s"] == pytest.approx(96.0)

    def test_unassessed_rows_are_their_own_bucket_not_level_zero(self) -> None:
        """Level 0 is a real claim about the diff; "not assessed" is the absence of one."""
        summary = summarise_by_evidence([_row(evidence_level=None, offset=0)])
        assert "none" in summary
        assert "L0" not in summary


class TestTheArtefacts:
    def test_all_three_files_are_written(self, tmp_path) -> None:
        written = export([_row()], tmp_path, corpus="certbot@2b817be", regime="anssi")
        assert set(written) == {"measurements", "run", "controls"}
        assert all(p.exists() for p in written.values())

    def test_controls_json_records_that_none_ran_rather_than_being_absent(self, tmp_path) -> None:
        """An absent file reads as an oversight; `"ran": false` is a finding.

        Without the oracle's admission controls a reader cannot tell a gate that discriminates
        from one that says yes to everything, and every evidence level in the CSV is then
        unfalsifiable.
        """
        written = export([_row()], tmp_path, corpus="c", regime=None)
        assert json.loads(written["controls"].read_text(encoding="utf-8"))["ran"] is False

    def test_the_manifest_is_reproducible_and_sorted(self) -> None:
        kwargs = {
            "corpus": "certbot@2b817be",
            "regime": "anssi",
            "engines": ["b", "a"],
            "images": {"z": "1", "a": "2"},
        }
        first = run_manifest(**kwargs)  # type: ignore[arg-type]
        assert first == run_manifest(**kwargs)  # type: ignore[arg-type]
        payload = json.loads(first)
        assert payload["engines"] == ["a", "b"]
        assert list(payload["images"]) == ["a", "z"]

    def test_the_manifest_states_the_reporting_rules(self) -> None:
        """They travel with the data, so a reader reusing the CSV inherits them."""
        rules = json.loads(run_manifest(corpus="c", regime=None))["reporting_rules"]
        assert any("pooled mean" in r for r in rules)
        assert any("scheduling" in r for r in rules)


class TestRoutingCost:
    """What exploration cost, against the best fixed engine chosen with hindsight."""

    @staticmethod
    def _attempt(engine: str, level: int, offset: int) -> MigrationMeasurement:
        return _row(path="model", evidence_level=level, offset=offset, engine=engine)

    def test_a_single_engine_reports_nothing_rather_than_zero_regret(self) -> None:
        """With one engine there is no choice to regret. Reporting 0.0 would read as "the policy
        was optimal" rather than "the question did not arise"."""
        rows = [self._attempt("only", 3, i) for i in range(5)]
        assert routing_cost(rows) is None

    def test_codemod_attempts_are_excluded(self) -> None:
        """A codemod took no routing decision. Folding those in dilutes the figure with attempts
        the policy never saw — and, with enough of them, makes "no engine" the reported baseline.

        A codemod-only set is not enough to show this: it returns None either way, because one
        pseudo-engine is still fewer than two. The mix is what exposes it.
        """
        rows = [_row(offset=i, evidence_level=4) for i in range(6)]  # codemods, no engine
        rows += [self._attempt("engine-a", 2, 20), self._attempt("engine-b", 1, 21)]
        cost = routing_cost(rows)
        assert cost is not None
        assert cost.total_requests == 2, "only the routed attempts count"
        assert cost.best_engine == "engine-a"

    def test_a_perfect_policy_has_no_regret(self) -> None:
        """Every attempt on the hindsight-best engine."""
        rows = [self._attempt("good", 4, i) for i in range(6)]
        rows += [self._attempt("bad", 4, 10 + i) for i in range(6)]
        cost = routing_cost(rows)
        assert cost is not None
        assert cost.cumulative_regret == pytest.approx(0.0)

    def test_exploration_is_counted_in_requests(self) -> None:
        rows = [self._attempt("good", 4, i) for i in range(8)]
        rows += [self._attempt("bad", -1, 20 + i) for i in range(2)]
        cost = routing_cost(rows)
        assert cost is not None
        assert cost.best_engine == "good"
        assert cost.exploration_requests == 2
        assert cost.total_requests == 10
        assert cost.exploration_share == pytest.approx(0.2)

    def test_regret_grows_with_bad_routing(self) -> None:
        """The whole point of the number: a policy that keeps picking the worse engine should
        look worse."""
        good = [self._attempt("good", 4, i) for i in range(5)]
        light = good + [self._attempt("bad", -1, 20 + i) for i in range(1)]
        heavy = good + [self._attempt("bad", -1, 30 + i) for i in range(8)]
        a, b = routing_cost(light), routing_cost(heavy)
        assert a is not None and b is not None
        assert b.cumulative_regret > a.cumulative_regret

    def test_the_yardstick_is_reproducible_when_engines_tie(self) -> None:
        """Two engines with identical records must not make the reported baseline depend on dict
        order — the figure would change between runs on the same data."""
        rows = [self._attempt("alpha", 3, i) for i in range(3)]
        rows += [self._attempt("beta", 3, 10 + i) for i in range(3)]
        first = routing_cost(rows)
        second = routing_cost(list(reversed(rows)))
        assert first is not None and second is not None
        assert first.best_engine == second.best_engine == "alpha"

    def test_regret_is_measured_against_the_best_available_not_perfection(self) -> None:
        """The comparison is "the best fixed choice available", which is itself imperfect. Against
        a perfect score every real policy would look bad and the number would say nothing."""
        rows = [self._attempt("mediocre", 1, i) for i in range(4)]
        rows += [self._attempt("worse", 0, 10 + i) for i in range(1)]
        cost = routing_cost(rows)
        assert cost is not None
        assert cost.best_mean_reward == pytest.approx(0.4)
        assert cost.cumulative_regret < 1.0
