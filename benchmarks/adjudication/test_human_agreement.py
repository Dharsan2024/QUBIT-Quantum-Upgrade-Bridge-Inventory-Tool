"""The human pass is the only part of this benchmark a reviewer cannot re-derive from the artifacts.

Everything else in `benchmarks/` can be re-run: the sweep, the draw, the scoring. A person's
judgements cannot, so the machinery that collects them has to be right the first time. Two failure
modes would be silent and would invalidate the result rather than merely dent it:

* **Leaking provenance into the worksheet.** If the annotator can see what the model or the
  heuristic said, the reported kappa measures anchoring. Nothing would look wrong; the number would
  simply be about the wrong thing.
* **Getting the stratification and its reweighting out of step.** The sample is deliberately
  enriched for disagreement. If `agreement.py` reweights against a differently-computed population
  than `human.py` sampled from, the post-stratified figure is arithmetic on unrelated quantities.

Both are pinned here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "oracles"))

from adjudicate import CODE, NOT_APPLICABLE, STRING_LITERAL, SUBSTRING
from agreement import kappa
from human import AGREE, DISAGREE, machine_labels, stratum_of

HERE = Path(__file__).resolve().parent


class TestStratification:
    """The rule that decides which items a person is asked to read."""

    def test_machines_agreeing_is_the_uninformative_stratum(self) -> None:
        assert stratum_of({"heuristic": SUBSTRING}, "ABSENT") == AGREE
        assert stratum_of({"heuristic": CODE}, "USE") == AGREE

    def test_machines_disagreeing_is_the_informative_one(self) -> None:
        assert stratum_of({"heuristic": CODE}, "MENTION") == DISAGREE
        assert stratum_of({"heuristic": SUBSTRING}, "USE") == DISAGREE

    def test_a_category_the_heuristic_declines_to_judge_counts_as_disagreement(self) -> None:
        """Every HNDL finding lands here, and they are the ones no machine has an opinion on.

        `PII: EMAIL ADDRESS` and `HARDCODED PASSWORD/SECRET` cannot be judged by asking whether an
        algorithm name survives outside quotes, so the heuristic abstains. Treating an abstention as
        agreement would drop the entire HNDL subsystem out of the human sample -- the one whose
        measured precision was 20.5%, and the one most in need of a person looking at it.
        """
        assert stratum_of({"heuristic": NOT_APPLICABLE}, "USE") == DISAGREE
        assert stratum_of({"heuristic": ""}, "MENTION") == DISAGREE
        assert stratum_of({}, "ABSENT") == DISAGREE

    def test_string_literal_and_comment_both_predict_mention(self) -> None:
        assert stratum_of({"heuristic": STRING_LITERAL}, "MENTION") == AGREE


class TestKappa:
    def test_perfect_agreement_is_one(self) -> None:
        assert kappa([("USE", "USE"), ("ABSENT", "ABSENT"), ("USE", "USE")]) == pytest.approx(1.0)

    def test_chance_level_agreement_is_about_zero(self) -> None:
        """Two raters who agree only as often as their marginals predict score ~0, not ~50%."""
        pairs = [("USE", "USE"), ("USE", "ABSENT"), ("ABSENT", "USE"), ("ABSENT", "ABSENT")]
        assert kappa(pairs) == pytest.approx(0.0, abs=1e-9)

    def test_total_disagreement_is_negative(self) -> None:
        assert kappa([("USE", "ABSENT"), ("ABSENT", "USE")]) < 0

    def test_no_pairs_is_undefined_rather_than_zero(self) -> None:
        assert kappa([]) is None

    def test_one_class_only_is_undefined_rather_than_one(self) -> None:
        """Everyone answering ABSENT agrees perfectly and has demonstrated nothing."""
        assert kappa([("ABSENT", "ABSENT")] * 5) is None

    def test_weights_change_the_answer_towards_the_reweighted_stratum(self) -> None:
        """Post-stratification has to actually move the number, in the direction of the weight."""
        pairs = [("USE", "USE"), ("USE", "USE"), ("USE", "ABSENT"), ("ABSENT", "ABSENT")]
        favour_agreement = kappa(pairs, [9.0, 9.0, 1.0, 1.0])
        favour_disagreement = kappa(pairs, [1.0, 1.0, 9.0, 1.0])
        assert favour_agreement is not None and favour_disagreement is not None
        assert favour_agreement > favour_disagreement

    def test_uniform_weights_match_the_unweighted_figure(self) -> None:
        pairs = [("USE", "MENTION"), ("USE", "USE"), ("ABSENT", "ABSENT"), ("MENTION", "USE")]
        assert kappa(pairs, [2.0] * 4) == pytest.approx(kappa(pairs))


class TestMachineLabels:
    def test_the_last_row_for_an_id_wins(self, tmp_path: Path) -> None:
        """`label.py` appends corrections rather than rewriting, so later rows supersede."""
        path = tmp_path / "labels.jsonl"
        rows = [
            {"id": "a", "label": "USE"},
            {"id": "b", "label": "ABSENT"},
            {"id": "a", "label": "MENTION"},
        ]
        path.write_text("".join(json.dumps(row) + chr(10) for row in rows), encoding="utf-8")
        assert machine_labels(path) == {"a": "MENTION", "b": "ABSENT"}

    def test_a_missing_file_is_empty_not_an_error(self, tmp_path: Path) -> None:
        assert machine_labels(tmp_path / "nothing.jsonl") == {}


WORKSHEET = HERE / "human_worksheet.json"


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    """The drawn worksheet ships with the repository, so this is a hard requirement, not a skip.

    Skipping would mean the blinding assertions below quietly stop running the moment the file is
    missing -- which is exactly the circumstance in which they matter most.
    """
    assert WORKSHEET.exists(), f"{WORKSHEET.name} is missing; run `human.py draw`"
    return json.loads(WORKSHEET.read_text(encoding="utf-8"))


class TestTheWorksheetIsBlind:
    """The drawn worksheet, as it stands in the repository, must carry no provenance."""

    def test_no_field_reveals_what_a_machine_thought(self, rows: list[dict]) -> None:
        forbidden = {"stratum", "detectors", "rule_id", "heuristic", "label", "cohort"}
        seen: set[str] = set()
        for row in rows:
            seen |= set(row)
        assert not (forbidden & seen), f"provenance leaked into the worksheet: {forbidden & seen}"

    def test_it_carries_what_the_annotator_needs_and_no_more(self, rows: list[dict]) -> None:
        expected = {"seq", "id", "repository", "path", "line", "family", "source", "context"}
        for row in rows:
            assert set(row) == expected

    def test_repeats_are_far_enough_apart_to_be_a_second_judgement(self, rows: list[dict]) -> None:
        """A repeat three items later measures short-term memory, not stability of judgement."""
        positions: dict[str, list[int]] = {}
        for index, row in enumerate(rows):
            positions.setdefault(row["id"], []).append(index)
        gaps = [p[1] - p[0] for p in positions.values() if len(p) > 1]
        assert gaps, "no item is repeated, so there is no intra-rater estimate"
        assert min(gaps) >= 4

    def test_sequence_numbers_are_dense_and_ordered(self, rows: list[dict]) -> None:
        assert [row["seq"] for row in rows] == list(range(1, len(rows) + 1))


class TestTheSecondRatersSheet:
    """A second annotator's sheet exists so an inter-rater kappa is possible at all.

    It must be blind in the same way the primary sheet is, and it must be drawn from the items the
    first annotator judged -- an inter-rater figure is only defined over items both people saw.
    """

    @pytest.fixture
    def second(self) -> list[dict]:
        path = HERE / "human_worksheet.second.json"
        if not path.exists():
            pytest.skip("no second-rater sheet drawn")
        return json.loads(path.read_text(encoding="utf-8"))

    @pytest.fixture
    def primary(self) -> list[dict]:
        return json.loads((HERE / "human_worksheet.json").read_text(encoding="utf-8"))

    def test_it_is_blind(self, second: list[dict]) -> None:
        expected = {"seq", "id", "repository", "path", "line", "family", "source", "context"}
        for row in second:
            assert set(row) == expected

    def test_every_item_was_also_shown_to_the_first_annotator(
        self, second: list[dict], primary: list[dict]
    ) -> None:
        shared = {row["id"] for row in primary}
        unseen = {row["id"] for row in second} - shared
        assert not unseen, f"{len(unseen)} items the first annotator never saw"

    def test_the_order_is_not_the_first_annotators_order(
        self, second: list[dict], primary: list[dict]
    ) -> None:
        """Same sequence would let one annotator's pacing anchor the other's."""
        first_order = [row["id"] for row in primary]
        second_order = [row["id"] for row in second]
        assert second_order != first_order[: len(second_order)]

    def test_it_carries_its_own_repeats(self, second: list[dict]) -> None:
        positions: dict[str, list[int]] = {}
        for index, row in enumerate(second):
            positions.setdefault(row["id"], []).append(index)
        gaps = [p[1] - p[0] for p in positions.values() if len(p) > 1]
        assert gaps, "no repeats, so the second rater has no intra-rater estimate either"
        assert min(gaps) >= 4
