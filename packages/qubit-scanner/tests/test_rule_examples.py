"""Every rule ships its own fixtures: each embedded positive example must produce >=1 detection
from that rule; each negative example must produce 0. Writing a rule IS writing its test
(doc 01 §8.2). This also catches grammar/pack drift (a rule that suddenly matches nothing fails CI).
"""

from __future__ import annotations

import pytest
from qubit_scanner import CodeScanner, RuleCatalog

_CATALOG = RuleCatalog.load()
_SCANNER = CodeScanner(_CATALOG)

_POSITIVE = [
    (c.rule.id, c.language, ex) for c in _CATALOG.all_rules() for ex in c.rule.examples.positive
]
_NEGATIVE = [
    (c.rule.id, c.language, ex) for c in _CATALOG.all_rules() for ex in c.rule.examples.negative
]


@pytest.mark.parametrize(
    "rule_id,language,src", _POSITIVE, ids=[f"{r}#{i}" for i, (r, _, _) in enumerate(_POSITIVE)]
)
def test_positive_examples_detect(rule_id: str, language: str, src: str) -> None:
    dets = _SCANNER.scan_source(src.encode(), language, file_path="ex")
    assert any(d.rule_id == rule_id for d in dets), f"{rule_id} did not match its positive example"


@pytest.mark.parametrize(
    "rule_id,language,src", _NEGATIVE, ids=[f"{r}#{i}" for i, (r, _, _) in enumerate(_NEGATIVE)]
)
def test_negative_examples_do_not_detect(rule_id: str, language: str, src: str) -> None:
    dets = _SCANNER.scan_source(src.encode(), language, file_path="ex")
    assert not any(d.rule_id == rule_id for d in dets), f"{rule_id} matched its negative example"


def test_there_are_examples_to_run() -> None:
    assert _POSITIVE, "no positive rule examples found"
