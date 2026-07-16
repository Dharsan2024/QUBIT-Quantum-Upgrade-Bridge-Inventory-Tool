from __future__ import annotations

from pathlib import Path

import pytest
from qubit_scanner import RuleCatalog
from qubit_scanner.catalog import RuleLoadError


def test_builtin_catalog_loads_and_compiles() -> None:
    cat = RuleCatalog.load()
    assert len(cat) >= 4
    assert "python" in cat.languages()
    ids = {c.rule.id for c in cat.all_rules()}
    assert {"PY-HASHLIB-MD5", "PY-HASHLIB-SHA1", "PY-CRYPTOGRAPHY-RSA-KEYGEN"} <= ids


def test_every_rule_defines_algorithm_extractor() -> None:
    for c in RuleCatalog.load().all_rules():
        assert "algorithm" in c.rule.extract, c.rule.id


def test_bad_query_fails_loudly(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "schema: qubit-rule/v1\n"
        "language: python\n"
        "library: {name: x, detect_imports: [x]}\n"
        "rules:\n"
        "  - id: BAD\n"
        "    match: {query: '(this is not a valid query'}\n"
        "    extract: {algorithm: {literal: X}}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        RuleCatalog.load([tmp_path])


def test_missing_algorithm_extractor_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "schema: qubit-rule/v1\n"
        "language: python\n"
        "library: {name: x, detect_imports: [x]}\n"
        "rules:\n"
        "  - id: NOALGO\n"
        "    match: {query: '(identifier) @i'}\n"
        "    extract: {key_size: {literal: '2048'}}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        RuleCatalog.load([tmp_path])
