"""Tier-1 sensitivity-classifier synthesizer (doc 02 §6.3.4)."""

from __future__ import annotations

from collections import Counter

from qubit_risk.ml import SYNTH_CLASSES, generate_dataset, write_jsonl
from qubit_risk.ml.synth import train_val_split
from qubit_risk.ml.train import class_weights
from qubit_risk.ml.vocab import IDENTIFIERS


def test_dataset_is_balanced_and_labelled() -> None:
    data = generate_dataset(per_class=100, seed=7)
    assert len(data) == 100 * len(SYNTH_CLASSES)
    counts = Counter(e.label for e in data)
    assert set(counts) == set(SYNTH_CLASSES)
    assert set(counts.values()) == {100}  # perfectly balanced


def test_context_window_format() -> None:
    ex = generate_dataset(per_class=5, seed=1)[0]
    for marker in ("path:", "ids:", "comments:", "code:"):
        assert marker in ex.text
    assert ex.language in {"python", "java", "go", "javascript"}


def test_examples_carry_on_class_signal() -> None:
    # every example must contain at least one identifier stem from its own class
    for ex in generate_dataset(per_class=50, seed=3):
        assert any(tok in ex.text for tok in IDENTIFIERS[ex.label]), ex.text


def test_deterministic_given_seed() -> None:
    a = [e.text for e in generate_dataset(per_class=80, seed=99)]
    b = [e.text for e in generate_dataset(per_class=80, seed=99)]
    assert a == b
    c = [e.text for e in generate_dataset(per_class=80, seed=100)]
    assert a != c  # different seed -> different corpus


def test_train_val_split_disjoint_and_sized() -> None:
    data = generate_dataset(per_class=100, seed=5)
    train, val = train_val_split(data, val_frac=0.1, seed=5)
    assert len(val) == int(len(data) * 0.1)
    assert len(train) + len(val) == len(data)
    assert not ({e.text for e in train} & {e.text for e in val})


def test_class_weights_sum_reasonable() -> None:
    w = class_weights(generate_dataset(per_class=100, seed=5))
    assert len(w) == len(SYNTH_CLASSES)
    assert all(x > 0 for x in w)


def test_write_jsonl(tmp_path) -> None:
    import json

    data = generate_dataset(per_class=10, seed=2)
    out = tmp_path / "corpus.jsonl"
    n = write_jsonl(data, out)
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert n == len(lines) == len(data)
    rec = json.loads(lines[0])
    assert set(rec) == {"text", "label", "language"}
    assert rec["label"] in SYNTH_CLASSES
