"""Tier-1 template synthesis for the sensitivity classifier (doc 02 §6.3.4 step 1).

Generates balanced, labelled context windows in the exact §6.3.1 format:

    path: <file> | ids: <id, id, ...> | comments: <comment> | code: <snippet>

Labels are true by construction (the dominant class's vocabulary is planted; class-neutral
distractors are mixed in so the model must weigh signal, not just detect any domain word).
Fully deterministic given a seed, so the corpus is reproducible and unit-testable.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path

from . import vocab

SYNTH_CLASSES = vocab.CLASSES


@dataclass(frozen=True)
class SynthExample:
    text: str
    label: str
    language: str


def _half(items: list[str], split: str) -> list[str]:
    """Partition a vocab pool for disjoint train/eval generalization splits.

    ``train`` -> first half, ``eval`` -> second half, ``all`` -> everything. The eval half shares
    no identifier/comment/path tokens with train, so eval macro-F1 measures generalization, not
    memorization. Small pools (<4) are used whole in both (can't split meaningfully).
    """
    if split == "all" or len(items) < 4:
        return items
    mid = len(items) // 2
    return items[:mid] if split == "train" else items[mid:]


def _context_window(rng: random.Random, cls: str, split: str) -> tuple[str, str]:
    """Build one (context_window, language) for the target class under the given split."""
    ids_pool = _half(vocab.IDENTIFIERS[cls], split)
    on = rng.sample(ids_pool, k=min(len(ids_pool), rng.randint(2, 3)))
    noise = rng.sample(vocab.DISTRACTOR_IDS, k=rng.randint(1, 2))
    ids = on + noise
    rng.shuffle(ids)

    comment = rng.choice(_half(vocab.COMMENTS[cls], split))
    if rng.random() < 0.4:  # sometimes append a neutral distractor comment
        comment = f"{comment}; {rng.choice(vocab.DISTRACTOR_COMMENTS)}"
    file_path = rng.choice(_half(vocab.FILE_PATHS[cls], split))

    language = rng.choice(vocab.LANGUAGES)
    # eval uses structurally different (held-out) code templates
    templates = (
        vocab.HOLDOUT_CODE_TEMPLATES[language]
        if split == "eval"
        else vocab.CODE_TEMPLATES[language]
    )
    template = rng.choice(templates)
    a, b = (on * 2)[0], (on * 2)[1]
    code = template.format(comment=comment, a=a, b=b)

    text = f"path: {file_path} | ids: {', '.join(ids)} | comments: {comment} | code: {code}"
    return text, language


def generate_dataset(
    *, per_class: int = 1500, seed: int = 42, split: str = "all"
) -> list[SynthExample]:
    """Balanced synthetic corpus. ``split`` in {all, train, eval}; train/eval use disjoint vocab
    + templates so eval measures generalization (doc 02 §6.3.4 anti-circularity)."""
    rng = random.Random(seed)
    examples: list[SynthExample] = []
    for cls in SYNTH_CLASSES:
        for _ in range(per_class):
            text, language = _context_window(rng, cls, split)
            examples.append(SynthExample(text=text, label=cls, language=language))
    rng.shuffle(examples)
    return examples


def write_jsonl(examples: list[SynthExample], path: Path) -> int:
    """Write examples as JSON Lines; returns the count written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(asdict(ex), ensure_ascii=False) + "\n")
    return len(examples)


def train_val_split(
    examples: list[SynthExample], *, val_frac: float = 0.1, seed: int = 42
) -> tuple[list[SynthExample], list[SynthExample]]:
    """Deterministic split (10% held out for early stopping, doc 02 §6.3.5)."""
    rng = random.Random(seed)
    shuffled = examples[:]
    rng.shuffle(shuffled)
    n_val = int(len(shuffled) * val_frac)
    return shuffled[n_val:], shuffled[:n_val]


__all__ = [
    "SYNTH_CLASSES",
    "SynthExample",
    "generate_dataset",
    "train_val_split",
    "write_jsonl",
]
