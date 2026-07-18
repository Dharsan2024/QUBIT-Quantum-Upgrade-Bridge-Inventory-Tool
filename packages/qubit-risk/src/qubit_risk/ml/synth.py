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


def _context_window(rng: random.Random, cls: str) -> tuple[str, str]:
    """Build one (context_window, language) for the target class."""
    ids_pool = vocab.IDENTIFIERS[cls]
    # 2-3 on-class identifiers + 1-2 distractors, shuffled
    on = rng.sample(ids_pool, k=min(len(ids_pool), rng.randint(2, 3)))
    noise = rng.sample(vocab.DISTRACTOR_IDS, k=rng.randint(1, 2))
    ids = on + noise
    rng.shuffle(ids)

    comment = rng.choice(vocab.COMMENTS[cls])
    if rng.random() < 0.4:  # sometimes append a neutral distractor comment
        comment = f"{comment}; {rng.choice(vocab.DISTRACTOR_COMMENTS)}"
    file_path = rng.choice(vocab.FILE_PATHS[cls])

    language = rng.choice(vocab.LANGUAGES)
    template = rng.choice(vocab.CODE_TEMPLATES[language])
    a, b = (on * 2)[0], (on * 2)[1]
    code = template.format(comment=comment, a=a, b=b)

    text = (
        f"path: {file_path} | ids: {', '.join(ids)} | comments: {comment} | code: {code}"
    )
    return text, language


def generate_dataset(
    *, per_class: int = 1500, seed: int = 42
) -> list[SynthExample]:
    """Balanced synthetic corpus: ``per_class`` examples for each of the 7 classes."""
    rng = random.Random(seed)
    examples: list[SynthExample] = []
    for cls in SYNTH_CLASSES:
        for _ in range(per_class):
            text, language = _context_window(rng, cls)
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
