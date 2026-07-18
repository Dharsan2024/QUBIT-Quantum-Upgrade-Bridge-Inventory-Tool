"""DistilBERT fine-tuning harness for the sensitivity classifier (doc 02 §6.3.3/6.3.5).

transformers + torch are imported lazily so the base ``qubit-risk`` install never requires them
(install the optional extra: ``uv sync --extra ml``). Defaults match doc 02 §6.3.5:
3 epochs, lr 2e-5, batch 16, weighted cross-entropy, 10% val for early stopping.

This is the *training* entrypoint; inference lives in ``infer`` once a checkpoint exists. We do not
commit a checkpoint — it is produced by this script (Colab T4 <1h / CPU overnight) and fetched by
`fetch-models`, sha256-pinned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .synth import SYNTH_CLASSES, SynthExample, generate_dataset, train_val_split

_MODEL = "distilbert-base-uncased"


@dataclass
class TrainConfig:
    out_dir: Path
    epochs: int = 3
    lr: float = 2e-5
    batch_size: int = 16
    per_class: int = 1500
    max_len: int = 256
    seed: int = 42


def _require_transformers():
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "Training needs the 'ml' extra: run `uv sync --extra ml` "
            "(installs torch + transformers + datasets)."
        ) from e


def class_weights(examples: list[SynthExample]) -> list[float]:
    """Inverse-frequency weights for weighted cross-entropy (doc 02 §6.3.5)."""
    counts = {c: 0 for c in SYNTH_CLASSES}
    for ex in examples:
        counts[ex.label] += 1
    total = sum(counts.values())
    n = len(SYNTH_CLASSES)
    return [total / (n * counts[c]) if counts[c] else 0.0 for c in SYNTH_CLASSES]


def train(cfg: TrainConfig) -> Path:  # pragma: no cover - heavy, run manually / in CI-GPU
    """Fine-tune DistilBERT on the synthetic corpus; returns the checkpoint dir."""
    _require_transformers()
    import numpy as np
    import torch
    from torch import nn
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
    )

    label2id = {c: i for i, c in enumerate(SYNTH_CLASSES)}
    data = generate_dataset(per_class=cfg.per_class, seed=cfg.seed)
    train_ex, val_ex = train_val_split(data, seed=cfg.seed)
    weights = torch.tensor(class_weights(train_ex), dtype=torch.float)

    tok = AutoTokenizer.from_pretrained(_MODEL)

    def encode(batch: list[SynthExample]):
        enc = tok(
            [e.text for e in batch],
            truncation=True,
            max_length=cfg.max_len,
            padding="max_length",
        )
        enc["labels"] = [label2id[e.label] for e in batch]
        return enc

    class DS(torch.utils.data.Dataset):
        def __init__(self, ex: list[SynthExample]) -> None:
            self.enc = encode(ex)

        def __len__(self) -> int:
            return len(self.enc["labels"])

        def __getitem__(self, i: int) -> dict:
            return {k: torch.tensor(v[i]) for k, v in self.enc.items()}

    model = AutoModelForSequenceClassification.from_pretrained(
        _MODEL,
        num_labels=len(SYNTH_CLASSES),
        id2label=dict(enumerate(SYNTH_CLASSES)),
        label2id=label2id,
    )

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            loss = nn.CrossEntropyLoss(weight=weights.to(out.logits.device))(out.logits, labels)
            return (loss, out) if return_outputs else loss

    def metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {"accuracy": float((preds == labels).mean())}

    args = TrainingArguments(
        output_dir=str(cfg.out_dir),
        num_train_epochs=cfg.epochs,
        learning_rate=cfg.lr,
        per_device_train_batch_size=cfg.batch_size,
        per_device_eval_batch_size=cfg.batch_size,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        seed=cfg.seed,
        logging_steps=50,
    )
    trainer = WeightedTrainer(
        model=model,
        args=args,
        train_dataset=DS(train_ex),
        eval_dataset=DS(val_ex),
        compute_metrics=metrics,
    )
    trainer.train()
    trainer.save_model(str(cfg.out_dir))
    tok.save_pretrained(str(cfg.out_dir))
    return cfg.out_dir


__all__ = ["TrainConfig", "class_weights", "train"]
