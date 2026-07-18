"""DistilBERT fine-tuning harness for the sensitivity classifier (doc 02 §6.3.3/6.3.5).

transformers + torch are imported lazily so the base ``qubit-risk`` install never requires them
(install the optional extra: ``uv sync --extra ml`` or ``uv pip install`` the CUDA torch build).

Defaults follow doc 02 §6.3.5 (lr 2e-5, batch 16, weighted cross-entropy, 10% val for early
stopping) but train for as many epochs as needed: a high ``max_epochs`` ceiling with early stopping
on macro-F1 finds the right number rather than hard-coding 3. macro-F1 is the doc's acceptance
metric, not accuracy.

We do not commit a checkpoint — this script produces it (fetched later, sha256-pinned).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .synth import SYNTH_CLASSES, SynthExample, generate_dataset, train_val_split

_MODEL = "distilbert-base-uncased"


@dataclass
class TrainConfig:
    out_dir: Path
    max_epochs: int = 20  # ceiling; early stopping picks the effective number
    patience: int = 3  # epochs without macro-F1 improvement before stopping
    lr: float = 2e-5
    batch_size: int = 32
    per_class: int = 3000
    max_len: int = 256
    seed: int = 42
    fp16: bool = True  # mixed precision on GPU (ignored on CPU)


def _require_transformers() -> None:
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "Training needs the 'ml' extra: `uv sync --extra ml` "
            "(or install a CUDA torch build + transformers datasets accelerate scikit-learn)."
        ) from e


def class_weights(examples: list[SynthExample]) -> list[float]:
    """Inverse-frequency weights for weighted cross-entropy (doc 02 §6.3.5)."""
    counts = dict.fromkeys(SYNTH_CLASSES, 0)
    for ex in examples:
        counts[ex.label] += 1
    total = sum(counts.values())
    n = len(SYNTH_CLASSES)
    return [total / (n * counts[c]) if counts[c] else 0.0 for c in SYNTH_CLASSES]


def train(cfg: TrainConfig) -> dict:  # pragma: no cover - heavy, run manually / on GPU
    """Fine-tune DistilBERT on the synthetic corpus; returns a metrics dict and writes the model."""
    _require_transformers()
    import numpy as np
    import torch
    from sklearn.metrics import classification_report, f1_score
    from torch import nn
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        EarlyStoppingCallback,
        Trainer,
        TrainingArguments,
    )

    device = "cuda" if torch.cuda.is_available() else "cpu"
    label2id = {c: i for i, c in enumerate(SYNTH_CLASSES)}

    # Train on the "train" vocab/template split; the generalization eval uses the disjoint
    # "eval" split (unseen tokens + unseen templates) — the honest number (doc 02 §6.3.4).
    data = generate_dataset(per_class=cfg.per_class, seed=cfg.seed, split="train")
    train_ex, val_ex = train_val_split(data, seed=cfg.seed)
    holdout_ex = generate_dataset(
        per_class=max(200, cfg.per_class // 3), seed=cfg.seed + 1, split="eval"
    )
    weights = torch.tensor(class_weights(train_ex), dtype=torch.float)

    tok = AutoTokenizer.from_pretrained(_MODEL)

    def encode(ex: list[SynthExample]) -> dict:
        enc = tok(
            [e.text for e in ex], truncation=True, max_length=cfg.max_len, padding="max_length"
        )
        enc["labels"] = [label2id[e.label] for e in ex]
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

    def metrics(eval_pred) -> dict:
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {
            "macro_f1": float(f1_score(labels, preds, average="macro")),
            "accuracy": float((preds == labels).mean()),
        }

    args = TrainingArguments(
        output_dir=str(cfg.out_dir),
        num_train_epochs=cfg.max_epochs,
        learning_rate=cfg.lr,
        per_device_train_batch_size=cfg.batch_size,
        per_device_eval_batch_size=cfg.batch_size,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        fp16=cfg.fp16 and device == "cuda",
        seed=cfg.seed,
        logging_steps=50,
        report_to=[],
    )
    trainer = WeightedTrainer(
        model=model,
        args=args,
        train_dataset=DS(train_ex),
        eval_dataset=DS(val_ex),
        compute_metrics=metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=cfg.patience)],
    )
    trainer.train()
    trainer.save_model(str(cfg.out_dir))
    tok.save_pretrained(str(cfg.out_dir))

    def _report(ex: list[SynthExample]) -> dict:
        pred = trainer.predict(DS(ex))
        y_pred = pred.predictions.argmax(axis=-1)
        y_true = pred.label_ids
        rep = classification_report(
            y_true, y_pred, target_names=SYNTH_CLASSES, output_dict=True, zero_division=0
        )
        return {
            "macro_f1": float(rep["macro avg"]["f1-score"]),
            "accuracy": float(rep["accuracy"]),
            "per_class_f1": {c: float(rep[c]["f1-score"]) for c in SYNTH_CLASSES},
        }

    in_dist = _report(val_ex)
    holdout = _report(holdout_ex)  # the honest generalization number
    result = {
        "device": device,
        "model": _MODEL,
        "classes": SYNTH_CLASSES,
        "per_class": cfg.per_class,
        "epochs_ceiling": cfg.max_epochs,
        "in_distribution_macro_f1": in_dist["macro_f1"],
        "holdout_macro_f1": holdout["macro_f1"],
        "holdout_accuracy": holdout["accuracy"],
        "holdout_per_class_f1": holdout["per_class_f1"],
        "note": (
            "holdout_* uses disjoint vocab + unseen templates (generalization); "
            "in_distribution_* shares the training distribution and will read high."
        ),
    }
    (cfg.out_dir / "metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


__all__ = ["TrainConfig", "class_weights", "train"]
