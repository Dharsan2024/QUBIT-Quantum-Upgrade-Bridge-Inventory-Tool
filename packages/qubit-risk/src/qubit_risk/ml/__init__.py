"""DistilBERT data-sensitivity tier (doc 02 §6.3): dataset synthesis + training harness.

Tier 1 (template synthesis) is dependency-free and lives in ``synth``. The optional training
harness in ``train`` imports transformers/torch lazily so the base package never requires them.
"""

from .synth import SYNTH_CLASSES, SynthExample, generate_dataset, write_jsonl

__all__ = ["SYNTH_CLASSES", "SynthExample", "generate_dataset", "write_jsonl"]
