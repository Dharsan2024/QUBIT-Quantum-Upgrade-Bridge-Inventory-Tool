# Sensitivity classifier — DistilBERT (Tier 2)

**Status: strong synthetic generalization, gated by an abstention threshold. Bootstrap for Tier-2,
not yet the human-verified ship checkpoint.**

## What was trained
- Base: `distilbert-base-uncased`, 7-class head (phi, financial, pii, credentials, ip, ephemeral, public).
- Data: **Tier-1 template synthesis**, trained on the *train* vocab/template split only.
- Hardware: RTX 4060 Laptop (8 GB), torch 2.6.0+cu124, fp16, batch 32, lr 2e-5, weighted CE.
- Early stopping on in-distribution val macro-F1 (ceiling 20 epochs, patience 3) — converged epoch 1.

## Results — measured honestly
Two numbers, because they mean different things:

| Metric | macro-F1 | What it proves |
|---|---|---|
| in-distribution val | 1.000 | same templates/vocab as training — **memorization ceiling, not capability** |
| **held-out generalization** | **0.992** | **disjoint vocabulary + structurally unseen code templates** — real in-family generalization |

Per-class holdout F1 all ≥ 0.98. The held-out split shares **no** identifier/comment/path tokens with
training and uses different crypto templates, so 0.992 is an honest generalization result, not the
earlier vanity 1.0.

### Out-of-vocabulary behavior (the real limit) + why it's safe
On phrasing outside the designed vocab families entirely:
- `user_pwd, salt / "hash login secret"` → ephemeral **@ 0.487** (wrong, but **below 0.55**)
- `bp_reading, glucose / "store vitals"` → phi **@ 0.541** (right; generalized to unseen health terms)
- ambiguous `value, data` → ephemeral **@ 0.988** (confident-wrong — the genuine weakness)

Per doc 02 §6.3.3 the model is **accepted only if softmax ≥ 0.55 and it doesn't contradict a
weight-≥1.0 heuristic hit; otherwise it abstains → heuristic Tier-1**. Two of the three OOV cases fall
below threshold and abstain safely; the residual risk is confident-wrong on genuinely ambiguous input,
which the heuristic-contradiction guard further constrains.

## Conclusion
- The training pipeline (synthesis → disjoint-split GPU fine-tune → generalization macro-F1 → checkpoint
  → inference) is **real, GPU-proven, and honestly measured**.
- **Compute/epochs are not the bottleneck** (in-dist F1 = 1.0 at epoch 1); more epochs only memorize.
  The bottleneck is **real labeled data** — synthetic vocab can't cover real-world phrasing.
- **Production stays on heuristic Tier-1** (`sensitivity.py`), with this model available behind the
  §6.3.3 confidence+contradiction gate as an optional assist.

## To reach the Oct-15 ship gate
1. Tier-2 weak-labeling over **real permissive repos** (scanner + local Ollama) — needs repos supplied.
2. Human-adjudicated disagreement queue (3× weight) folded into training.
3. 600-example human-verified eval set (never trained on): report macro-F1 vs heuristic + Cohen's κ.
