# Sensitivity classifier — DistilBERT (Tier 2), synthetic-only checkpoint

**Status: bootstrap / pipeline-proven — NOT the ship checkpoint.**

## What was trained
- Base: `distilbert-base-uncased`, 7-class head (phi, financial, pii, credentials, ip, ephemeral, public).
- Data: **Tier-1 template synthesis only** — 21,000 examples (3000/class), `qubit risk gen-dataset` seed 42.
- Hardware: RTX 4060 Laptop (8 GB), torch 2.6.0+cu124, fp16, batch 32, lr 2e-5, weighted CE.
- Early stopping on validation macro-F1 (ceiling 20 epochs, patience 3).

## Result (and why the number is misleading)
- **Validation macro-F1 = 1.000** — reached at **epoch 1**, stopped at epoch 4.
- This is **not** evidence of real-world capability. It is exactly the *structural circularity*
  doc 02 §6.3.4 warns about: the synthetic templates are trivially separable, so the model learned
  the template surface form, not data-sensitivity semantics.
- Sanity check on **novel** phrasing confirms poor generalization:
  - `ids: user_pwd, salt | "hash login secret"` → predicted **pii** (should be **credentials**).
  - ambiguous `ids: value, data` → **ephemeral** @ 0.90 (overconfident, wrong).

## Honest conclusion
The training pipeline (synthesis → GPU fine-tune → macro-F1 gate → checkpoint → inference) is
**real and works end-to-end**. The *model* is a bootstrap only. Per doc 02 §6.3.4 the real
ship/no-ship gate (Oct-15) requires:
1. Tier-2 weak-labeled **real** code (scanner + local Ollama over permissive repos),
2. the **human-adjudicated disagreement queue** (3× weighted) in training,
3. a **600-example human-verified eval set** (never trained on) reporting macro-F1 vs the heuristic
   baseline and Cohen's κ.

Until that exists, QUBIT uses the **heuristic Tier-1 classifier** (`sensitivity.py`) in production —
which is the design's explicit fallback (cut-line C3: "M2 may ship heuristic-only"). This checkpoint
is retained to prove the harness and to seed Tier-2 experiments, not to make risk decisions.
