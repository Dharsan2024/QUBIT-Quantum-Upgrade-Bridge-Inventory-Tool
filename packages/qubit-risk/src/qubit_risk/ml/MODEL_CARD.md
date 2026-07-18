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

## Real-world transfer — MEASURED (the decisive result)
Harvested **108 genuine crypto-context windows** from 19 permissive real repos (auth/identity:
authentik, dex, gitea, kratos, authlib; payments: saleor, killbill; secrets: infisical; health:
fhir-server; + teleport, caddy, synapse, …) using the crash-isolated scanner worker.

Weak-labeled each with the heuristic **and** local-LLM (qwen2.5-coder:7b), and evaluated the
synthetic-trained model against the agreed consensus:

| Signal | Value | Interpretation |
|---|---|---|
| heuristic → `unknown` | **93 / 108** | heuristic abstains on ~86% of real crypto snippets |
| LLM → `unknown` | **98 / 108** | the LLM abstains even more |
| heuristic↔LLM confident agreement | **3 / 108 (2.8%)** | almost no consensus signal exists to train/eval on |
| model vs consensus (n=3) | 2/3 | N far too small to claim anything |

**Root cause (inspected):** the ±5-line window around a real crypto call contains *crypto-mechanism*
tokens (`RSA`, `SECP256R1`, `md5`, `hexdigest`, `PrivateKey`, `SHA1`, `curve`) — **not** data-sensitivity
tokens (`patient`, `card_number`, `ssn`). The sensitive data lives in the caller / DB schema / request
handler, which the evidence contract (doc 02 §6.3.1) deliberately does **not** capture ("no
route-to-crypto attribution; context is thin").

**Conclusion (honest, and it's a real research result):** data-sensitivity classification from a
±5-line crypto snippet **does not transfer to real code** — both independent weak labelers abstain
~90% of the time, so the premise, not just this model, is what fails on real inputs. The synthetic
0.992 measured a task that barely occurs in real code.

**Decision:** QUBIT M2 **ships heuristic-only** (design cut-line C3), and the heuristic's high
abstention (`unknown`) on real code is now shown to be the *correct* behaviour, not a weakness. The
BERT tier is reported as a documented negative result. A capable model would require **widening the
context window** (enclosing function / call-site data flow / schema) — explicitly out of scope for v1
in doc 02 §6.3.1, so it is correctly deferred, not cut under pressure.

## To reach the Oct-15 ship gate
1. Tier-2 weak-labeling over **real permissive repos** (scanner + local Ollama) — needs repos supplied.
2. Human-adjudicated disagreement queue (3× weight) folded into training.
3. 600-example human-verified eval set (never trained on): report macro-F1 vs heuristic + Cohen's κ.
