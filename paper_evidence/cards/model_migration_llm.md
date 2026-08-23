# Model card — migration code transformer

The only learned component in QUBIT. Everything else (detection, risk, CBOM) is rule-based, so there
is exactly one of these cards. Fields the repository cannot settle are `UNKNOWN` and appear in
`GAPS.md` with the action that would resolve them.

## Task

| field | value |
|---|---|
| task | Rewrite one source file so a named quantum-vulnerable algorithm is replaced by its post-quantum or hardened equivalent, preserving behaviour |
| input_repr | Whole source file as text, plus the migration rule, the asset's algorithm and line, and a verified target shape quoted from the scanner's own rule examples |
| output_repr | Whole rewritten file, fenced; a unified diff is derived from it, never requested directly |
| pretrained_or_scratch | **Pretrained, used as-is** |
| finetune_method | **None.** No training, no LoRA, no adapters. This is prompt-driven inference against a stock checkpoint |

## Model

| field | value |
|---|---|
| model_family | Qwen2.5-Coder (instruct) |
| checkpoint | `qwen2.5-coder:7b-instruct-q4_K_M` |
| fallback checkpoint | `qwen2.5-coder:1.5b-instruct-q4_K_M` |
| quantisation | Q4_K_M (4-bit, k-quant medium) |
| serving | Ollama, local HTTP, no network egress |
| version_or_commit | Ollama tag as above; blob digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` (`env/model_provenance.txt`) |
| api_version_pin | Ollama server `0.32.15`, captured in `env/model_provenance.txt` |

Source: `packages/qubit-migrate/src/qubit_migrate/config.py`.

## Inference parameters

| field | value |
|---|---|
| temperature | **0.0** |
| top_p | not set (Ollama default) |
| max_tokens (`num_predict`) | computed per call by `_output_budget(prompt)`, not fixed |
| stop | not set |
| llm_timeout | 180.0 s per completion |
| self_consistency_n | 1 — no sampling ensemble |
| retry_policy | `max_repair_rounds = 2`; a failed rescan is fed back as a correction rather than rejected |
| min_confidence | 0.5 |
| seeds | `20260822`, pinned in `llm.GENERATION_SEED` and sent with every request. Previously unset: greedy decoding at `temperature=0.0` is near-deterministic, which is not the same as reproducible |

Source: `packages/qubit-migrate/src/qubit_migrate/transform/llm.py`.

## Retrieval and tooling

| field | value |
|---|---|
| rag_corpus | **None.** No vector store, no embeddings, no retriever |
| chunking / embed_model / top_k / reranker | not applicable |
| agent_tools | None. Single-turn completion inside a fixed repair loop, not an agent |
| loop_termination | Validation passes, or `max_repair_rounds` exhausted, or timeout |

The prompt does carry a **verified target shape** — a code example pulled from the scanner's own
rule catalogue via `qubit rules examples --language <l> --algorithm-prefix <a>`. This is retrieval
in the loose sense, but from a fixed local catalogue rather than a learned index, and the same
catalogue is used to check the answer. Generator and checker take their instructions from one
authority so they cannot drift apart.

## The safety gate

Output is never trusted. Five stages run on every patch — applies, parses, compiles, tests, rescan —
and the verdict is exhaustively enumerated in `tables/T12_validation_gate.md` over all 243
combinations. A failure at any stage rejects the patch; a skipped stage marks the report `partial`,
which means accepted-but-not-fully-verified and must not be read as a pass.

## Measurement status

| field | value |
|---|---|
| latency_p50 / p95 | **UNKNOWN** — not measured under controlled conditions |
| throughput | **UNKNOWN** |
| memory | **UNKNOWN** |
| train_wallclock | not applicable (no training) |
| energy_or_cost | **UNKNOWN**. Local inference, so no API cost; kWh not instrumented |
| baselines_compared | **None.** No comparison against another model or against a deterministic-only pipeline |
| ablations_run | **None** for this component |
| class_balance / split_strategy / leakage_prevention | not applicable — nothing is trained, so there is no train/test split to leak across |

**The patch success rate is UNKNOWN at corpus scale.** The only number in the repository is a
55% in the risk register of `docs/design/03-migration-orchestrator.md`, where it illustrates what
would still be publishable rather than reporting anything observed. It must not be quoted as a
result. See the Limitations appendix, L3.

## Known failure modes

Documented in the code, from real runs:

* **Truncation at `num_predict`.** Ollama reports `done_reason: "length"`; the file comes back cut
  off. Handled by budgeting output from prompt size and by detecting an unclosed fence, rather than
  by treating the truncated file as a wrong answer.
* **Reasoning exhausting the budget** before any code is emitted, on models that think aloud.
* **A rewrite that leaves the finding in place** — caught by the rescan stage and fed back.
* **Cross-language rules** (`language: multi`) cannot say what the patched file is; the extension
  decides. Two bugs came from getting this wrong.

## Prompt templates

Verbatim in `cards/prompts.md`.
