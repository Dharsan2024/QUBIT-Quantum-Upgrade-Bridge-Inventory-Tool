# Learned tiers and model cards

Three learned or generative components sit inside QUBIT. Each is optional, each degrades to a deterministic path when absent, and none of them decides anything on its own — the scanner's findings and the validation gate are rule-based throughout.

### XGBoost risk regressor (distilled scoring tier)

Distils the closed-form risk score so the app can return a score plus a calibrated interval without re-running the Monte-Carlo timeline per asset. Loaded only when `QUBIT_RISK_XGB_DIR` points at a trained directory; otherwise the pipeline falls back to the closed form, which is why the tier is optional rather than required.

| property | value |
|---|---|
| training population | 50,000 synthetic assets, 200 timeline draws each |
| split | 34,997 train / 7,500 calibration / 7,503 test |
| test MAE | 0.0021 (risk score is on 0-1) |
| conformal target coverage | 90% |
| empirical test coverage | **90.51%** |
| mean interval width | 0.0109 |
| q̂ (conformal quantile) | 0.0063 |
| input features | 34 |

The coverage line is the one that matters: split-conformal prediction gives a distribution-free guarantee that the interval contains the true value at the target rate, and the measured 90.51% against a 90% target is the check that the guarantee held on data the model never saw. An interval 0.0109 wide on a 0-1 score is narrow enough to be useful rather than vacuously correct.

**Trained on synthetic data, and that is a limitation, not a footnote.** The population is generated from the same priors the closed-form score uses, so the regressor is distilling a model rather than learning from observed breaches — it inherits every assumption in `qubit_risk` and can be no better calibrated than they are.

Feature groups: algorithm family (10 one-hot), key size, quantum-attack ordinal, CRQC arrival probabilities at 2030/2035/2040, median break year, data-sensitivity class (7 one-hot), shelf-life mean and P90, exposure class, usage ordinal, and four posture flags (pre-TLS-1.3, expired certificate, deprecated library, HNDL probability).


### DistilBERT data-sensitivity classifier

Decides what KIND of data a finding protects — PHI, PII, financial, credentials, intellectual property, ephemeral, public — which is the input that sets shelf-life, and therefore the Mosca margin. The shipped default is the deterministic rule tier in `qubit_risk.sensitivity`; this is the optional learned replacement.

| property | value |
|---|---|
| base checkpoint | `distilbert-base-uncased` |
| task | 7-class single-label classification |
| synthetic training corpus | 2,100 labelled examples (`datasets/sensitivity/synth.jsonl`) |
| trained artifact present in this checkout | **no** |

Not trained in this checkout, so **no accuracy is reported for it** — the pack does not carry a number for a model it cannot point at. `qubit_risk.ml.weaklabel` exists to score it honestly when it is trained: it measures agreement against a weak-consensus label on REAL code, not against the synthetic set it was fitted to, because the second number would only measure memorisation.


### Local code-rewriting model (migration tier)

The patch generator for rules with no deterministic codemod. Runs entirely on the machine through Ollama — no code leaves the host, which is a hard requirement for a tool pointed at private source.

| property | value |
|---|---|
| model | `qwen2.5-coder:7b-instruct-q4_K_M` |
| fallback | `qwen2.5-coder:1.5b-instruct-q4_K_M` |
| decoding | greedy (`temperature=0.0`), seed pinned at `llm.GENERATION_SEED` |
| repair loop | up to 3 attempts, each re-validated |
| provenance | blob digest and server version in `env/model_provenance.txt` |

Every generated patch passes the same five-stage gate a template patch does (applies, parses, compiles, tests, rescan) and is never applied without an explicit human approval step. Measured acceptance over the 26-repository corpus is in §10.
