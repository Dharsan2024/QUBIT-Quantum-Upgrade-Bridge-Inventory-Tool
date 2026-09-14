"""MigrateConfig — pydantic-settings (doc 03 §2)."""

from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class MigrateConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QUBIT_MIGRATE_",
        env_file=".env",
        extra="ignore",
    )

    #: The regulatory regime targets are resolved under. `None` is the shipped default and
    #: leaves resolution exactly as it was — the regimes add a lens, they do not move the
    #: default, and every number already measured was measured on that path.
    #:
    #: One of `cnsa-2.0`, `anssi`, `bsi-tr-02102`, `asd-ism`, `nist-civil`. An unrecognised
    #: value falls through rather than failing: an operator's typo must not silently change
    #: the target, and must not stop the run either.
    #: `owner/repo@commit` for the corpus under migration. Denormalised onto every
    #: measurement row so an exported CSV identifies its own corpus without a join into a
    #: database the reader does not have — which is what makes the artefact citable on its
    #: own. Empty for an ordinary interactive run, where there is no corpus to name.
    corpus: str = ""
    regime: str | None = None
    model: str = "qwen2.5-coder:7b-instruct-q4_K_M"
    fallback_model: str = "qwen2.5-coder:1.5b-instruct-q4_K_M"
    #: Seconds to wait for one model completion. The default suits a 7B coder model; a 12B
    #: model exceeded it on the development machine for a two-line file, so it is settable
    #: rather than hardcoded.
    llm_timeout: float = 180.0
    #: Run the rule's rescan expectation between LLM attempts, so a rewrite that leaves the
    #: finding behind is fed back for correction instead of being rejected at the end. Costs
    #: one scanner subprocess per attempt.
    llm_verify_rescan: bool = True
    #: Ask the model to review its own draft against the rule's hard constraints before the draft
    #: is validated, and to return a corrected file if it finds a violation.
    #:
    #: The repair loop only ever fired on REJECTION, so a rewrite that passed every mechanical
    #: check shipped without anything ever asking the question a reviewer asks first: does this
    #: actually do the migration, or does it just contain the right token? The constraints that go
    #: unmet are the semantic ones — a fresh nonce per message, the auth tag stored, the legacy
    #: decrypt path kept so existing data stays readable. Costs one extra model call per
    #: generation; settable because that is a real cost on a slow machine.
    llm_self_review: bool = True
    #: For the STRUCTURAL rewrites only, make the model plan the change before writing it.
    #:
    #: A 7B model asked to rewrite a file in one step reliably gets the substitution right and the
    #: consequences wrong - it swaps the cipher and forgets the nonce must be fresh per message,
    #: or that existing ciphertext is now unreadable. Made to answer "what changes, what new
    #: values appear, what stops being readable, what must not move" first, it has already said
    #: those things by the time it writes. Gated on the rule declaring a data-compatibility hazard
    #: or four or more constraints, so the cheap substitutions do not pay for it.
    llm_plan_first: bool = True
    max_repair_rounds: int = 2
    min_confidence: float = 0.5

    # ── Routing: spend model time where it has been shown to pay ──────────────
    #: The model's context window, in tokens. Must match what Ollama actually loads (`ollama ps`
    #: reports it); 8192 is the default for the shipped 7B model on an 8 GB card.
    #:
    #: The window has to hold the prompt AND the answer. `_output_budget` already scales
    #: `num_predict` to the file, but nothing checked the INPUT side, so a file too large to fit
    #: was silently truncated by Ollama, the model saw a fragment, and the rewrite was rejected
    #: three times over. Measured on node-forge: `pkcs1.js` needs ~27,400 tokens and `rsa.js`
    #: ~20,900 against a window of 8,192 — 3.3x and 2.5x over. Neither could ever have succeeded.
    llm_context_tokens: int = 8192
    #: Which engine the router reaches for FIRST.
    #:
    #: `cheapest-first` (the default, and the historical behaviour) puts local Ollama at the head
    #: of the list: it costs nothing and has no daily quota, so a finding it can handle should
    #: never reach a metered endpoint.
    #:
    #: That is the right default and it was also, silently, a ceiling. An install can have a pool
    #: of large hosted engines attached — measured on this one: eleven, mostly a 120B — and every
    #: generation still went to a local 7B, because external was reachable only when local FAILED
    #: or the file was oversize. The evaluation's own design notes recorded this as
    #: "external-only is not expressible without a code change"; this is that change.
    #:
    #: `external-first` inverts the order and keeps local as the fallback, so an operator who has
    #: attached capacity can actually spend it. It is opt-in precisely because it spends a metered
    #: quota: nothing about the default changes, and results measured under one order must not be
    #: pooled with results measured under the other.
    engine_order: Literal["cheapest-first", "external-first"] = "cheapest-first"
    #: Permit an external model provider to receive repository source during generation.
    #:
    #: A configured provider is not sufficient consent: the generated prompt contains the target
    #: file and its migration context.  Keep this off until an operator has explicitly accepted
    #: that egress for the repository being migrated.  Local Ollama remains available either way.
    allow_external_source_processing: bool = False
    #: Restrict generation to the single primary local engine — no escalation to any external
    #: tier, regardless of failure or oversize. This remains useful for fixed-model evaluation
    #: arms even when external source processing has been explicitly enabled.
    #:
    #: Exists for the fixed-model ablation arms (a single-factor isolation of "does cost-ranked
    #: routing itself help, independent of ownership planning and behavioral validation, which
    #: are separate config toggles"): with this on, a finding the primary engine cannot handle
    #: goes to guided remediation exactly as it would with an empty pool, so the arm's outcome
    #: reflects one fixed model's capability, not the pool's.
    single_engine_only: bool = False
    #: Fraction of the window the prompt may occupy before the finding is routed to the guided
    #: path instead of the model. The remainder is left for the answer, which for a whole-file
    #: rewrite is about as long as the input.
    llm_max_prompt_fraction: float = 0.45
    #: Skip the model for a (rule, language) pair it has never once succeeded at, after this many
    #: recorded failures. The pairing matters: `code-kex-01` in Go is a different proposition from
    #: `code-weakhash-02` in Python, and the store already records both separately.
    #:
    #: This is a routing preference, never a permanent refusal. The guided path it routes to is a
    #: real remediation plan, the task stays retryable, and an explicit `generator="llm"` still
    #: goes to the model — a ceiling measured on one model is not a property of the task, and the
    #: next engine may clear it.
    llm_skip_after_failures: int = 4

    # validation sandbox
    no_docker: bool = False  # set True to skip stages 3-4
    #: Image the `tests` and `compiles` stages run in.
    #:
    #: The default is a bare interpreter, and that is precisely why `tests` reported `skipped` on
    #: every patch this installation has ever produced: it carries no pytest and none of the target
    #: repo's dependencies, so the suite dies on its own imports, the stage re-runs the untouched
    #: tree, that is red too, and it honestly declines to judge the patch. 292 patches, 292 skips.
    #:
    #: Point this at an image built from the target repo's PINNED dependency spec and the stage
    #: becomes a real behaviour-preservation oracle. Build it with the dependencies ONLY, never the
    #: project itself: an installed copy shadows the file the stage overlays into /work, so
    #: `import pkg` resolves to site-packages, the patch is never imported, and the stage would
    #: report `pass` for every patch regardless of what the model wrote.
    test_sandbox_image: str = "python:3.12-slim"
    #: What to run inside it. Overridable because a monorepo has to have its collection root pinned.
    #:
    #: `--continue-on-collection-errors` is not incidental. Real repositories carry modules that
    #: import optional dependencies, and a collection error is FATAL to a pytest run by default:
    #: measured on tornado, two unrelated modules under `maint/test/` (cython, redbot) aborted
    #: collection entirely and not one of its 1,174 passing tests ran. With the flag, those modules
    #: contribute nothing and everything else runs. That is safe here precisely because the verdict
    #: is a set difference against the untouched tree -- a test that could not be collected before
    #: the patch is not in the baseline, so it cannot be counted against the patch.
    test_command: str = "python -m pytest -q --continue-on-collection-errors"
    #: Seconds for one suite run. Was hardcoded at 300; a large suite legitimately exceeds that, and
    #: a timeout used to be scored as a patch failure rather than as "we could not tell".
    #:
    #: Raised to 900 on measurement, not on principle. wagtail's Django suite takes ~320s per run on
    #: this machine, so at 300 BOTH the baseline and the patched run timed out and the stage
    #: reported `skipped` -- a repository with a perfectly good oracle (its controls pass) producing
    #: no verdict at all, purely because the clock was set too tight. The cost of a generous ceiling
    #: is bounded: it is reached only when a suite is already going to be useless, and the container
    #: is killed by name at the limit either way.
    test_timeout_s: float = 900.0


__all__ = ["MigrateConfig"]
