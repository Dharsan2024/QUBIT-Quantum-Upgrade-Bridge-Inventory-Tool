"""MigrateConfig — pydantic-settings (doc 03 §2)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class MigrateConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QUBIT_MIGRATE_",
        env_file=".env",
        extra="ignore",
    )

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


__all__ = ["MigrateConfig"]
