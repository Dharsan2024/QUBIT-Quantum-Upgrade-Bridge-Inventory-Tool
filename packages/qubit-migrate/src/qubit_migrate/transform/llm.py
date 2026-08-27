"""LLM patch generation via local Ollama (doc 03 §6.3.2).

The model receives the full source file plus the rule's semantic note and constraints,
and must return the complete rewritten file in a fenced code block. The result is never
trusted blindly: the normal validation pipeline (parse, rescan, git-apply check) gates
every LLM patch exactly like a template patch.
"""

from __future__ import annotations

import ast
import json
import logging
import re
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from difflib import SequenceMatcher
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..kb import lookup_impact
from .languages import (
    LANGUAGE_TO_EXT,
    SUFFIX_TO_LANGUAGE,
    language_aliases,
    parse_error,
)
from .rules import MigrationRule
from .target_shapes import verified_target_shapes

if TYPE_CHECKING:
    from qubit_core import CryptoAsset

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://127.0.0.1:11434"

_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)


class OllamaError(Exception):
    """Raised when the local Ollama server fails or returns unusable output."""


class ModelOutputError(OllamaError):
    """The server answered, but the answer is not a usable file.

    Separated from its parent because the two need opposite handling. A server that is not running,
    a model that is not pulled and a request that timed out are all fatal -- retrying three times
    just makes the user wait three times as long for the same message. An answer that was truncated
    or came back unfenced is the model getting it wrong, which is exactly what the repair loop
    exists for, and it gets another attempt with the reason fed back.

    Subclasses OllamaError so every existing `except OllamaError` still catches it.
    """


#: Decoding seed, pinned so a run is reproducible rather than merely near-deterministic. Greedy
#: decoding at `temperature=0.0` is not the same guarantee: sampling is still seeded, ties are
#: broken by it, and a result nobody can reproduce exactly is not a result anyone can check.
GENERATION_SEED = 20260822

#: Floor for the output budget. Enough for a small file plus the fences around it.
_MIN_PREDICT = 4096
#: Ceiling. Beyond this a local 7B model is slower than the timeout allows, and a file needing more
#: than this is past what a whole-file rewrite should be attempting anyway.
_MAX_PREDICT = 16384


#: How much longer the rewritten file is than the original, for a STRUCTURAL migration.
#:
#: Measured across every before/after pair in the rule pack: the kex/signature examples average
#: **3.15x** and reach 5.3x, because replacing public-key encryption with a KEM is not a
#: substitution — it is a KEM+DEM construction with new imports, a derived key, a nonce, and an
#: AEAD call where there was one line. Even the "simple" swaps average 2.56x once the new
#: imports and error handling are counted.
#:
#: 3.5 is chosen above the structural mean rather than at it: overshooting costs nothing (Ollama
#: stops at the natural end of the answer; `num_predict` is a ceiling, not a target), while
#: undershooting truncates the file and throws away a rewrite that may have been correct.
_ANSWER_EXPANSION = 3.5


def _output_budget(prompt: str, source: str = "") -> int:
    """How many tokens the answer is allowed, scaled to the file being rewritten.

    `num_predict` was a fixed 4096 regardless of input. The task is to return a WHOLE FILE with one
    algorithm replaced, so any file whose answer exceeded the budget got a truncated answer, and the
    truncation surfaced as the baffling "the returned file has only 9 non-blank lines vs the
    original's 47". Three of the twelve LLM failures on the polyglot corpus were this, and none of
    them were the model being wrong.

    Scaling from the PROMPT fixed that only for small files, and the reason is arithmetic. The
    prompt is instructions + example + file; the answer is `_ANSWER_EXPANSION` x file. Budgeting
    `len(prompt)/3` therefore suffices only while instructions + example exceed ~2.15x the file —
    true for a 40-line file, false for a 1 800-line one. That is exactly the observed pattern:
    small files passed, large files came back truncated. Measured on this run's go-ethereum
    failures, three of five recorded Go rejections were `num_predict` truncation at the 4096 floor,
    not the model failing the task.

    Budgeting from `source` when it is known removes the dependency on how large the instructions
    happen to be. The prompt-derived figure is kept as a floor for the callers that have no source
    to hand (and because a long prompt does imply a long answer), so this can only ever raise the
    budget, never lower one that was already working.

    ~3 characters per token is a deliberate under-estimate for code (real tokenizers do better on
    ASCII), so both estimates err high.
    """
    from_prompt = len(prompt) // 3
    from_source = int(len(source) * _ANSWER_EXPANSION) // 3 if source else 0
    estimated_tokens = max(from_prompt, from_source)
    return max(_MIN_PREDICT, min(_MAX_PREDICT, estimated_tokens))


def _ollama_generate(
    prompt: str,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 180.0,
    source: str = "",
) -> str:
    """`_ollama_generate_once`, with a wall-clock deadline that does not trust `urlopen` alone.

    A property of `urllib.request.urlopen(timeout=N)` worth defending against even though it
    was not, in the end, what a specific slow run turned out to be: `timeout` on a blocking socket
    read bounds each INDIVIDUAL read, not the call as a whole. If the peer keeps the connection
    open and sends anything at all (a keep-alive byte, a partial chunk) before the deadline, the
    clock resets and the read can block again. A local model wedged on the GPU (a stuck kernel,
    VRAM contention with another process) is exactly the situation where a connection stays open
    without ever completing -- and the configured timeout would not save the caller from it.

    Because a real OS thread cannot be forced to stop mid-syscall, this cannot make the wedged
    request go away -- only Ollama restarting can do that. What it CAN do is stop that request from
    also wedging the caller: `_ollama_generate_once` runs in its own thread, and this function
    returns control (raising `OllamaError`) once `timeout` has genuinely elapsed, regardless of
    whether the inner call has noticed. The abandoned thread is daemonised so it cannot block
    process exit, and it is left to fail or return into a `Future` nothing is waiting on.

    Without this, nothing enforced the bound the config already claimed to have, so a wedged
    request would surface as unbounded silence rather than as a named error. (The run that
    prompted this was NOT in fact such a hang — it completed normally in 513s, and the apparent
    multi-hour stall was a UTC-vs-local timestamp misreading. The defence stands on the urllib
    property above, which is real and independently verifiable; it is recorded honestly here
    because a fix justified by a fictional incident invites being reverted by the next reader.)
    See `recover_orphaned`'s task-recovery half for what closes the gap this leaves in a task's
    own state when a hang happens anyway.
    """
    # A raw daemon thread, not `ThreadPoolExecutor`. Measured, not assumed: an EARLIER version of
    # this fix used a pool and correctly made THIS FUNCTION return in bounded time — but the
    # process as a whole still would not exit, because `ThreadPoolExecutor` registers its worker
    # threads with an `atexit` hook (`threading._register_atexit`) that JOINS every one of them
    # before the interpreter is allowed to shut down, wedged or not. `pool.shutdown(wait=False)`
    # only stops THIS call from waiting; it does not unregister the thread from that hook. A test
    # script making one abandoned call was itself unkillable past the process's own `timeout 45`
    # wrapper — proof the abandoned thread was still being waited on somewhere.
    #
    # A `threading.Thread` created with `daemon=True` is invisible to that hook by design: the
    # interpreter exits without waiting for daemon threads, which is exactly "abandon it" rather
    # than "abandon it, but only sort of".
    result: dict[str, Any] = {}

    def _worker() -> None:
        try:
            result["value"] = _ollama_generate_once(
                prompt, model=model, base_url=base_url, timeout=timeout, source=source
            )
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=_worker, name="ollama-generate", daemon=True)
    thread.start()
    # A grace margin over `timeout`, not the SAME value: `_ollama_generate_once` is meant to raise
    # its own, more specific `OllamaError` first (HTTP 404, a clean socket timeout, ...), and this
    # outer bound exists only to catch what that one fails to catch, not to race it.
    thread.join(timeout=timeout + 15)
    if thread.is_alive():
        raise OllamaError(
            f"the model {model!r} did not answer within {timeout:.0f}s and the connection "
            "itself did not report a timeout either — Ollama may be wedged. Restart it "
            "(`ollama serve`) and try again, or raise QUBIT_MIGRATE_LLM_TIMEOUT."
        )
    if "error" in result:
        raise result["error"]
    return result["value"]  # type: ignore[no-any-return]


def _ollama_generate_once(
    prompt: str,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 180.0,
    source: str = "",
) -> str:
    """Single non-streaming completion against the local Ollama server."""
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            # Reasoning models spend the output budget on reasoning QUBIT then discards, and the
            # answer never arrives. Measured on qwen3:8b: with thinking on, one request produced
            # 2 604 characters of reasoning and 35 of answer in 14.8 s; with it off, the same
            # request answered in 2.9 s. On a real file the reasoning exhausted `num_predict`
            # entirely and Ollama returned an empty response, which surfaced as a failed task.
            # Ollama ignores this field for models that do not support it.
            "think": False,
            "options": {
                "temperature": 0.0,
                "num_predict": _output_budget(prompt, source),
                "seed": GENERATION_SEED,
            },
        }
    ).encode("utf-8")
    if not base_url.startswith(("http://", "https://")):
        raise OllamaError(f"Invalid Ollama base URL scheme: {base_url}")
    req = urllib.request.Request(  # noqa: S310 — scheme validated above, local server
        f"{base_url}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data: dict[str, Any] = json.load(resp)
    except urllib.error.HTTPError as exc:
        # Ollama answers 404 for a model it does not have pulled. Reporting that as "unreachable"
        # sends the user to check a server that is running perfectly well, so name the real problem
        # and the command that fixes it.
        if exc.code == 404:
            raise OllamaError(_model_missing_message(model, base_url)) from exc
        raise OllamaError(f"Ollama returned HTTP {exc.code}: {exc.reason}") from exc
    except TimeoutError as exc:
        # A timeout is NOT "unreachable", and telling the user to start a server that is already
        # running sends them the wrong way. Measured: gemma4:12b exceeded the 180 s default on this
        # machine for a two-line Rust file, while the 7B coder model answered the same prompt in
        # 7.5 s. Model size is the usual cause, so name it.
        raise OllamaError(
            f"the model {model!r} did not answer within {timeout:.0f}s. A larger model needs more "
            f"time on this machine — raise QUBIT_MIGRATE_LLM_TIMEOUT, or use a smaller one."
        ) from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        # urllib wraps a socket timeout in URLError, so unwrap before blaming reachability.
        if isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
            raise OllamaError(
                f"the model {model!r} did not answer within {timeout:.0f}s. A larger model needs "
                "more time on this machine — raise QUBIT_MIGRATE_LLM_TIMEOUT, or use a smaller "
                "one."
            ) from exc
        raise OllamaError(
            f"Ollama is not reachable at {base_url}: {exc}. Start it with `ollama serve`."
        ) from exc
    text = data.get("response", "")
    if not text:
        raise OllamaError("Ollama returned an empty response")
    # Ollama says WHY it stopped. "length" means the answer hit `num_predict` and the file is cut
    # off mid-rewrite -- which used to reach the validator as a short file and be reported as the
    # model returning something wrong, sending the repair loop to argue with a model that had been
    # interrupted. Naming it means the caller can say so, and the operator can raise the budget.
    if str(data.get("done_reason", "")) == "length":
        raise ModelOutputError(
            f"the model {model!r} hit its output limit before finishing the file "
            f"(num_predict={_output_budget(prompt)}). The rewrite is truncated, not wrong. This "
            f"file may be too large for a whole-file rewrite by a local model."
        )
    return text


def installed_models(base_url: str = DEFAULT_BASE_URL) -> list[str]:
    """Model tags the local Ollama server actually has pulled, or [] if it cannot be asked."""
    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=5) as resp:  # noqa: S310
            payload: dict[str, Any] = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return []
    return [str(m.get("name", "")) for m in payload.get("models", []) if m.get("name")]


def _model_missing_message(model: str, base_url: str) -> str:
    available = installed_models(base_url)
    if available:
        have = ", ".join(sorted(available))
        return (
            f"the model {model!r} is not installed in Ollama. Installed: {have}. "
            f"Pull it with: ollama pull {model}"
        )
    return (
        f"the model {model!r} is not installed in Ollama, and no models are. "
        f"Pull one with: ollama pull {model}"
    )


def present_prefixes(rule: MigrationRule) -> list[str]:
    """The algorithms the rule's rescan requires to be PRESENT after a successful migration.

    This is the expectation the patch is finally judged against, so it is also the one the
    generator has to be told about.
    """
    expect = getattr(rule, "rescan_expect", None)
    if not isinstance(expect, dict):
        return []
    spec = expect.get("present", {})
    raw = spec.get("algorithm_prefix", "") if isinstance(spec, dict) else ""
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, list):
        return [p for p in raw if isinstance(p, str) and p]
    return []


def _scoped_constraints(
    rule: MigrationRule, language: str, *, have_target_shape: bool = False
) -> str:
    """Render the rule's constraints with each language's guidance addressed to that language.

    A cross-language rule writes its per-language API guidance as "Go: use crypto/mlkem ...".
    Every one of those lines was previously shown to every file it matched, unlabelled, so a `.rs`
    file's only concrete instruction was Go's — and the model followed it exactly, emitting
    `mlkem::GenerateKey768(&mut rng)` in Rust, where no such crate exists. The scanner cannot detect
    that, so the rescan reported the target missing and the task failed all three attempts. It was
    read as the model being too small for a structural rewrite; it was the prompt naming the wrong
    language.

    Scoping them away, though, cost more than it saved on the first measurement: `Wallet.swift`'s
    3DES → AES migration had been passing, and dropping every language-specific line left a Swift
    file with no concrete API named at all — the rule has guidance for four languages and Swift is
    not one of them. The wrong-language lines had been carrying real semantics (use GCM, keep the
    tag) along with the misdirection.

    So nothing is dropped. The lines addressed to this file's language are promoted to plain
    instructions; the rest are kept, still labelled with the language they belong to, under a note
    saying they are for reference and their APIs are not this file's. That removes the misdirection
    — which came from an unlabelled foreign instruction reading as an order — without removing what
    the rule knows.

    The fallback is last-resort only. When `have_target_shape` is set the scanner has supplied a
    verified example of the migrated state in this language, which is strictly better evidence than
    another language's prose, so the foreign lines are dropped rather than competing with it.

    A line is language-specific when everything before its first colon names languages and nothing
    else. Anything else, including a line with no colon at all, is universal and always shown.
    """
    aliases = language_aliases(language)
    kept: list[str] = []
    foreign: list[str] = []
    matched_own_language = False
    for line in rule.prompt_constraints or []:
        head, sep, tail = line.partition(":")
        if sep and tail.strip():
            names = [n.strip().lower() for n in head.replace(",", "/").split("/")]
            # EVERY name must be a language for this to count as language-specific guidance —
            # otherwise an ordinary sentence like "Note: keep the old decrypt path" would be
            # silently dropped from every prompt it appears in.
            if names and all(n in _ALL_LANGUAGE_NAMES for n in names):
                if aliases.intersection(names):
                    kept.append(tail.strip())
                    matched_own_language = True
                else:
                    foreign.append(line.strip())
                continue
        kept.append(line)

    rendered = "\n".join("- " + c for c in kept)
    if foreign and not matched_own_language and not have_target_shape:
        label = language or "this language"
        rendered += (
            f"\n\nThis rule has no guidance written for {label}. The lines below describe how "
            f"OTHER languages do it. Read them for the shape of the migration, not for API "
            f"names. Use "
            f"{label}'s own crypto library; do not translate these calls literally.\n"
        )
        rendered += "\n".join("- " + c for c in foreign)
    return rendered


def _target_shape_block(rule: MigrationRule, language: str) -> str:
    """Show the model a shape the scanner is verified to recognise as the migrated state.

    A patch is kept only if the rescan DETECTS the target algorithm in the rewritten file, so the
    shapes the scanner can recognise are the only rewrites that can ever pass. Nothing published
    that set, and the model was left to infer the API from prose. Handing it one verified example
    turned a case refused after three attempts into one accepted on its second — same model, same
    machine, same file.

    The shapes come from the scanner's own rule examples via `verified_target_shapes`, so the
    instruction the generator follows and the check that judges it have one source and cannot
    drift apart.
    """
    for prefix in present_prefixes(rule):
        shapes = verified_target_shapes(language, prefix)
        if not shapes:
            continue
        best = shapes[0]
        return (
            "QUBIT confirms a migration by DETECTING the new algorithm in your output. In "
            + language
            + " it recognises "
            + ", ".join(best.algorithms)
            + " from code shaped like this — use this module and these call names, adapted to "
            + "the file you are given:\n```"
            + language
            + "\n"
            + best.source
            + "\n```\n\n"
        )
    return ""


def _attack_note(asset: CryptoAsset) -> str:
    """One line saying what KIND of broken this finding is, taken from the finding itself.

    Without it the model read "RSA-1024" as a short key and returned RSA-2048 -- correct for a
    key-length problem, useless against Shor's algorithm, and rejected by the rescan. Grover is the
    opposite case: for a symmetric primitive a larger key genuinely is part of the answer, so this
    is read from the asset rather than asserted for every finding.
    """
    attack = getattr(getattr(asset, "quantum_vulnerable", None), "attack", None)
    value = getattr(attack, "value", attack)
    if value == "shor":
        return (
            f"{asset.algorithm} is broken by Shor's algorithm at EVERY key size. Increasing the "
            f"key length is not a migration and will be rejected: only a post-quantum algorithm "
            f"fixes this.\n"
        )
    if value == "grover":
        return (
            f"{asset.algorithm} is weakened by Grover's algorithm, which halves the effective "
            f"strength of a symmetric primitive. A large enough key and a modern construction are "
            f"the fix here.\n"
        )
    return ""


def _weakness_block(asset: CryptoAsset) -> str:
    """The classical weaknesses the SCANNER read at this call site, stated as facts.

    The difference between "migrate this AES call" and "this AES call runs in ECB mode; encrypt
    with an AEAD mode instead" is the difference between a rewrite that guesses at the defect and
    one that addresses it. Same for a KDF: "PBKDF2" says nothing, while "1,000 iterations against
    a published floor of 600,000" says exactly what to change and to what.

    These come from `qubit_core.weaknesses`, derived from the mode, padding, iteration count and
    PRF captured at the call - so they are observations about THIS code, not a general warning the
    model has to work out applies.
    """
    evidence = getattr(asset, "evidence", None)
    context = getattr(evidence, "context", None)
    raw = (getattr(context, "extra", None) or {}).get("weaknesses")
    found = [w for w in raw if isinstance(w, dict)] if isinstance(raw, list) else []
    if not found:
        return ""
    lines = ["What the scanner observed AT THIS CALL, beyond the algorithm name:"]
    for weakness in found:
        detail = weakness.get("detail") or {}
        facts = ", ".join(f"{k}={v}" for k, v in detail.items() if v not in (None, "", "unknown"))
        lines.append(f"- {weakness.get('title', '')}" + (f" ({facts})" if facts else ""))
        remedy = str(weakness.get("remedy", "")).strip()
        if remedy:
            lines.append(f"  Required: {remedy}")
    return "\n".join(lines) + "\n\n"


def _impact_block(rule: MigrationRule) -> str:
    """Tell the model what this migration BREAKS, not just what to call instead.

    The biggest gap between a QUBIT patch and a real migration was that the prompt asked for a
    primitive swap and got one — which is also the reason a reviewer could fairly ask what the tool
    adds over a developer doing the same substitution by hand. An ML-DSA-65 signature is 3309 bytes
    where RSA-2048 gave 256, so the `VARCHAR(256)` column, the `[64]byte` array and the 4 KB cookie
    holding it are all broken by a patch that looks correct at the call site — and none of that is
    visible from the flagged line, which is exactly why it is missed by hand.

    Sourced from the KB's `artifact_impact` (`params/migration_kb.yaml`) rather than written into
    the prompt, so the numbers have one home and cite their FIPS parameter tables. Renders empty
    for a target with no recorded impact (a weak-hash swap genuinely IS a small change), so this
    never manufactures gravity a migration does not have.
    """
    target = str((rule.target or {}).get("algorithm", ""))
    impact = lookup_impact(target) if target else None
    if impact is None:
        return ""

    parts = [
        f"This migration targets {target}"
        + (f" ({impact.fips})" if impact.fips else "")
        + ". Migrating to it is NOT a rename — it changes sizes and shapes:\n"
    ]
    if impact.sizes:
        sizes = ", ".join(f"{k.replace('_', ' ')} {v} bytes" for k, v in impact.sizes.items())
        parts.append(f"- {target} sizes: {sizes}.\n")
    for classical, was in impact.replaces.items():
        parts.append(f"- It replaces {classical}, which had: {was}.\n")
    if impact.breaks:
        parts.append(
            "\nA correct patch handles ALL of the following. Where a consequence lives outside "
            "this file, still fix what you can here and leave a clear comment naming what else "
            "must change:\n"
        )
        parts.extend(f"- {b.strip()}\n" for b in impact.breaks)
    parts.append(
        "\nDo not produce a one-line substitution. Migrate the whole flow present in this file: "
        "key generation, serialisation, storage widths, length fields, and the verify/decrypt "
        "path.\n\n"
    )
    return "".join(parts)


#: Lines of stored reasoning replayed per example. The diff is the demonstration; this is the
#: gloss on it, and a long gloss crowds out the file the model is supposed to be reading.
_REASONING_LINES = 4


def _experience_examples(experience: Any | None, language: str) -> str:
    """What this project has already learned about migrations like this one.

    Three kinds of evidence, said differently on purpose:

    * a rewrite of the SAME structural shape, which is as close to "here is the answer" as
      grounding gets and is labelled so;
    * verified rewrites for the same rule and language, each with the reasoning the model gave
      when it passed - a verified explanation of a verified change is stronger few-shot content
      than the diff alone, because it says WHY the shape is what it is;
    * rejections recorded against this shape, said as warnings rather than examples. Mixing those
      in with the successes would invite the model to copy the thing that failed.

    Accepts either the current `learn.Experience` or the older flat list of (before, after) pairs,
    because `generate_llm_source` is called from tests and the CLI that still pass the latter.
    """
    if not experience:
        return ""

    proven: list[tuple[str, str, str]] = []
    failures: list[str] = []
    exact = near = False
    if isinstance(experience, list):
        proven = [(before, after, "") for before, after in experience]
    else:
        proven = list(getattr(experience, "proven", []) or [])
        failures = list(getattr(experience, "failures", []) or [])
        exact = bool(getattr(experience, "exact_shape", False))
        near = bool(getattr(experience, "near_miss", False))
    if not proven and not failures:
        return ""

    parts: list[str] = []
    if proven:
        if exact:
            lead = (
                "QUBIT has already migrated code of EXACTLY this shape and the result passed "
                "validation. Follow it closely - the differences between that code and yours are "
                "names, not structure:"
            )
        elif near:
            # Said differently on purpose. A near miss shares most of its tokens but genuinely
            # differs by a statement, and telling the model it is looking at the same shape would
            # invite it to copy a structure that does not quite fit.
            lead = (
                "QUBIT has migrated code very close to this - the same calls, differing by a "
                "statement or two. Use it as the shape of the answer, but read your own file "
                "rather than transcribing it:"
            )
        else:
            lead = (
                "QUBIT has previously verified the following patches for this rule. Use them as "
                "a strong guide for your rewrite:"
            )
        rendered = []
        for i, (before, after, reasoning) in enumerate(proven, 1):
            block = (
                f"Verified patch {i} — BEFORE:\n```{language}\n{before.rstrip()}\n```\n"
                f"Verified patch {i} — AFTER:\n```{language}\n{after.rstrip()}\n```\n"
            )
            if reasoning.strip():
                # Trimmed hard. The retrieval literature is consistent that the DIFF is the
                # primary signal, and that adding context past a small amount stops helping and
                # starts hurting: a few hundred characters of prose per example competes with the
                # file being edited for a 7B model's attention. Kept because this reasoning is
                # verified — it accompanied a patch that passed the gate — but kept short.
                summary = "\n".join(reasoning.strip().splitlines()[:_REASONING_LINES])
                block += f"Verified patch {i} — why that was correct:\n{summary}\n"
            rendered.append(block)
        parts.append(lead + "\n\n" + "\n".join(rendered))

    if failures:
        parts.append(
            "A previous attempt at this same code was REJECTED for the reason(s) below. Do not "
            "repeat it — this is what to avoid, not an example to copy:\n"
            + "\n".join(f"- {reason.strip()}" for reason in failures if reason.strip())
        )

    return "\n".join(parts) + "\n\n"


#: Rules whose rewrite is structural rather than a substitution get a planning pass first. Judged
#: from the rule itself rather than a hand-kept list: a rule that declares its data cannot be read
#: after the change (`reencrypt_required` / `dual_read`), or that carries four or more hard
#: constraints, is describing a change with several moving parts.
_PLAN_MIN_CONSTRAINTS = 4


def needs_planning(rule: MigrationRule) -> bool:
    """Whether this rewrite is structural enough to be worth planning before writing.

    Two conditions, and BOTH are required. The rule must declare that existing data is affected
    (`reencrypt_required` / `dual_read`), because forgetting that stored ciphertext is now
    unreadable is the specific mistake this pass exists to prevent - and it must carry at least
    four constraints, as a proxy for how many parts move at once.

    Either alone is too broad. `code-weakhash-02` is `dual_read` with two constraints and is a
    token swap with a deterministic codemod behind it; `code-tls-01` has six constraints, is
    `in_place`, and already succeeds at a rate planning could only slow down. What is left is the
    set the model measurably gets wrong: the key length changes, a nonce appears that must be
    fresh per message, an authentication tag appears with nowhere to go in the old call site, and
    the stored format changes so existing data stops being readable.
    """
    hazard = getattr(rule, "data_compat", "in_place") in {"reencrypt_required", "dual_read"}
    return hazard and len(rule.prompt_constraints or []) >= _PLAN_MIN_CONSTRAINTS


def _plan_block(plan: str) -> str:
    """The model's own plan, handed back to it as the thing to implement."""
    if not plan.strip():
        return ""
    return (
        "This is YOUR plan for this change, written before you saw the requirement to produce a "
        "file. Implement it. If any step of it turns out to be wrong, say so in the security "
        "notes rather than silently doing something else:\n"
        f"{plan.strip()}\n\n"
    )


def _build_plan_prompt(
    source: str, rule: MigrationRule, asset: CryptoAsset, language: str, experience: Any | None
) -> str:
    constraints = _scoped_constraints(rule, language)
    return (
        "You are a cryptographic migration engineer. Before writing any code, plan the change.\n\n"
        f"Flagged: {asset.algorithm} used for {asset.usage_context.value} on line "
        f"{asset.location.line if asset.location else '?'}.\n"
        f"Migration: {rule.title}\n"
        f"Guidance: {rule.semantic_note or ''}\n"
        f"Requirements a correct change must meet:\n{constraints}\n\n"
        f"{_weakness_block(asset)}"
        f"{_experience_examples(experience, language)}"
        f"```{language}\n{source}\n```\n\n"
        "Write a SHORT plan, no code. Answer these five questions in order, one or two lines "
        "each:\n"
        "1. Which function(s) in this file change, and what does each become?\n"
        "2. What new values does the change introduce (a key of a different length, a nonce, a "
        "tag, a salt), and where does each one come from and get stored?\n"
        "3. What can no longer be read after this change - stored ciphertext, stored hashes, "
        "tokens already issued - and what keeps working while it is migrated?\n"
        "4. What OUTSIDE this file has to change as a result (callers, column widths, key "
        "formats)?\n"
        "5. What must NOT change?\n\n"
        "Plan only. Do not write the rewritten file yet."
    )


def plan_rewrite(
    source: str,
    rule: MigrationRule,
    asset: CryptoAsset,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 180.0,
    language: str = "",
    experience: Any | None = None,
) -> str:
    """Ask the model what it intends to do, before asking it to do it.

    A 7B model asked to rewrite a file in one step reliably gets the SUBSTITUTION right and the
    consequences wrong - it swaps the cipher and forgets that the nonce must be fresh, or that the
    old ciphertext is now unreadable. Made to answer "what changes, what appears, what breaks,
    what must not move" first, it has already said those things once by the time it writes, and
    they are in its context while it does.

    Returns "" on any failure. The plan is an aid; a generation that cannot get one proceeds
    without it rather than failing.
    """
    lang = language or _prompt_language(rule, asset)
    try:
        raw = _ollama_generate(
            _build_plan_prompt(source, rule, asset, lang, experience),
            model=model,
            base_url=base_url,
            timeout=timeout,
        )
    except (OSError, OllamaError) as exc:
        logger.info("planning pass unavailable (%s); generating without a plan", exc)
        return ""
    # A plan that came back as a code block is not a plan - the model skipped ahead and wrote the
    # file. Its rewrite is not trustworthy here (nothing has validated it) and pasting it into the
    # generation prompt as "the plan" would invite it to be copied unchecked.
    text = raw.split("```")[0].strip() if "```" in raw else raw.strip()
    if len(text.split()) < 15:
        return ""
    return "\n".join(text.splitlines()[:20]).strip()


def _build_prompt(
    source: str,
    rule: MigrationRule,
    asset: CryptoAsset,
    feedback: str | None = None,
    experience: Any | None = None,
    plan: str = "",
) -> str:
    language = _prompt_language(rule, asset)
    target_shape = _target_shape_block(rule, language)
    constraints = _scoped_constraints(rule, language, have_target_shape=bool(target_shape))
    return (
        "You are a cryptographic migration engineer. Rewrite the file below to migrate the "
        "flagged weak cryptography.\n\n"
        "Answer in EXACTLY this shape:\n"
        "1. The complete rewritten file inside ONE fenced code block. Put nothing but code in "
        "the fence — no prose, no commentary, no explanation inside it.\n"
        "2. AFTER the closing fence, a section beginning `SECURITY NOTES:` with 2-4 short "
        "bullets: what you changed and why it is quantum-safe, what an operator must change "
        "OUTSIDE this file (storage widths, key formats, callers), and anything you could not "
        "fix here. State this honestly — a note saying a change is incomplete is far more "
        "useful than a claim that it is done.\n\n"
        f"Flagged asset: algorithm={asset.algorithm}, usage_context={asset.usage_context.value}, "
        f"line={asset.location.line if asset.location else '?'}\n"
        f"{_attack_note(asset)}"
        f"{_weakness_block(asset)}"
        f"Migration rule: {rule.title}\n"
        f"Guidance: {rule.semantic_note or ''}\n"
        f"Hard constraints:\n{constraints}\n\n"
        # A rule may describe more than one replacement path (py-weakhash-01 offers argon2id for
        # credential hashing and SHA-256 for generic digests). Nothing previously told the model to
        # BRANCH, so with usage_context="unknown" it hedged: qwen2.5-coder produced the correct
        # SHA-256 migration but also emitted a bare `import argon2`, adding an unused, undeclared
        # third-party dependency that raises ModuleNotFoundError wherever argon2-cffi is absent.
        # Making the branch explicit, and banning imports that are not actually used, removes the
        # hedge without constraining which path a rule offers.
        "If the guidance offers more than one replacement path, choose EXACTLY ONE: the path that "
        f"matches usage_context={asset.usage_context.value}. When usage_context is 'unknown', "
        "decide from the surrounding code (does it store or verify a credential, or merely digest "
        "data?) and prefer the general-purpose digest path unless the code clearly handles "
        "credentials.\n"
        "Do NOT add an import for a library you do not actually call in the rewritten file.\n"
        # An import left behind for an algorithm no longer called is dead code, and in a language
        # whose rules match import statements it is also still a finding. Measured in Rust it is
        # not: `use rsa::RsaPrivateKey;` alone produces no detection, because the rule matches the
        # keygen call. So this instruction is hygiene, not the fix it was once described as — the
        # rewrites that were failing had removed the old algorithm entirely and were rejected for
        # the opposite reason, that the NEW one could not be found. See `_target_shape_block`.
        "REMOVE any import, use-statement or include that your rewritten file no longer "
        "references. An import for the algorithm you just migrated leaves that algorithm present "
        "in the file, which means the migration did not happen.\n\n"
        "Preserve all unrelated code, comments, and formatting exactly.\n"
        # A file of unrelated crypto calls reads like a list of examples, and the model answered
        # one of them: asked to migrate 3DES in this 15-line file it returned a clean 6-line
        # AES-GCM module and dropped the other nine calls. The truncation guard caught it, but
        # "return the COMPLETE file" as retry feedback did not fix it three attempts running.
        # Stating the size up front makes the requirement one the model can check as it writes,
        # rather than one only the guard can check afterwards.
        f"The file below has {len(source.splitlines())} lines. Your output must contain all of "
        "them, in order, changing only what this migration requires. Do not summarise, "
        "reorganise, or drop code unrelated to the flagged algorithm.\n\n"
        f"{_impact_block(rule)}"
        f"{target_shape}"
        f"{_worked_examples(rule, language)}"
        f"{_experience_examples(experience, language)}"
        f"{_plan_block(plan)}"
        f"{_repair_feedback(feedback)}"
        f"```{language}\n{source}\n```\n"
    )


# Suffixes of `example_*` keys that name a LANGUAGE rather than a replacement branch. Derived from
# the shared table so a rule can carry `example_ruby` / `example_swift` and have it recognised —
# a hardcoded list would silently treat those as replacement branches and render them for every
# language at once.
_EXAMPLE_LANGUAGES = frozenset(SUFFIX_TO_LANGUAGE.values())

# Every name any supported language answers to. Derived from the shared suffix map and the
# alias table rather than listed here, so a language added to the scanner is recognised in
# rule guidance without a second edit — the drift that put Go's API into a Rust prompt.
_ALL_LANGUAGE_NAMES = frozenset(
    name for lang in _EXAMPLE_LANGUAGES for name in language_aliases(lang)
)


def _prompt_language(rule: MigrationRule, asset: CryptoAsset) -> str:
    """The language to label code fences with, and to pick worked examples for.

    A cross-language rule declares `language: multi`, so labelling the prompt's fences with
    `rule.language` told the model the file was written in "multi". The file's extension is the real
    answer.
    """
    path = asset.location.file_path if asset.location else None
    if path:
        derived = SUFFIX_TO_LANGUAGE.get(Path(path).suffix.lower())
        if derived is not None:
            return derived
    return rule.language or ""


def _primary_example_language(rule: MigrationRule) -> str:
    """The language the rule's unlabelled `example:` block is written in.

    A single-language rule (`language: python`) states it directly. A cross-language rule declares
    `multi`, and its primary example is written in whichever language the author reached for —
    recorded as `example_language:` in the rule so it is stated rather than guessed. Without that,
    the primary example was attached to files in every other language too.
    """
    declared = getattr(rule, "example_language", None)
    if declared:
        return str(declared).lower()
    if rule.language and rule.language.lower() != "multi":
        return rule.language.lower()
    return ""


def _worked_examples(rule: MigrationRule, language: str = "") -> str:
    """Render the rule's before/after pairs as few-shot demonstrations.

    Every rule file already carries `example: {before, after}` (and some an `example_<path>` for a
    second branch), but none of it ever reached the model — it was documentation only. For a local
    7B-class model a concrete before/after pair is the single strongest signal available, far more
    reliable than prose constraints, so the examples are now part of the prompt.

    Cross-language rules carry one example PER LANGUAGE (`example_java`, `example_c`, …). Rendering
    all of them meant a Go file arrived with Java, JavaScript and C demonstrations attached — three
    quarters of the prompt's strongest signal pointing at the wrong language, which invites a 7B
    model to mix idioms. Only the matching language's example is included.

    An `example_*` key whose suffix is NOT a language names a replacement BRANCH instead
    (`example_generic_digest` on py-weakhash-01) and is always kept: those demonstrate a choice the
    rule offers rather than a language.
    """
    lang = (language or rule.language or "").lower()
    language_specific = {
        name.replace("example_", "").lower(): (name, value)
        for name, value in rule.extra_examples.items()
        if name.replace("example_", "").lower() in _EXAMPLE_LANGUAGES
    }

    pairs: list[tuple[str, dict[str, str]]] = []
    match = language_specific.get(lang)
    if match is not None:
        # This language has its own example, so the primary belongs to a different one — drop it.
        pairs.append(match)
    elif rule.example and _primary_example_language(rule) == lang:
        pairs.append(("example", rule.example))
    # Otherwise: NO example. Attaching one written in another language is worse than attaching
    # none — measured, the 7B model returned the example's language verbatim for 3 of 4 files.
    # The prose constraints and the target algorithm still reach the model.

    for name, value in sorted(rule.extra_examples.items()):
        if name.replace("example_", "").lower() in _EXAMPLE_LANGUAGES:
            continue  # handled above; other languages are noise
        pairs.append((name, value))

    rendered: list[str] = []
    for name, pair in pairs:
        before, after = pair.get("before"), pair.get("after")
        if not before or not after:
            continue
        label = name.replace("example_", "").replace("_", " ") or "example"
        rendered.append(
            f"Worked {label} — BEFORE:\n```{lang}\n{before.rstrip()}\n```\n"
            f"Worked {label} — AFTER:\n```{lang}\n{after.rstrip()}\n```\n"
        )
    if not rendered:
        return ""
    return (
        "Follow the transformation shown in these worked examples. They demonstrate the intended "
        "shape of the change, not the file you must edit:\n\n" + "\n".join(rendered) + "\n"
    )


def _repair_feedback(feedback: str | None) -> str:
    """Render the previous attempt's failure so the model can correct it.

    Without this the generator was strictly one-shot: a truncated or unparseable rewrite was simply
    a failed task, even though the specific defect is usually trivial for the model to fix when told
    what it was.
    """
    if not feedback:
        return ""
    return (
        "Your previous attempt was REJECTED for this reason:\n"
        f"  {feedback}\n"
        "Produce a corrected, complete file that does not repeat that mistake.\n\n"
    )


#: An opening fence with no closing one. The usual cause is an answer cut off at `num_predict`:
#: the model opened ```python, wrote most of the file, and ran out of budget. `_FENCE_RE` needs the
#: closing fence, so it found nothing and the whole answer was discarded.
_OPEN_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*)\Z", re.DOTALL)

#: Openings that mean the model is talking rather than emitting a file. Checked only on the
#: last-resort path, where there are no fences to trust.
_PROSE_OPENERS = (
    "i ",
    "i'm",
    "sure",
    "certainly",
    "here is",
    "here's",
    "of course",
    "to migrate",
    "the file",
    "this file",
    "unfortunately",
    "note that",
    "okay",
    "ok,",
)


#: The rationale section the prompt asks for, after the closing fence.
_NOTES_RE = re.compile(r"SECURITY\s+NOTES\s*:?\s*(?P<body>.+)\Z", re.IGNORECASE | re.DOTALL)


def extract_security_notes(text: str) -> str:
    """The model's own account of what it changed and what it could not, or "" if absent.

    A patch is reviewed by a person, and a diff alone does not say whether the model UNDERSTOOD
    the migration or merely pattern-matched it. Asking for the reasoning and keeping it beside the
    diff is what lets a reviewer check semantic correctness — "did it move the whole flow, and does
    it admit what it left behind" — rather than only that the target token now appears.

    Deliberately optional and never fatal: a model that returns a perfect file and forgets the
    section has still produced a good patch, and failing it over a missing heading would trade real
    coverage for a formatting preference. Anything found inside the code fence is ignored, because
    the fence is parsed for source first and prose there is a defect the existing guards catch.
    """
    tail = text
    last_fence = text.rfind("```")
    if last_fence != -1:
        tail = text[last_fence + 3 :]
    m = _NOTES_RE.search(tail)
    if m is None:
        return ""
    body = m.group("body").strip()
    # Keep it short: this is shown next to a diff, not a document.
    return "\n".join(body.splitlines()[:8]).strip()


def extract_code_block(text: str) -> str:
    """Pull the rewritten file out of the model output.

    Three ways in, in descending order of how much the model told us:

    1. **A closed fenced block.** What the prompt asks for; largest wins when there are several.
    2. **An unterminated fence.** The model marked where the code starts and then hit its output
       limit before closing it. The content is still the model's own idea of code, and discarding
       it loses a rewrite that is merely incomplete -- which the caller's length check will catch
       and report accurately anyway.
    3. **Bare output with no fence at all.** Two of the twelve LLM failures on the polyglot corpus
       were "Model output contained no fenced code block" -- a formatting slip, not a wrong answer.

    Case 3 is the risky one, because accepting an apology as source code would be worse than
    failing. It is gated on the text not opening like prose, and everything that gets through is
    parsed by the caller before it can become a patch, so a bad guess is rejected one step later
    with a better message than "no fenced code block".
    """
    blocks = _FENCE_RE.findall(text)
    if blocks:
        return max(blocks, key=len)

    unterminated = _OPEN_FENCE_RE.search(text)
    if unterminated and unterminated.group(1).strip():
        return unterminated.group(1)

    stripped = text.strip()
    lowered = stripped.lower()
    if (
        stripped
        and "```" not in stripped
        and len(stripped.splitlines()) >= 2
        and not lowered.startswith(_PROSE_OPENERS)
    ):
        return stripped

    raise ModelOutputError("Model output contained no fenced code block")


# A rewrite that loses this much of the original file is treated as truncation/deletion rather than
# a migration. Patches legitimately shrink a little (dropping an import, collapsing a helper), but a
# whole-file rewrite that comes back at 60% of the original has almost certainly dropped code the
# prompt asked it to preserve — and the sandbox cannot catch that in a repo without tests.
_MIN_RETAINED_FRACTION = 0.7

# How many times to re-prompt with the rejection reason before giving up.
_MAX_ATTEMPTS = 3


def _normalised(text: str) -> str:
    """Whitespace-insensitive form, so an echo is not disguised by re-indentation."""
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


#: How close to a worked example an output may be before it is treated as a copy of it. Below 1.0
#: because a model reproducing an example rarely does so byte-for-byte -- it renames a variable or
#: drops a comment. Measured on the observed failure, which was an exact copy.
_ECHO_RATIO = 0.9


def _echoes_worked_example(source: str, new_source: str, rule: MigrationRule | None) -> str | None:
    """Reject an output that is the rule's demonstration rather than a rewrite of this file.

    The exemption matters: when the file being migrated IS an example's `before` block, returning
    that example's `after` block is the correct migration, not an echo. Rule-fixture tests do
    exactly this.
    """
    if rule is None:
        return None
    candidate = _normalised(new_source)
    if not candidate:
        return None
    given = _normalised(source)

    pairs: list[tuple[str, dict[str, str]]] = []
    if rule.example:
        pairs.append(("example", rule.example))
    pairs.extend(sorted(rule.extra_examples.items()))

    for name, pair in pairs:
        after = _normalised(str(pair.get("after") or ""))
        before = _normalised(str(pair.get("before") or ""))
        if not after:
            continue
        if before and SequenceMatcher(None, given, before).ratio() >= _ECHO_RATIO:
            continue  # this file IS the example; reproducing its `after` is correct
        if SequenceMatcher(None, candidate, after).ratio() >= _ECHO_RATIO:
            label = name.replace("example_", "").replace("_", " ") or "example"
            return (
                f"the output is the rule's worked {label}, not a rewrite of the file you were "
                f"given. The examples demonstrate the shape of the change; apply that shape to "
                f"every line of THIS file and return it in full"
            )
    return None


def check_rewrite(
    source: str, new_source: str, language: str | None, rule: MigrationRule | None = None
) -> str | None:
    """Return a rejection reason for an LLM rewrite, or None if it looks acceptable.

    These are the CHEAP local checks: they run before the patch is stored and cost nothing, so a
    truncated or unparseable rewrite is caught and re-prompted immediately instead of consuming a
    full sandbox validation run. The sandbox pipeline still gates the result afterwards — this only
    filters out the failures that are obvious without executing anything.
    """
    if not new_source.strip():
        return "the returned file was empty"
    if new_source.strip() == source.strip():
        return "the file came back unchanged — the flagged algorithm was not migrated"

    echoed = _echoes_worked_example(source, new_source, rule)
    if echoed is not None:
        return echoed

    original_lines = [ln for ln in source.splitlines() if ln.strip()]
    new_lines = [ln for ln in new_source.splitlines() if ln.strip()]
    if original_lines:
        retained = len(new_lines) / len(original_lines)
        if retained < _MIN_RETAINED_FRACTION:
            return (
                f"the returned file has only {len(new_lines)} non-blank lines versus "
                f"{len(original_lines)} in the original, so code was dropped or the output was "
                "truncated; return the COMPLETE file"
            )

    # Python can be parsed for free with the stdlib, which catches truncation mid-statement.
    if (language or "").lower() == "python":
        try:
            ast.parse(new_source)
        except SyntaxError as exc:
            return f"the returned Python file does not parse: {exc.msg} at line {exc.lineno}"

    # Language-agnostic truncation signal: unbalanced brackets almost always means a cut-off file.
    for opener, closer in (("{", "}"), ("(", ")"), ("[", "]")):
        if new_source.count(opener) != new_source.count(closer):
            return (
                f"the returned file has unbalanced '{opener}{closer}' brackets, which means it was "
                "truncated; return the COMPLETE file"
            )

    # Did it come back in the RIGHT LANGUAGE? Measured against the real 7B model, the most common
    # failure was not truncation but the model returning the worked example's language: a Ruby file
    # came back as Go, a Kotlin file as Python. Parsing the result under the file's own grammar
    # catches that in the repair loop, where the reason can be fed back, instead of letting it reach
    # the sandbox as a wasted attempt.
    lang = (language or "").lower()
    if lang and lang != "multi":
        problem = parse_error(new_source, lang)
        # Only blame the rewrite for an error the ORIGINAL did not already have. A file the grammar
        # cannot fully parse (SQL with `:name` bind parameters) would otherwise burn every repair
        # attempt on a defect the model did not introduce and cannot remove.
        if problem is not None and parse_error(source, lang) is None:
            return (
                f"the returned file {problem}. The file you must edit is written in {lang} — "
                f"return {lang}, not any other language, and change only the flagged algorithm"
            )
    return None


#: What the model must answer with when its own review finds nothing wrong.
_REVIEW_OK = "VERDICT: OK"

_REVIEW_OK_RE = re.compile(r"VERDICT\s*:\s*OK", re.IGNORECASE)


def _build_review_prompt(
    source: str, draft: str, rule: MigrationRule, asset: CryptoAsset, language: str
) -> str:
    """Ask the model to check its own rewrite against the constraints that actually matter.

    Deliberately NOT "is this good?" — a model asked that says yes. It is given the specific list
    of things this migration has to get right, which the rule already carries as
    `prompt_constraints`, and asked to name the ones its own output missed. That is a question with
    a checkable answer, and the failures it catches are exactly the ones every other stage is blind
    to: the syntax parses, the target algorithm is present, the rescan is satisfied, and the nonce
    is still reused across messages.
    """
    constraints = _scoped_constraints(rule, language)
    return (
        "You are reviewing a cryptographic migration patch before it goes to a human reviewer.\n\n"
        f"The finding: {asset.algorithm} used for {asset.usage_context.value} on line "
        f"{asset.location.line if asset.location else '?'}.\n"
        f"The migration: {rule.title}\n\n"
        "These are the requirements a correct patch must meet:\n"
        f"{constraints}\n\n"
        "ORIGINAL FILE:\n"
        f"```{language}\n{source}\n```\n\n"
        "PROPOSED REWRITE:\n"
        f"```{language}\n{draft}\n```\n\n"
        "Check the rewrite against EACH requirement above, and against these questions:\n"
        "- Does every call site that used the old algorithm now use the new one, or is one left "
        "behind further down the file?\n"
        "- Is any value that must be unique per operation (a nonce, an IV, a salt) actually "
        "fresh each time, rather than fixed, reused, or derived from the data?\n"
        "- Is anything the new algorithm produces and the old one did not - an authentication "
        "tag, a longer ciphertext, a different stored format - actually stored and used?\n"
        "- Can data written by the OLD code still be read after this change? If not, is there a "
        "path that keeps it readable during the transition?\n"
        "- Does the rewrite call anything that does not exist in this language's library?\n\n"
        f"If the rewrite meets every requirement, answer with exactly `{_REVIEW_OK}` and nothing "
        "else.\n"
        "If it does not, answer with the corrected COMPLETE file in ONE fenced code block, "
        "followed by `SECURITY NOTES:` explaining what you fixed. Do not explain anything before "
        "the fence.\n"
    )


def self_review(
    source: str,
    draft: str,
    rule: MigrationRule,
    asset: CryptoAsset,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 180.0,
    language: str = "",
) -> tuple[str, str]:
    """Return ``(possibly corrected source, notes)`` after one self-review pass.

    Never regresses. A review that answers OK, returns something unusable, or fails entirely
    leaves the draft exactly as it was — the pass can only improve a patch or cost time, which is
    what makes it safe to run before the expensive validation rather than after.
    """
    lang = language or _prompt_language(rule, asset)
    try:
        raw = _ollama_generate(
            _build_review_prompt(source, draft, rule, asset, lang),
            model=model,
            base_url=base_url,
            timeout=timeout,
            source=source,
        )
    except (OSError, OllamaError) as exc:
        logger.info("self-review pass unavailable (%s); keeping the draft", exc)
        return draft, ""

    if _REVIEW_OK_RE.search(raw) and "```" not in raw:
        return draft, ""

    try:
        corrected = extract_code_block(raw)
    except ModelOutputError:
        # The model said something, but not a file. Its opinion without a rewrite is not
        # actionable here, and the draft has already passed the mechanical checks.
        return draft, ""
    if not corrected.endswith("\n"):
        corrected += "\n"

    # The correction has to clear the same bar the draft did. A review that "fixes" the file into
    # a truncated or wrong-language version is worse than the draft it replaced, and this is the
    # only place that can tell.
    if check_rewrite(source, corrected, lang, rule) is not None:
        return draft, ""
    return corrected, extract_security_notes(raw)


#: Phrases a model uses when it is telling you the job is not finished. Matched on the notes, which
#: the prompt explicitly asks to be honest — so these raise a CAVEAT, never a rejection.
#:
#: The asymmetry is deliberate and load-bearing. Rejecting a patch because its notes admit a gap,
#: while accepting an identical patch whose notes stay silent, makes honesty the losing strategy.
#: The claims are checked strictly; the admissions are surfaced.
_INCOMPLETE_MARKERS = (
    "could not",
    "couldn't",
    "not implemented",
    "not possible",
    "not covered",
    "todo",
    "left unchanged",
    "still uses",
    "outside this file",
    "outside the scope",
    "this patch does not",
    "re-encrypt",
    "reencrypt",
    "must be updated",
    "requires manual",
    "unable to",
    "separately",
)

#: (claim as a model writes it, token that proves it in source). The token is chosen to survive
#: every spelling an ecosystem uses, because a claim check that fires on correct code is far worse
#: than one that misses: `AES.MODE_GCM`, `crypto.createCipheriv("aes-256-gcm", ...)`,
#: `cipher.NewGCM(block)` and `new GCMParameterSpec(128, nonce)` are all the same migration, and
#: comparing against the literal string "AES-256-GCM" rejects three of the four.
#:
#: Parameter sizes are deliberately NOT part of the token. A model writing "migrated to
#: AES-256-GCM" over Python that says `AES.MODE_GCM` is describing its patch correctly — the key
#: length lives in the key variable, not in the call — and demanding the digits back would turn an
#: accurate note into a rejection.
_CLAIMABLE_PRIMITIVES: tuple[tuple[str, str], ...] = (
    ("ML-KEM", "mlkem"),
    ("ML-DSA", "mldsa"),
    ("SLH-DSA", "slhdsa"),
    ("X25519MLKEM768", "mlkem"),
    ("AES-256-GCM", "gcm"),
    ("AES-GCM", "gcm"),
    ("ChaCha20-Poly1305", "chacha20"),
    ("SHA-256", "sha256"),
    ("SHA-384", "sha384"),
    ("SHA-512", "sha512"),
    ("SHA3-256", "sha3"),
    ("argon2id", "argon2"),
    ("argon2", "argon2"),
    ("bcrypt", "bcrypt"),
    ("scrypt", "scrypt"),
    ("PBKDF2", "pbkdf2"),
    ("OAEP", "oaep"),
    ("PSS", "pss"),
)


def _flat(text: str) -> str:
    """Lowercased with every separator removed, so `ml_kem768` and `ML-KEM-768` compare equal."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _mentions(text: str, needle: str) -> bool:
    return _flat(needle) in _flat(text)


def check_reasoning(notes: str, new_source: str) -> tuple[str | None, list[str]]:
    """Validate the model's stated reasoning against the file it actually produced.

    Returns ``(rejection reason or None, caveats)``.

    This is the check that reads the model's own account of the migration as evidence rather than
    decoration. Two different things come out of it:

    * **A rejection**, when the notes claim a primitive the rewritten file does not contain. That
      is not a formatting problem — it means the model wrote a description of the migration it
      intended and a file that does something else, and a reviewer reading the two together would
      be actively misled. Every other stage passes such a patch: it parses, and the rescan only
      asks whether the OLD algorithm is gone.
    * **Caveats**, when the notes admit something is unfinished. Those are surfaced beside the
      diff, never used to reject — see `_INCOMPLETE_MARKERS`.

    What it deliberately does NOT check: BEHAVIOURAL claims. Measured on a real accepted patch,
    the model wrote "stored the iteration count with the hash to allow future updates" over a diff
    that raised the iteration count and did not touch the storage format. The patch was correct
    and an improvement; the note over-stated it. Catching that reliably needs semantic analysis
    well past string matching, and a heuristic for it rejects correct patches - so this verifies
    the primitives a patch claims to USE, which is decidable, and leaves the prose to the reviewer,
    who now has the note and the diff side by side.
    """
    if not notes.strip():
        return None, []
    caveats = [
        line.strip()
        for line in notes.splitlines()
        if any(marker in line.lower() for marker in _INCOMPLETE_MARKERS) and line.strip()
    ]
    unsupported = [
        claim
        for claim, token in _CLAIMABLE_PRIMITIVES
        if _mentions(notes, claim) and not _mentions(new_source, token)
    ]
    if unsupported:
        named = ", ".join(unsupported)
        return (
            f"your security notes claim this patch uses {named}, but the file you returned does "
            f"not contain it. Either make the change you described, or describe the change you "
            f"made"
        ), caveats
    return None, caveats


def unverifiable_reason(rule: MigrationRule, language: str) -> str | None:
    """Why a failed rewrite in ``language`` may have been unwinnable, or None if it looks winnable.

    A patch is kept only if the rescan DETECTS the rule's target algorithm in the rewritten file.
    Where QUBIT ships no verified shape for that algorithm in this language, a `present` failure is
    likely to be the check being unsatisfiable rather than the model being wrong — `code-kex-01`
    claims 21 file suffixes and the shipped shapes cover 9 languages.

    **This is a diagnosis, never a gate.** It was briefly used to refuse such tasks before calling
    the model at all, and that was wrong: absence of a rule *example* resolving to the target is not
    evidence that no rule detects it. Measured, the guard refused ten tasks, of which two —
    `Wallet.swift` 3DES and `Crypto.kt` RSA — had passed their rescan on the previous run. So it
    now runs only after every attempt has already failed, where it can sharpen the message it
    reports and cannot remove a capability.
    """
    prefixes = present_prefixes(rule)
    if not prefixes:
        return None
    # The rescan only runs when the language maps to a file extension the scanner reads; otherwise
    # the stage skips and never blocks the patch, so there is nothing to be unwinnable about.
    if LANGUAGE_TO_EXT.get(language) is None:
        return None
    for prefix in prefixes:
        answer = verified_target_shapes(language, prefix)
        if answer is None or answer:
            return None
    targets = " or ".join(prefixes)
    return (
        f"QUBIT ships no verified {targets} shape for {language or 'this language'}, so the rescan "
        f"may be unsatisfiable here regardless of what is generated — this finding is a candidate "
        f"for migration advice rather than a patch"
    )


def generate_llm_source(
    source: str,
    rule: MigrationRule,
    asset: CryptoAsset,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    max_attempts: int = _MAX_ATTEMPTS,
    fallback_model: str | None = None,
    timeout: float = 180.0,
    verify: Callable[[str], str | None] | None = None,
    experience: Any | None = None,
    on_notes: Callable[[str], None] | None = None,
    self_review_pass: bool = True,
    on_caveats: Callable[[list[str]], None] | None = None,
    plan_first: bool = True,
    feedback: str | None = None,
) -> str:
    """Return the LLM-rewritten file content, or raise :class:`OllamaError`.

    Retries with the rejection reason fed back into the prompt (doc 03 §6.3's "repair loop", which
    the module previously described but did not implement — generation was strictly one-shot, so a
    truncated rewrite simply failed the task).

    ``experience``: this project's own previously-validated (before, after) line pairs for this
    same rule — the strongest grounding a fresh call can get short of retraining the model itself.
    See `_experience_examples`.

    ``feedback``: seeds the repair loop with a rejection the CALLER already observed, so attempt
    one is informed rather than repeating a mistake already made. The orchestrator passes the full
    validator's verdict here — the `compiles`, `tests`, `applies` and `symbols` stages that run
    only after this function has already returned, and whose failures the in-loop `verify` closure
    (rescan only) can never see on its own.

    ``on_notes``: called with the model's SECURITY NOTES for the rewrite that was ACCEPTED, so a
    reviewer sees the reasoning beside the diff. A callback rather than a second return value
    because every existing caller and test treats this function as returning the file, and the
    notes are supplementary — a rewrite is not worse for lacking them.

    ``self_review_pass``: run a second model pass over the draft before it is validated, asking
    the model to check its own work against the rule's requirements and correct it. See
    `self_review` — it can only improve a draft or cost time, never return something worse.

    ``on_caveats``: called with the lines of the accepted notes that admit something is unfinished.
    Surfaced beside the diff rather than used to reject, because rejecting honest notes while
    accepting silent ones would make honesty the losing strategy.
    """
    # `fallback_model` was configured and referenced by nothing, so a machine without the primary
    # model pulled had no safety net at all — just a 404 reported as "Ollama unreachable". It is
    # only used when the primary is genuinely absent, never to silently downgrade a working setup.
    available = installed_models(base_url)
    if available and model not in available:
        if fallback_model and fallback_model in available:
            logger.warning(
                "Ollama model %r is not installed; falling back to %r", model, fallback_model
            )
            model = fallback_model
        else:
            raise OllamaError(_model_missing_message(model, base_url))

    # Pass one, for the structural rewrites only: make the model say what it intends to change
    # before it changes anything. Done ONCE and carried across every repair attempt - the plan
    # does not become wrong because the first draft of it was truncated, and re-planning on each
    # retry would triple the cost of the tasks that already cost the most.
    plan = ""
    if plan_first and needs_planning(rule):
        plan = plan_rewrite(
            source,
            rule,
            asset,
            model=model,
            base_url=base_url,
            timeout=timeout,
            language=_prompt_language(rule, asset),
            experience=experience,
        )
        if plan:
            logger.info("planned the rewrite for %s before generating", rule.id)

    last_reason = "unknown"
    for _attempt in range(max(1, max_attempts)):
        # Generation is INSIDE the retry because a truncated or unfenced answer is the model
        # getting it wrong, and that is what the repair loop is for. It was outside, so a
        # truncation ended the whole attempt immediately -- measured on Crypto.kt and
        # Ledger.scala, two ~400-character files the model looped on until it exhausted the
        # output budget. A transport failure (server down, model not pulled, timeout) is a plain
        # OllamaError and still propagates on the first try, because retrying it only makes the
        # user wait three times over for the same message.
        try:
            raw = _ollama_generate(
                _build_prompt(source, rule, asset, feedback, experience, plan),
                model=model,
                base_url=base_url,
                timeout=timeout,
                source=source,
            )
            new_source = extract_code_block(raw)
        except ModelOutputError as exc:
            last_reason = str(exc)
            feedback = (
                f"{last_reason}. Return ONLY the complete file inside ONE fenced code block, "
                "with no commentary before or after it."
            )
            continue

        if not new_source.endswith("\n"):
            new_source += "\n"

        # The FILE's language, not the rule's: a cross-language rule says "multi", which
        # matches no grammar and skipped every language-aware check in the guard.
        language = _prompt_language(rule, asset)
        reason = check_rewrite(source, new_source, language, rule)
        notes = extract_security_notes(raw)
        caveats: list[str] = []

        # Pass two: the rescan. The only check that answers "did the finding actually go away",
        # and the one whose answer is worth feeding back to the model. It runs BEFORE the review
        # for a measured reason: on `code-kex-01` the draft routinely passes the cheap checks and
        # then fails the rescan, so reviewing first spent a full model call on a draft that was
        # about to be thrown away — three per task, on the tasks least likely to succeed. A rescan
        # is a one-second subprocess; a review is fifteen to thirty seconds of 7B inference.
        if reason is None and verify is not None:
            reason = verify(new_source)

        # Pass three: the model reads its own draft against the rule's requirements and either
        # confirms it or returns a corrected file. Reached only by a draft that has already
        # satisfied the rescan, so it costs at most one extra call per SUCCESSFUL task rather than
        # one per attempt. A correction is re-verified below, because a review that "fixes" a
        # patch into one the rescan no longer accepts must not be allowed to ship.
        if reason is None and self_review_pass:
            reviewed, review_notes = self_review(
                source,
                new_source,
                rule,
                asset,
                model=model,
                base_url=base_url,
                timeout=timeout,
                language=language,
            )
            if reviewed != new_source:
                recheck = verify(reviewed) if verify is not None else None
                if recheck is None:
                    logger.info("self-review corrected the draft for rule %s", rule.id)
                    new_source = reviewed
                    notes = review_notes or notes
                else:
                    logger.info(
                        "self-review correction for %s failed the rescan (%s); keeping the draft",
                        rule.id,
                        recheck,
                    )

        # Pass four: does the model's own account match the file it returned? A patch whose notes
        # claim ML-KEM and whose file contains none passes every other stage in the pipeline.
        if reason is None:
            reason, caveats = check_reasoning(notes, new_source)

        if reason is None:
            # Only the ACCEPTED attempt's reasoning is reported. Notes from a rejected rewrite
            # describe a file that was thrown away, and showing those beside the diff that
            # shipped would actively mislead the reviewer.
            if on_notes is not None and notes:
                on_notes(notes)
            if on_caveats is not None and caveats:
                on_caveats(caveats)
            return new_source
        last_reason = reason
        feedback = reason

    # A `present` failure that persists in a language QUBIT ships no verified shape for is more
    # likely an unsatisfiable check than a bad rewrite, and saying which one costs nothing here.
    suffix = ""
    if "present, but not found" in last_reason:
        hint = unverifiable_reason(rule, _prompt_language(rule, asset))
        if hint:
            suffix = f". {hint}"
    raise OllamaError(
        f"LLM rewrite rejected after {max_attempts} attempt(s): {last_reason}{suffix}"
    )


__all__ = [
    "DEFAULT_BASE_URL",
    "OllamaError",
    "check_reasoning",
    "check_rewrite",
    "extract_code_block",
    "extract_security_notes",
    "generate_llm_source",
    "installed_models",
    "needs_planning",
    "plan_rewrite",
    "present_prefixes",
    "self_review",
    "unverifiable_reason",
]
