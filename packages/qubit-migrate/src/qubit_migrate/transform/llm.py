"""LLM patch generation via local Ollama (doc 03 §6.3.2).

The model receives the full source file plus the rule's semantic note and constraints,
and must return the complete rewritten file in a fenced code block. The result is never
trusted blindly: the normal validation pipeline (parse, rescan, git-apply check) gates
every LLM patch exactly like a template patch.
"""

from __future__ import annotations

import ast
import contextlib
import contextvars
import json
import logging
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Container, Iterator, Sequence
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import TYPE_CHECKING, Any

from platformdirs import user_data_dir

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

#: Sent on every EXTERNAL provider request. Not cosmetic: hosted providers sit behind bot
#: protection that rejects the stdlib default `Python-urllib/x.y` outright -- see
#: `_openai_compatible_generate` for the measured 403-vs-200 case that made this necessary.
HTTP_USER_AGENT = "qubit-migrate/0.1 (+https://github.com/qubit-pqc)"

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


def _duration_seconds(raw: str) -> float:
    """A provider's human-written duration as a number of seconds. Unparseable means 0.0.

    Providers report rate-limit resets as prose rather than a count: Groq sends `7.66s` and
    `2m59.56s` in headers and *"Please try again in 4.86s"* in a 429 body, and an exhausted DAILY
    request quota comes back as `7h32m14.4s`. Every decision made against these -- wait or move on,
    cool for ninety seconds or retire the engine -- needs a number, and 0.0 always means "no reason
    to wait" rather than a fabricated delay.
    """
    text = (raw or "").strip().lower()
    if not text:
        return 0.0
    # `ms` has to go first or its `m` reads as MINUTES, turning `500ms` into 30,000 seconds --
    # which would look like a window worth abandoning the engine over rather than one already open.
    text = text.replace("ms", "\x00")
    units = {"\x00": 0.001, "h": 3600.0, "m": 60.0, "s": 1.0}
    total = 0.0
    number = ""
    for char in text:
        if char.isdigit() or char == ".":
            number += char
            continue
        if not number:
            continue
        with contextlib.suppress(ValueError):
            total += float(number) * units.get(char, 0.0)
        number = ""
    # A bare number with no unit is seconds, which is how several providers spell it (and how
    # `Retry-After` is defined).
    if number and not total:
        with contextlib.suppress(ValueError):
            total = float(number)
    return total


@dataclass(frozen=True)
class RateBudget:
    """How much of a provider's rate limit is left, as the provider itself last reported it.

    A hosted free tier is rationed in REQUESTS PER DAY far more tightly than in tokens -- measured
    on this installation: Groq allows 1,000 requests/day and 8,000 tokens per request, and one
    patch can cost up to fourteen requests. So the binding constraint is the request count, and
    QUBIT could not see it: every response carries `x-ratelimit-remaining-requests`, and the only
    header ever read was `x-ratelimit-limit-tokens`, once, to size a single request.

    The consequence is that exhaustion was discovered by being refused. There was no way to pace
    work, to spend the last requests of a day on the findings that most deserve them, or to tell
    an operator how much budget a run would need before starting it.

    Not every provider sends these. Google's OpenAI-compatible endpoint sends none of them, so
    every field here is optional and `None` means "this provider does not say", which is different
    from zero and must never be displayed as though the budget were exhausted.
    """

    engine: str
    remaining_requests: int | None = None
    remaining_tokens: int | None = None
    limit_requests: int | None = None
    limit_tokens: int | None = None
    reset_requests: str = ""
    reset_tokens: str = ""
    observed_at: float = 0.0

    @property
    def reported(self) -> bool:
        """Did the provider say anything at all about what is left?"""
        return self.remaining_requests is not None or self.remaining_tokens is not None

    @property
    def reset_tokens_seconds(self) -> float:
        """`reset_tokens` as a number, so a caller can decide whether it is worth waiting.

        Providers report this as a human duration rather than a count: Groq sends `7.66s` and
        `2m59.56s`, and its 429 body says *"Please try again in 4.86s"*. A token window REFILLS,
        which makes it categorically different from an exhausted daily quota -- waiting eight
        seconds for it beats falling back to an engine measured at ~14 minutes per finding. That
        decision cannot be made against a string, so it is parsed here rather than at the call site.

        Unparseable or absent means 0.0 -- "no reason to wait" -- never a fabricated delay.
        """
        raw = (self.reset_tokens or "").strip().lower()
        if not raw:
            return 0.0
        # `ms` has to go first or its `m` reads as MINUTES, turning `500ms` into 30,000 seconds --
        # which would look like a window worth abandoning the engine over rather than one already
        # open.
        raw = raw.replace("ms", "\x00")
        units = {"\x00": 0.001, "h": 3600.0, "m": 60.0, "s": 1.0}
        total = 0.0
        number = ""
        for char in raw:
            if char.isdigit() or char == ".":
                number += char
                continue
            if not number:
                continue
            with contextlib.suppress(ValueError):
                total += float(number) * units.get(char, 0.0)
            number = ""
        # A bare number with no unit is seconds, which is how several providers spell it.
        if number and not total:
            with contextlib.suppress(ValueError):
                total = float(number)
        return total

    @property
    def stale(self) -> bool:
        """Has the window this observation described already reset?

        A rate-limit header is a fact about a specific reset WINDOW, not a fact that holds
        forever. Once wall-clock time passes `observed_at` plus that window, the provider has
        refilled the quota this budget describes -- so a persisted `remaining_requests: 0` that
        outlives its own reset is not "still exhausted", it is simply out of date. Treating it as
        current is exactly the process-restart defect this property exists to close: an engine
        drained on Monday would otherwise read as drained on Tuesday, forever, because nothing
        ever told the reader the window had turned over. See `_load_budgets` for where a
        persisted record re-enters `_BUDGETS`, and `rate_budget` for where `stale` is applied.

        `reset_requests` is checked first because `remaining_requests` is the field
        `scheduling.choose` actually gates an engine on (~scheduling.py:186); `reset_tokens` is
        the fallback for a provider that reported a token window but not a request one. No reset
        hint at all -- `_duration_seconds` returns 0.0 for unparseable or absent input, its own
        way of saying "cannot judge this" -- means no expiry is applied. Silence must never be
        read as "already stale", only as "cannot say".
        """
        if not self.observed_at:
            return False
        reset_seconds = _duration_seconds(self.reset_requests) or _duration_seconds(
            self.reset_tokens
        )
        if reset_seconds <= 0:
            return False
        return time.time() >= self.observed_at + reset_seconds

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "remaining_requests": self.remaining_requests,
            "remaining_tokens": self.remaining_tokens,
            "limit_requests": self.limit_requests,
            "limit_tokens": self.limit_tokens,
            "reset_requests": self.reset_requests,
            "reset_tokens": self.reset_tokens,
            "reset_tokens_seconds": self.reset_tokens_seconds,
            "observed_at": self.observed_at,
            "reported": self.reported,
        }


#: Latest budget seen per engine, for as long as this process lives -- and, via `_load_budgets` /
#: `_save_budgets` below, for the NEXT process too.
#:
#: This used to be purely process-local, on the reasoning that a rate-limit observation "is a fact
#: about right now that goes stale in seconds, and a stored copy would be read long after it
#: stopped being true." That holds for a TOKEN window (resets in seconds to low minutes) and does
#: NOT hold for the REQUEST window on a free tier, which is routinely a DAILY quota -- measured on
#: this installation, Groq's own reset header reads `7h32m14.4s` once the daily budget is spent.
#: An unattended campaign restarts the whole process between repositories (see
#: `scripts/run_all_pooled.ps1`), so an engine exhausted on repo 1 looked completely fresh on repo
#: 2: the scheduler routed to it again, it answered 429 again, and the campaign re-tested a dead
#: engine every `_COOLDOWN_SECONDS` for the rest of the day.
#:
#: `RateBudget.stale` is what makes persisting this safe rather than merely durable: a record is
#: honoured only until the reset it itself reported has passed, so a restart can see YESTERDAY's
#: exhaustion without being stuck believing it forever.
_BUDGETS: dict[str, RateBudget] = {}

#: Set once `_load_budgets` has run, successfully or not, so a process reads its persisted state
#: at most once. The file only changes from OUTSIDE this process (another one exiting), so
#: re-reading it on every call would be pure disk I/O on a path measured to run per model call.
_BUDGETS_LOADED = False


def _budget_store_path() -> Path | None:
    """Where a budget survives a process restart, or None if there is nowhere safe to put one.

    "Beside the database" is not a new location -- it is THE existing one, resolved the same way
    `qubit_core.db.session.default_db_url` resolves the database's own path: `QUBIT_DB_URL` when
    an operator set one, `platformdirs.user_data_dir("qubit", appauthor=False)` otherwise. This
    honours that env var rather than inventing a second convention, and doing so is not optional:
    `scripts/run_arms.py` sets `QUBIT_DB_URL` to a private sqlite file per EVALUATION ARM
    specifically so concurrent arms share no state, and a budget file that ignored the variable
    would leak one arm's rate-limit history into another's -- defeating the isolation
    `test_cli_db_isolation.py` exists to guarantee for the database itself.

    A non-sqlite `QUBIT_DB_URL` (Postgres, ...) names no on-disk sibling to sit beside. This
    returns None for that case rather than inventing an unrelated location, and every caller
    treats None as "skip persistence for this process" -- always a safe fallback, since it is
    exactly today's (process-local-only) behaviour.
    """
    try:
        url = os.getenv("QUBIT_DB_URL") or ""
        prefix = "sqlite:///"
        if url:
            if not url.startswith(prefix):
                return None
            db_path = Path(url[len(prefix) :])
        else:
            db_path = Path(user_data_dir("qubit", appauthor=False)) / "qubit.db"
        return db_path.parent / "llm_rate_budgets.json"
    except Exception:
        return None


def _coerce_budget(engine: str, fields: Any) -> RateBudget | None:
    """One persisted engine record, defensively typed -- or None for anything that does not look
    like what `_save_budgets` itself would have written.

    A hand-edited, truncated, or previous-schema file must degrade to "not remembered", never to
    a crash: this is a best-effort cache read that runs unattended, on the hot path of every
    model call.
    """
    if not isinstance(fields, dict):
        return None

    def as_int(value: Any) -> int | None:
        if isinstance(value, bool) or value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    try:
        return RateBudget(
            engine=str(fields.get("engine") or engine),
            remaining_requests=as_int(fields.get("remaining_requests")),
            remaining_tokens=as_int(fields.get("remaining_tokens")),
            limit_requests=as_int(fields.get("limit_requests")),
            limit_tokens=as_int(fields.get("limit_tokens")),
            reset_requests=str(fields.get("reset_requests") or ""),
            reset_tokens=str(fields.get("reset_tokens") or ""),
            observed_at=float(fields.get("observed_at") or 0.0),
        )
    except (TypeError, ValueError):
        return None


def _load_budgets() -> None:
    """Merge whatever the last process persisted into `_BUDGETS`, once, lazily. Never raises.

    Lazy and single-shot: called from both `rate_budget` (so a fresh process sees yesterday's
    exhaustion before it ever makes a call) and `_record_budget` (so a save from THIS process
    does not clobber every OTHER engine's history with a file containing only the one just
    updated). Entries already in `_BUDGETS` win over the file -- this process's own observation
    is never staler than one made before the file was last written.
    """
    global _BUDGETS_LOADED
    if _BUDGETS_LOADED:
        return
    _BUDGETS_LOADED = True
    path = _budget_store_path()
    if path is None:
        return
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # No file yet (nothing persisted), or content that is not valid JSON at all -- either
        # way, today's behaviour: start with nothing remembered.
        return
    if not isinstance(raw, dict):
        return
    for engine, fields in raw.items():
        if engine in _BUDGETS:
            continue
        budget = _coerce_budget(str(engine), fields)
        if budget is not None:
            _BUDGETS[engine] = budget


def _save_budgets() -> None:
    """Write `_BUDGETS` out so the NEXT process starts already knowing it. Never raises.

    Whole-dict overwrite rather than a read-modify-write of the file: `_load_budgets` always runs
    first at every call site that reaches this (see its own docstring), so `_BUDGETS` in memory is
    already a superset of whatever the file holds, and re-deriving that here would just repeat
    the same merge a second time.

    Written to a per-process temp file and `os.replace`d into place rather than written directly,
    so a process killed mid-write during an unattended run leaves the last GOOD version in place
    instead of a truncated file for the next process's `_load_budgets` to have to shrug off.
    """
    path = _budget_store_path()
    if path is None:
        return
    with contextlib.suppress(Exception):
        payload = {name: budget.as_dict() for name, budget in _BUDGETS.items()}
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        tmp_path.replace(path)


def _as_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(float(raw.strip().rstrip("s")))
    except (ValueError, AttributeError):
        return None


#: The same four facts, spelled differently by each provider. Measured on live calls: Groq sends
#: `x-ratelimit-remaining-requests` (a DAILY budget), Mistral sends
#: `x-ratelimit-remaining-req-minute` (a per-minute one), and Google and NVIDIA send nothing at all.
#: Reading only one spelling meant the most generous provider in the pool looked unmeasurable --
#: Mistral allows 125 requests/minute against Groq's 1,000/day.
_BUDGET_HEADERS: dict[str, tuple[str, ...]] = {
    "remaining_requests": (
        "x-ratelimit-remaining-requests",
        "x-ratelimit-remaining-req-minute",
        "ratelimit-remaining",
    ),
    "remaining_tokens": (
        "x-ratelimit-remaining-tokens",
        "x-ratelimit-remaining-tokens-minute",
    ),
    "limit_requests": (
        "x-ratelimit-limit-requests",
        "x-ratelimit-limit-req-minute",
        "ratelimit-limit",
    ),
    "limit_tokens": ("x-ratelimit-limit-tokens", "x-ratelimit-limit-tokens-minute"),
}


def _first_header(headers: Any, names: tuple[str, ...]) -> str | None:
    for name in names:
        value = headers.get(name)
        if value is not None:
            return str(value)
    return None


def _record_budget(engine: str, headers: Any) -> None:
    """Read whatever the provider volunteered about the remaining budget. Never raises."""
    with contextlib.suppress(Exception):
        get = headers.get
        budget = RateBudget(
            engine=engine,
            remaining_requests=_as_int(
                _first_header(headers, _BUDGET_HEADERS["remaining_requests"])
            ),
            remaining_tokens=_as_int(_first_header(headers, _BUDGET_HEADERS["remaining_tokens"])),
            limit_requests=_as_int(_first_header(headers, _BUDGET_HEADERS["limit_requests"])),
            limit_tokens=_as_int(_first_header(headers, _BUDGET_HEADERS["limit_tokens"])),
            reset_requests=str(get("x-ratelimit-reset-requests") or ""),
            reset_tokens=str(get("x-ratelimit-reset-tokens") or ""),
            observed_at=time.time(),
        )
        if budget.reported or budget.limit_requests or budget.limit_tokens:
            # Merge in whatever a PREVIOUS process persisted before this write can overwrite it --
            # see `_load_budgets`'s own docstring for why the order matters.
            _load_budgets()
            _BUDGETS[engine] = budget
            _save_budgets()


def rate_budget(engine: str | None = None) -> dict[str, Any]:
    """What is left on the attached provider(s), as last reported -- including what a PREVIOUS
    process last reported, via `_load_budgets`.

    Returns one engine's budget, or every engine's when none is named. An engine absent from the
    result has never been called, never reported, or was observed so long ago that the reset its
    own record named has already passed (`RateBudget.stale`) -- all three mean "unknown", never
    "empty". The last case matters most after a restart: a `remaining_requests: 0` persisted from
    an earlier process must stop being honoured once its own reset window has closed, or an
    engine that has been usable again for hours would still read as permanently exhausted.
    """
    _load_budgets()
    if engine is not None:
        found = _BUDGETS.get(engine)
        return found.as_dict() if found and not found.stale else {}
    return {name: b.as_dict() for name, b in _BUDGETS.items() if not b.stale}


@dataclass(frozen=True)
class ModelCall:
    """One request to whatever model is attached, and what it cost."""

    engine: str
    prompt_tokens: int
    completion_tokens: int
    seconds: float
    ok: bool


class CallLedger:
    """Every model call made while producing one patch.

    QUBIT's whole claim about an attached model is an efficiency claim: it does the deterministic
    work without the model, replays what it has already learned, sends an excerpt rather than a
    file, and refuses engines that have never succeeded at a pairing. None of that was measurable,
    because nothing counted the calls or the tokens -- both engines return usage figures in their
    responses (`prompt_eval_count`/`eval_count` from Ollama, `usage` from an OpenAI-compatible
    endpoint) and QUBIT read the answer text and discarded the rest.

    That matters most where the budget is smallest. A free tier is rationed in REQUESTS PER DAY --
    measured: 1,000/day on Groq -- and one patch can cost up to fourteen of them (a planning pass,
    three generate-plus-review rounds, doubled by the outer feedback retry). A tool that cannot
    count its own requests cannot pace them, cannot prioritise them, and cannot tell you why it
    ran out.
    """

    def __init__(self) -> None:
        self.calls: list[ModelCall] = []

    def record(self, call: ModelCall) -> None:
        self.calls.append(call)

    @property
    def prompt_tokens(self) -> int:
        return sum(c.prompt_tokens for c in self.calls)

    @property
    def completion_tokens(self) -> int:
        return sum(c.completion_tokens for c in self.calls)

    def summary(self) -> dict[str, Any]:
        """Small enough to store on every patch, complete enough to audit the claim."""
        per_engine: dict[str, int] = {}
        for call in self.calls:
            per_engine[call.engine] = per_engine.get(call.engine, 0) + 1
        return {
            "calls": len(self.calls),
            "failed_calls": sum(1 for c in self.calls if not c.ok),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "seconds": round(sum(c.seconds for c in self.calls), 2),
            "by_engine": per_engine,
        }


#: The ledger the current generation is writing to. A ContextVar rather than a parameter because
#: every function between `generate_patch` and the HTTP call would otherwise have to carry it, and
#: each of those signatures is pinned by tests that would then all have to change to measure
#: something none of them are about.
_LEDGER: contextvars.ContextVar[CallLedger | None] = contextvars.ContextVar(
    "qubit_llm_ledger", default=None
)


def start_ledger() -> CallLedger:
    """Begin counting model calls, and return the ledger they land in.

    Deliberately not only a context manager. `generate_patch` is several hundred lines between the
    first model call and the patch it writes, and wrapping that body in a `with` would re-indent
    every one of them to measure something none of them are about.
    """
    book = CallLedger()
    _LEDGER.set(book)
    return book


def current_ledger() -> CallLedger | None:
    """The ledger in force, if anything is counting.

    Needed because the most expensive events produce no patch to hang a cost on: a finding that
    exhausts its repair attempts raises, and the orchestrator parks the task. Reading the ledger
    from the failure path is what stops the spend on those attempts vanishing -- and they are
    precisely the attempts worth knowing about, so losing them biases the efficiency figure in the
    flattering direction.
    """
    return _LEDGER.get()


@contextlib.contextmanager
def ledger() -> Iterator[CallLedger]:
    """Collect the model calls made inside this block."""
    book = CallLedger()
    token = _LEDGER.set(book)
    try:
        yield book
    finally:
        _LEDGER.reset(token)


#: Calls and total seconds per engine, for as long as this process lives.
#:
#: Separate from `CallLedger` on purpose. The ledger answers "what did THIS patch cost" and only
#: exists while one is being produced; routing needs the opposite -- how an engine behaves ACROSS
#: findings -- and has to work on the very first patch of a run, when no ledger is collecting.
#:
#: Measured rather than configured, because the spread is far too large to guess and is specific to
#: the machine and the tier: on this installation Mistral's `codestral-2508` answers a real
#: migration in ~1.0s, Groq's `gpt-oss-120b` in ~2.0s, NVIDIA's `nemotron-3-ultra` in ~68s, and the
#: local 7B takes minutes. An average over real calls also tracks a tier that has started to
#: throttle, which a static table never would.
_ENGINE_LATENCY: dict[str, tuple[int, float]] = {}


def observed_seconds_per_call(engine: str) -> float | None:
    """Mean seconds this engine has taken on this installation, or None if it has never answered.

    None is not a slow engine -- it is an unmeasured one, and the caller must fall back to its own
    default rather than treat silence as a number.
    """
    calls, total = _ENGINE_LATENCY.get(engine, (0, 0.0))
    return total / calls if calls else None


def _record_call(
    engine: str, prompt_tokens: int, completion_tokens: int, seconds: float, ok: bool = True
) -> None:
    """Record a call if anyone is collecting.

    Never raises: measurement must never be able to break generation.
    """
    if ok:
        # Kept OUTSIDE the ledger check: routing needs this on the first patch of a run, before any
        # ledger exists. Failures are excluded because a call that errored in 0.2s is not evidence
        # that the engine is fast.
        with contextlib.suppress(Exception):
            calls, total = _ENGINE_LATENCY.get(engine, (0, 0.0))
            _ENGINE_LATENCY[engine] = (calls + 1, total + max(float(seconds), 0.0))
    book = _LEDGER.get()
    if book is None:
        return
    with contextlib.suppress(Exception):
        book.record(
            ModelCall(
                engine=engine,
                prompt_tokens=int(prompt_tokens or 0),
                completion_tokens=int(completion_tokens or 0),
                seconds=round(float(seconds), 3),
                ok=ok,
            )
        )


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

    # Run the worker inside a COPY of this context. A `threading.Thread` starts with an empty
    # context, so the call ledger `generate_patch` installed is invisible inside `_worker` and
    # every local-model call would be recorded as costing nothing -- which is precisely the
    # claim the ledger exists to substantiate, silently inverted.
    context = contextvars.copy_context()
    thread = threading.Thread(
        target=lambda: context.run(_worker), name="ollama-generate", daemon=True
    )
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
    started = time.monotonic()
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
    # Recorded before anything can reject the answer: the request was made and the quota was
    # spent whether or not the text turns out to be usable. Counting only successful calls is how
    # a tool comes to believe it is thriftier than it is.
    _record_call(
        engine=model,
        prompt_tokens=data.get("prompt_eval_count", 0),
        completion_tokens=data.get("eval_count", 0),
        seconds=time.monotonic() - started,
    )
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


#: Output ceiling for an EXTERNAL provider, in tokens. Far above `_MAX_PREDICT` (16,384) because
#: that ceiling exists for a 7B model on an 8 GB card -- it is a statement about local hardware,
#: not about how long a rewritten file is. Kept below the 65,536 that today's largest free-tier
#: model advertises, so the number stays plausible for the smaller models a user may also pick;
#: a provider that cannot honour it clamps or answers 400, and `_TUNING_FIELDS` handles the 400.
_MAX_EXTERNAL_TOKENS = 32768

#: Below this many tokens of room for the ANSWER, a whole-file rewrite cannot come back at all, so
#: the request is refused before it is sent. Not a tuning knob: 512 tokens is roughly 40 lines of
#: code, well under any file worth migrating, so anything at or below it means the prompt has eaten
#: the entire allowance.
_MIN_ANSWER_TOKENS = 512


def _external_output_budget(prompt: str, source: str = "", budget_tokens: int | None = None) -> int:
    """`_output_budget`'s scaling, with a ceiling sized for a hosted model rather than a local one.

    Same arithmetic and the same reason: the answer is a WHOLE FILE, roughly `_ANSWER_EXPANSION`
    times the input for a structural migration, at ~3 characters per token.

    ``budget_tokens`` is the provider's EFFECTIVE limit on one request -- input plus output. On a
    free tier that is a rate limit, not a context window, and the two are wildly different:
    gpt-oss-120b advertises a 131,072-token context while Groq's free tier caps a single request at
    8,000 tokens per minute and answers 413 above it. Ignoring that produced a request for 38,840
    tokens against a limit of 8,000 -- refused outright, no generation attempted. So the output
    budget is whatever is LEFT after the prompt, never the model's theoretical ceiling.
    """
    from_prompt = len(prompt) // 3
    from_source = int(len(source) * _ANSWER_EXPANSION) // 3 if source else 0
    wanted = max(from_prompt, from_source)
    ceiling = _MAX_EXTERNAL_TOKENS
    if budget_tokens:
        # What the prompt itself will consume has to come out of the same allowance. A small
        # margin is left for the provider's own tokenizer disagreeing with the ~3 chars/token
        # estimate, which errs high for code.
        remaining = int(budget_tokens * 0.9) - from_prompt
        if remaining < _MIN_ANSWER_TOKENS:
            # Fail here rather than sending a request that cannot succeed. The alternative is a
            # 413, or an answer truncated at a handful of tokens which the repair loop then spends
            # its whole three-attempt budget arguing with -- and the model was never at fault.
            # `_llm_detour_reason` normally catches this first; this is the backstop for when the
            # prompt's instructions and examples push it over a limit the file alone did not.
            raise OllamaError(
                f"this file needs about {from_prompt:,} tokens of prompt against the provider's "
                f"{budget_tokens:,}-token per-request allowance, leaving no room for the rewritten "
                f"file to come back. This is the provider's rate/size limit, not the model's "
                f"context window — a paid or self-hosted endpoint lifts it."
            )
        ceiling = min(ceiling, remaining)
    return max(min(ceiling, wanted), min(_MIN_PREDICT, ceiling))


@dataclass(frozen=True)
class ExternalEndpoint:
    """One OpenAI-compatible endpoint in the failover chain.

    A value object rather than four loose parameters because the chain has two of them and the
    fields must not get crossed -- pairing one provider's key with another's URL would read as an
    authentication failure and be impossible to diagnose from the message.
    """

    base_url: str
    model: str
    api_key: str
    #: The provider's effective per-request token allowance; see `_external_output_budget`. Each
    #: endpoint carries its own, because that is precisely what differs between free tiers.
    budget_tokens: int | None = None


#: Request fields that TUNE a completion rather than define it, in the order they may be dropped
#: when a provider rejects them. Every one is an optimisation QUBIT can do without: losing
#: `chat_template_kwargs` or `reasoning_effort` costs some output budget to discarded reasoning,
#: and losing `max_tokens` falls back to the provider's default length. Losing the prompt or the
#: model would not be a degradation, it would be a different request -- which is why only these
#: three are droppable.
#:
#: `chat_template_kwargs` is dropped FIRST, because a 400 that says only "thinking" matches both it
#: and `reasoning_effort` and one of them has to be picked. It is the better guess twice over: it
#: is the non-standard field of the two, and it is the one a provider is more likely to be
#: complaining about when it mentions thinking at all. A wrong guess is not a failure either way --
#: the loop simply drops the other field on the next pass -- it just costs one more round trip.
_TUNING_FIELDS = ("chat_template_kwargs", "reasoning_effort", "max_tokens")

#: How a provider might NAME a tuning field when rejecting it. Matching only the literal field name
#: was not enough, measured: Google answers `reasoning_effort: "low"` on `gemma-4-31b-it` with
#: *"Thinking level is not supported for this model."* — a 400 that never contains the string
#: `reasoning_effort`, so the drop-and-retry never fired and a perfectly usable model looked broken.
#: Providers describe these fields in prose, so the match has to cover the prose too.
#: Statuses that can mean "I do not accept that field". 400 is the OpenAI-documented answer and
#: what Groq and Google send. Mistral does NOT: `codestral-2508` refuses `chat_template_kwargs` with
#: **HTTP 422** and a pydantic `extra_forbidden` body. Treating only 400 as droppable would have
#: propagated that 422 as a hard failure and taken the pool's fastest engine (1.1s, measured) out of
#: service for a field it never needed -- so the status list is measured, like everything else here.
_TUNING_REJECTION_CODES = frozenset({400, 422})

_TUNING_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    # Deliberately NOT including a bare "thinking" here: Google's `gemma-4-31b-it` rejects
    # `reasoning_effort` with *"Thinking level is not supported for this model."*, and that is the
    # field it means. Keeping this entry to the literal spellings lets the common case resolve on
    # the first pass, and leaves the ambiguous wording to `_TUNING_FIELDS`' ordering.
    "chat_template_kwargs": ("chat_template_kwargs", "chat template", "chat_template"),
    "reasoning_effort": ("reasoning_effort", "reasoning", "thinking level", "thinking"),
    "max_tokens": ("max_tokens", "max_completion_tokens", "maxoutputtokens", "output token"),
}

#: Settings tried, in order, to stop a reasoning model spending its output budget on reasoning
#: QUBIT then discards. There is no single value every provider accepts, measured on real keys:
#:
#: * Groq's `openai/gpt-oss-120b` accepts `"low"` and answers normally.
#: * Google's `gemini-3.6-flash` also ACCEPTS `"low"` -- HTTP 200 -- and then returns
#:   `content: None` with `completion_tokens: 0`, having spent the whole budget thinking. It
#:   accepts `"minimal"` and answers correctly, and rejects `"none"` outright with HTTP 400.
#:
#: So neither an HTTP error nor a fixed value is enough on its own: an EMPTY answer from a model
#: that was given a reasoning setting is itself the signal to try the next rung. `None` is last,
#: meaning "send no reasoning field at all", which is always valid.
_REASONING_LADDER: tuple[str | None, ...] = ("low", "minimal", None)

#: The rung that last WORKED for a given (base_url, model), so the ladder is walked once per engine
#: rather than once per call.
#:
#: This is a quota fix, not a micro-optimisation. Generating one patch already costs up to seven
#: model calls (a planning pass, then three rounds of generate + self-review), doubled by the
#: orchestrator's feedback retry. Re-discovering the reasoning setting on each of those multiplies
#: it again -- and requests, not tokens, are what free tiers actually ration: `gemini-3.6-flash`
#: allows **20 per day** (`GenerateRequestsPerDayPerProjectPerModel-FreeTier`, quotaValue 20), so a
#: single task could exhaust a day's quota purely on rediscovery.
#:
#: Process-local and unbounded-by-design: it holds at most one short string per configured engine,
#: and a wrong entry self-corrects because an empty answer walks the ladder again from that rung.
_REASONING_CHOICE: dict[tuple[str, str], str | None] = {}

#: Sent ALONGSIDE `reasoning_effort`, because the two are different mechanisms for the same goal and
#: neither covers the pool on its own. `reasoning_effort` is an API-level field the PROVIDER
#: interprets; `chat_template_kwargs` is handed to the model's own chat template, which is where
#: NVIDIA- and vLLM-hosted models actually take the switch. Both spellings go in -- NVIDIA's own
#: examples use `thinking`, vLLM's Qwen templates use `enable_thinking` -- and a template that knows
#: only one ignores the other.
#:
#: Measured on NVIDIA's endpoint against a real migration, with both models answering CORRECTLY
#: either way, so this buys budget rather than correctness:
#:
#: * `nemotron-3-ultra-550b-a55b`: 660 completion tokens -> 98, and 78.2s -> 68.3s.
#: * `deepseek-v4-pro-0813`: 81.3s -> 43.3s.
#:
#: Cutting billed output tokens by ~85% is worth a request field precisely because the part QUBIT
#: KEEPS is identical either way: it parses one fenced file out of the answer and discards the
#: reasoning it just paid for.
_TEMPLATE_KWARGS: dict[str, Any] = {"thinking": False, "enable_thinking": False}

#: Engines that answered 400 for `chat_template_kwargs`, so it is never sent to them twice.
#:
#: Same purpose as `_REASONING_CHOICE`, and it earns its keep for the same reason: the field is a
#: vLLM/NIM extension rather than part of the OpenAI schema, so a strict provider refuses it -- and
#: a refusal still SPENDS a request against a tier that rations requests, not tokens. Without this,
#: every call to such a provider would pay a wasted round trip to rediscover the same no.
_TEMPLATE_KWARGS_REFUSED: set[tuple[str, str]] = set()

#: Engines that just failed transiently, and the moment they may be tried again.
#:
#: A provider that is overloaded stays overloaded for longer than one request, and finding that out
#: is expensive: measured on a certbot run, NVIDIA took **three minutes** to answer
#: `503 Service temporarily overloaded`, and every task in the plan paid that toll again because
#: nothing remembered the previous one. Twenty minutes of a migration went on re-discovering that
#: the same endpoint was still busy, while the local model sat at 0% GPU.
#:
#: Deliberately short. This is congestion, not a verdict on the engine -- `poolside/laguna` answers
#: in ~2s when it answers at all and 503s the rest of the time, and a long exclusion would throw
#: away a genuinely fast engine over a moment's load.
_ENGINE_COOLDOWN: dict[str, float] = {}

#: How long an engine is skipped after a transient failure.
_COOLDOWN_SECONDS = 90.0

#: A 429 reset hint at or beyond this is read as a DAILY quota rather than a momentary rate
#: window. Comfortably above every per-minute figure measured on a real key (Groq's token window:
#: `31.305s`, `2m59.56s`) and comfortably below the DAILY exhaustion measured on the same account
#: (`7h32m14.4s`), so an hour cannot be mistaken for either.
_QUOTA_EXHAUSTED_SECONDS = 3600.0

#: Statuses that mean "busy, try later" rather than "wrong". 429 is rate limiting, 5xx is the
#: provider failing to serve; neither says anything about whether the request was valid.
_TRANSIENT_CODES = frozenset({429, 500, 502, 503, 504})


def _cooling(base_url: str, model: str) -> bool:
    """Is this engine still inside its cooldown window?"""
    until = _ENGINE_COOLDOWN.get(f"{base_url}::{model}")
    return until is not None and time.monotonic() < until


def _start_cooldown(base_url: str, model: str, *, seconds: float = _COOLDOWN_SECONDS) -> None:
    """Skip this engine until `seconds` from now (`_COOLDOWN_SECONDS` by default).

    `seconds` exists for a 429 that names its own reset -- see the call site in
    `_openai_compatible_generate_once`, which passes the provider's own hint when it is longer
    than the flat default. A `2m59.56s` window re-tested every 90s would fail twice for no
    reason. Never shorter than the default, though: a provider naming a SHORT window is not
    promising to be usable that soon, only that its own window reopens then, and
    `_COOLDOWN_SECONDS` is the floor already calibrated for "busy" in general.
    """
    _ENGINE_COOLDOWN[f"{base_url}::{model}"] = time.monotonic() + max(seconds, 0.0)


def _reset_seconds_from_headers(headers: Any) -> float:
    """How long until the window a 429 just hit reopens, or 0.0 if nothing usable was said.

    `reset_requests` is preferred: it is the field a DAILY quota reports against, and the field
    `scheduling.choose` actually gates an engine on (~scheduling.py:186). `reset_tokens` is the
    fallback for a provider that named only a token window. `headers` may be `None` -- an
    `HTTPError` built with no header object at all, exactly like several existing tests construct
    -- and that must read as "nothing said", never raise.
    """
    if headers is None:
        return 0.0
    try:
        get = headers.get
    except AttributeError:
        return 0.0
    seconds = _duration_seconds(str(get("x-ratelimit-reset-requests") or ""))
    if seconds:
        return seconds
    return _duration_seconds(str(get("x-ratelimit-reset-tokens") or ""))


#: Engines that rejected the key. Retired for the life of the process, not cooled: a key the
#: provider refuses will be refused again in ninety seconds and in ninety minutes.
_ENGINE_REFUSED: set[str] = set()


def _retire(
    base_url: str, model: str, *, reason: str = "the provider rejected the API key"
) -> None:
    """Stop asking an engine for the rest of this session.

    Measured on the certbot run: the configured primary answered HTTP 403 (Cloudflare 1010 — the
    key had been revoked, almost certainly by the provider's own secret scanning after it was
    pasted somewhere public). Nothing remembered that, so all 297 findings began by asking the same
    dead endpoint. Each call was cheap on its own, which is exactly why it went unnoticed: no
    timeout, no rate limit, just a run that quietly never used the engine it was configured to use
    and never said so.

    Deliberately not a cooldown. A transient failure is worth re-testing; a rejected key is a
    configuration fact that will not change until someone changes it -- and so, for the rest of
    THIS session, is a daily quota that will not refill for hours (see the 429 handling in
    `_openai_compatible_generate_once`). `reason` exists because those two are not the same
    finding and must not read as the same log line: a rejected key means "this configuration is
    broken", and an exhausted quota means "this configuration is fine, come back later". The
    default keeps the original wording for the 401/403 call site; the quota call site passes its
    own honest reason rather than letting either get conflated with the other in the logs.
    """
    _ENGINE_REFUSED.add(f"{base_url}::{model}")
    logger.warning("retiring %s at %s for this session: %s", model, base_url, reason)


def _refused(base_url: str, model: str) -> bool:
    return f"{base_url}::{model}" in _ENGINE_REFUSED


def _content_of(data: dict[str, Any]) -> str:
    """The assistant text from an OpenAI-compatible response, or "" if there is none.

    Total-function on purpose: an absent `content`, a null one, and a malformed envelope all mean
    the same thing to the caller -- no answer -- and the reasoning-ladder retry needs to ask that
    question without an exception in the middle of its loop.
    """
    try:
        return str(data["choices"][0]["message"].get("content") or "")
    except (KeyError, IndexError, TypeError, AttributeError):
        return ""


def _openai_compatible_generate(
    prompt: str,
    *,
    model: str,
    base_url: str,
    api_key: str,
    timeout: float = 180.0,
    source: str = "",
    budget_tokens: int | None = None,
) -> str:
    """`_openai_compatible_generate_once`, with the SAME hard wall-clock deadline `_ollama_generate`
    gives the local model — and for the identical reason.

    `urlopen(timeout=N)` bounds each individual socket READ, not the call as a whole: a hosted
    provider that keeps the connection open and sends so much as a keep-alive byte before the
    deadline resets the clock, and the read can block again indefinitely. `_ollama_generate`
    documents this and defends against it with a daemon-thread watchdog; this function called
    `urlopen` directly and had no such defense, so every HOSTED provider inherited exactly the gap
    the Ollama path was built to close.

    Measured live, through the desktop app: a MediVault migration task and a Paymesh one both sat
    in `generating` for 15+ minutes with no docker container running and Ollama itself idle —
    consistent with a hosted call wedged on a connection that never completed and never timed out.

    The watchdog thread is a plain daemon thread rather than a pool, for the same reason
    `_ollama_generate`'s comment gives: a `ThreadPoolExecutor` registers its workers with an atexit
    hook that joins them before the interpreter exits, so a wedged pooled thread can still block
    process shutdown even after this function has itself returned an error.
    """
    result: dict[str, Any] = {}

    def _worker() -> None:
        try:
            result["value"] = _openai_compatible_generate_once(
                prompt,
                model=model,
                base_url=base_url,
                api_key=api_key,
                timeout=timeout,
                source=source,
                budget_tokens=budget_tokens,
            )
        except BaseException as exc:
            result["error"] = exc

    context = contextvars.copy_context()
    thread = threading.Thread(
        target=lambda: context.run(_worker), name="openai-compatible-generate", daemon=True
    )
    thread.start()
    thread.join(timeout=timeout + 15)
    if thread.is_alive():
        raise OllamaError(
            f"{model!r} at {base_url!r} did not answer within {timeout:.0f}s and the connection "
            "itself did not report a timeout either — the provider may be wedged. Try again, or "
            "raise QUBIT_MIGRATE_LLM_TIMEOUT."
        )
    if "error" in result:
        raise result["error"]
    return result["value"]  # type: ignore[no-any-return]


def _openai_compatible_generate_once(
    prompt: str,
    *,
    model: str,
    base_url: str,
    api_key: str,
    timeout: float = 180.0,
    source: str = "",
    budget_tokens: int | None = None,
) -> str:
    """Single non-streaming chat-completion against an OpenAI-compatible `/chat/completions`
    endpoint.

    One shape covers OpenAI itself, Azure OpenAI, a free hosted tier (Groq, OpenRouter, ...), and
    the self-hosted inference servers (vLLM, LM Studio, a company's internal gateway) a production
    deployment would actually point QUBIT at -- so one function serves all of them; the difference
    between a company's private model and a free public one is only which `base_url`/`api_key` a
    user configures, never a code path.

    An earlier version of this function deliberately sent NO `max_tokens`, reasoning that
    `_output_budget` solves a small LOCAL model's problem and an external provider has headroom.
    **That was wrong, and measured to be wrong.** A provider's DEFAULT answer length is not its
    maximum: asked to rewrite pyjwt's 913-line `test_api_jwt.py`, gpt-oss-120b (which advertises
    `max_completion_tokens: 65536`) returned 44 non-blank lines and the repair loop burned all
    three attempts on a truncation the model was never given room to avoid. The bug was invisible
    until the context-window fix started routing large files to the external engine at all --
    the two changes have to land together or the second makes the first look worse than useless.
    """
    if not base_url.startswith(("http://", "https://")):
        raise OllamaError(f"Invalid provider base URL scheme: {base_url}")
    started = time.monotonic()
    url = base_url.rstrip("/") + "/chat/completions"

    payload: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        # `_ollama_generate_once` pins `seed` alongside `temperature: 0` and is genuinely
        # reproducible; this path sent temperature alone. Hosted OpenAI-compatible backends
        # (Groq, OpenRouter, vLLM-style servers) are widely documented as NOT bit-reproducible at
        # temperature 0 without a seed -- MoE routing and batching both vary the answer run to
        # run. `seed` is a standard OpenAI chat-completions field every target here recognizes
        # (OpenAI, Groq, vLLM); an unrecognized field is not something this shape of API errors
        # on, so this costs nothing where a provider ignores it.
        "seed": GENERATION_SEED,
        # Same reason `_ollama_generate_once` sends `think: False`: QUBIT parses a fenced file
        # out of the answer and DISCARDS reasoning, so a model that spends its output budget
        # thinking returns a truncated file. The strong models on hosted free tiers (gpt-oss,
        # qwen3.x) advertise a `reasoning` feature and default it ON, which is exactly the
        # failure mode this avoids.
        "max_tokens": _external_output_budget(prompt, source, budget_tokens),
    }
    # Start from whatever last worked for this engine, so the ladder costs one walk per engine
    # rather than one per call. See `_REASONING_CHOICE`.
    engine_key = (base_url, model)
    rung = 0
    if engine_key in _REASONING_CHOICE:
        remembered = _REASONING_CHOICE[engine_key]
        rung = _REASONING_LADDER.index(remembered) if remembered in _REASONING_LADDER else 0
    if _REASONING_LADDER[rung] is not None:
        payload["reasoning_effort"] = _REASONING_LADDER[rung]
    if engine_key not in _TEMPLATE_KWARGS_REFUSED:
        payload["chat_template_kwargs"] = dict(_TEMPLATE_KWARGS)

    def _post(body_obj: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(  # noqa: S310 — scheme validated above
            url,
            data=json.dumps(body_obj).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                # Measured, not precautionary: Groq answers `curl` with HTTP 200 and the DEFAULT
                # `Python-urllib/3.12` User-Agent with HTTP 403, on the same valid key.
                # Bot-protection in front of hosted providers routinely blocks the stdlib
                # default, and the failure is indistinguishable from a rejected key unless the
                # User-Agent is set.
                "User-Agent": HTTP_USER_AGENT,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            loaded: dict[str, Any] = json.load(resp)
            # Every response carries what is left. Reading it here is the difference between
            # pacing a run and discovering exhaustion by being refused.
            # `getattr`, not `resp.headers`: the attribute access happens HERE, outside
            # `_record_budget`'s own suppression, so a response object without headers
            # would take down the generation it was only supposed to be measuring.
            _record_budget(f"{base_url}::{model}", getattr(resp, "headers", None))
            return loaded

    try:
        # Tuning fields are NOT universally accepted, measured against Groq's own catalogue on one
        # account: gpt-oss-120b/20b and qwen3.8 take `reasoning_effort: "low"`, while qwen3.6-27b
        # answers 400 ("must be one of `none` or `default`") and groq/compound answers 400 ("not
        # supported with this model"). Hardcoding them makes QUBIT unusable on a subset of models a
        # user can legitimately pick from the provider's own live list. So a 400 that NAMES one of
        # them drops exactly that field and retries; anything else is a real error and propagates.
        # Bounded by construction -- each pass removes one field, so at most len(_TUNING_FIELDS)
        # extra round trips, and only for models that reject them.
        attempt = dict(payload)
        # `HTTPError.read()` drains the body once, and the outer handler needs it to build a
        # useful message -- so it is captured here rather than re-read there.
        last_body = ""
        while True:
            try:
                data = _post(attempt)
            except urllib.error.HTTPError as exc:
                last_body = ""
                with contextlib.suppress(Exception):
                    last_body = exc.read().decode("utf-8", errors="replace")
                if exc.code not in _TUNING_REJECTION_CODES:
                    raise
                lowered = last_body.lower()
                offending = next(
                    (
                        f
                        for f in _TUNING_FIELDS
                        if f in attempt
                        and any(alias in lowered for alias in _TUNING_FIELD_ALIASES[f])
                    ),
                    None,
                )
                if offending is None:
                    raise
                logger.info(
                    "%r does not accept %s; retrying without it (%s)",
                    model,
                    offending,
                    last_body[:120].strip(),
                )
                if offending == "chat_template_kwargs":
                    # Remembered for the whole process, not just this call -- the 400 that taught
                    # us this cost a request. See `_TEMPLATE_KWARGS_REFUSED`.
                    _TEMPLATE_KWARGS_REFUSED.add(engine_key)
                attempt.pop(offending)
                continue

            # An empty answer from a model that WAS given a reasoning setting is not a refusal --
            # it is the reasoning having consumed the whole output budget. Measured on
            # `gemini-3.6-flash`: `reasoning_effort: "low"` returns HTTP 200 with `content: None`
            # and `completion_tokens: 0`, while `"minimal"` on the identical request answers
            # correctly. No HTTP status distinguishes those, so the empty body is the only signal
            # available. Walk the ladder before giving up.
            if (
                not _content_of(data)
                and "reasoning_effort" in attempt
                and rung + 1 < len(_REASONING_LADDER)
            ):
                rung += 1
                next_effort = _REASONING_LADDER[rung]
                logger.info(
                    "%r returned an empty answer at reasoning_effort=%r; retrying with %r",
                    model,
                    attempt.get("reasoning_effort"),
                    next_effort,
                )
                if next_effort is None:
                    attempt.pop("reasoning_effort", None)
                else:
                    attempt["reasoning_effort"] = next_effort
                continue
            # Remember what finally worked, so the next call for this engine starts here instead
            # of spending the ladder again -- see `_REASONING_CHOICE`.
            _REASONING_CHOICE[engine_key] = attempt.get("reasoning_effort")
            break
    except urllib.error.HTTPError as exc:
        detail = last_body[:300]
        # 401/403 means the key is wrong; report that distinctly from a generic HTTP failure so
        # "Save & verify" in Settings can tell a bad key apart from the provider being unreachable.
        if exc.code in (401, 403):
            # Retired, not cooled: this engine cannot work until its key is replaced, so every
            # later finding in this run should go straight past it to one that can.
            _retire(base_url, model)
            raise OllamaError(
                f"the external LLM provider at {base_url} rejected the API key (HTTP {exc.code})"
            ) from exc
        if exc.code == 402:
            # A VALID key with no usable quota, which is neither an auth failure nor a rate limit
            # and must not be reported as either. Measured on a real Cerebras key: `GET /models`
            # answers 200 (so "Save & verify" against the catalogue looks healthy) while
            # `/chat/completions` answers 402 "Payment required to access this resource" — so the
            # only way to learn the account cannot generate is to try to generate.
            raise OllamaError(
                f"the external LLM provider at {base_url} accepted the key but has no available "
                f"quota (HTTP 402) — the free allowance is exhausted or the account needs billing "
                f"enabled. Detail: {detail}"
            ) from exc
        if exc.code in _TRANSIENT_CODES:
            if exc.code == 429:
                # A 429 carries the provider's OWN reset clock, and a flat 90s cooldown throws
                # that number away. Measured on this account: an exhausted DAILY quota reports
                # `7h32m14.4s` in `x-ratelimit-reset-requests` -- re-testing that every 90 seconds
                # would hit the same dead engine roughly 300 times before it recovers on its own.
                # The 429 response also often carries the same remaining/limit headers a 200
                # would, so record them too: a `remaining_requests: 0` learned here is exactly
                # what lets the NEXT process (via `_load_budgets`) see this engine as exhausted
                # from its very first call, instead of re-discovering it the same expensive way.
                _record_budget(f"{base_url}::{model}", exc.headers)
                reset_seconds = _reset_seconds_from_headers(exc.headers)
                if reset_seconds > _QUOTA_EXHAUSTED_SECONDS:
                    # An hours-long reset is a DAILY quota, not a moment of congestion. Cooling
                    # for it literally would mean skipping the engine for the rest of most runs
                    # anyway; retiring it is the same outcome stated honestly, and it is what
                    # lets `_refused` skip straight past it instead of a cooldown that would
                    # expire and get re-tried long before the quota actually refills.
                    _retire(
                        base_url,
                        model,
                        reason=(
                            f"its rate-limit quota will not reset for "
                            f"{reset_seconds / 3600:.1f}h (HTTP 429) — this is a quota running "
                            f"out, not a rejected key, and the two must not be read as the same "
                            f"problem"
                        ),
                    )
                else:
                    # Longer than the flat default: honour it. Never shorter: see
                    # `_start_cooldown`'s own docstring for why a short hint does not shrink the
                    # cooldown below the calibrated "busy" floor.
                    _start_cooldown(base_url, model, seconds=max(reset_seconds, _COOLDOWN_SECONDS))
            else:
                # Busy, not broken. Remember it so the next finding in this run does not pay the
                # same wait to learn the same thing.
                _start_cooldown(base_url, model)
        if exc.code == 429:
            raise OllamaError(
                f"the external LLM provider at {base_url} rate-limited this request (HTTP 429) "
                f"— free tiers cap requests per minute/day; wait and retry, or configure a "
                f"different provider"
            ) from exc
        if exc.code == 413:
            # Distinct from 429 and from a context-window problem, because the fix is different
            # and the message people get otherwise is misleading. Measured against Groq's free
            # tier: gpt-oss-120b advertises a 131,072-token CONTEXT, but the tier caps one request
            # at 8,000 tokens per minute and answers 413 ("Request too large ... on tokens per
            # minute (TPM): Limit 8000, Requested 38840") above it. The model can hold the file;
            # the plan cannot afford it.
            raise OllamaError(
                f"the external LLM provider at {base_url} refused this request as too large "
                f"(HTTP 413). This is the provider's per-request/per-minute TOKEN allowance, not "
                f"the model's context window — a free tier typically caps a single request far "
                f"below the model's advertised context. Re-run Save & verify in Settings so QUBIT "
                f"re-reads the real allowance, or use a paid/self-hosted endpoint for files this "
                f"size. Detail: {detail}"
            ) from exc
        raise OllamaError(
            f"the external LLM provider at {base_url} returned HTTP {exc.code}: {exc.reason} "
            f"{detail}".strip()
        ) from exc
    except TimeoutError as exc:
        raise OllamaError(
            f"the model {model!r} at {base_url} did not answer within {timeout:.0f}s"
        ) from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        if isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
            raise OllamaError(
                f"the model {model!r} at {base_url} did not answer within {timeout:.0f}s"
            ) from exc
        raise OllamaError(
            f"the external LLM provider is not reachable at {base_url}: {exc}"
        ) from exc
    if not isinstance(data.get("choices"), list) or not data["choices"]:
        raise OllamaError(
            f"the external LLM provider at {base_url} returned an unexpected response shape"
        )
    usage = data.get("usage") or {}
    _record_call(
        engine=f"{base_url}::{model}",
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
        seconds=time.monotonic() - started,
    )
    text = _content_of(data)
    if not text:
        # Reached only after `_REASONING_LADDER` is exhausted, so the reasoning-budget explanation
        # has already been ruled out and the message can say what is actually left.
        finish = str(data["choices"][0].get("finish_reason", ""))
        raise OllamaError(
            f"the external LLM provider at {base_url} returned an empty response "
            f"(finish_reason={finish!r}). If this model reasons before answering, it spent the "
            f"whole output budget doing so."
        )
    return text


def _first_answer(
    chain: Sequence[ExternalEndpoint],
    prompt: str,
    *,
    timeout: float,
    source: str,
    avoid: Container[str] = frozenset(),
    on_fallback: Callable[[str], None] | None = None,
    on_engine: Callable[[str], None] | None = None,
    announce_first: bool = True,
) -> str | None:
    """The first engine in `chain` that answers, or None when none of them did.

    Shared by both routes of `_generate`, because "walk down the pool until something answers"
    is the same operation whether the walk started at an external primary or escalated to the
    pool from a local model.

    `avoid` names engines that already produced a candidate the repair loop REJECTED for this
    finding. They are skipped for the same reason `_refused` and `_cooling` entries are: asking
    costs a request and the answer is already known to be unusable.

    `announce_first` is False for a walk that BEGINS at the configured primary -- index 0 is not
    a fallback, so `on_fallback` must not fire for it. It is True for a walk the local route
    escalated into, where every engine reached is by definition a fallback.
    """
    for index, endpoint in enumerate(chain):
        # An engine whose key was rejected is skipped unconditionally, including when it is the
        # only one left. There is no request it could answer, so trying it can only turn a clear
        # "every engine is unusable, here is why" into one more identical rejection.
        if _refused(endpoint.base_url, endpoint.model):
            continue
        if f"openai-compatible:{endpoint.model}" in avoid:
            logger.info(
                "skipping %s: it already produced a candidate this finding rejected",
                endpoint.model,
            )
            continue
        # An engine that answered 503 seconds ago will answer 503 again, and asking costs whatever
        # its timeout is. Skipped rather than removed: the window is short and the pool is small.
        if _cooling(endpoint.base_url, endpoint.model) and index < len(chain) - 1:
            logger.info("skipping %s: still cooling down after a transient failure", endpoint.model)
            continue
        try:
            answer = _openai_compatible_generate(
                prompt,
                model=endpoint.model,
                base_url=endpoint.base_url,
                api_key=endpoint.api_key,
                timeout=timeout,
                source=source,
                budget_tokens=endpoint.budget_tokens,
            )
        except OllamaError as exc:
            logger.warning("external LLM provider %s failed (%s)", endpoint.base_url, exc)
            continue
        name = f"openai-compatible:{endpoint.model}"
        if on_fallback is not None and (announce_first or index > 0):
            on_fallback(name)
        if on_engine is not None:
            on_engine(name)
        return answer
    return None


def _generate(
    prompt: str,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 180.0,
    source: str = "",
    provider: str = "ollama",
    api_key: str | None = None,
    fallback_ollama_model: str | None = None,
    on_fallback: Callable[[str], None] | None = None,
    budget_tokens: int | None = None,
    backup: ExternalEndpoint | None = None,
    backups: Sequence[ExternalEndpoint] = (),
    avoid: Container[str] = frozenset(),
    on_engine: Callable[[str], None] | None = None,
) -> str:
    """Dispatch generation down the configured chain of engines.

    `provider="ollama"` (the default -- every existing caller and every test that mocks
    `_ollama_generate` directly) calls it unchanged; nothing about this dispatcher touches that
    path's behaviour.

    `provider="openai-compatible"` walks: **primary external -> backup external (if configured)
    -> local Ollama**. A step is taken on a connection/auth/rate-limit failure, and on a
    content-shape rejection the repair loop above has already seen -- the latter through `avoid`,
    which names the engines that produced a candidate THIS finding rejected.

    That second case used to be excluded on the reasoning that a rejected candidate is a
    successful HTTP response and therefore the repair loop's business. The repair loop does own
    the decision; what it lacked was any way to act on it, so all three of its attempts went back
    to the engine that had just been measured as unable to do the work. Measured on
    `medivault-emr` before this change: 6 candidates generated, 1 survived the gates, and the
    other five spent every attempt on the same local 7B while eight pooled engines stayed idle.

    `on_engine` fires with whichever engine actually produced the answer, on EVERY route
    including the primary -- that is what lets the repair loop populate `avoid`. `on_fallback`
    keeps its narrower meaning (a step was taken) and is unchanged.

    The backup exists because a free tier's real constraint is its token allowance, not its model:
    Groq's free tier permits 8,000 tokens/minute, so one large file exhausts a minute. A second key
    on a different provider multiplies the usable budget with no new code path -- it is this same
    call with different config. Ollama stays underneath both, so an install with no keys at all is
    unchanged.

    `on_fallback` is called with the name of the engine that ended up producing the answer, so the
    caller can attribute the patch to what actually ran rather than what was configured.
    """
    if provider != "openai-compatible":
        #: The pooled engines this install can escalate INTO, in the order routing ranked them.
        escalation = [e for e in (backup, *backups) if e and e.api_key and e.base_url and e.model]
        # Local already produced a candidate this finding rejected. Asking it again is asking the
        # one engine measured as unable to do this work to correct itself, while the pool that
        # routing ranked as capable is never consulted. Step into the pool instead; the local
        # model stays underneath as the answer of last resort below.
        if model in avoid and escalation:
            answer = _first_answer(
                escalation,
                prompt,
                timeout=timeout,
                source=source,
                avoid=avoid,
                on_fallback=on_fallback,
                on_engine=on_engine,
            )
            if answer is not None:
                return answer
        try:
            answer = _ollama_generate(
                prompt, model=model, base_url=base_url, timeout=timeout, source=source
            )
        except OllamaError:
            # The chain runs BOTH ways. Routing sends a finding to the local model when it has
            # proven it can do that work and costs nothing -- but "free" is not "always running".
            # With Ollama stopped, every locally-routed finding failed even though a working
            # external engine was configured and idle, which is a worse outcome than spending one
            # request. Only taken when a backup actually exists, so an install with no keys behaves
            # exactly as it always has and every test that mocks `_ollama_generate` is unaffected.
            if backup is None or not (backup.api_key and backup.base_url and backup.model):
                raise
            logger.warning("local Ollama failed; escalating to %s", backup.model)
            answer = _openai_compatible_generate(
                prompt,
                model=backup.model,
                base_url=backup.base_url,
                api_key=backup.api_key,
                timeout=timeout,
                source=source,
                budget_tokens=backup.budget_tokens,
            )
            if on_fallback is not None:
                on_fallback(f"openai-compatible:{backup.model}")
            if on_engine is not None:
                on_engine(f"openai-compatible:{backup.model}")
            return answer
        if on_engine is not None:
            on_engine(model)
        return answer

    if not api_key:
        raise OllamaError(
            "the external LLM provider is selected in Settings but no API key is configured"
        )

    chain: list[ExternalEndpoint] = [
        ExternalEndpoint(
            base_url=base_url, model=model, api_key=api_key, budget_tokens=budget_tokens
        )
    ]
    if backup is not None and backup.api_key and backup.base_url and backup.model:
        chain.append(backup)
    # Everything else the scheduler ranked, in its order. One spare was never enough: hosted
    # engines fail INDEPENDENTLY and often, which is the whole reason to pool several free tiers.
    # Measured on NVIDIA's `poolside/laguna-xs-2.1`, which answers a real migration in ~2s but
    # returned 503 "ResourceExhausted" on 3 of 4 attempts -- an engine that good and that flaky is
    # only usable if the next one picks the work up, and useless if a 503 fails the finding.
    #
    # De-duplicated on (base_url, model, KEY), and the key is the part that matters.
    #
    # It used to be (base_url, model) alone, on the reasoning that asking the same endpoint twice
    # costs two requests for one answer. That is true of the same ACCOUNT and false of a different
    # one: a free tier rations per key, so a 429 from one key says nothing whatever about another,
    # and collapsing them threw away the second account's whole allowance. Measured on this install:
    # four keys drive `nemotron-3-super`, and three of them were unreachable through the chain --
    # the pool looked four engines wide and behaved as one.
    for extra in backups:
        if not (extra.api_key and extra.base_url and extra.model):
            continue
        if any(
            e.base_url == extra.base_url and e.model == extra.model and e.api_key == extra.api_key
            for e in chain
        ):
            continue
        chain.append(extra)

    answer = _first_answer(
        chain,
        prompt,
        timeout=timeout,
        source=source,
        avoid=avoid,
        on_fallback=on_fallback,
        on_engine=on_engine,
        announce_first=False,
    )
    if answer is None and avoid:
        # Every engine in the pool has now produced a candidate this finding rejected, so
        # escalation has nothing further to offer. Walk the chain again without the filter
        # rather than failing the finding: one more attempt at the best engine, carrying the
        # validator's own words about what was wrong, is strictly better than no attempt.
        answer = _first_answer(
            chain,
            prompt,
            timeout=timeout,
            source=source,
            on_fallback=on_fallback,
            on_engine=on_engine,
            announce_first=False,
        )
    if answer is not None:
        return answer

    local_model = fallback_ollama_model or model
    logger.warning("every external provider failed; falling back to local Ollama %r", local_model)
    if on_fallback is not None:
        on_fallback(local_model)
    if on_engine is not None:
        on_engine(local_model)
    return _ollama_generate(
        prompt, model=local_model, base_url=DEFAULT_BASE_URL, timeout=timeout, source=source
    )


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
    provider: str = "ollama",
    api_key: str | None = None,
    fallback_ollama_model: str | None = None,
    budget_tokens: int | None = None,
    backup: ExternalEndpoint | None = None,
    backups: Sequence[ExternalEndpoint] = (),
    on_fallback: Callable[[str], None] | None = None,
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
        raw = _generate(
            _build_plan_prompt(source, rule, asset, lang, experience),
            model=model,
            base_url=base_url,
            timeout=timeout,
            provider=provider,
            api_key=api_key,
            fallback_ollama_model=fallback_ollama_model,
            budget_tokens=budget_tokens,
            backup=backup,
            backups=backups,
            on_fallback=on_fallback,
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


#: Marker standing in for the middle of a file the model is not shown. Diff-like and deliberately
#: NOT comment syntax: comment markers differ across the twenty-odd languages QUBIT migrates, and a
#: model returning a C file "corrects" a `#` line into `/* */`, which would break the splice.
EXCERPT_MARKER = "@@QUBIT_UNCHANGED_REGION@@"

#: Lines of the file's head to show. The head is where imports live and nearly every PQC migration
#: adds one, so a window that omitted them would produce patches the `symbols` stage rejects for
#: using `mldsa65.PublicKey` without importing it.
#:
#: Sized from the corpus rather than picked: across the 300 oversize findings on this installation,
#: the import block ends by line 35 at the median but by line 84 at p95 -- a licence header alone
#: can run 17 lines before the first import. Across 300 large real files here, 40 lines covered
#: the whole block for only 75% of them and cut through it for the rest -- worse than it sounds,
#: because a model shown HALF an import list can re-add an import it was not shown it already has.
#: 120 covers 98%, and costs about 900 tokens against a budget the median excerpt uses ~1,800 of.
_EXCERPT_HEAD_LINES = 120

#: Lines either side of the flagged line. Measured over the 27 findings this installation still
#: cannot send whole (against its real 28,800-token prompt budget): 120 + 60 gives a median excerpt
#: of 1,800 tokens and a worst case of 2,527, against a whole-file median of 35,279 and a worst
#: case of 115,994 -- a 96.3% reduction. Every one of them now fits. None of them fitted before.
_EXCERPT_WINDOW_LINES = 60


@dataclass(frozen=True)
class Excerpt:
    """A head-and-window view of a file too large to send whole, and the splice back into it.

    QUBIT's generation contract is whole-file: the model is shown a file and returns all of it.
    That contract is what lets `check_rewrite` catch truncation -- and it is also why 27 findings
    on this installation never reach the model at all. A 9,702-line file needs ~115,994 tokens
    against a 28,800-token prompt budget, and `_llm_detour_reason` tells the operator, accurately,
    that "splitting the change by hand is what this needs".

    This does that splitting. The model is shown the imports, a marker standing for the region it
    is not shown, and the neighbourhood of the flagged line; it returns the same shape; `splice`
    puts the two rewritten regions back into the untouched original. Everything downstream -- the
    truncation guards, the rescan, every sandbox stage -- still receives a complete file, which is
    why none of them needed changing for this.

    The saving is not only in what is sent. A whole-file rewrite ANSWERS at roughly the length of
    its input, and the answer is both the billed half and the slow half, so a 96% smaller prompt
    is also a ~96% smaller completion -- and the truncation that produced those answers stops
    being reachable at all. Measured live on `eip7928_test.go` (29,164 tokens): three full repair
    attempts in 101 seconds, against 16.5 minutes for ONE whole-file attempt on a smaller file.

    **What this cannot do, stated plainly.** A window fixes only what is inside it. Where the same
    weak primitive appears throughout a file, a whole-file rewrite could replace every occurrence
    and this replaces the flagged one -- the rest are restored unchanged from the original, because
    that is exactly what makes the splice safe. QUBIT builds one task per finding, so the other
    occurrences have their own tasks and their own windows; but a rule whose rescan asks whether
    the algorithm is gone from the WHOLE file can still refuse a windowed patch that is locally
    correct. That is a real ceiling, not a bug, and it is why windowing is reached only when the
    alternative is no patch at all.
    """

    text: str
    #: The flagged line's 1-based position WITHIN `text`, which is what the prompt must quote.
    line: int
    lines: tuple[str, ...]
    head: int
    lo: int
    hi: int

    def splice(self, returned: str) -> str:
        """Rebuild the complete file from the model's rewritten excerpt.

        Raises `ModelOutputError` when the marker is missing or duplicated, which sends the answer
        through the same repair loop as any other malformed output instead of failing the task.
        """
        # A text answer's final newline is a TERMINATOR, not an extra blank line -- the fenced
        # block the model returns carries one whether or not the excerpt ended with a blank line,
        # so reading it as content adds a line the model never wrote. `splitlines()` is exactly
        # that convention, and it is unambiguous here only because `build_excerpt` guarantees the
        # excerpt never ends on a blank line; see the trim there for what that is protecting.
        body = returned.replace("\r\n", "\n").replace("\r", "\n").splitlines()
        if self.head:
            seen = sum(1 for line in body if EXCERPT_MARKER in line)
            if seen != 1:
                raise ModelOutputError(
                    f"your answer must contain the line {EXCERPT_MARKER} exactly once, standing "
                    f"for the region of the file you were not shown, but it appeared {seen} times"
                )
            cut = next(i for i, line in enumerate(body) if EXCERPT_MARKER in line)
            head_new, window_new = body[:cut], body[cut + 1 :]
        else:
            head_new, window_new = [], body
        rebuilt = [
            *head_new,
            *self.lines[self.head : self.lo],
            *window_new,
            *self.lines[self.hi :],
        ]
        text = "\n".join(rebuilt)
        return text if text.endswith("\n") else text + "\n"


def build_excerpt(
    source: str,
    line: int | None,
    *,
    head_lines: int = _EXCERPT_HEAD_LINES,
    window_lines: int = _EXCERPT_WINDOW_LINES,
) -> Excerpt | None:
    """An `Excerpt` of ``source`` centred on ``line``, or None when windowing buys nothing.

    None means "send the whole file", and is returned in the two cases where an excerpt would be
    impossible or pointless: there is no usable line to centre on, or the window already covers
    the file -- where the whole-file path is strictly better, because it needs no marker, no
    splice, and no instruction the model can get wrong.
    """
    # Same reason as `Excerpt.splice`: this list has to rejoin into exactly the file it came from,
    # and only `split("\n")` guarantees that.
    lines = source.split("\n")
    if line is None or not (1 <= line <= len(lines)):
        return None
    idx = line - 1
    half = max(1, window_lines // 2)
    lo = max(0, idx - half)
    hi = min(len(lines), idx + half + 1)
    # Never end the excerpt on a blank line. `"a\n"` is genuinely ambiguous between one line and
    # two, and `Excerpt.splice` has to read the model's answer under the ordinary text convention
    # that a final newline terminates rather than adds. Trimming the window's trailing blanks --
    # they stay in the file, as part of the untouched tail -- removes the ambiguity instead of
    # guessing at it. Measured cost of getting this wrong: 29 of 304 real source files came back
    # every line after the splice point shifted up by one, each still parsing and still passing
    # the rescan, so nothing downstream would have caught it.
    while hi - 1 > idx and not lines[hi - 1].strip():
        hi -= 1
    head = min(max(0, head_lines), len(lines))
    if lo <= head:
        # The window already reaches the imports, so there is no gap to elide and the excerpt can
        # be one contiguous region starting at the file's first line -- no marker needed.
        head, lo = 0, 0
    if head == 0 and lo == 0 and hi >= len(lines):
        return None
    if head:
        body = [*lines[:head], EXCERPT_MARKER, *lines[lo:hi]]
        at = head + 1 + (idx - lo) + 1
    else:
        body = list(lines[lo:hi])
        at = idx - lo + 1
    return Excerpt(text="\n".join(body), line=at, lines=tuple(lines), head=head, lo=lo, hi=hi)


def _excerpt_asset(asset: CryptoAsset, excerpt: Excerpt) -> CryptoAsset:
    """The same finding renumbered onto the excerpt, so `line=` in the prompt points at real code.

    The prompt quotes the flagged line number and the model counts lines to find it. Leaving the
    original number would point 8,600 lines past the end of a 100-line excerpt.
    """
    if asset.location is None:
        return asset
    return asset.model_copy(
        update={"location": asset.location.model_copy(update={"line": excerpt.line})}
    )


def _excerpt_feedback(reason: str) -> str:
    """Restate a whole-file rejection in terms of the excerpt the model was actually given.

    Every check from `check_rewrite` onwards runs on the SPLICED file and speaks its language --
    "return the COMPLETE file", "the returned file has only N non-blank lines versus M". Fed back
    verbatim to a model that was handed an excerpt, that is an instruction it cannot follow about
    a file it never saw, and the repair attempt is spent on the wrong problem.

    Measured on `evp_pkey_provided_test.c`: gemma-4-31b kept the marker correctly, left one
    unbalanced brace inside its own region, and was then told to "return the COMPLETE file". The
    brace is the actual fault and the one thing the message never mentioned.
    """
    return (
        f"{reason}\n\nThat verdict is about the WHOLE file, which QUBIT rebuilt from your answer "
        f"plus the regions you were not shown -- it is not a request for the whole file. You are "
        f"still editing an EXCERPT: return only the regions you were given, separated by the "
        f"`{EXCERPT_MARKER}` line, and make sure every brace, bracket and parenthesis you open "
        f"inside your regions is also closed inside them."
    )


def _closing_instruction(source: str, excerpt: bool) -> str:
    """What the model must return, stated immediately before the code it must return it for."""
    count = len(source.splitlines())
    if excerpt:
        return (
            "Below is an EXCERPT of a larger file, not the whole of it: its opening lines, where "
            f"the imports live, then the line `{EXCERPT_MARKER}` standing for a region you are "
            "not being shown, then the code around the flagged line. Return BOTH regions in the "
            f"same order, separated by that same `{EXCERPT_MARKER}` line appearing exactly once, "
            f"with all {count} lines you were given present and in order. Put any import this "
            "migration needs in the first region. Do NOT try to reproduce the region you were "
            "not shown, and do not drop the marker.\n\n"
        )
    return (
        f"The file below has {count} lines. Your output must contain all of them, in order, "
        "changing only what this migration requires. Do not summarise, reorganise, or drop code "
        "unrelated to the flagged algorithm.\n\n"
    )


def _build_prompt(
    source: str,
    rule: MigrationRule,
    asset: CryptoAsset,
    feedback: str | None = None,
    experience: Any | None = None,
    plan: str = "",
    excerpt: bool = False,
) -> str:
    language = _prompt_language(rule, asset)
    target_shape = _target_shape_block(rule, language)
    constraints = _scoped_constraints(rule, language, have_target_shape=bool(target_shape))
    # An excerpt and a whole file are answered differently, and the difference has to be stated in
    # BOTH places the shape is described -- the answer contract here and the closing instruction
    # below -- or the two contradict each other and the model satisfies whichever it read last.
    # Each mode's opening is constant WITHIN that mode, so both keep a cacheable prefix.
    if excerpt:
        answer_shape = (
            "1. The rewritten EXCERPT inside ONE fenced code block, in exactly the shape you "
            f"were given it, including its `{EXCERPT_MARKER}` line. Put nothing but code in the "
            "fence — no prose, no commentary, no explanation inside it.\n"
        )
    else:
        answer_shape = (
            "1. The complete rewritten file inside ONE fenced code block. Put nothing but code "
            "in the fence — no prose, no commentary, no explanation inside it.\n"
        )
    return (
        "You are a cryptographic migration engineer. Rewrite the file below to migrate the "
        "flagged weak cryptography.\n\n"
        "Answer in EXACTLY this shape:\n"
        f"{answer_shape}"
        "2. AFTER the closing fence, a section beginning `SECURITY NOTES:` with 2-4 short "
        "bullets: what you changed and why it is quantum-safe, what an operator must change "
        "OUTSIDE this file (storage widths, key formats, callers), and anything you could not "
        "fix here. State this honestly — a note saying a change is incomplete is far more "
        "useful than a claim that it is done.\n\n"
        # ── STATIC HALF ────────────────────────────────────────────────────────────────────
        # Everything from here to the DYNAMIC HALF marker is identical for every finding of this
        # (rule, language) pair, and it is deliberately FIRST. Providers cache on an unbroken
        # PREFIX, so one dynamic token early in the prompt strands everything after it.
        #
        # Measured on this rule pack: 95.7% of a `code-signature-01` prompt is identical between
        # two findings — but with the flagged asset's line number sitting at character 723, only
        # 10.8% was reachable as a prefix. 85% of every prompt was cacheable content that could
        # never be cached, re-billed on each of the up-to-seven calls a single patch makes.
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
        # Refers to the flagged asset BELOW rather than interpolating its usage_context here: one
        # dynamic value in this sentence would end the cacheable prefix before the rule's own
        # guidance, examples and target shape — the largest static block in the prompt.
        "matches the usage_context named in the flagged asset below. When that is 'unknown', "
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
        f"{_impact_block(rule)}"
        f"{target_shape}"
        f"{_worked_examples(rule, language)}"
        # ── DYNAMIC HALF ───────────────────────────────────────────────────────────────────
        # Everything below varies per finding, so none of it can be cached. Keeping it in one
        # contiguous block at the END is precisely what makes the static half above a usable
        # prefix — and it is also the conventional shape for a long prompt: instructions and
        # reference material first, the specific task last.
        f"Flagged asset: algorithm={asset.algorithm}, usage_context={asset.usage_context.value}, "
        f"line={asset.location.line if asset.location else '?'}\n"
        f"{_attack_note(asset)}"
        f"{_weakness_block(asset)}"
        f"{_experience_examples(experience, language)}"
        f"{_plan_block(plan)}"
        f"{_repair_feedback(feedback)}"
        f"{_closing_instruction(source, excerpt)}"
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
    provider: str = "ollama",
    api_key: str | None = None,
    fallback_ollama_model: str | None = None,
    budget_tokens: int | None = None,
    backup: ExternalEndpoint | None = None,
    backups: Sequence[ExternalEndpoint] = (),
    on_fallback: Callable[[str], None] | None = None,
    avoid: Container[str] = frozenset(),
) -> tuple[str, str]:
    """Return ``(possibly corrected source, notes)`` after one review pass over the draft.

    Never regresses. A review that answers OK, returns something unusable, or fails entirely
    leaves the draft exactly as it was — the pass can only improve a patch or cost time, which is
    what makes it safe to run before the expensive validation rather than after.

    `avoid` normally names the engine that WROTE the draft, which makes this a cross-model review
    rather than a model checking its own work. A model asked whether its own answer is correct
    agrees with itself; a second model reads the draft with none of the reasoning that produced it
    and has to find the fault in the code. On a single-engine install the set has nothing to
    escalate to and the pass stays a self-review, exactly as before.
    """
    lang = language or _prompt_language(rule, asset)
    try:
        raw = _generate(
            _build_review_prompt(source, draft, rule, asset, lang),
            model=model,
            base_url=base_url,
            timeout=timeout,
            source=source,
            provider=provider,
            api_key=api_key,
            fallback_ollama_model=fallback_ollama_model,
            budget_tokens=budget_tokens,
            backup=backup,
            backups=backups,
            on_fallback=on_fallback,
            avoid=avoid,
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
    provider: str = "ollama",
    api_key: str | None = None,
    fallback_ollama_model: str | None = None,
    on_fallback: Callable[[str], None] | None = None,
    budget_tokens: int | None = None,
    backup: ExternalEndpoint | None = None,
    backups: Sequence[ExternalEndpoint] = (),
    windowed: bool = False,
) -> str:
    """Return the LLM-rewritten file content, or raise :class:`OllamaError`.

    ``provider``/``api_key``: select an external OpenAI-compatible endpoint instead of the local
    Ollama server (see `_generate`). Default ``"ollama"`` is exactly today's behaviour -- ``model``
    and ``base_url`` name the local server as they always have.

    ``fallback_ollama_model``/``on_fallback``: only meaningful when ``provider`` is
    ``"openai-compatible"``. If the external call fails to connect/authenticate, generation falls
    back to this local Ollama model for that attempt rather than failing the task outright, and
    ``on_fallback`` (if given) is called so the caller can record which engine actually produced
    the result.

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

    ``windowed``: show the model an `Excerpt` -- the file's imports plus the neighbourhood of the
    flagged line -- instead of the whole file, and splice its answer back before anything inspects
    it. Set by the caller for files no configured engine can hold, which on this installation is
    27 findings that are otherwise refused before the first token. The excerpt is a PROMPT
    concern only: every check from `check_rewrite` onwards still sees a complete file.
    """
    # `fallback_model` was configured and referenced by nothing, so a machine without the primary
    # model pulled had no safety net at all — just a 404 reported as "Ollama unreachable". It is
    # only used when the primary is genuinely absent, never to silently downgrade a working setup.
    #
    # Ollama-only: `model`/`base_url` name an EXTERNAL provider when `provider` is
    # "openai-compatible", and `/api/tags` is an Ollama-specific endpoint that has nothing to say
    # about a remote provider's model catalogue.
    if provider == "ollama":
        available = installed_models(base_url)
        if available and model not in available:
            if fallback_model and fallback_model in available:
                logger.warning(
                    "Ollama model %r is not installed; falling back to %r", model, fallback_model
                )
                model = fallback_model
            else:
                raise OllamaError(_model_missing_message(model, base_url))

    # Windowed generation, for files no engine can hold whole. The excerpt replaces the source
    # in the PROMPT only -- `splice` restores the complete file before a single downstream check
    # runs -- so `check_rewrite`, the rescan and every sandbox stage are untouched by this.
    excerpt = (
        build_excerpt(source, asset.location.line if asset.location else None) if windowed else None
    )
    prompt_source = excerpt.text if excerpt is not None else source
    prompt_asset = _excerpt_asset(asset, excerpt) if excerpt is not None else asset
    if excerpt is not None:
        # The review pass carries BOTH the original and the draft, so a file that did not fit once
        # certainly does not fit twice. Disabled rather than windowed: a review that reads only a
        # fragment of the change it is judging is worse than no review at all.
        self_review_pass = False

    # Pass one, for the structural rewrites only: make the model say what it intends to change
    # before it changes anything. Done ONCE and carried across every repair attempt - the plan
    # does not become wrong because the first draft of it was truncated, and re-planning on each
    # retry would triple the cost of the tasks that already cost the most.
    plan = ""
    if plan_first and needs_planning(rule):
        plan = plan_rewrite(
            prompt_source,
            rule,
            prompt_asset,
            model=model,
            base_url=base_url,
            timeout=timeout,
            language=_prompt_language(rule, asset),
            experience=experience,
            provider=provider,
            api_key=api_key,
            fallback_ollama_model=fallback_ollama_model,
            budget_tokens=budget_tokens,
            backup=backup,
            backups=backups,
            on_fallback=on_fallback,
        )
        if plan:
            logger.info("planned the rewrite for %s before generating", rule.id)

    last_reason = "unknown"
    #: Times the model was asked for an excerpt and did not return the marker. Capped separately
    #: from `max_attempts` because it is not the same kind of failure -- see the break below.
    marker_failures = 0
    #: Engines that produced a candidate THIS loop rejected. `_generate` steps past them, so a
    #: second attempt reaches a different model instead of asking the same one to correct itself.
    #: Without this the pool's width was decorative: a nine-engine install spent all three
    #: attempts on whichever single engine routing picked first.
    spent: set[str] = set()
    #: Whichever engine answered the attempt in flight, reported by `_generate` on every route.
    produced_by: list[str] = []

    def _note_engine(name: str) -> None:
        produced_by.clear()
        produced_by.append(name)

    for _attempt in range(max(1, max_attempts)):
        # Reaching a second iteration means the previous candidate was REJECTED -- every accepted
        # one returns from inside the loop. So whichever engine produced it is retired from this
        # finding here, at the one point that is true for all of the loop's rejection paths
        # (unparseable answer, missing marker, failed verification, failed self-review).
        spent.update(produced_by)
        # Generation is INSIDE the retry because a truncated or unfenced answer is the model
        # getting it wrong, and that is what the repair loop is for. It was outside, so a
        # truncation ended the whole attempt immediately -- measured on Crypto.kt and
        # Ledger.scala, two ~400-character files the model looped on until it exhausted the
        # output budget. A transport failure (server down, model not pulled, timeout) is a plain
        # OllamaError and still propagates on the first try, because retrying it only makes the
        # user wait three times over for the same message.
        try:
            raw = _generate(
                _build_prompt(
                    prompt_source,
                    rule,
                    prompt_asset,
                    feedback,
                    experience,
                    plan,
                    excerpt=excerpt is not None,
                ),
                model=model,
                base_url=base_url,
                timeout=timeout,
                source=prompt_source,
                provider=provider,
                api_key=api_key,
                fallback_ollama_model=fallback_ollama_model,
                on_fallback=on_fallback,
                budget_tokens=budget_tokens,
                backup=backup,
                backups=backups,
                avoid=spent,
                on_engine=_note_engine,
            )
            new_source = extract_code_block(raw)
            if excerpt is not None:
                # Back to a complete file before anything else looks at it.
                new_source = excerpt.splice(new_source)
        except ModelOutputError as exc:
            last_reason = str(exc)
            wanted = (
                f"the excerpt, including its `{EXCERPT_MARKER}` line"
                if excerpt is not None
                else "the complete file"
            )
            feedback = (
                f"{last_reason}. Return ONLY {wanted} inside ONE fenced code block, with no "
                "commentary before or after it."
            )
            if excerpt is not None and EXCERPT_MARKER in last_reason:
                marker_failures += 1
                # Dropping the marker is a different kind of failure from a truncated or unfenced
                # answer, and the repair loop's assumption -- that telling the model what was
                # wrong will fix it -- does not hold for it. Measured on
                # `evp_pkey_provided_test.c`: the local 7B dropped the marker on 4 of 4 attempts,
                # taking 302 seconds to reach the same answer three times, while gpt-oss-120b kept
                # it in 9.0s and gemma-4-31b in 110.4s on the identical prompt. So this is a
                # property of the ENGINE, not of the phrasing. One repair attempt is worth making;
                # a second only spends time and quota to be told the same thing. Failing here
                # records the outcome, which is what lets `_select_engine`'s reliability gate
                # route the next windowed finding somewhere that can answer it.
                if marker_failures >= 2:
                    break
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
                provider=provider,
                api_key=api_key,
                fallback_ollama_model=fallback_ollama_model,
                budget_tokens=budget_tokens,
                backup=backup,
                backups=backups,
                on_fallback=on_fallback,
                # Whoever wrote this draft does not get to mark its own work. `produced_by` holds
                # the engine that answered THIS attempt, so the review is routed to a different
                # one wherever the pool has another to offer.
                avoid=set(produced_by),
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
            if excerpt is not None:
                # The reviewer has to be told this. Every other caveat is the MODEL admitting a
                # limit; this one is QUBIT admitting one, and it is the more important of the two
                # -- a reader who assumes the model weighed the whole file would credit the patch
                # with a judgement it never made. The regions outside the window are safe because
                # they were copied from the original, not because anything checked them.
                caveats = [
                    "QUBIT showed the model an excerpt of this file, not all of it: the imports "
                    "and the lines around the finding. Everything outside that window was "
                    "preserved unchanged from the original and was not read by the model.",
                    *caveats,
                ]
            # Only the ACCEPTED attempt's reasoning is reported. Notes from a rejected rewrite
            # describe a file that was thrown away, and showing those beside the diff that
            # shipped would actively mislead the reviewer.
            if on_notes is not None and notes:
                on_notes(notes)
            if on_caveats is not None and caveats:
                on_caveats(caveats)
            return new_source
        last_reason = reason
        feedback = _excerpt_feedback(reason) if excerpt is not None else reason

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
    "EXCERPT_MARKER",
    "HTTP_USER_AGENT",
    "Excerpt",
    "ExternalEndpoint",
    "OllamaError",
    "RateBudget",
    "build_excerpt",
    "check_reasoning",
    "check_rewrite",
    "extract_code_block",
    "extract_security_notes",
    "generate_llm_source",
    "installed_models",
    "needs_planning",
    "plan_rewrite",
    "present_prefixes",
    "rate_budget",
    "self_review",
    "unverifiable_reason",
]
