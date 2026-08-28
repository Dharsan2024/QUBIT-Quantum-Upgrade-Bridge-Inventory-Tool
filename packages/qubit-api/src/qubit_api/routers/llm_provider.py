"""Which engine `qubit_migrate` calls for patch generation: local Ollama (default, always
available) or an external OpenAI-compatible endpoint the user configures here.

Mirrors `threat_intel.py`'s shape deliberately: a singleton row (`id` fixed at 1), lazily created
on first read, PATCH-able one field at a time. The one thing this router must never do, unlike
every other config endpoint in this codebase, is put the plaintext API key in a response -- see
`_to_config_out`.
"""

from __future__ import annotations

import contextlib
import json
import logging
import urllib.error
import urllib.request
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from qubit_core.db import secrets_at_rest
from qubit_core.db.models import LlmEngine, LlmProviderConfig
from qubit_core.db.session import commit_with_retry
from qubit_migrate.config import MigrateConfig
from qubit_migrate.transform.llm import (
    DEFAULT_BASE_URL,
    HTTP_USER_AGENT,
    installed_models,
    rate_budget,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import (
    LlmEngineIn,
    LlmEngineOut,
    LlmEnginePatch,
    LlmProviderConfigOut,
    LlmProviderConfigPatch,
    LlmProviderModelsOut,
    LlmProviderVerifyResult,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/llm-provider", tags=["llm-provider"])

#: Per-request token allowance assumed for an external provider that reports none of its own.
#: Chosen to be comfortably larger than any local model's window (so a silent provider is not
#: crippled to the local 7B model's 8,192) while staying modest enough that an over-estimate is
#: corrected by a 413/429 carrying the real number, rather than by silent truncation.
_EXTERNAL_DEFAULT_TOKENS = 64000


def _get_or_create_config(session: Session) -> LlmProviderConfig:
    # Singleton row, id fixed at 1 -- same reasoning as ThreatIntelConfig: lazily created so a
    # fresh install doesn't need a data migration just to seed one default-Ollama row.
    config = session.get(LlmProviderConfig, 1)
    if config is None:
        config = LlmProviderConfig(id=1, provider="ollama")
        commit_with_retry(session, config)
        session.refresh(config)
    return config


def _fetch_model_rows(base_url: str, api_key: str) -> list[dict[str, Any]]:
    """The provider's raw `/models` rows. Raises on any transport/parse failure.

    Returns the FULL rows, not just ids, because callers need the metadata beside the id --
    `context_window` in particular, which decides whether a large file gets a real rewrite
    attempt or is routed to guided advice.
    """
    if not base_url.startswith(("http://", "https://")):
        raise ValueError(f"invalid base URL: {base_url}")
    req = urllib.request.Request(  # noqa: S310 — scheme validated above
        base_url.rstrip("/") + "/models",
        headers={"Authorization": f"Bearer {api_key}", "User-Agent": HTTP_USER_AGENT},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        payload = json.load(resp)
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    return [r for r in rows if isinstance(r, dict)]


def _is_text_model(row: dict[str, Any]) -> bool:
    """Whether this catalogue entry can actually do a text-in/text-out whole-file rewrite.

    Judged from the provider's OWN declared modalities rather than a name blocklist, so a model
    QUBIT has never heard of is classified correctly. An entry that declares no modalities at all
    is assumed usable -- most OpenAI-compatible servers omit the field entirely, and excluding
    those would empty the list for every self-hosted deployment.
    """
    inputs = row.get("input_modalities")
    outputs = row.get("output_modalities")
    if isinstance(inputs, list) and "text" not in inputs:
        return False
    return not (isinstance(outputs, list) and "text" not in outputs)


def _model_context_window(base_url: str, api_key: str, model: str | None) -> int | None:
    """The selected model's advertised context window, from the provider's `/models` metadata."""
    if not model:
        return None
    for row in _fetch_model_rows(base_url, api_key):
        if row.get("id") == model:
            window = row.get("context_window") or row.get("context_length")
            return window if isinstance(window, int) and window > 0 else None
    return None


def _request_token_limit(base_url: str, api_key: str, model: str | None) -> int | None:
    """The provider's per-request token allowance, read from its own rate-limit headers.

    Costs one minimal completion (`max_tokens: 1`). Worth it: this is the number that actually
    decides whether a file can be migrated at all, it is not discoverable from `/models`, and
    guessing it wrong means every large file is refused with 413 after QUBIT has already committed
    to trying. `x-ratelimit-limit-tokens` is the OpenAI-compatible convention and Groq, OpenAI and
    OpenRouter all send it; a provider that does not just returns None and the model's context
    window is used alone.
    """
    if not model:
        return None
    body = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}
    ).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 — scheme validated by the caller
        base_url.rstrip("/") + "/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": HTTP_USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            raw = resp.headers.get("x-ratelimit-limit-tokens")
    except urllib.error.HTTPError as exc:
        # The 413/429 responses carry the same headers, and reading the limit off a refusal is
        # just as valid as reading it off a success.
        raw = exc.headers.get("x-ratelimit-limit-tokens") if exc.headers else None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None
    try:
        limit = int(str(raw))
    except (TypeError, ValueError):
        return None
    return limit if limit > 0 else None


def _effective_allowance(
    base_url: str | None, api_key_encrypted: bytes | None, model: str | None
) -> int | None:
    """How many tokens ONE request to this endpoint may actually use, or None if unknown.

    The minimum of what the model can hold and what the plan permits, both read from the provider
    rather than assumed. Those two numbers are not close: gpt-oss-120b advertises a 131,072-token
    context while Groq's free tier caps a single request at 8,000 tokens/minute and answers 413
    above it. Trusting the context window alone sent 38,840-token requests at an 8,000 limit —
    refused outright, no generation attempted, every such finding scored as a rejection.

    Best-effort: an unreachable provider returns None and generation falls back to
    `MigrateConfig.llm_context_tokens`.
    """
    if not base_url or not api_key_encrypted or not model:
        return None
    with contextlib.suppress(Exception):
        key = secrets_at_rest.decrypt(api_key_encrypted)
        limits = [
            v
            for v in (
                _model_context_window(base_url, key, model),
                _request_token_limit(base_url, key, model),
            )
            if v
        ]
        if limits:
            return min(limits)
    # The provider told us nothing -- measured, Google's OpenAI-compatible endpoint returns neither
    # `context_window` in `/models` nor an `x-ratelimit-limit-tokens` header. Returning None here
    # would fall through to `MigrateConfig.llm_context_tokens`, which is the LOCAL 7B model's
    # 8,192-token window: a number with nothing to do with this provider, and one that would route
    # most real files to guided advice on an endpoint offering a million tokens a minute.
    #
    # `_EXTERNAL_DEFAULT_TOKENS` is a deliberate, documented assumption rather than a measurement,
    # and it is self-correcting in the safe direction: if it is too high the provider answers 413
    # or 429, which now carry messages naming the real limit and telling the user to re-verify.
    return _EXTERNAL_DEFAULT_TOKENS


def _to_config_out(config: LlmProviderConfig) -> LlmProviderConfigOut:
    return LlmProviderConfigOut(
        provider=config.provider,  # type: ignore[arg-type]
        base_url=config.base_url,
        model=config.model,
        api_key_configured=config.api_key_encrypted is not None,
        api_key_last4=config.api_key_last4,
        context_tokens=config.context_tokens,
        backup_base_url=config.backup_base_url,
        backup_model=config.backup_model,
        backup_api_key_configured=config.backup_api_key_encrypted is not None,
        backup_api_key_last4=config.backup_api_key_last4,
        backup_context_tokens=config.backup_context_tokens,
        updated_at=config.updated_at,
    )


@router.get("/config", response_model=LlmProviderConfigOut)
def get_config(session: Annotated[Session, Depends(get_session)]) -> LlmProviderConfigOut:
    return _to_config_out(_get_or_create_config(session))


@router.patch("/config", response_model=LlmProviderConfigOut)
def patch_config(
    payload: LlmProviderConfigPatch, session: Annotated[Session, Depends(get_session)]
) -> LlmProviderConfigOut:
    config = _get_or_create_config(session)
    # What the endpoints looked like BEFORE this patch. Re-probing a provider costs up to four
    # network round trips (a catalogue read and a one-token completion, per endpoint), so it is
    # worth doing only when the thing being probed actually changed. Measured: a request that only
    # flips `provider` back to "ollama" was spending ~20s re-asking two unchanged endpoints for
    # limits it already had.
    before = (
        config.base_url,
        config.model,
        config.api_key_encrypted,
        config.backup_base_url,
        config.backup_model,
        config.backup_api_key_encrypted,
    )
    if payload.provider is not None:
        config.provider = payload.provider
    if payload.base_url is not None:
        config.base_url = payload.base_url
    if payload.model is not None:
        config.model = payload.model
    if payload.api_key is not None:
        # Empty string is how a client clears a previously-saved key; a non-empty one replaces it.
        # Either way the plaintext never gets stored -- only its encryption and its last 4 chars.
        if payload.api_key == "":
            config.api_key_encrypted = None
            config.api_key_last4 = None
        else:
            config.api_key_encrypted = secrets_at_rest.encrypt(payload.api_key)
            config.api_key_last4 = payload.api_key[-4:]
    if payload.backup_base_url is not None:
        config.backup_base_url = payload.backup_base_url
    if payload.backup_model is not None:
        config.backup_model = payload.backup_model
    if payload.backup_api_key is not None:
        if payload.backup_api_key == "":
            config.backup_api_key_encrypted = None
            config.backup_api_key_last4 = None
        else:
            config.backup_api_key_encrypted = secrets_at_rest.encrypt(payload.backup_api_key)
            config.backup_api_key_last4 = payload.backup_api_key[-4:]

    # Record the EFFECTIVE per-request token allowance for the selected model. This decides whether
    # a large file gets a genuine rewrite attempt or is routed to guided advice
    # (`_llm_detour_reason`), so leaving it at the local 7B model's 8,192 while an external model
    # offers more would keep sending files to advice the configured model could handle.
    #
    # "Effective" is the load-bearing word, and getting it wrong cost a whole measurement run.
    # The model's advertised CONTEXT WINDOW is not what a request may actually use: gpt-oss-120b
    # reports 131,072, while Groq's free tier caps one request at 8,000 tokens per minute and
    # answers 413 above it. Trusting the context window sent 38,840-token requests at an 8,000
    # limit — refused outright, no generation even attempted, and every such finding scored as a
    # rejection. So the allowance is the MINIMUM of what the model can hold and what the plan
    # permits, both read from the provider itself rather than assumed.
    #
    # Best-effort: a provider that cannot be reached leaves it NULL and the caller falls back to
    # `MigrateConfig.llm_context_tokens`.
    after = (
        config.base_url,
        config.model,
        config.api_key_encrypted,
        config.backup_base_url,
        config.backup_model,
        config.backup_api_key_encrypted,
    )
    if before[:3] != after[:3] or config.context_tokens is None:
        config.context_tokens = _effective_allowance(
            config.base_url, config.api_key_encrypted, config.model
        )
    if before[3:] != after[3:] or config.backup_context_tokens is None:
        config.backup_context_tokens = _effective_allowance(
            config.backup_base_url, config.backup_api_key_encrypted, config.backup_model
        )

    # Retried, not a bare commit. SQLite allows one writer at a time, and a migration generating in
    # the background holds the write lock in bursts -- measured, this endpoint answered HTTP 500
    # after 23.7s (`PRAGMA busy_timeout` is 20s) while a generation was in flight, and the same
    # request succeeded in-process with nothing else running. Saving Settings must not fail because
    # a migration happens to be running; see `commit_with_retry`'s own docstring for the earlier
    # instance of exactly this race.
    commit_with_retry(session)
    session.refresh(config)
    return _to_config_out(config)


def _verify_openai_compatible(
    base_url: str, api_key: str, model: str | None = None
) -> LlmProviderVerifyResult:
    """One minimal real completion -- the only thing that proves the endpoint can GENERATE.

    An earlier version used `GET /models`, reasoning that a catalogue read is cheaper than a
    completion against a free tier's daily quota. Measured, that verified the wrong thing: a real
    Cerebras key answers `GET /models` with 200 and a full catalogue, then answers
    `/chat/completions` with 402 "Payment required to access this resource". Verify reported OK and
    every migration then failed. `max_tokens: 1` keeps the cost of being correct to one token.
    """
    if not base_url.startswith(("http://", "https://")):
        return LlmProviderVerifyResult(ok=False, detail=f"Invalid base URL scheme: {base_url}")
    if not model:
        return LlmProviderVerifyResult(ok=False, detail="a model must be selected before verifying")
    body = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}
    ).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 — scheme validated above
        base_url.rstrip("/") + "/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": HTTP_USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return LlmProviderVerifyResult(
                ok=False, detail=f"the API key was rejected (HTTP {exc.code})"
            )
        if exc.code == 402:
            return LlmProviderVerifyResult(
                ok=False,
                detail="the key is valid but the account has no available quota (HTTP 402) — "
                "the free allowance is exhausted, or billing must be enabled",
            )
        if exc.code == 404:
            return LlmProviderVerifyResult(
                ok=False, detail=f"the provider does not offer a model called {model!r} (HTTP 404)"
            )
        return LlmProviderVerifyResult(ok=False, detail=f"HTTP {exc.code}: {exc.reason}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return LlmProviderVerifyResult(ok=False, detail=f"not reachable at {base_url}: {exc}")
    return LlmProviderVerifyResult(ok=True, detail=f"{model} reachable at {base_url}")


def _engine_out(row: LlmEngine) -> LlmEngineOut:
    return LlmEngineOut(
        id=row.id,
        label=row.label,
        base_url=row.base_url,
        model=row.model,
        api_key_last4=row.api_key_last4,
        context_tokens=row.context_tokens,
        enabled=row.enabled,
    )


@router.get("/engines", response_model=list[LlmEngineOut])
def list_engines(session: Annotated[Session, Depends(get_session)]) -> list[LlmEngineOut]:
    """Every engine in the pool.

    The pool exists because a hosted free tier is rationed per PROJECT, so capacity comes from
    attaching MORE INDEPENDENT TIERS rather than from a better model -- and the two slots on
    `llm_provider_config` meant a third key had nowhere to go.
    """
    rows = session.scalars(select(LlmEngine).order_by(LlmEngine.created_at)).all()
    return [_engine_out(r) for r in rows]


@router.post("/engines", response_model=LlmEngineOut, status_code=status.HTTP_201_CREATED)
def add_engine(
    body: LlmEngineIn, session: Annotated[Session, Depends(get_session)]
) -> LlmEngineOut:
    """Attach an engine. The key is encrypted at rest and never returned."""
    row = LlmEngine(
        label=body.label,
        base_url=body.base_url.rstrip("/"),
        model=body.model,
        api_key_encrypted=secrets_at_rest.encrypt(body.api_key),
        api_key_last4=body.api_key[-4:],
        context_tokens=body.context_tokens,
        enabled=body.enabled,
    )
    session.add(row)
    commit_with_retry(session, row)
    logger.info("attached pooled engine %s (%s)", row.label, row.model)
    return _engine_out(row)


@router.patch("/engines/{engine_id}", response_model=LlmEngineOut)
def update_engine(
    engine_id: UUID, body: LlmEnginePatch, session: Annotated[Session, Depends(get_session)]
) -> LlmEngineOut:
    row = session.get(LlmEngine, engine_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such engine")
    for field in ("label", "context_tokens", "enabled"):
        value = getattr(body, field)
        if value is not None:
            setattr(row, field, value)
    session.commit()
    return _engine_out(row)


@router.delete("/engines/{engine_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_engine(engine_id: UUID, session: Annotated[Session, Depends(get_session)]) -> None:
    row = session.get(LlmEngine, engine_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such engine")
    session.delete(row)
    session.commit()


@router.get("/budget")
def get_rate_budget() -> dict[str, Any]:
    """How much of the attached provider's rate limit is left, as the provider last reported it.

    A hosted free tier is rationed far more tightly in REQUESTS than in tokens -- measured against
    Groq from this installation: 1,000 requests/day and 8,000 tokens/minute, and one patch can cost
    up to fourteen requests. Every response carries the remaining figures; until now QUBIT read
    only `x-ratelimit-limit-tokens`, once, to size a single request, and so discovered exhaustion
    by being refused.

    Empty until a request has actually been made, and empty forever for a provider that does not
    send these headers -- Google's OpenAI-compatible endpoint sends none of them. Empty means
    "unknown", never "exhausted", and must not be rendered as a depleted bar.
    """
    return {"engines": rate_budget()}


@router.get("/models", response_model=LlmProviderModelsOut)
def list_models(session: Annotated[Session, Depends(get_session)]) -> LlmProviderModelsOut:
    """The models the configured provider actually offers, read live from it.

    For Ollama that is `/api/tags` (what is pulled locally); for an external provider it is the
    OpenAI-compatible `/models`. Never a hardcoded list -- see `LlmProviderModelsOut`'s docstring.
    """
    config = _get_or_create_config(session)
    if config.provider != "openai-compatible":
        # DEFAULT_BASE_URL, never `config.base_url`: that column holds the EXTERNAL endpoint and is
        # deliberately kept when a user switches back to Local, so their settings survive the round
        # trip. Reading it here made QUBIT probe the external URL as though it were an Ollama
        # server -- measured live: provider=ollama with a leftover Groq base_url reported "Ollama
        # not reachable at https://api.groq.com/openai/v1" while Ollama was running perfectly well
        # on localhost, and returned an empty model list.
        return LlmProviderModelsOut(models=installed_models(DEFAULT_BASE_URL))

    if not config.base_url or not config.api_key_encrypted:
        return LlmProviderModelsOut(
            models=[], error="save a base URL and API key first, then the model list can be read"
        )
    api_key = secrets_at_rest.decrypt(config.api_key_encrypted)
    try:
        rows = _fetch_model_rows(config.base_url, api_key)
    except urllib.error.HTTPError as exc:
        return LlmProviderModelsOut(models=[], error=f"HTTP {exc.code}: {exc.reason}")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        return LlmProviderModelsOut(models=[], error=f"could not read the model list: {exc}")
    # Text-generating models only. A provider's catalogue mixes in speech, transcription and
    # safety-classifier models (Groq lists Whisper, Orpheus and Prompt Guard alongside the coders)
    # and offering those as a patch-generation engine would be offering a choice that cannot work.
    ids = [str(r["id"]) for r in rows if r.get("id") and _is_text_model(r)]
    return LlmProviderModelsOut(models=sorted(ids))


@router.post("/verify", response_model=LlmProviderVerifyResult)
def verify(session: Annotated[Session, Depends(get_session)]) -> LlmProviderVerifyResult:
    """Make one real, cheap call against the currently-saved config and report reachability.

    Never accepts a key in the request body -- always verifies whatever is already saved, so a
    partially-typed key can never leak into a log line or an error message via this endpoint.
    """
    config = _get_or_create_config(session)
    if config.provider == "openai-compatible":
        if not config.base_url or not config.api_key_encrypted:
            return LlmProviderVerifyResult(
                ok=False, detail="base URL and API key must both be saved before verifying"
            )
        api_key = secrets_at_rest.decrypt(config.api_key_encrypted)
        primary = _verify_openai_compatible(config.base_url, api_key, config.model)
        # Report the WHOLE chain, not just the primary: the backup exists precisely because the
        # primary will refuse requests (token allowance, daily cap), so "is the backup actually
        # reachable" is the question worth answering before that happens rather than after.
        if not config.backup_api_key_encrypted or not config.backup_base_url:
            return primary
        backup_key = secrets_at_rest.decrypt(config.backup_api_key_encrypted)
        backup = _verify_openai_compatible(config.backup_base_url, backup_key, config.backup_model)
        allowance = (
            f" — allowance {config.context_tokens:,} tokens/request"
            if config.context_tokens
            else ""
        )
        backup_allowance = (
            f" ({config.backup_context_tokens:,} tokens/request)"
            if config.backup_context_tokens
            else ""
        )
        return LlmProviderVerifyResult(
            # Either endpoint working is a usable chain; both failing is not.
            ok=primary.ok or backup.ok,
            detail=(
                f"primary {'OK' if primary.ok else 'FAILED: ' + primary.detail}{allowance}; "
                f"backup {'OK' if backup.ok else 'FAILED: ' + backup.detail}{backup_allowance}"
            ),
        )

    # DEFAULT_BASE_URL, never `config.base_url` -- see `list_models` for the measured failure that
    # reading the external endpoint here produced.
    base_url = DEFAULT_BASE_URL
    available = installed_models(base_url)
    if not available:
        return LlmProviderVerifyResult(ok=False, detail=f"Ollama not reachable at {base_url}")
    # The model generation will ACTUALLY use on this path, which is `MigrateConfig.model` (the
    # env-configured local model) -- not `LlmProviderConfig.model`, which names the EXTERNAL
    # model and is kept across a switch back to Local. Checking the latter made verify report
    # "Ollama is reachable, but 'openai/gpt-oss-120b' is not pulled" for a perfectly healthy local
    # setup, naming a model Ollama was never going to be asked for.
    wanted = MigrateConfig().model
    if wanted and wanted not in available:
        return LlmProviderVerifyResult(
            ok=False,
            detail=f"Ollama is reachable, but {wanted!r} is not pulled. "
            f"Installed: {', '.join(sorted(available))}",
        )
    return LlmProviderVerifyResult(ok=True, detail=f"reachable at {base_url}")
