"""The rate-limit budget must survive a process restart, and a persisted record must not disable
an engine forever.

`_BUDGETS` used to be purely process-local, which was correct for a token window (resets in
seconds) and wrong for the request window a free tier actually rations by: Groq's own
`x-ratelimit-reset-requests` reads `7h32m14.4s` once the DAILY quota is spent. An unattended
campaign restarts the whole process between repositories (`scripts/run_all_pooled.ps1`), so an
engine exhausted on repository 1 looked completely fresh on repository 2 -- the scheduler routed to
it again, it answered 429 again, and the flat 90s cooldown (`_COOLDOWN_SECONDS`) meant the campaign
re-tested a dead engine roughly every 90 seconds for the rest of the day.

These tests cover the three pieces that close that gap: the budget is written beside the database
(`llm._budget_store_path`, honouring `QUBIT_DB_URL` the same way `default_db_url` does) and reread
lazily; a persisted record expires once the reset it itself reported has passed
(`RateBudget.stale`); and a 429 that names its own reset scales the cooldown, or retires the engine
outright for a daily-length one, instead of a flat 90s regardless of what the provider said.
"""

from __future__ import annotations

import io
import json
import logging
import time
import urllib.error
from email.message import Message

import pytest
from qubit_migrate.transform import llm
from qubit_migrate.transform.llm import OllamaError, RateBudget

GROQ_HEADERS = {
    # Exactly the shape observed on a live call.
    "x-ratelimit-limit-requests": "1000",
    "x-ratelimit-remaining-requests": "999",
    "x-ratelimit-limit-tokens": "8000",
    "x-ratelimit-remaining-tokens": "3826",
    "x-ratelimit-reset-requests": "1m26.4s",
    "x-ratelimit-reset-tokens": "31.305s",
}


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """Every test gets its own on-disk location (never the real user-data dir) and starts from
    the same process-local state a freshly started app would have.
    """
    monkeypatch.setenv("QUBIT_DB_URL", f"sqlite:///{(tmp_path / 'qubit.db').as_posix()}")
    llm._BUDGETS.clear()
    llm._BUDGETS_LOADED = False
    llm._ENGINE_COOLDOWN.clear()
    llm._ENGINE_REFUSED.clear()
    yield
    llm._BUDGETS.clear()
    llm._BUDGETS_LOADED = False
    llm._ENGINE_COOLDOWN.clear()
    llm._ENGINE_REFUSED.clear()


def _restart() -> None:
    """Simulate the process boundary: wipe every process-local structure, leave the file alone."""
    llm._BUDGETS.clear()
    llm._BUDGETS_LOADED = False


# --- Storage location -----------------------------------------------------------------------


def test_the_store_path_sits_beside_the_database_named_by_qubit_db_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    target = tmp_path / "arm-a" / "isolated.db"
    monkeypatch.setenv("QUBIT_DB_URL", f"sqlite:///{target.as_posix()}")

    path = llm._budget_store_path()

    assert path is not None
    assert path.parent == target.parent
    assert path.name == "llm_rate_budgets.json"


def test_the_store_path_falls_back_to_the_user_data_dir_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("QUBIT_DB_URL", raising=False)

    path = llm._budget_store_path()

    assert path is not None
    assert path.name == "llm_rate_budgets.json"
    assert "qubit" in str(path.parent).lower()


def test_a_non_sqlite_db_url_disables_persistence_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Postgres URL names no on-disk sibling. Persistence is skipped, not faked, and recording
    a budget must still work in-memory for the rest of the process."""
    monkeypatch.setenv("QUBIT_DB_URL", "postgresql://user:pass@localhost/qubit")

    assert llm._budget_store_path() is None

    llm._record_budget("groq::x", GROQ_HEADERS)

    assert llm.rate_budget("groq::x")["remaining_requests"] == 999


# --- Requirement: a budget survives a simulated restart --------------------------------------


def test_a_budget_survives_a_simulated_restart() -> None:
    llm._record_budget("groq::gpt-oss-120b", GROQ_HEADERS)
    assert llm.rate_budget("groq::gpt-oss-120b")["remaining_requests"] == 999

    _restart()

    # Nothing in this process has called the engine yet, but the file from "the previous process"
    # is still on disk -- exactly the scenario `scripts/run_all_pooled.ps1` creates between repos.
    budget = llm.rate_budget("groq::gpt-oss-120b")
    assert budget["remaining_requests"] == 999
    assert budget["reset_requests"] == "1m26.4s"


def test_every_engine_survives_the_restart_not_just_the_last_one_recorded() -> None:
    """`_record_budget` must not clobber other engines' history when it saves its own update."""
    llm._record_budget("groq::a", GROQ_HEADERS)
    llm._record_budget("groq::b", {**GROQ_HEADERS, "x-ratelimit-remaining-requests": "12"})

    _restart()

    everything = llm.rate_budget()
    assert everything["groq::a"]["remaining_requests"] == 999
    assert everything["groq::b"]["remaining_requests"] == 12


# --- Requirement: a stale (past-reset) budget is ignored --------------------------------------


def test_a_persisted_stale_budget_is_ignored_after_a_simulated_restart() -> None:
    """A `remaining_requests: 0` observed an hour ago, with a 5-second reset window, has long
    since reopened -- it must read as unknown on restart, never as still exhausted.
    """
    llm._BUDGETS["groq::short-lived"] = RateBudget(
        engine="groq::short-lived",
        remaining_requests=0,
        reset_requests="5s",
        observed_at=time.time() - 3600,
    )
    llm._save_budgets()

    _restart()

    assert llm.rate_budget("groq::short-lived") == {}
    assert "groq::short-lived" not in llm.rate_budget()


def test_a_fresh_persisted_budget_is_still_honoured_after_a_restart() -> None:
    """The control for the test above: without staleness filtering AND without it being applied
    selectively, this would also fail -- proving the filter checks the reset, not just clearing
    everything on load.
    """
    llm._BUDGETS["groq::just-observed"] = RateBudget(
        engine="groq::just-observed",
        remaining_requests=0,
        reset_requests="6h",
        observed_at=time.time(),
    )
    llm._save_budgets()

    _restart()

    budget = llm.rate_budget("groq::just-observed")
    assert budget["remaining_requests"] == 0, "a genuinely current exhaustion must still show"


# --- Requirement: a corrupt file degrades to empty, never raises ------------------------------


def test_invalid_json_does_not_raise() -> None:
    path = llm._budget_store_path()
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not valid json at all", encoding="utf-8")

    assert llm.rate_budget() == {}
    assert llm.rate_budget("anything") == {}


def test_valid_json_of_the_wrong_shape_does_not_raise() -> None:
    path = llm._budget_store_path()
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)

    # A JSON array where a dict of engines was expected.
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    assert llm.rate_budget() == {}

    _restart()

    # A dict whose per-engine value is not itself a dict.
    path.write_text(json.dumps({"groq::x": "not-a-record"}), encoding="utf-8")
    assert llm.rate_budget() == {}


def test_a_corrupt_file_does_not_stop_a_later_write_from_healing_it() -> None:
    """A malformed file must not become a permanent trap -- the next real observation should
    overwrite it with something valid."""
    path = llm._budget_store_path()
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json", encoding="utf-8")

    llm._record_budget("groq::healed", GROQ_HEADERS)

    _restart()

    assert llm.rate_budget("groq::healed")["remaining_requests"] == 999


# --- Requirement: a 429's own reset hint drives the cooldown, not a flat 90s ------------------


def _headers(fields: dict[str, str]) -> Message:
    """An `email.message.Message`, the type `urllib`'s real response headers actually are --
    matching that shape (rather than a plain dict) is what lets `HTTPError.headers` be used the
    same way in a test as it is on a live response."""
    msg = Message()
    for key, value in fields.items():
        msg[key] = value
    return msg


def _raise_429(fields: dict[str, str]):
    def fake_urlopen(req, timeout: float):
        raise urllib.error.HTTPError(
            req.full_url, 429, "Too Many Requests", _headers(fields), io.BytesIO(b"")
        )

    return fake_urlopen


def test_a_short_reset_hint_keeps_the_flat_cooldown_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """`7.66s` is shorter than `_COOLDOWN_SECONDS` -- it must not SHRINK the cooldown below the
    floor already calibrated for ordinary congestion."""
    monkeypatch.setattr(
        "urllib.request.urlopen", _raise_429({"x-ratelimit-reset-requests": "7.66s"})
    )

    with pytest.raises(OllamaError, match="rate-limited"):
        llm._openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
        )

    key = "https://api.example.com/v1::m"
    assert key not in llm._ENGINE_REFUSED
    remaining = llm._ENGINE_COOLDOWN[key] - time.monotonic()
    assert 80 <= remaining <= 95, f"expected ~{llm._COOLDOWN_SECONDS}s, got {remaining:.1f}s"


def test_a_reset_hint_longer_than_the_flat_cooldown_scales_the_wait_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`2m59.56s` (measured on a real Groq token window) is longer than the flat 90s default and
    shorter than the daily-quota threshold -- it must set a proportionally longer cooldown, not
    the flat one and not a retirement."""
    monkeypatch.setattr(
        "urllib.request.urlopen", _raise_429({"x-ratelimit-reset-requests": "2m59.56s"})
    )

    with pytest.raises(OllamaError, match="rate-limited"):
        llm._openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
        )

    key = "https://api.example.com/v1::m"
    assert key not in llm._ENGINE_REFUSED, "a 3-minute window is not a daily quota"
    remaining = llm._ENGINE_COOLDOWN[key] - time.monotonic()
    assert remaining > 150, f"a 2m59.56s hint must produce a long cooldown, got {remaining:.1f}s"


def test_an_hours_long_reset_retires_the_engine_with_an_honest_reason(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Measured on a real account: an exhausted DAILY quota reports `7h32m14.4s`. That is not a
    moment of congestion, so the engine is retired for the session (like a rejected key) -- but
    the log must say WHY, and must not read as the same finding as a rejected key.
    """
    monkeypatch.setattr(
        "urllib.request.urlopen", _raise_429({"x-ratelimit-reset-requests": "7h32m14.4s"})
    )

    with caplog.at_level(logging.WARNING):
        with pytest.raises(OllamaError, match="rate-limited"):
            llm._openai_compatible_generate(
                "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
            )

    key = "https://api.example.com/v1::m"
    assert key in llm._ENGINE_REFUSED, "an hours-long reset must retire the engine for the session"

    retirement_lines = [line for line in caplog.text.splitlines() if "retiring" in line]
    assert retirement_lines, f"expected a retirement log line, got: {caplog.text!r}"
    joined = " ".join(retirement_lines).lower()
    assert "quota" in joined
    assert "rejected the api key" not in joined, (
        "quota exhaustion must not be conflated with a rejected key in the log"
    )


def test_a_429_records_the_budget_from_its_own_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 429 response often carries the same remaining/limit headers a 200 would -- reading them
    here is what lets the NEXT process see this engine as exhausted from its first call, via
    `_load_budgets`, instead of paying a request to rediscover it."""
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _raise_429({"x-ratelimit-remaining-requests": "0", "x-ratelimit-reset-requests": "45s"}),
    )

    with pytest.raises(OllamaError, match="rate-limited"):
        llm._openai_compatible_generate(
            "prompt", model="m", base_url="https://api.example.com/v1", api_key="k"
        )

    budget = llm.rate_budget("https://api.example.com/v1::m")
    assert budget["remaining_requests"] == 0
    assert budget["reported"] is True
