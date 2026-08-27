"""`_ollama_generate` must return in bounded wall-clock time, even if the connection itself never
reports a timeout.

Defends against a property of `urllib.request.urlopen(timeout=N)`: it bounds each
INDIVIDUAL socket read, not the call as a whole. If the peer keeps the connection open and sends
anything at all before the deadline (a keep-alive byte, a partial chunk), the clock resets and the
read can block again. A local model wedged on the GPU is exactly the situation where a connection
stays open without ever completing. (What first looked like a live five-hour instance of this
turned out, on closer check, to be a UTC-vs-local timestamp misread on my part over a run that had
actually finished in 513s — the property below is real and worth guarding regardless.)

Two more bugs were found fixing this one, each caught by running the fix rather than trusting it:

* A first version wrapped the call in `with ThreadPoolExecutor(...) as pool:`. `Executor.__exit__`
  calls `shutdown(wait=True)` UNCONDITIONALLY, including when the block is exited by an exception
  — so raising past it blocked on the exact call the fix exists to stop blocking on. Caught by a
  test that actually waited on the wall clock instead of asserting an exception type.
* A second version used `pool.shutdown(wait=False)` in a `finally`, which does make the FUNCTION
  return promptly — but `ThreadPoolExecutor` registers its worker threads with an `atexit` hook
  that joins every one of them before the interpreter may exit, wedged or not. A one-shot test
  script making a single abandoned call was itself unkillable past an external `timeout` wrapper.
  Caught the same way: running it, not reading it. The fix is a raw `threading.Thread(daemon=True)`,
  which is invisible to that hook by design.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest
from qubit_migrate.transform import llm


def test_a_normal_fast_call_is_unaffected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(llm, "_ollama_generate_once", lambda *a, **k: "the answer")

    started = time.time()
    result = llm._ollama_generate("prompt", model="x", timeout=5)

    assert result == "the answer"
    assert time.time() - started < 1, "the watchdog must add no overhead on the common path"


def test_a_real_exception_from_the_inner_call_is_relayed_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: object, **_k: object) -> str:
        raise llm.OllamaError("a specific, real reason")

    monkeypatch.setattr(llm, "_ollama_generate_once", boom)

    with pytest.raises(llm.OllamaError, match="a specific, real reason"):
        llm._ollama_generate("prompt", model="x", timeout=5)


def test_a_call_that_never_returns_is_bounded_and_named(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact shape of the live incident: the inner call never raises AND never returns."""

    def never_returns(*_a: object, **_k: object) -> str:
        time.sleep(3600)
        return "far too late to matter"

    monkeypatch.setattr(llm, "_ollama_generate_once", never_returns)

    started = time.time()
    with pytest.raises(llm.OllamaError, match="did not answer within"):
        llm._ollama_generate("prompt", model="x", timeout=1)
    elapsed = time.time() - started

    # Bounded near `timeout + 15` (the wrapper's grace margin), not anywhere near 3600s.
    assert elapsed < 30, f"the watchdog let a call run for {elapsed:.0f}s — the bound is not real"


def test_the_abandoned_thread_does_not_keep_the_process_alive() -> None:
    """The regression the first two fix attempts each hit: the FUNCTION returning is not enough
    if the interpreter still cannot exit afterward, because a real production job runner will,
    at some point, need this process to shut down.

    Run out-of-process with a hard OS-level deadline: if the fix regresses to a non-daemon thread
    (a bare `ThreadPoolExecutor`, or a thread not marked `daemon=True`), this test times out
    itself rather than reporting a clean failure — which is exactly the failure mode being
    guarded against, so an unambiguous test error is the right outcome either way.
    """
    script = (
        "import sys, time\n"
        "sys.path.insert(0, 'packages/qubit-migrate/src')\n"
        "import qubit_migrate.transform.llm as llm\n"
        "llm._ollama_generate_once = lambda *a, **k: (time.sleep(3600), 'late')[1]\n"
        "try:\n"
        "    llm._ollama_generate('p', model='x', timeout=1)\n"
        "except llm.OllamaError:\n"
        "    pass\n"
        "print('WRAPPER RETURNED', flush=True)\n"
    )

    started = time.time()
    proc = subprocess.run(
        [sys.executable, "-u", "-c", script],
        capture_output=True,
        text=True,
        timeout=40,  # generous: 1s timeout + 15s grace, plus process startup
    )
    elapsed = time.time() - started

    assert "WRAPPER RETURNED" in proc.stdout, proc.stdout + proc.stderr
    assert elapsed < 35, (
        f"the child process took {elapsed:.0f}s to exit — an abandoned worker thread is still "
        "blocking interpreter shutdown"
    )
