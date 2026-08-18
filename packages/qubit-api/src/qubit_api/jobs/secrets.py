"""Process-local, single-use handoff for a job's secret input.

A Vault scan needs a token with read access to the transit and PKI mounts. Job inputs normally
travel in `Job.payload`, which is a JSON column — so putting the token there would write a live
credential to the database, where it would sit in the scan history indefinitely, be returned by
`GET /jobs/{id}`, and land in every backup of the file. For a tool whose entire purpose is finding
credentials that people left lying around, that would be indefensible.

So the token never enters the payload. The route deposits it here, keyed by job id; the handler pops
it exactly once, in the same process. The consequences of that design are deliberate and worth
stating plainly:

* **It does not survive a restart.** A Vault job interrupted by a server restart cannot be resumed —
  the runner's crash recovery marks it failed and the user re-enters the token. That is the correct
  trade: a resumable job would require the secret to be persisted, which is the thing being avoided.
* **It does not work across processes.** Multiple uvicorn workers would each have their own store,
  so a job submitted to one worker must run in that worker. This holds today because the job runner
  is in-process by design (`app.state.job_runner`), and QUBIT ships as a single-process desktop app.
  If the runner ever moves to a separate process or a queue, this needs a real secret broker, not a
  wider dictionary — hence the explicit note rather than a silent assumption.

Single-use is enforced by `take`, so a leaked job id cannot be replayed to read the token back, and
nothing lingers after the scan completes.
"""

from __future__ import annotations

import threading
from uuid import UUID

_lock = threading.Lock()
_store: dict[UUID, str] = {}


def put(job_id: UUID, secret: str) -> None:
    """Stash a job's secret for the handler that will run it."""
    with _lock:
        _store[job_id] = secret


def take(job_id: UUID) -> str | None:
    """Pop the secret for `job_id`. Returns None if absent — never raises, so a missing secret
    surfaces as the handler's own "needs a token" validation error rather than a KeyError."""
    with _lock:
        return _store.pop(job_id, None)


def discard(job_id: UUID) -> None:
    """Drop a secret without consuming it — used when submitting the job fails."""
    with _lock:
        _store.pop(job_id, None)
