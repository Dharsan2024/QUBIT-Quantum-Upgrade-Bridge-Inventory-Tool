"""Per-client rate limiting for mutating requests.

Scope is deliberately narrow: **mutating verbs only**. A dashboard polling `GET /scans` every
second while a scan runs is normal behaviour and must never be throttled, whereas the expensive
and abusable operations are all writes — `POST /scans` starts a filesystem walk,
`POST /migrate/tasks/{id}/generate` invokes a language model, and
`POST /projects/{id}/scans/network` opens sockets to other hosts.

An in-process fixed-window counter, not a distributed token bucket. That is the honest fit for a
single-process app: it is exact for one worker and it resets on restart. Multiple workers would
each enforce their own window, so the effective limit multiplies by the worker count — stated here
rather than pretended away, because a shared deployment needs a real store (Redis) instead.

Disabled by setting `QUBIT_RATE_LIMIT_PER_MINUTE=0`, which is the right choice for the desktop app
where the only client is the operator's own window.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Verbs that never change state. Kept identical to auth.py's list so the two agree about what a
# "read" is; a mismatch there would be a quiet security-relevant inconsistency.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_WINDOW_SECONDS = 60.0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window limit on mutating requests, keyed by client IP."""

    def __init__(self, app, requests_per_minute: int) -> None:
        super().__init__(app)
        self.limit = requests_per_minute
        self._lock = threading.Lock()
        # client -> (window_start, count)
        self._windows: defaultdict[str, tuple[float, int]] = defaultdict(lambda: (0.0, 0))

    def _client_key(self, request: Request) -> str:
        # `request.client.host` is the peer address. X-Forwarded-For is deliberately NOT trusted: it
        # is caller-controlled, so honouring it without a vetted proxy in front would let anyone
        # bypass the limit by varying a header.
        return request.client.host if request.client else "unknown"

    def _over_limit(self, key: str) -> tuple[bool, int]:
        """Record a hit; return (over_limit, seconds_until_reset)."""
        now = time.monotonic()
        with self._lock:
            window_start, count = self._windows[key]
            if now - window_start >= _WINDOW_SECONDS:
                self._windows[key] = (now, 1)
                return False, int(_WINDOW_SECONDS)
            if count >= self.limit:
                return True, max(1, int(_WINDOW_SECONDS - (now - window_start)))
            self._windows[key] = (window_start, count + 1)
            return False, int(_WINDOW_SECONDS - (now - window_start))

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if self.limit <= 0 or request.method.upper() in _SAFE_METHODS:
            return await call_next(request)

        over, retry_after = self._over_limit(self._client_key(request))
        if over:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        f"Rate limit exceeded: more than {self.limit} mutating "
                        f"requests per minute. Retry in {retry_after}s, or raise "
                        f"QUBIT_RATE_LIMIT_PER_MINUTE."
                    )
                },
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)


__all__ = ["RateLimitMiddleware"]
