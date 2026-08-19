"""Print the first TCP port on 127.0.0.1 that this machine will actually let us bind.

Used by `qubit-desktop.bat`; the Tauri shell has the same logic in Rust (`src-tauri/src/main.rs`).

Why this exists: a port being free is not the same as a port being bindable on Windows. Hyper-V, WSL
and Docker Desktop reserve whole blocks of ports, and a bind inside one of those blocks fails with
WinError 10013 ("an attempt was made to access a socket in a way forbidden by its access
permissions") even though nothing is listening and `netstat` shows the port idle. On this project's
development machine `netsh int ipv4 show excludedportrange protocol=tcp` reported 8695-8794
reserved, which contains QUBIT's default 8787 — so the desktop launcher could not bind its own port
and died at startup with no obvious cause. Those ranges are assigned dynamically and move when
Hyper-V or Docker restarts (they were gone again a few hours later), so this cannot be solved by
picking a different constant.

Two checks, as defence in depth: a candidate is accepted only if nothing answers a connect AND an
exclusive bind succeeds. The bind alone can be insufficient on Windows, where a second socket may
join a port another process is already listening on depending on the options that first socket set
(SO_REUSEADDR / SO_EXCLUSIVEADDRUSE); a connect probe answers the question the bind cannot, namely
whether anything is actually serving there. On provenance: the connect check was added after I
misread a process tree and believed a bind-only probe had chosen an occupied port. It had not — the
"orphan" was the venv `uvicorn.exe` stub's own python child. It stays because it is cheap and
strictly more correct, not because it fixed a bug that existed.
"""

from __future__ import annotations

import contextlib
import socket
import sys

# 8787 first (the documented default), then memorable alternatives, then "anything the OS gives".
CANDIDATES: tuple[int, ...] = (8787, 8080, 8099, 9797, 17870, 0)

_CONNECT_TIMEOUT = 0.35


def in_use(port: int) -> bool:
    """True if something already accepts connections on this port.

    Catches the case a bind test misses on Windows: an existing listener that did not claim the port
    exclusively, which a second bind is allowed to join.
    """
    if port == 0:
        return False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(_CONNECT_TIMEOUT)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def bindable(port: int) -> int | None:
    """Return the port actually bound, or None if this machine refuses it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Claim the port exclusively where the platform supports it, so this bind fails in exactly
        # the cases uvicorn's would. Deliberately NOT SO_REUSEADDR, which would do the opposite.
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            # Not fatal if unsupported — the connect check above is the primary defence.
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return None
        return int(sock.getsockname()[1])


def main() -> int:
    for candidate in CANDIDATES:
        if in_use(candidate):
            continue
        bound = bindable(candidate)
        if bound is not None:
            print(bound)
            return 0
    # Unreachable in practice: port 0 asks the OS to choose and only fails if networking is broken.
    print("no bindable port found on 127.0.0.1", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
