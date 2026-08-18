"""Print the first TCP port on 127.0.0.1 that this machine will actually let us bind.

Used by `qubit-desktop.bat` / `qubit-desktop.sh` instead of hardcoding 8787.

Why this exists: a port being free is not the same as a port being bindable on Windows. Hyper-V, WSL
and Docker Desktop reserve whole blocks of ports, and a bind inside one of those blocks fails with
WinError 10013 ("an attempt was made to access a socket in a way forbidden by its access
permissions") even though nothing is listening and `netstat` shows the port idle. On the development
machine `netsh int ipv4 show excludedportrange protocol=tcp` reported 8695-8794 reserved, which
contains 8787 — so the desktop launcher's hardcoded port could not be bound at all and the app died
at startup with no obvious cause.

Probing with an actual bind is the only reliable test, because it is the same operation uvicorn will
perform. The candidate list keeps the familiar port first so nothing changes on machines where it
works; 0 is the final fallback, which asks the OS for any free port and therefore always succeeds.
"""

from __future__ import annotations

import socket
import sys

# 8787 first (the documented default), then a few memorable alternatives, then "anything".
CANDIDATES: tuple[int, ...] = (8787, 8080, 8099, 9797, 17870, 0)


def bindable(port: int) -> int | None:
    """Return the port actually bound, or None if this machine refuses it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # No SO_REUSEADDR: we want to know whether uvicorn can take the port exclusively, and on
        # Windows SO_REUSEADDR would let this bind succeed where uvicorn's would still fail.
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return None
        return int(sock.getsockname()[1])


def main() -> int:
    for candidate in CANDIDATES:
        bound = bindable(candidate)
        if bound is not None:
            print(bound)
            return 0
    # Unreachable in practice: port 0 asks the OS to choose and only fails if networking is broken.
    print("no bindable port found on 127.0.0.1", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
