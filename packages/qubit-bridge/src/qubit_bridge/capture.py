import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

# Well-known install locations for tshark, checked when it is not on PATH.
#
# Resolving via PATH alone is not enough in practice: the Windows Wireshark installer does not
# reliably add itself to PATH, and even when it does, an ALREADY-RUNNING process keeps the PATH it
# started with — so a freshly installed tshark stays invisible until every shell is restarted. That
# produced a silent downgrade: capture printed a warning, wrote an EMPTY pcap, and the handshake
# diff then had nothing to compare, while the demo still reported success.
_TSHARK_CANDIDATES = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
)


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104 — matching, not binding


def _select_interface(tshark: str, host: str, iface: str) -> str:
    """Resolve a capture interface that actually exists on this platform.

    ``-i any`` is a Linux-only pseudo-interface. On Windows it fails outright —
    ``Error opening adapter: The filename, directory name, or volume label syntax is incorrect
    (123)`` — with exit code 1 and no output file, and on macOS there is no ``any`` either. Because
    the caller never checked the exit code, the demo printed "Saved capture to …" for a file that
    was never created, and the handshake byte-size diff then silently compared two things that did
    not exist.

    The bridge demo captures ``localhost:8443``, and loopback traffic needs the dedicated loopback
    adapter on Windows (Npcap's ``\\Device\\NPF_Loopback``) or ``lo``/``lo0`` elsewhere — a physical
    NIC sees none of it. So the requested host decides the interface rather than a fixed default.
    """
    if iface != "any":
        return iface  # an explicit choice is respected as-is

    want_loopback = host.split("%")[0] in _LOOPBACK_HOSTS
    if sys.platform.startswith("linux"):
        # `any` is real here and already captures loopback.
        return "lo" if want_loopback else "any"

    try:
        listing = subprocess.run(
            [tshark, "-D"], capture_output=True, text=True, timeout=20
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return iface

    devices: list[str] = []
    for line in listing:
        # Lines look like: `10. \Device\NPF_Loopback (Adapter for loopback traffic capture)`
        _, _, rest = line.partition(". ")
        name = (rest.split(" (")[0] or "").strip()
        if name:
            devices.append(name)

    if want_loopback:
        for name in devices:
            lowered = name.lower()
            if "loopback" in lowered or lowered in {"lo", "lo0"}:
                return name
    # Remote host, or no loopback adapter: fall back to the first real device, skipping the remote
    # capture pseudo-extensions (ciscodump/sshdump) which need their own configuration.
    for name in devices:
        if not name.endswith("dump") and "loopback" not in name.lower():
            return name
    return devices[0] if devices else iface


def find_tshark() -> str | None:
    """Absolute path to a usable tshark, or None if it is genuinely not installed.

    ``QUBIT_TSHARK`` overrides everything, for a non-standard install or a wrapper.
    """
    override = os.environ.get("QUBIT_TSHARK")
    if override and Path(override).exists():
        return override
    on_path = shutil.which("tshark")
    if on_path:
        return on_path
    for candidate in _TSHARK_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def capture_handshake(
    host: str,
    port: int,
    out: Path,
    *,
    iface: str = "any",
    handshakes: int = 1,
    timeout: float = 15.0,
    during: Callable[[], None] | None = None,
) -> Path:
    """Capture TLS handshake packets with tshark, optionally triggering the handshake mid-capture.

    ``during`` is the whole point of this function being useful. Without it, callers ran the capture
    to completion and only THEN performed the TLS handshake — so the window contained nothing but
    incidental loopback traffic, and `extract_key_share_sizes` reported zeros for every field. The
    pcaps looked plausible (both 448 bytes, a valid header and a few stray packets) which is exactly
    why it went unnoticed: the harvest demo's entire point is showing the hybrid key_share is ~1.2
    KB larger than the classical one, and it was comparing two empty measurements.

    Passing a callable that performs the handshake runs it INSIDE the capture window, after a short
    delay to let tshark bind the interface.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    tshark = find_tshark()
    if tshark is None:
        print(
            "Warning: tshark not found (install Wireshark, or set QUBIT_TSHARK). "
            "pcap capture is disabled and an EMPTY file is being written, so the handshake "
            "byte-size diff will have nothing to compare."
        )
        out.touch()
        return out

    bpf_filter = f"tcp port {port}"
    resolved_iface = _select_interface(tshark, host, iface)
    cmd = [
        tshark,
        "-i",
        resolved_iface,
        "-f",
        bpf_filter,
        "-w",
        str(out),
        "-a",
        f"duration:{int(timeout)}",
    ]

    # stderr is CAPTURED rather than discarded: tshark reports a bad interface or a missing capture
    # privilege there, and sending it to DEVNULL is why an interface error looked like a successful
    # capture for as long as it did.
    stderr = ""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if during is not None:
            # tshark needs a moment to open the adapter; firing the handshake immediately races the
            # capture and loses the ClientHello, which is the one packet that matters here.
            time.sleep(1.0)
            try:
                during()
            except Exception as exc:  # a failed handshake must not abort the capture teardown
                print(f"Warning: handshake trigger failed during capture: {exc}")
            # The handshake is done, so stop early rather than idling for the full duration.
            time.sleep(0.5)
            proc.terminate()
        try:
            _, stderr = proc.communicate(timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            _, stderr = proc.communicate()
    except FileNotFoundError:
        # find_tshark() already confirmed the binary exists, so reaching here means it vanished or
        # is not executable between the check and the spawn — still not a reason to abort the demo.
        print(f"Warning: tshark at {tshark} could not be executed. Writing an empty pcap.")
        out.touch()
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait()

    # Verify a capture actually happened. Without this the caller printed "Saved capture to <path>"
    # for a file tshark never created — the interface error was invisible, and the downstream
    # key_share byte-size diff quietly compared nothing. An empty file is still written so callers
    # keep working, but the reason is now stated.
    if not out.exists() or out.stat().st_size == 0:
        detail = (stderr or "").strip().splitlines()
        reason = detail[-1] if detail else "tshark produced no packets"
        print(
            f"Warning: no packets captured on interface {resolved_iface!r} for "
            f"{host}:{port} — {reason}. The handshake byte-size diff will be empty. "
            "On Windows this usually means Npcap is missing or needs elevation; "
            "pass a specific interface if auto-selection picked the wrong one."
        )
        out.touch()

    return out


def _tshark_fields(tshark: str, pcap: Path, display_filter: str, fields: list[str]) -> list[str]:
    """Run tshark in field-extraction mode and return one tab-joined row per matching packet."""
    cmd = [tshark, "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        cmd += ["-e", field]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    return [line for line in proc.stdout.splitlines() if line.strip()]


def _sum_lengths(raw: str) -> int:
    """Sum a tshark field that may repeat within one packet (comma-separated).

    A ClientHello legitimately offers SEVERAL key shares, so the field occurs once per group and
    tshark joins them with commas. Reading only the first would understate the client's key_share by
    however many groups it offered.
    """
    total = 0
    for part in raw.replace(" ", "").split(","):
        if part.isdigit():
            total += int(part)
    return total


def extract_key_share_sizes(pcap: Path) -> dict[str, int]:
    """Extract TLS key_share extension sizes from a captured handshake.

    This is the measurement the whole harvest demo rests on: a hybrid X25519MLKEM768 key share is
    ~1.2 KB where a classical X25519 one is 32 bytes, and that size difference is the visible,
    on-the-wire evidence that a deployment actually moved to post-quantum key establishment.

    It previously read `tls.handshake.extensions_key_share_client_length` and `..._server_length`
    via pyshark. **Neither field exists.** Wireshark exposes the size as
    `tls.handshake.extensions_key_share_key_exchange_length`, once per key-share entry, so both
    lookups always missed and every size came back 0 — silently, because a missing pyshark attribute
    is just a False from `hasattr`. Verified against a real capture: the field reports 1120 for the
    ServerHello's X25519MLKEM768 share.

    Uses `tshark -T fields` rather than pyshark: the field names are then explicit and checkable
    against `tshark -V` output instead of being guessed at as Python attributes, and it avoids
    pyshark's own tshark subprocess plus XML parsing for what is a four-number extraction.
    """
    sizes: dict[str, int] = {
        "client_hello_bytes": 0,
        "server_hello_bytes": 0,
        "client_key_share_bytes": 0,
        "server_key_share_bytes": 0,
    }

    tshark = find_tshark()
    if tshark is None or not pcap.exists() or pcap.stat().st_size == 0:
        return sizes

    _KEY_SHARE_LEN = "tls.handshake.extensions_key_share_key_exchange_length"
    for handshake_type, hello_key, share_key in (
        (1, "client_hello_bytes", "client_key_share_bytes"),
        (2, "server_hello_bytes", "server_key_share_bytes"),
    ):
        rows = _tshark_fields(
            tshark,
            pcap,
            f"tls.handshake.type=={handshake_type}",
            ["tls.handshake.length", _KEY_SHARE_LEN],
        )
        for row in rows:
            parts = row.split("\t")
            hello_len = _sum_lengths(parts[0]) if parts else 0
            share_len = _sum_lengths(parts[1]) if len(parts) > 1 else 0
            # Keep the largest observed handshake: a capture window can contain more than one
            # connection, and the full one is the informative sample.
            sizes[hello_key] = max(sizes[hello_key], hello_len)
            sizes[share_key] = max(sizes[share_key], share_len)

    return sizes


def diff_handshakes(before_pcap: Path, after_pcap: Path) -> dict[str, str]:
    """Compare two pcaps and return human readable differences."""
    return {"before": str(before_pcap), "after": str(after_pcap)}
