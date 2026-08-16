"""tshark discovery, interface selection and key_share extraction.

Every bug these cover shared one shape: the capture path failed silently and the demo reported
success anyway. tshark not on PATH wrote an empty pcap; `-i any` is invalid on Windows and wrote no
file at all while the caller printed "Saved capture to <path>"; the capture ran to completion BEFORE
the handshake so the window held no TLS; and the key_share field names did not exist, so every size
read 0. The harvest demo's entire claim is that a hybrid key_share is ~1.2 KB against a classical
32 bytes, and it was comparing two zeros.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from qubit_bridge import capture as cap


def test_explicit_interface_is_respected() -> None:
    """An operator naming an interface must win over auto-selection."""
    assert cap._select_interface("tshark", "localhost", "eth0") == "eth0"


def test_loopback_host_selects_a_loopback_adapter(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Loopback traffic is invisible on a physical NIC, and the bridge demo captures
    localhost:8443 — so `localhost` must resolve to the loopback adapter or nothing is recorded."""
    listing = (
        "1. \\Device\\NPF_{AAAA} (Wi-Fi)\n"
        "10. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
        "11. ciscodump (Cisco remote capture)\n"
    )
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr(
        cap.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=listing, stderr=""),
    )
    assert cap._select_interface("tshark", "127.0.0.1", "any") == "\\Device\\NPF_Loopback"


def test_remote_host_skips_loopback_and_remote_capture_plugins(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`ciscodump`/`sshdump` are remote-capture extensions needing their own configuration; picking
    one would fail rather than capture."""
    listing = (
        "1. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
        "2. sshdump (SSH remote capture)\n"
        "3. \\Device\\NPF_{BBBB} (Ethernet)\n"
    )
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr(
        cap.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=listing, stderr=""),
    )
    assert cap._select_interface("tshark", "example.test", "any") == "\\Device\\NPF_{BBBB}"


def test_linux_keeps_the_any_pseudo_interface(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`any` is real on Linux — replacing it there would be a regression, so the platform check
    matters in both directions."""
    monkeypatch.setattr("sys.platform", "linux")
    assert cap._select_interface("tshark", "example.test", "any") == "any"
    assert cap._select_interface("tshark", "localhost", "any") == "lo"


def test_find_tshark_honours_the_env_override(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """A non-standard install must be usable without editing code."""
    fake = tmp_path / "tshark.exe"
    fake.write_text("", encoding="utf-8")
    monkeypatch.setenv("QUBIT_TSHARK", str(fake))
    assert cap.find_tshark() == str(fake)


def test_find_tshark_falls_back_to_known_install_locations(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The Windows Wireshark installer does not reliably add itself to PATH, and an already-running
    process keeps the PATH it started with — so PATH-only lookup reported "not installed" for a
    tshark sitting in Program Files."""
    fake = tmp_path / "tshark.exe"
    fake.write_text("", encoding="utf-8")
    monkeypatch.delenv("QUBIT_TSHARK", raising=False)
    monkeypatch.setattr(cap.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cap, "_TSHARK_CANDIDATES", (str(fake),))
    assert cap.find_tshark() == str(fake)


def test_find_tshark_returns_none_when_genuinely_absent(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("QUBIT_TSHARK", raising=False)
    monkeypatch.setattr(cap.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cap, "_TSHARK_CANDIDATES", ())
    assert cap.find_tshark() is None


def test_key_share_extraction_sums_repeated_fields() -> None:
    """A ClientHello legitimately offers SEVERAL key shares, so tshark emits the length field once
    per entry, comma-joined. Reading only the first understates the client's key_share."""
    assert cap._sum_lengths("1216,32") == 1248
    assert cap._sum_lengths("1120") == 1120
    assert cap._sum_lengths("") == 0
    assert cap._sum_lengths("not-a-number") == 0


def test_key_share_extraction_returns_zeros_without_a_pcap(tmp_path: Path) -> None:
    """A missing or empty pcap must not raise — the caller reports an unusable capture instead."""
    assert cap.extract_key_share_sizes(tmp_path / "nope.pcap")["server_key_share_bytes"] == 0
    empty = tmp_path / "empty.pcap"
    empty.touch()
    assert cap.extract_key_share_sizes(empty)["client_key_share_bytes"] == 0


class _FakeProc:
    """Stands in for the tshark process. `writes` decides whether a pcap appears."""

    def __init__(self, order: list[str], out: Path, *, writes: bool, stderr: str = "") -> None:
        self._order = order
        self._out = out
        self._writes = writes
        self._stderr = stderr

    def communicate(self, timeout: float | None = None) -> tuple[str, str]:
        self._order.append("capture-finished")
        if self._writes:
            # A pcap header plus a little data, so the emptiness check does not fire.
            self._out.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
        return "", self._stderr

    def terminate(self) -> None:
        self._order.append("terminate")

    def wait(self) -> None:
        return None


def test_capture_reports_when_no_packets_were_captured(monkeypatch, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    """The regression that hid every other bug here: tshark failing left no file, and the caller
    still printed "Saved capture to <path>". An empty capture must say so, with tshark's reason."""
    out = tmp_path / "x.pcap"
    order: list[str] = []
    monkeypatch.setattr(cap, "find_tshark", lambda: "tshark")
    monkeypatch.setattr(cap, "_select_interface", lambda *a: "any")
    monkeypatch.setattr(
        cap.subprocess,
        "Popen",
        lambda *a, **k: _FakeProc(
            order,
            out,
            writes=False,
            stderr='tshark: The capture session could not be initiated on "any".',
        ),
    )

    cap.capture_handshake("localhost", 8443, out, timeout=1.0)
    printed = capsys.readouterr().out
    assert "no packets captured" in printed
    assert "could not be initiated" in printed  # tshark's own reason surfaced, not swallowed


def test_capture_triggers_the_handshake_inside_the_window(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """`during` must run while tshark is live. Capturing first and connecting afterwards is what
    made every key_share size read 0 from a pcap that looked perfectly valid."""
    out = tmp_path / "y.pcap"
    order: list[str] = []
    monkeypatch.setattr(cap, "find_tshark", lambda: "tshark")
    monkeypatch.setattr(cap, "_select_interface", lambda *a: "any")
    monkeypatch.setattr(cap.time, "sleep", lambda _s: None)
    monkeypatch.setattr(cap.subprocess, "Popen", lambda *a, **k: _FakeProc(order, out, writes=True))

    cap.capture_handshake(
        "localhost", 8443, out, timeout=1.0, during=lambda: order.append("handshake")
    )
    assert order.index("handshake") < order.index("capture-finished")


def test_capture_survives_a_failing_handshake_trigger(monkeypatch, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    """A refused connection must not abort capture teardown, or the tshark process leaks."""
    out = tmp_path / "z.pcap"
    order: list[str] = []
    monkeypatch.setattr(cap, "find_tshark", lambda: "tshark")
    monkeypatch.setattr(cap, "_select_interface", lambda *a: "any")
    monkeypatch.setattr(cap.time, "sleep", lambda _s: None)
    monkeypatch.setattr(cap.subprocess, "Popen", lambda *a, **k: _FakeProc(order, out, writes=True))

    def _boom() -> None:
        raise OSError("connection refused")

    cap.capture_handshake("localhost", 8443, out, timeout=1.0, during=_boom)
    assert "handshake trigger failed" in capsys.readouterr().out


def test_capture_without_tshark_is_explicit_about_the_consequence(
    monkeypatch, tmp_path, capsys
) -> None:  # type: ignore[no-untyped-def]
    """The old message said only "pcap capture is disabled", which read as harmless. It is not: the
    downstream byte-size diff silently has nothing to compare."""
    monkeypatch.setattr(cap, "find_tshark", lambda: None)
    out = cap.capture_handshake("localhost", 8443, tmp_path / "none.pcap")
    assert out.exists() and out.stat().st_size == 0
    printed = capsys.readouterr().out
    assert "tshark not found" in printed
    assert "nothing to compare" in printed
