"""Invoking the scanner's public CLI — the one boundary qubit-migrate may cross.

doc 03 §2 forbids qubit-migrate from importing qubit-scanner internals, so every question this
package asks the scanner goes through the ``qubit`` CLI. Two callers now ask (the rescan stage and
the target-shape lookup), and the command-resolution logic they need is identical, so it lives here
once rather than being copied into the second caller.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from typing import Any

__all__ = ["cli_command", "run_cli_json"]


def cli_command(*args: str) -> list[str]:
    """The argv that runs the scanner's public CLI with ``args``.

    What this must NOT depend on is ``uv``:

    * ``uv`` need not be installed at all in a pip-installed or containerized deployment, in which
      case every call fails for a reason unrelated to what was asked.
    * ``uv run`` nested inside an already-running ``uv run`` contends for the environment lock,
      which was observed hanging until the timeout rather than returning.

    So the current interpreter runs the CLI module directly — the same public entry point
    (``qubit_cli.main``) without the resolver in front of it. The installed ``qubit`` console script
    and ``uv run`` remain as fallbacks so this keeps working in every install shape.
    """
    if importlib.util.find_spec("qubit_cli") is not None:
        return [sys.executable, "-m", "qubit_cli.main", *args]
    console_script = shutil.which("qubit")
    if console_script:
        return [console_script, *args]
    return ["uv", "run", "qubit", *args]


def run_cli_json(*args: str, timeout: float = 60.0) -> Any | None:
    """Run the CLI and parse its stdout as JSON, or return None if that is not possible.

    Returns None rather than raising: every caller here is asking for something that makes the
    result *better* when present, and a missing scanner CLI must not turn into a failed migration.
    """
    try:
        result = subprocess.run(
            cli_command(*args),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    raw = result.stdout.decode("utf-8", errors="replace").strip()
    if not raw:
        return None
    # `console.print_json` may pretty-print with a leading banner-free payload, but rich can also
    # emit nothing on error; find the first JSON value rather than assuming the whole stream is one.
    start = min((i for i in (raw.find("["), raw.find("{")) if i != -1), default=-1)
    if start == -1:
        return None
    try:
        return json.loads(raw[start:])
    except json.JSONDecodeError:
        return None
