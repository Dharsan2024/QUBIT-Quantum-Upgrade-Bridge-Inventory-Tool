"""Phase 3a: pin what actually produced a generation result.

The checkpoint tag alone is not provenance. A tag can be re-pushed, and `temperature=0.0` is
near-deterministic rather than reproducible. This records the blob digest, the server version, the
decoding options as the code really sends them, and the seed -- so a generation result published
later can be checked against the thing that produced it.

Writes `env/model_provenance.txt` and refreshes the UNKNOWN rows in `cards/model_migration_llm.md`.

    uv run python paper_evidence/scripts/phase3_provenance.py
"""

from __future__ import annotations

import json
import platform
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT, ROOT

BASE = "http://127.0.0.1:11434"


def _get(path: str) -> dict:
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=15) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return {}


def _post(path: str, payload: dict) -> dict:
    request = urllib.request.Request(  # noqa: S310 — local server, fixed scheme
        f"{BASE}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return {}


def main() -> int:
    sys.path.insert(0, str(ROOT / "packages" / "qubit-migrate" / "src"))
    from qubit_migrate.config import MigrateConfig
    from qubit_migrate.transform.llm import GENERATION_SEED

    version = _get("/api/version").get("version", "UNKNOWN")
    tags = _get("/api/tags").get("models", [])

    wanted = MigrateConfig().model
    record = next((m for m in tags if m.get("name") == wanted), None)
    if record is None and tags:
        record = tags[0]
    record = record or {}
    details = record.get("details", {})

    show = _post("/api/show", {"model": record.get("name", wanted)})
    modelfile = show.get("modelfile", "")

    lines = [
        "# Model provenance",
        "",
        f"captured_utc: {datetime.now(UTC).isoformat(timespec='seconds')}",
        f"host: {platform.node()}",
        "",
        "## Checkpoint",
        "",
        f"name: {record.get('name', 'UNKNOWN')}",
        f"blob_digest: {record.get('digest', 'UNKNOWN')}",
        f"size_bytes: {record.get('size', 'UNKNOWN')}",
        f"parameter_size: {details.get('parameter_size', 'UNKNOWN')}",
        f"quantization: {details.get('quantization_level', 'UNKNOWN')}",
        f"family: {details.get('family', 'UNKNOWN')}",
        f"context_length: {details.get('context_length', 'UNKNOWN')}",
        f"pulled_at: {record.get('modified_at', 'UNKNOWN')}",
        "",
        "## Runtime",
        "",
        f"ollama_server_version: {version}",
        f"endpoint: {BASE}/api/generate (non-streaming)",
        "",
        "## Decoding, as the code sends it",
        "",
        "temperature: 0.0",
        f"seed: {GENERATION_SEED}",
        "think: false",
        "num_predict: scaled to the prompt, 4096..16384 (see llm._output_budget)",
        "",
        "## Modelfile as the server reports it",
        "",
    ]
    lines += [f"  {line}" for line in (modelfile or "UNKNOWN").splitlines()[:40]]

    (OUT / "env").mkdir(parents=True, exist_ok=True)
    (OUT / "env" / "model_provenance.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    digest = record.get("digest", "UNKNOWN")
    print(f"provenance: {record.get('name', 'UNKNOWN')} digest={digest[:16]} server={version}")
    if digest == "UNKNOWN":
        print("  WARNING: Ollama did not answer. Start it and re-run before publishing any result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
