"""csnp/cryptoscan as the third detector — and the only other one that builds an *inventory*.

The other two oracles answer a narrower question than QUBIT does. `pqaudit` is 178 regular
expressions looking for risky APIs; semgrep's CWE-selected rules fire only on cryptography its
authors considered *wrong*, so on go-jose it reports 4 SHA-1 sites against QUBIT's 451 assets. Both
are useful witnesses and neither is trying to enumerate what a codebase uses.

cryptoscan is. It is CSNP's discovery scanner for the QRAMM maturity model, it emits a CBOM, and it
reports strong cryptography alongside weak — `RSA-2048` and `AES-256-GCM` as readily as `MD5`. That
makes it the first detector in this comparison whose output is comparable to QUBIT's in KIND, which
matters more for the population estimator than for the recall table: capture-recapture assumes every
source samples the same population, and a detector that structurally cannot report strong
cryptography is not sampling the same population at all.

Its `crypto-samples/` directory is deliberately NOT used as corpus here. Those files are a
detector's own pattern tables rendered as source; scoring QUBIT against them measures agreement with
a word list. That corpus scored 22.3% in the first run of this benchmark and the number meant
nothing. See `docs/EVALUATION_PLAN.md`, Phase 2.

Provenance: git help/cryptoscan @ 11f0e46 (MIT), built from the repository's own Dockerfile as
`qubit-bench-cryptoscan:11f0e46` so the binary is pinned to that commit rather than to whatever a
`go install` resolves today.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from base import Finding

IMAGE = "qubit-bench-cryptoscan:11f0e46"

BUILD_HINT = (
    "docker build -t qubit-bench-cryptoscan:11f0e46 'git help/cryptoscan'  "
    "(clone github.com/csnp/cryptoscan at 11f0e46 first)"
)


class CryptoscanDetector:
    """Runs cryptoscan over a tree and reports what it inventoried."""

    name = "cryptoscan"
    provenance = f"{IMAGE} — csnp/cryptoscan @ 11f0e46 (MIT), built from its own Dockerfile"

    def __init__(self, timeout: int = 3600) -> None:
        self.timeout = timeout

    def available(self) -> tuple[bool, str]:
        try:
            probe = subprocess.run(  # noqa: S603
                ["docker", "image", "inspect", IMAGE],  # noqa: S607
                capture_output=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"docker unavailable: {exc}"
        if probe.returncode != 0:
            return False, f"image not built: {BUILD_HINT}"
        return True, "ok"

    def scan(self, root: Path) -> list[Finding]:
        root = root.resolve()
        # See semgrep_oracle.scan: without this, MSYS rewrites the container-side `/src` and the
        # bind mount silently resolves to an empty directory.
        env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
        result = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "docker", "run", "--rm",
                "-v", f"{root.as_posix()}:/src:ro",
                IMAGE,
                "scan", "/src",
                "--format", "json",
            ],
            capture_output=True,
            timeout=self.timeout,
            env=env,
            check=False,
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        start = stdout.find("{")
        if start == -1:
            return []
        try:
            payload = json.loads(stdout[start:])
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for hit in payload.get("findings", []):
            path = str(hit.get("file", ""))
            line = int(hit.get("line") or 0)
            algorithm = str(hit.get("algorithm") or "")
            if not path or not line or not algorithm:
                continue
            rel = path[len("/src/") :] if path.startswith("/src/") else path.lstrip("/")
            findings.append(
                Finding(
                    detector=self.name,
                    path=Path(rel).as_posix(),
                    line=line,
                    algorithm=algorithm,
                    rule_id=str(hit.get("id") or hit.get("type") or ""),
                    text=str(hit.get("context") or "")[:160].strip(),
                )
            )
        return findings


__all__ = ["BUILD_HINT", "IMAGE", "CryptoscanDetector"]
