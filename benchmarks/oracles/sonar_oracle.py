"""cbomkit/sonar-cryptography as the fifth detector — the one a reviewer in this area will name.

IBM wrote it, donated it to the Linux Foundation's Post-Quantum Cryptography Alliance, and it is the
reference implementation of "generate a CBOM from source". Leaving it out of a study about
cryptographic discovery would be a conspicuous omission, and it is the only detector here besides
QUBIT and cryptoscan whose output is an *inventory* rather than a list of things someone considered
wrong.

It is also the most awkward to run, and the awkwardness is worth stating because it shapes what the
comparison can claim.

**It is a SonarQube plugin, not a CLI.** There is no `sonar-cryptography scan ./repo`. A scan
needs a running SonarQube server with the plugin installed, a quality profile with the `Inventory`
rule active, and a `sonar-scanner` run that uploads an analysis report. `setup()` below does all
of that against a container, so the arrangement is reproducible rather than a paragraph of
instructions someone has to follow by hand.

**It analyses three languages: Java, Python and Go** (C# is in development and is not enabled here).
That is narrower than the corpus, and it is not a defect — it is a fact about the detector that the
comparison has to represent honestly. `run_multi.shared_vocabulary` already restricts every
comparison to families at least two detectors *can* report, so a repository sonar cannot read
contributes nothing rather than counting as a miss. A Rust repository where sonar reports zero is
not evidence that sonar missed anything.

**It does not need compiled classes.** This was the risk that would have killed the integration:
SonarQube's Java analyser normally wants `sonar.java.binaries`, and building 17 third-party
repositories at pinned commits is not on. Measured on a probe project, the plugin reports
`AES-128-CBC-PKCS5`, `3DES-CBC` and `MD5` from Java source alone. Detection from source is therefore
what is being compared, on the same footing as every other detector here.

One consequence of the quality profile: only the `Inventory` rule is active, so SonarQube's own
thousands of code-smell rules never run. That is not a shortcut — it is the only rule whose output
this study reads, and skipping the rest makes a large repository analysable in minutes instead of
an hour.

Provenance: `cbomkit/sonar-cryptography` 1.6.1 (Apache-2.0), the released plugin jar, run inside
`sonarqube:community`. The jar is fetched to `benchmarks/oracles/vendor/` (gitignored, 50 MB) rather
than vendored into the repository.

    uv run python benchmarks/oracles/sonar_oracle.py --setup   # once: container, profiles, token
    uv run python benchmarks/oracles/sonar_oracle.py --check   # is it ready
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from base import Finding

HERE = Path(__file__).resolve().parent
VENDOR = HERE / "vendor"
TOKEN_FILE = VENDOR / "sonar.token"

PLUGIN_VERSION = "1.6.1"
PLUGIN_JAR = VENDOR / f"sonar-cryptography-plugin-{PLUGIN_VERSION}.jar"
PLUGIN_URL = (
    f"https://github.com/cbomkit/sonar-cryptography/releases/download/"
    f"{PLUGIN_VERSION}/sonar-cryptography-plugin-{PLUGIN_VERSION}.jar"
)

SERVER_IMAGE = "sonarqube:community"
SCANNER_IMAGE = "sonarsource/sonar-scanner-cli:latest"
CONTAINER = "qubit-bench-sonarqube"
SONAR_URL = os.environ.get("QUBIT_BENCH_SONAR_URL", "http://127.0.0.1:9000")

#: The one rule per language whose output this study reads. Everything else stays off.
INVENTORY_RULES = {
    "java": "sonar-java-crypto:Inventory",
    "py": "sonar-python-crypto:Inventory",
    "go": "sonar-go-crypto:Inventory",
}
PROFILE = "cbom-only"

#: A repository is scanned only if it has this many analysable files AND they are this share of it.
#: Both halves are needed, and the corpus shows why: openwrt has 25 `.py`/`.go` files, as many as a
#: genuinely mixed Kotlin project, but they are 0.2% of 11,555 files and every one is a build
#: script. redis has 48, at 2.5%. A count-only rule scans both for an hour to produce a zero; a
#: share-only rule scans a tiny repo with three files in it. Together they cut cleanly: the
#: repositories that pass sit at 9.5%-95%, the ones that fail at 2.5% and below.
_MIN_READABLE_FILES = 25
_MIN_READABLE_SHARE = 0.05

SETUP_HINT = f"uv run python {Path(__file__).name} --setup"


def _api(path: str, data: dict[str, str] | None = None, auth: str = "admin:admin") -> str:
    """One call against the SonarQube web API. Basic auth: this is a throwaway local container."""
    url = f"{SONAR_URL}{path}"
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body)  # noqa: S310 - fixed localhost URL
    token = __import__("base64").b64encode(auth.encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return response.read().decode("utf-8", errors="replace")


def server_status() -> str:
    try:
        return str(json.loads(_api("/api/system/status")).get("status", "?"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return "DOWN"


def _docker(*args: str, timeout: int = 600) -> subprocess.CompletedProcess[bytes]:
    # MSYS_NO_PATHCONV: without it, Git Bash rewrites container-side paths and every bind mount
    # silently resolves to an empty directory. Same reason as semgrep_oracle and cryptoscan_oracle.
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    return subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        capture_output=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def setup() -> int:
    """Fetch the plugin, start the server, activate the one rule, and mint a token.

    Idempotent on purpose: a reviewer re-running this should not have to know whether a previous
    attempt got half way.
    """
    VENDOR.mkdir(parents=True, exist_ok=True)
    if not PLUGIN_JAR.exists():
        print(f"fetching {PLUGIN_JAR.name} ...", flush=True)
        urllib.request.urlretrieve(PLUGIN_URL, PLUGIN_JAR)  # noqa: S310 - pinned release URL
    print(f"plugin: {PLUGIN_JAR.name} ({PLUGIN_JAR.stat().st_size // 1024} KB)")

    for image in (SERVER_IMAGE, SCANNER_IMAGE):
        if _docker("image", "inspect", image, timeout=60).returncode != 0:
            print(f"pulling {image} ...", flush=True)
            _docker("pull", image, timeout=1800)

    if server_status() == "DOWN":
        _docker("rm", "-f", CONTAINER, timeout=120)
        plugins = "/opt/sonarqube/extensions/plugins"
        mount = f"{PLUGIN_JAR.resolve().as_posix()}:{plugins}/{PLUGIN_JAR.name}:ro"
        started = _docker(
            "run", "-d", "--name", CONTAINER, "-p", "9000:9000",
            "-e", "SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true",
            "-v", mount, SERVER_IMAGE, timeout=300,
        )  # fmt: skip
        if started.returncode != 0:
            print(started.stderr.decode("utf-8", errors="replace")[:400])
            return 1
        print("waiting for SonarQube ...", flush=True)
        for _ in range(60):
            if server_status() == "UP":
                break
            time.sleep(10)
    if server_status() != "UP":
        print("SonarQube did not come up")
        return 1
    print(f"server: UP at {SONAR_URL}")

    installed = json.loads(_api("/api/plugins/installed")).get("plugins", [])
    if not any(p.get("key") == "crypto" for p in installed):
        print("the crypto plugin is not loaded; remove the container and re-run --setup")
        return 1

    for language in INVENTORY_RULES:
        _api("/api/qualityprofiles/create", {"name": PROFILE, "language": language})
    profiles = json.loads(_api("/api/qualityprofiles/search")).get("profiles", [])
    keys = {p["language"]: p["key"] for p in profiles if p["name"] == PROFILE}
    for language, rule in INVENTORY_RULES.items():
        if language in keys:
            _api("/api/qualityprofiles/activate_rule", {"key": keys[language], "rule": rule})
        _api(
            "/api/qualityprofiles/set_default",
            {"qualityProfile": PROFILE, "language": language},
        )
    active = {
        p["language"]: p["activeRuleCount"]
        for p in json.loads(_api("/api/qualityprofiles/search")).get("profiles", [])
        if p["name"] == PROFILE
    }
    print(f"profiles: {active} (1 active rule each = the Inventory rule)")

    if not TOKEN_FILE.exists():
        minted = json.loads(
            _api("/api/user_tokens/generate", {"name": f"qubit-bench-{int(time.time())}"})
        )
        TOKEN_FILE.write_text(minted["token"], encoding="utf-8")
    print(f"token: {TOKEN_FILE}")
    print("\nready. `run_multi.py` will now include the `sonar` detector.")
    return 0


class SonarCryptographyDetector:
    """Runs sonar-cryptography over a tree and reports the CBOM it produced."""

    name = "sonar"
    provenance = (
        f"{SERVER_IMAGE} + cbomkit/sonar-cryptography {PLUGIN_VERSION} (Apache-2.0), "
        f"Inventory rule only; Java/Python/Go"
    )

    def __init__(self, timeout: int = 3600) -> None:
        self.timeout = timeout

    def available(self) -> tuple[bool, str]:
        if shutil.which("docker") is None:
            return False, "docker not on PATH"
        if _docker("image", "inspect", SCANNER_IMAGE, timeout=60).returncode != 0:
            return False, f"{SCANNER_IMAGE} not pulled: {SETUP_HINT}"
        if not TOKEN_FILE.exists():
            return False, f"no analysis token: {SETUP_HINT}"
        status = server_status()
        if status != "UP":
            return False, f"SonarQube at {SONAR_URL} is {status}: {SETUP_HINT}"
        return True, "ok"

    def coverage(self, root: Path) -> tuple[int, float]:
        """How many files in this tree the plugin could analyse, and what share of it they are.

        `sonar-scanner` indexes every file it is pointed at, whatever the language, and only then
        hands the analysable ones to the plugin. On a large C repository that is an hour of work to
        produce a guaranteed zero -- openwrt alone would cost more than the rest of the sweep put
        together. Measuring first turns "sonar cannot read this repository" into a fact established
        in seconds rather than one paid for in wall time, and it is a different statement from
        "sonar found nothing", which is what a zero would otherwise be mistaken for.
        """
        readable = sum(1 for suffix in (".java", ".py", ".go") for _ in root.rglob(f"*{suffix}"))
        total = sum(1 for path in root.rglob("*") if path.is_file())
        return readable, (readable / total if total else 0.0)

    def scan(self, root: Path) -> list[Finding]:
        root = root.resolve()
        readable, share = self.coverage(root)
        if readable < _MIN_READABLE_FILES or share < _MIN_READABLE_SHARE:
            return []
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        # A project key per repository, so analyses do not overwrite each other's history and a
        # failed run is identifiable in the server's UI afterwards.
        key = f"qubit-bench-{root.name}".replace("/", "-")[:100]

        with tempfile.TemporaryDirectory() as out:
            out_dir = Path(out)
            # The plugin appends `.json` to whatever it is given, hence the extension-less path.
            # The repository itself is mounted read-only: a benchmark that writes into the corpus
            # it is measuring has changed the thing under measurement.
            result = _docker(
                "run", "--rm", "--network", "host",
                "-e", f"SONAR_HOST_URL={SONAR_URL}",
                "-e", f"SONAR_TOKEN={token}",
                "-v", f"{root.as_posix()}:/usr/src:ro",
                "-v", f"{out_dir.resolve().as_posix()}:/out",
                SCANNER_IMAGE,
                f"-Dsonar.projectKey={key}",
                "-Dsonar.sources=/usr/src",
                "-Dsonar.projectBaseDir=/usr/src",
                "-Dsonar.scm.disabled=true",
                "-Dsonar.cryptoScanner.cbom=/out/cbom",
                timeout=self.timeout,
            )  # fmt: skip
            cbom = out_dir / "cbom.json"
            if not cbom.exists():
                return []
            try:
                payload = json.loads(cbom.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []
        del result  # the scanner's exit code is not the signal; the CBOM's existence is

        return list(self._findings(payload))

    def _findings(self, payload: dict) -> list[Finding]:
        findings: list[Finding] = []
        for component in payload.get("components", []):
            properties = component.get("cryptoProperties", {}) or {}
            # `related-crypto-material` is a key or certificate, not an algorithm at a call site.
            # Including it would put this detector into a population the others never sample.
            if properties.get("assetType") != "algorithm":
                continue
            algorithm = str(component.get("name") or "").strip()
            if not algorithm:
                continue
            for occurrence in component.get("evidence", {}).get("occurrences", []):
                location = str(occurrence.get("location") or "").strip()
                line = int(occurrence.get("line") or 0)
                if not location or not line:
                    continue
                findings.append(
                    Finding(
                        detector=self.name,
                        path=Path(location).as_posix(),
                        line=line,
                        algorithm=algorithm,
                        rule_id=str(
                            (properties.get("algorithmProperties", {}) or {}).get("primitive") or ""
                        ),
                        text="",
                    )
                )
        return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true", help="container, profiles and token")
    parser.add_argument("--check", action="store_true", help="report whether it is ready")
    args = parser.parse_args()
    if args.setup:
        return setup()
    ok, why = SonarCryptographyDetector().available()
    print(f"sonar: {'ready' if ok else 'unavailable'} — {why}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
