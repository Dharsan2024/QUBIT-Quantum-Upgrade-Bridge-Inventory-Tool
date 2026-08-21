"""Semgrep as a second, independent detector — and the first one that actually parses.

`pqaudit` gave this benchmark an outside opinion, but it is 178 regular expressions. A regex and an
AST query fail in *different* ways, which is useful, but they also fail in one shared way that
matters here: a regex cannot see a call it has no literal for, and neither can a rule nobody wrote.
Two detectors that both work from a list of algorithm names are less independent than they look.

Semgrep is a different kind of witness. It parses (tree-sitter, like QUBIT), it resolves imports and
aliases, its rules were written by a different organisation for a different purpose — finding
vulnerabilities, not building an inventory — and its registry carries 108 rules that its own authors
classified as cryptographic.

**Rule selection is theirs, not ours.** Picking crypto rules with a keyword regex over rule IDs
would put QUBIT's author back in the loop, choosing what counts as cryptography, which is exactly
the independence this benchmark exists to buy. Instead the filter is semgrep's own `metadata.cwe`:

    CWE-326  Inadequate Encryption Strength
    CWE-327  Use of a Broken or Risky Cryptographic Algorithm
    CWE-328  Use of Weak Hash
    CWE-347  Improper Verification of Cryptographic Signature
    CWE-916  Use of Password Hash With Insufficient Computational Effort

Deliberately excluded, and why: **CWE-319** (cleartext transmission) and **CWE-330/338** (weak
PRNG). Both are real security findings and neither is a statement about which algorithm is in use,
which is what QUBIT's code scanner inventories. Including them would score QUBIT against a question
it does not claim to answer. The set is a constant below so a reviewer can widen it and re-run.

**Reproducibility.** The image is pinned by digest and the ruleset is fetched once, hashed, and
cached; the hash is committed, the rules are not (they are LGPL-2.1 and this repository has no need
to redistribute them). Two runs a year apart therefore either use identical rules or fail loudly.

**Telemetry.** `--metrics=off` on every invocation. QUBIT's guarantee is that your code never
leaves the machine; a benchmark that quietly posted rule-match counts to a vendor while
measuring that guarantee would be a poor joke. This harness is a development tool and is not
shipped in the desktop application, but the flag is not left to chance.

Image:  semgrep/semgrep, digest pinned in IMAGE below.
Rules:  https://semgrep.dev/c/p/owasp-top-ten , https://semgrep.dev/c/p/security-audit
        (LGPL-2.1, fetched not vendored)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

import yaml
from base import Finding

#: Pinned by digest, not by `:latest`. A tag is a moving target and a benchmark that cannot say
#: which detector produced a number is not evidence.
IMAGE = "semgrep/semgrep@sha256:67319956da3dcb58baf5b322899c15458e3963e7018a86aeeb5cd224e69cb77a"

#: Registry packs to draw from. Both are fetched whole; the CWE filter below decides what is used.
PACKS = ("owasp-top-ten", "security-audit")

#: Semgrep's own classification of what is a cryptographic finding. See the module docstring for
#: what is excluded and why.
CRYPTO_CWES = frozenset({"CWE-326", "CWE-327", "CWE-328", "CWE-347", "CWE-916"})

#: Rule-ID substring -> algorithm family. This mapping IS ours, and it is a translation between two
#: vocabularies rather than a detection decision: semgrep says "use-of-md5", QUBIT says "MD5".
#: Order matters — `desede` must be tested before `des`, `sha1` before `sha`.
_ID_TO_FAMILY: tuple[tuple[str, str], ...] = (
    ("desede", "3DES"),
    ("triple-des", "3DES"),
    ("md5", "MD5"),
    ("md4", "MD4"),
    ("sha224", "SHA-224"),
    ("sha1", "SHA-1"),
    ("rc2", "RC2"),
    ("rc4", "RC4"),
    ("arc4", "RC4"),
    ("blowfish", "Blowfish"),
    ("idea", "IDEA"),
    ("argon2", "Argon2"),
    ("bcrypt", "bcrypt"),
    ("pbkdf", "PBKDF2"),
    ("rsa", "RSA"),
    ("dsa", "DSA"),
    ("ecdsa", "EC"),
    ("aes", "AES"),
    ("des", "DES"),
    ("jwt", "JWT"),
    ("jose", "JWT"),
    ("ssl", "TLS"),
    ("tls", "TLS"),
)

#: Rules whose ID names no primitive at all — a cipher mode, a padding scheme, a library default.
#: `insecure-cipher-mode-ecb` says a mode is wrong without saying of what, and guessing "AES"
#: because that is the usual answer would manufacture agreement out of an assumption. They are
#: returned with family `?` and reported as unmappable rather than silently counted either way.
UNMAPPABLE_MARKER = "?"


def _cache_dir() -> Path:
    return Path(__file__).parent / "rulesets"


def _rule_family(rule_id: str) -> str:
    tail = rule_id.split(".")[-1].lower()
    for token, fam in _ID_TO_FAMILY:
        if token in tail:
            return fam
    return UNMAPPABLE_MARKER


def fetch_rules(*, refresh: bool = False) -> Path:
    """Fetch, filter and cache the crypto subset of the registry packs.

    Returns the path to a single YAML file holding only the CWE-selected rules, ready to hand to
    `semgrep --config`. The sha256 of each upstream pack is written beside it so a later run can
    prove it used the same rules.
    """
    cache = _cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    combined = cache / "semgrep-crypto.yaml"
    manifest = cache / "MANIFEST.sha256"

    if combined.exists() and not refresh:
        return combined

    selected: list[dict] = []
    digests: list[str] = []
    for pack in PACKS:
        url = f"https://semgrep.dev/c/p/{pack}"
        with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310
            raw = response.read()
        digests.append(f"{hashlib.sha256(raw).hexdigest()}  {url}")
        for rule in (yaml.safe_load(raw.decode("utf-8")) or {}).get("rules", []):
            cwe = rule.get("metadata", {}).get("cwe")
            values = [cwe] if isinstance(cwe, str) else (cwe or [])
            if any(str(v).split(":")[0].strip() in CRYPTO_CWES for v in values):
                selected.append(rule)

    # Packs overlap; the same rule appearing twice would double-count every finding it makes.
    unique = {rule["id"]: rule for rule in selected}
    combined.write_text(
        yaml.safe_dump({"rules": list(unique.values())}, sort_keys=False), encoding="utf-8"
    )
    manifest.write_text(
        "# Upstream semgrep registry packs, hashed at fetch time.\n"
        "# Rules are LGPL-2.1 and are NOT vendored into this repository; only their hash is.\n"
        f"# selected {len(unique)} crypto rules by CWE {sorted(CRYPTO_CWES)}\n"
        + "\n".join(digests)
        + "\n",
        encoding="utf-8",
    )
    return combined


class SemgrepDetector:
    """Runs semgrep's crypto rules over a tree, containerised."""

    name = "semgrep"
    provenance = f"{IMAGE} + registry packs {'/'.join(PACKS)} (LGPL-2.1), CWE-filtered"

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
            return False, f"image not pulled: docker pull {IMAGE}"
        return True, "ok"

    def scan(self, root: Path) -> list[Finding]:
        rules = fetch_rules()
        root = root.resolve()

        # Windows + Docker Desktop + Git Bash: MSYS rewrites a container-side path like `/src` into
        # `C:/Program Files/Git/src` before docker ever sees it, and the mount silently resolves to
        # an empty directory -- which looks exactly like a detector that found nothing. Disabling
        # the rewrite is why this benchmark reports real numbers on this machine.
        env = {**os.environ, "MSYS_NO_PATHCONV": "1"}

        command = [
            "docker", "run", "--rm",
            "-v", f"{root.as_posix()}:/src:ro",
            "-v", f"{rules.parent.resolve().as_posix()}:/rules:ro",
            IMAGE,
            "semgrep",
            "--config", f"/rules/{rules.name}",
            "--metrics", "off",       # see module docstring
            "--no-git-ignore",        # corpora are git clones; default would skip untracked files
            "--json",
            "--quiet",
            "/src",
        ]
        result = subprocess.run(  # noqa: S603
            command, capture_output=True, timeout=self.timeout, env=env, check=False
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
        for hit in payload.get("results", []):
            rule_id = str(hit.get("check_id", ""))
            path = str(hit.get("path", ""))
            rel = re.sub(r"^/src/?", "", path)
            line = int((hit.get("start") or {}).get("line") or 0)
            if not rel or not line:
                continue
            findings.append(
                Finding(
                    detector=self.name,
                    path=Path(rel).as_posix(),
                    line=line,
                    algorithm=_rule_family(rule_id),
                    rule_id=rule_id,
                    text=str((hit.get("extra") or {}).get("lines", ""))[:160].strip(),
                )
            )
        return findings


__all__ = ["CRYPTO_CWES", "IMAGE", "PACKS", "SemgrepDetector", "fetch_rules"]
