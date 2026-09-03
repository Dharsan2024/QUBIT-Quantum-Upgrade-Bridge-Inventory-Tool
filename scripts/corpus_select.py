"""Apply the corpus gates in order, and publish the score for every candidate.

The table this writes is the **pre-registration artefact**. Its job is to show that corpus
selection was mechanical rather than chosen after the results were seen, which is the single most
common way an evaluation of one's own tool becomes unfalsifiable. Every candidate is scored,
including the ones that fail, including the two negative controls that are *expected* to fail —
publishing only the winners proves nothing.

The gates, in order, first candidate passing all of them wins:

* **G1 language** — Python >= 80% of source lines, and no compiled extensions. A repo whose crypto
  lives in C is not a test of a Python source-level migration tool.
* **G2 not a crypto library** — excluded when the repository IS the cryptography, by name or by
  more than a quarter of findings sitting in crypto-domain module paths. Migrating
  `pyca/cryptography` to post-quantum primitives is a category error, and it is the sort that
  produces an impressive-looking number.
* **G3 incidental** — the weak crypto must be incidental (cache keys, ETags, fingerprints) rather
  than protocol-mandated. HTTP Digest *requires* MD5; a tool "fixing" it has broken the client.
  Detected by path AND by evidence: a hash written into a request payload under a field name the
  remote service defines (`md5Pass`, `hash_password`, `X-Hub-Signature: sha1=`) is that same case,
  and the path check alone was measured missing all five of them in `pyload`.
* **G4 volume** — enough winnable findings, spread over enough rules and files, that the result is
  not three findings in one file.
* **G6 size** — small enough to build and run, with enough findings in files that fit a model's
  context WITHOUT windowing (windowing disables self-review and would silently change the
  treatment).

**G5 is deliberately not run here.** It needs a Docker image per corpus with that repo's own
dependencies installed, and a green baseline test suite measured three times. That is expensive
and only worth spending on candidates that already pass everything else, so it runs separately
against the survivors — and the survivors are named by this table first, in public, before their
suites are ever executed.

The four buckets are the plan's, not two:

* **winnable** — a rule matches AND its `gone` criterion names this asset's algorithm.
* **vacuous** — a rule matches but its criterion cannot be failed by this asset, so the finding is
  reported "already satisfied" without a model ever being asked. Counted separately because the
  SIZE of this bucket is a result in its own right.
* **present-gated** — the rule verifies by what appears rather than what disappears.
* **no rule** — nothing in the catalog covers it.

Usage::

    uv run python scripts/corpus_select.py --root X:/qubit-eval-corpus --out qubit-v2/08-evaluation
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))

from qubit_migrate.transform.rules import load_rules, match_rule
from qubit_migrate.transform.scanner_cli import cli_command

#: Repository names that ARE cryptography, however their findings look. Checked by name as well as
#: by finding distribution, because a library can be small enough that the ratio test misses it.
_CRYPTO_LIBRARIES = ("cryptography", "pycryptodome", "nacl", "openssl", "libsodium", "paramiko")

#: Module paths that mean "this file's job is cryptography". Used for G2's ratio test.
_CRYPTO_PATHS = ("/crypto", "/cipher", "/hazmat", "/tls", "/ssl", "/pkcs", "/x509", "/jose")

#: Paths whose findings are fixtures, not production usage.
_TEST_PATHS = ("/test", "/tests/", "_test.py", "test_", "/conftest", "/fixtures", "/testdata")

#: Protocol-mandated weak crypto, by PATH. RFC 2617 HTTP Digest REQUIRES MD5 — a tool that "fixes"
#: it has broken every client. This is the case `requests` exists to be a negative control for.
_PROTOCOL_MARKERS = (
    "digest",
    "auth.py",
    "ntlm",
    "kerberos",
    "sasl",
    "webdav",
    # Gravatar's API is DEFINED over an MD5 of the email address, so a SHA-256 there
    # addresses nothing and breaks the avatar. A path signal, not an evidence one: the call
    # itself reads `hashlib.md5(email.lower().encode())` and names no protocol.
    "gravatar",
)

#: Protocol-mandated weak crypto, by EVIDENCE — because the path check alone is not sufficient and
#: was measured failing.
#:
#: `pyload` scored `incidental_share = 1.00`: every finding incidental, none protocol-mandated. Its
#: source says otherwise. Five sites hash a password into an outbound request payload under a field
#: name the REMOTE SERVICE defines:
#:
#:     post = {"login": user, "md5Pass": hashlib.md5(password.encode()).hexdigest(), ...}
#:     data["hash_password"] = hashlib.sha1(hashlib.md5(password.encode()).hexdigest().encode())
#:
#: Changing those to SHA-256 does not harden anything; it fails authentication against
#: Linkifier, NoPremium, Rapideo, Twojlimit and StreamCz. That is the `requests` HTTP Digest case
#: exactly, and the only reason it was missed is that the directory is called `accounts/` rather
#: than `auth.py`.
#:
#: The principle these encode: **when the field name pins the algorithm, the algorithm is the
#: remote party's contract, not this codebase's choice.** A path heuristic cannot see that; the
#: snippet can.
#:
#: This is a fix to a measurement instrument, NOT a relaxed threshold. G3's criterion (≥ 0.60
#: incidental) is pre-registered and unchanged. Note also which direction the fix moves the
#: result: it REMOVES the best-looking remaining candidate, which is the direction that makes a
#: post-hoc instrument change credible rather than suspect.
_PROTOCOL_EVIDENCE = (
    "md5pass",
    "hash_password",
    "sha1=",
    "x-hub-signature",
    "md5(password",
    "md5(passwd",
    "digestmod=hashlib.sha1",
    "digestmod=hashlib.md5",
)

#: G6's windowing threshold. A file above roughly this size is excerpted rather than sent whole,
#: which auto-disables self-review — a materially different treatment that must not silently
#: dominate the corpus.
_WINDOW_BYTES = 11_000


@dataclass
class Score:
    name: str
    python_share: float = 0.0
    total_loc: int = 0
    compiled_extensions: int = 0
    findings: int = 0
    buckets: Counter[str] = field(default_factory=Counter)
    winnable_rules: int = 0
    winnable_files: int = 0
    winnable_small_files: int = 0
    incidental_share: float = 0.0
    crypto_path_share: float = 0.0
    gates: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(self.gates.values())

    def as_row(self) -> dict[str, Any]:
        return {
            "corpus": self.name,
            **{f"G{i}": ("pass" if self.gates.get(f"G{i}") else "FAIL") for i in (1, 2, 3, 4, 6)},
            "verdict": "SELECTED" if self.passed else "rejected",
            "python_share": f"{self.python_share:.2f}",
            "total_loc": self.total_loc,
            "compiled_extensions": self.compiled_extensions,
            "findings": self.findings,
            "winnable": self.buckets["winnable"],
            "vacuous": self.buckets["vacuous"],
            "present_gated": self.buckets["present-gated"],
            "no_rule": self.buckets["no-rule"],
            "winnable_rules": self.winnable_rules,
            "winnable_files": self.winnable_files,
            "winnable_small_files": self.winnable_small_files,
            "incidental_share": f"{self.incidental_share:.2f}",
            "crypto_path_share": f"{self.crypto_path_share:.2f}",
            "notes": "; ".join(self.notes),
        }


def _language_profile(repo: Path) -> tuple[float, int, int]:
    """(python share of source lines, total source lines, compiled extension count)."""
    counts: Counter[str] = Counter()
    compiled = 0
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix in (".pyd", ".so", ".dll") or suffix == ".pyx":
            compiled += 1
            continue
        if suffix not in (".py", ".go", ".java", ".js", ".ts", ".rb", ".c", ".cpp", ".rs", ".cs"):
            continue
        try:
            counts[suffix] += path.read_bytes().count(b"\n") + 1
        except OSError:
            continue
    total = sum(counts.values())
    return ((counts[".py"] / total) if total else 0.0, total, compiled)


def _classify(asset: dict[str, Any], rules: list[Any]) -> str:
    """Which of the four buckets this finding falls in.

    The scanner's `--json` output is already `CryptoAsset` shape, so it is validated directly.
    An earlier version routed it through `row_to_asset`, which maps a DATABASE row: it raised on
    every asset, the exception was swallowed, and every finding in every corpus was classified
    `no-rule` — a gate table that looked plausible and measured nothing.
    """
    from qubit_core import CryptoAsset

    try:
        crypto_asset = CryptoAsset.model_validate(asset)
    except Exception:
        return "no-rule"
    rule = match_rule(crypto_asset, rules)
    if rule is None or rule.rescan_expect is None:
        return "no-rule"

    gone = (rule.rescan_expect.get("gone") or {}).get("algorithm_prefix") or []
    gone = [gone] if isinstance(gone, str) else list(gone)
    if rule.rescan_expect.get("weakness_gone"):
        return "winnable"
    if not gone:
        return "present-gated"

    algorithm = str(asset.get("algorithm") or "")
    # The vacuous case: the rule lists algorithms it can migrate, and none of them describes THIS
    # asset — so the criterion is satisfied before any patch is written.
    return "winnable" if any(algorithm.startswith(p) for p in gone) else "vacuous"


def score_corpus(repo: Path, rules: list[Any]) -> Score:
    s = Score(name=repo.name)
    s.python_share, s.total_loc, s.compiled_extensions = _language_profile(repo)

    # `cli_command` builds the argv itself and the only interpolated value is a directory this
    # script was pointed at; there is no shell and no user string in the command.
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell, path from the operator
        cli_command("scan", str(repo), "--json"),
        capture_output=True,
        # Explicit encoding: `text=True` alone decodes with the LOCALE codec (cp1252 on
        # Windows), and a code snippet carrying any non-Latin-1 byte then raises inside the
        # reader THREAD — the traceback appears detached from the call that caused it, and
        # the scan silently produces nothing. Hit on a real corpus.
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=3600,
    )
    if result.returncode not in (0, 3):
        s.notes.append(f"scan failed ({result.returncode})")
        s.gates = dict.fromkeys(("G1", "G2", "G3", "G4", "G6"), False)
        return s
    # Code findings that are ALGORITHM USE, mirroring the migration harness.
    #
    # `source_scanner == "code"` alone is not enough: that bucket also carries `sensitive-data`
    # findings — a PII match in a SECURITY.md or a maintainer's address in `pyproject.toml`. They
    # are real, and they are not source-level migration work. Measured on `requests`: 15 code
    # findings, of which 10 are PII and only 5 are cryptography, so counting the bucket would have
    # tripled every denominator in this table.
    assets = [
        a
        for a in json.loads(result.stdout).get("assets", [])
        if str(a.get("source_scanner")) == "code" and str(a.get("asset_type")) == "algorithm-use"
    ]
    s.findings = len(assets)

    winnable_rules: set[str] = set()
    winnable_files: set[str] = set()
    small_files = 0
    incidental = protocol = crypto_path = 0
    for a in assets:
        bucket = _classify(a, rules)
        s.buckets[bucket] += 1
        path = str((a.get("location") or {}).get("file_path", "")).replace("\\", "/").lower()
        if any(m in path for m in _CRYPTO_PATHS):
            crypto_path += 1
        snippet = str((a.get("evidence") or {}).get("snippet") or "").lower()
        if any(m in path for m in _PROTOCOL_MARKERS) or any(
            m in snippet for m in _PROTOCOL_EVIDENCE
        ):
            protocol += 1
        elif not any(m in path for m in _TEST_PATHS):
            incidental += 1
        if bucket == "winnable":
            winnable_rules.add(str(a.get("rule_id") or ""))
            winnable_files.add(path)
            try:
                if (repo / path).stat().st_size <= _WINDOW_BYTES:
                    small_files += 1
            except OSError:
                pass

    s.winnable_rules = len(winnable_rules)
    s.winnable_files = len(winnable_files)
    s.winnable_small_files = small_files
    s.incidental_share = incidental / s.findings if s.findings else 0.0
    s.crypto_path_share = crypto_path / s.findings if s.findings else 0.0

    lowered = repo.name.lower()
    s.gates = {
        "G1": s.python_share >= 0.80 and s.compiled_extensions == 0,
        "G2": not any(lib in lowered for lib in _CRYPTO_LIBRARIES) and s.crypto_path_share <= 0.25,
        "G3": s.incidental_share >= 0.60,
        "G4": s.buckets["winnable"] >= 40 and s.winnable_rules >= 3 and s.winnable_files >= 8,
        "G6": s.total_loc <= 120_000 and s.winnable_small_files >= 25,
    }
    if s.compiled_extensions:
        s.notes.append(f"{s.compiled_extensions} compiled extensions")
    if any(lib in lowered for lib in _CRYPTO_LIBRARIES):
        s.notes.append("is a cryptography library (negative control)")
    if protocol:
        s.notes.append(f"{protocol} findings on protocol-mandated paths")
    return s


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("qubit-v2/08-evaluation"))
    ap.add_argument("--only", nargs="*", default=None)
    args = ap.parse_args()

    rules = load_rules()
    repos = sorted(p for p in args.root.iterdir() if p.is_dir())
    if args.only:
        repos = [p for p in repos if p.name in set(args.only)]

    scores: list[Score] = []
    for repo in repos:
        print(f"scoring {repo.name} ...", flush=True)
        try:
            scores.append(score_corpus(repo, rules))
        except Exception as exc:
            bad = Score(name=repo.name, notes=[f"{type(exc).__name__}: {exc}"])
            bad.gates = dict.fromkeys(("G1", "G2", "G3", "G4", "G6"), False)
            scores.append(bad)

    args.out.mkdir(parents=True, exist_ok=True)
    rows = [s.as_row() for s in scores]
    with (args.out / "corpus_gates.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["verdict"] != "SELECTED", r["corpus"])))

    selected = [s.name for s in scores if s.passed]
    print(f"\nscored {len(scores)} candidates; {len(selected)} pass G1-G4 + G6")
    for name in selected:
        print(f"  SELECTED  {name}")
    print(f"\nwritten: {args.out / 'corpus_gates.csv'}")


if __name__ == "__main__":
    main()
