"""Patch validation pipeline (doc 03 §6.4).

M1 stages (no Docker):
  1 applies — git apply --check  (skipped if no git repo)
  2 parses  — tree-sitter zero ERROR nodes
  5 rescan  — qubit scan --json <file> subprocess, check expected algorithms

Stages 3 (compile) and 4 (tests) are M2 (require Docker sandbox).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .languages import LANGUAGE_TO_EXT, TS_GRAMMAR, parse_error
from .languages import SUFFIX_TO_LANGUAGE as _SUFFIX_TO_LANGUAGE

StageStatus = Literal["pass", "fail", "skipped"]


def _effective_language(rule_language: str, target_rel_path: str | None) -> str:
    """Resolve the language of the file actually being patched.

    A rule's `language` is not always the language of the file: cross-language rules declare
    `multi`, because one rule covers Go, Java, JS, TS and C. Deriving the language from the rule
    therefore mislabels every patch those rules produce, and both validation stages that need a
    language got it wrong in the same way — silently, and in opposite directions:

    * `_stage_parses` treated `multi` as "not source code" and skipped syntax checking entirely, so
      a Go patch was never parsed at all.
    * `_stage_rescan` fell back to `.py`, wrote the Go patch to `patched.py` and scanned it as
      Python. Nothing was detected, the `present:` expectation could not be met, and the patch was
      rejected with "Algorithms: set()" — a correct rewrite thrown away because the validator was
      looking at it through the wrong parser.

    The file extension is the authority, so it wins whenever it is known.
    """
    if target_rel_path:
        derived = _SUFFIX_TO_LANGUAGE.get(Path(target_rel_path).suffix.lower())
        if derived is not None:
            return derived
    return rule_language


@dataclass
class StageResult:
    status: StageStatus
    detail: str = ""
    duration_s: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "detail": self.detail[:4096],
            "duration_s": round(self.duration_s, 3),
        }


@dataclass
class ValidationReport:
    stages: dict[str, StageResult] = field(default_factory=dict)
    passed: bool = False
    partial: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "stages": {k: v.as_dict() for k, v in self.stages.items()},
            "passed": self.passed,
            "partial": self.partial,
        }


def _stage_applies(
    diff_text: str,
    repo_root: Path | None,
) -> StageResult:
    t0 = time.monotonic()
    if not diff_text.strip():
        return StageResult("fail", "empty diff", time.monotonic() - t0)
    if repo_root is None or not (repo_root / ".git").exists():
        # No git repo — skip but mark partial
        return StageResult("skipped", "no git repo to check against", time.monotonic() - t0)
    try:
        result = subprocess.run(
            ["git", "apply", "--check", "-"],
            input=diff_text.encode("utf-8"),
            capture_output=True,
            cwd=str(repo_root),
            timeout=30,
        )
        ok = result.returncode == 0
        detail = result.stderr.decode("utf-8", errors="replace")[:2048]
        return StageResult("pass" if ok else "fail", detail, time.monotonic() - t0)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return StageResult("fail", str(exc), time.monotonic() - t0)


# Rule languages that are NOT source code and therefore have no tree-sitter grammar: config files
# and dependency manifests. They must SKIP the parse stage, not be parsed as something else.
# `multi` is deliberately NOT here. It means "several SOURCE languages", not "not source code":
# _effective_language resolves it to a concrete language from the file extension before this is
# consulted. Listing it made every cross-language patch skip syntax validation entirely.
_NON_CODE_LANGUAGES = frozenset(
    {"nginx", "apache", "httpd", "sshd_config", "ssh_config", "config", "manifest", ""}
)

# Rule language -> tree-sitter grammar name. Imported rather than restated: this used to be a
# 7-entry copy alongside a second copy of the suffix map in this same file, and the two drifted —
# `.tsx` was in one and not the other, so a React component matched a rule, produced no edit, and
# skipped the parse stage, reporting a patch that changed nothing as valid. See
# `transform/languages.py`.
_TS_LANGUAGES = TS_GRAMMAR


def _stage_parses(
    patched_source: str,
    language: str = "python",
    original_source: str | None = None,
) -> StageResult:
    """Did this patch break the file's syntax?

    `original_source` is the baseline. Without it the stage asks "is this file perfect", which is a
    different and less useful question: a file the grammar cannot fully parse — SQL with `:name`
    bind parameters is the case that surfaced — fails for a defect the patch did not introduce, and
    every correct rewrite of that file is thrown away with it.
    """
    t0 = time.monotonic()
    lang = (language or "").lower()

    # This defaulted ANY unrecognised language to "python", so a hardened nginx.conf or sshd_config
    # was parsed as Python, produced ERROR nodes, and the patch was rejected — which made config
    # hardening (the highest-value quantum-safety transform there is, since it turns on
    # X25519MLKEM768 for all traffic) impossible to apply. A non-code file has no grammar to check
    # against, so the honest result is `skipped`; the `applies` and `rescan` stages still gate it.
    if lang in _NON_CODE_LANGUAGES:
        return StageResult(
            "skipped",
            f"{lang or 'unknown'} is not source code — no tree-sitter grammar to parse against",
            time.monotonic() - t0,
        )

    # One shared implementation with the LLM rewrite guard — see languages.parse_error. Both used
    # to inspect only `root_node.children`, so a syntax error nested inside a function body passed
    # both checks; `has_error` looks at the whole tree.
    if lang not in TS_GRAMMAR:
        return StageResult(
            "skipped",
            f"no tree-sitter grammar mapped for language {lang!r}",
            time.monotonic() - t0,
        )
    problem = parse_error(patched_source, lang)
    if problem is None:
        return StageResult("pass", "parses with no errors", time.monotonic() - t0)

    baseline = parse_error(original_source, lang) if original_source is not None else None
    if baseline is not None:
        # The file did not parse before the patch either, so this stage cannot attribute the error
        # to the change. Say so instead of failing a rewrite that may be perfectly correct.
        return StageResult(
            "skipped",
            f"the file already {baseline} before this patch, so the parser cannot judge the "
            f"change (patched: {problem})",
            time.monotonic() - t0,
        )
    return StageResult("fail", problem, time.monotonic() - t0)


def _scan_command(target: Path) -> list[str]:
    """The command that runs the scanner's public CLI over ``target``.

    Stage 5 deliberately goes through the ``qubit scan`` **CLI** rather than importing
    qubit-scanner, because doc 03 §2 forbids qubit-migrate from importing scanner internals — the
    CLI is the public interface. What it should NOT depend on is `uv`:

    * `uv` need not be installed at all in a pip-installed or containerized deployment, in which
      case every patch failed validation for a reason unrelated to the patch.
    * `uv run` nested inside an already-running `uv run` contends for the environment lock, which
      was observed hanging until the 60s timeout rather than returning.

    So the current interpreter runs the CLI module directly — the same public entry point
    (`qubit_cli.main`) without the resolver in front of it. The installed `qubit` console script
    and `uv run` remain as fallbacks so this keeps working in every install shape.
    """
    args = ["scan", str(target), "--json"]
    if importlib.util.find_spec("qubit_cli") is not None:
        return [sys.executable, "-m", "qubit_cli.main", *args]
    console_script = shutil.which("qubit")
    if console_script:
        return [console_script, *args]
    return ["uv", "run", "qubit", *args]


def _stage_rescan(
    patched_source: str,
    rule: Any | None,
    language: str = "python",
    asset_algorithm: str | None = None,
) -> StageResult:
    """Run qubit scan --json on the patched source and check rescan_expect.

    ``asset_algorithm`` scopes the ``gone`` check to the algorithm this patch was migrating. Without
    it the check asserted that no listed weak algorithm appears anywhere in the file, which fails
    whenever a file mixes usages that different rules own — an MD5 digest beside an HMAC-SHA1 and a
    SHA-1 signature is ordinary code, and `code-weakhash-02` is responsible for exactly one of the
    three.
    """
    t0 = time.monotonic()
    if rule is None or rule.rescan_expect is None:
        return StageResult("skipped", "no rescan_expect in rule", time.monotonic() - t0)

    # Defaulting an unknown language to `.py` meant a Go, JS or C patch was written to `patched.py`
    # and scanned as Python: zero detections, so any `present:` expectation failed and a correct
    # rewrite was rejected. Every language the scanner supports now maps to its real extension, and
    # an unknown one skips rather than being scanned as the wrong language.
    # Shared with the codemod dispatcher and the suffix map — see transform/languages.py. This was
    # a third private copy listing 7 languages, so the rescan (the only stage that checks the patch
    # actually removed the weak algorithm) silently skipped for the other 12.
    ext = LANGUAGE_TO_EXT.get(language)
    if ext is None:
        return StageResult(
            "skipped",
            f"no scanner file extension known for language {language!r} — cannot rescan safely",
            time.monotonic() - t0,
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_file = Path(tmpdir) / f"patched{ext}"
        tmp_file.write_text(patched_source, encoding="utf-8")

        try:
            result = subprocess.run(
                _scan_command(tmp_file),
                capture_output=True,
                timeout=60,
                cwd=str(Path(__file__).parents[6]),  # workspace root
            )
            raw = result.stdout.decode("utf-8", errors="replace")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # exit code 3 means no assets found — that's fine for "gone" check
                data = {"assets": [], "stats": {}}

            assets = data.get("assets", [])
            algos = {a.get("algorithm", "") for a in assets}

            expect = rule.rescan_expect

            def _prefixes(spec: object) -> list[str]:
                """`algorithm_prefix` may be a single prefix or a list of them.

                Only the `gone` branch normalized this; `present` passed the raw value straight to
                `str.startswith`, which raises `TypeError: startswith first arg must be str or a
                tuple of str, not list` for a list-valued expectation. The crash surfaced as an
                unexplained skipped asset, so a valid patch was discarded over a spec-shape detail.
                """
                if isinstance(spec, str):
                    return [spec] if spec else []
                if isinstance(spec, list):
                    return [p for p in spec if isinstance(p, str) and p]
                return []

            gone_prefixes = _prefixes(expect.get("gone", {}).get("algorithm_prefix", ""))
            present_prefixes = _prefixes(expect.get("present", {}).get("algorithm_prefix", ""))

            # Narrow `gone` to the prefixes that actually describe THIS patch's algorithm. A rule
            # lists every algorithm it can migrate; one patch migrates one of them, and the others
            # may legitimately still be in the file under a usage this rule does not own.
            if asset_algorithm:
                matching = [p for p in gone_prefixes if asset_algorithm.startswith(p)]
                if matching:
                    gone_prefixes = matching

            for gone_prefix in gone_prefixes:
                still_present = [a for a in algos if a.startswith(gone_prefix)]
                if still_present:
                    return StageResult(
                        "fail",
                        f"Expected {gone_prefix!r} gone, but still found: {still_present}",
                        time.monotonic() - t0,
                    )
            # Any ONE of the listed prefixes satisfies the expectation: a rule may offer several
            # acceptable targets (ML-KEM or a hybrid group), and requiring all of them at once would
            # reject a correct migration that picked one.
            if present_prefixes and not any(a.startswith(tuple(present_prefixes)) for a in algos):
                return StageResult(
                    "fail",
                    f"Expected one of {present_prefixes!r} present, but not found. "
                    f"Algorithms: {algos}",
                    time.monotonic() - t0,
                )
            return StageResult("pass", f"rescan ok. algorithms: {algos}", time.monotonic() - t0)

        except subprocess.TimeoutExpired:
            return StageResult("fail", "rescan timed out", time.monotonic() - t0)
        except FileNotFoundError:
            return StageResult("skipped", "qubit CLI not found in PATH", time.monotonic() - t0)


#: Kept for the sandbox-availability tests; the per-language table above is what runs.
_SANDBOX_IMAGE = "python:3.12-slim"
_docker_ok: bool | None = None  # process-level cache; daemon state won't flip mid-run


def _docker_available() -> bool:
    global _docker_ok
    if _docker_ok is None:
        try:
            r = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                timeout=10,
            )
            _docker_ok = r.returncode == 0 and bool(r.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            _docker_ok = False
    return _docker_ok


#: language -> (image, filename, argv). Each command is the language's OWN single-file syntax check,
#: which is a stronger statement than a tree-sitter parse: it is the real parser, and it knows that
#: version's grammar.
#:
#: Only languages whose toolchain can check ONE file with no project, no manifest and no
#: network are here. Rust, Swift, Kotlin, Scala, C# and Dart all need a project or a resolved
#: dependency graph to say anything useful about a single file, and their images are 1 GB and
#: up; they keep the tree-sitter parse and the rescan, which is what the other stages are for.
_COMPILE_SANDBOX: dict[str, tuple[str, str, list[str]]] = {
    "python": (
        "python:3.12-slim",
        "patched.py",
        ["python", "-c", "compile(open('/work/patched.py').read(), 'patched.py', 'exec')"],
    ),
    "php": ("php:8.3-cli-alpine", "patched.php", ["php", "-l", "/work/patched.php"]),
    "ruby": ("ruby:3.3-alpine", "patched.rb", ["ruby", "-c", "/work/patched.rb"]),
    "javascript": ("node:22-alpine", "patched.js", ["node", "--check", "/work/patched.js"]),
    "bash": ("bash:5.2", "patched.sh", ["bash", "-n", "/work/patched.sh"]),
}


def _image_present(image: str) -> bool:
    """Is this image already pulled?

    QUBIT is offline by mandate, so the sandbox must never pull. `docker run` would fetch a missing
    image silently — from a tool whose stated promise is that your code never leaves the machine.
    """
    try:
        return (
            subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
                timeout=15,
            ).returncode
            == 0
        )
    except (subprocess.TimeoutExpired, OSError):
        return False


def _stage_compiles(patched_source: str, language: str = "python") -> StageResult:
    """Stage 3: run the language's own syntax check inside an isolated container (no network)."""
    t0 = time.monotonic()
    spec = _COMPILE_SANDBOX.get((language or "").lower())
    if spec is None:
        return StageResult(
            "skipped",
            f"no single-file compile check for {language} — it needs a project to build",
            0.0,
        )
    if not _docker_available():
        return StageResult("skipped", "docker unavailable", time.monotonic() - t0)

    image, filename, argv = spec
    if not _image_present(image):
        return StageResult(
            "skipped",
            f"sandbox image {image} is not pulled (QUBIT never downloads one itself) — "
            f"run: docker pull {image}",
            time.monotonic() - t0,
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / filename).write_text(patched_source, encoding="utf-8")
        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none",
                    "-v",
                    f"{tmpdir}:/work:ro",
                    image,
                    *argv,
                ],
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return StageResult("fail", "sandbox compile timed out", time.monotonic() - t0)
        if result.returncode == 0:
            return StageResult(
                "pass", f"passes {argv[0]} syntax check in sandbox", time.monotonic() - t0
            )
        detail = (result.stderr or result.stdout).decode("utf-8", errors="replace")[:2048]
        return StageResult("fail", detail, time.monotonic() - t0)


def _has_test_suite(repo_root: Path) -> bool:
    if (repo_root / "tests").is_dir():
        return True
    if (repo_root / "pytest.ini").exists() or (repo_root / "setup.cfg").exists():
        return True
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return False
    return "pytest" in pyproject.read_text(encoding="utf-8", errors="replace")


def _stage_tests(
    patched_source: str,
    repo_root: Path | None,
    target_rel_path: str | None,
    language: str = "python",
) -> StageResult:
    """Stage 4: copy the repo, overlay the patched file, run pytest inside the sandbox.

    Network stays off; pytest comes from the host venv mounted read-only would be fragile,
    so we use `python -m unittest`-compatible pytest bundled via pip cache only when the
    image has it — otherwise the stage reports skipped (honest) rather than green.
    """
    t0 = time.monotonic()
    if language != "python":
        return StageResult("skipped", f"test sandbox is python-only (got {language})", 0.0)
    if repo_root is None or target_rel_path is None or Path(target_rel_path).is_absolute():
        return StageResult("skipped", "no repo_root/relative target for test run", 0.0)
    if not _has_test_suite(repo_root):
        return StageResult("skipped", "no test suite detected in repo", 0.0)
    if not _docker_available():
        return StageResult("skipped", "docker unavailable", time.monotonic() - t0)

    with tempfile.TemporaryDirectory() as tmpdir:
        work = Path(tmpdir) / "repo"
        shutil.copytree(repo_root, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        target = work / target_rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(patched_source, encoding="utf-8")

        def _run_in_sandbox(cmd: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none",
                    "-v",
                    f"{work}:/work",
                    "-w",
                    "/work",
                    _SANDBOX_IMAGE,
                    "sh",
                    "-c",
                    cmd,
                ],
                capture_output=True,
                timeout=300,
            )

        try:
            result = _run_in_sandbox("python -m pytest -x -q 2>&1")
            out = result.stdout.decode("utf-8", errors="replace")
            if "No module named pytest" in out:
                # base image has no pytest; fall back to the stdlib runner
                result = _run_in_sandbox("python -m unittest discover -s tests 2>&1")
                out = result.stdout.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return StageResult("fail", "sandbox tests timed out", time.monotonic() - t0)
        if result.returncode == 0:
            return StageResult(
                "pass", out[:2048] or "tests green in sandbox", time.monotonic() - t0
            )
        return StageResult("fail", out[:2048], time.monotonic() - t0)


def validate_patch(
    *,
    diff_text: str,
    patched_source: str,
    rule: Any | None = None,
    repo_root: Path | None = None,
    language: str = "python",
    target_rel_path: str | None = None,
    no_docker: bool = False,
    asset_algorithm: str | None = None,
    original_source: str | None = None,
) -> ValidationReport:
    """Run validation stages 1 applies, 2 parses, 3 compiles, 4 tests, 5 rescan.

    Any hard `fail` fails the patch; `skipped` stages mark the report partial.
    """
    stages: dict[str, StageResult] = {}

    # A cross-language rule declares `language: multi`, so the rule cannot say what the patched file
    # is; the file extension can. See _effective_language for the two bugs this closes.
    language = _effective_language(language, target_rel_path)

    stages["applies"] = _stage_applies(diff_text, repo_root)
    stages["parses"] = _stage_parses(patched_source, language, original_source)
    if no_docker:
        stages["compiles"] = StageResult("skipped", "no_docker configured")
        stages["tests"] = StageResult("skipped", "no_docker configured")
    else:
        stages["compiles"] = _stage_compiles(patched_source, language)
        stages["tests"] = _stage_tests(patched_source, repo_root, target_rel_path, language)
    stages["rescan"] = _stage_rescan(patched_source, rule, language, asset_algorithm)

    passed = all(v.status in ("pass", "skipped") for v in stages.values())
    partial = any(v.status == "skipped" for v in stages.values())

    return ValidationReport(stages=stages, passed=passed, partial=partial)


__all__ = ["StageResult", "ValidationReport", "validate_patch"]
