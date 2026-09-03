"""Patch validation pipeline (doc 03 §6.4).

M1 stages (no Docker):
  1 applies — git apply --check  (skipped if no git repo)
  2 parses  — tree-sitter zero ERROR nodes
  5 rescan  — qubit scan --json <file> subprocess, check expected algorithms

Stages 3 (compile) and 4 (tests) are M2 (require Docker sandbox).
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ..oracles import relations_for
from ..oracles.controls import ControlReport, run_controls
from ..oracles.harness import build as build_harness
from ..regimes import hybrid_components
from .languages import (
    LANGUAGE_TO_EXT,
    TS_GRAMMAR,
    _import_names,
    parse_error,
    unresolved_qualifiers,
    unused_imports,
)
from .languages import SUFFIX_TO_LANGUAGE as _SUFFIX_TO_LANGUAGE
from .scanner_cli import cli_command

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
    #: Which rescan expectation failed — "gone" (the old algorithm survived) or "present" (the new
    #: one was not detected). They need opposite corrections, and a caller that cannot tell them
    #: apart gives the wrong one: the repair loop was telling the model "your rewrite still leaves
    #: RSA in the file" for rewrites that had removed RSA entirely. Deliberately not serialized by
    #: `as_dict` — this is guidance for the repair loop, not part of the stored validation record.
    expectation: str = ""
    #: The algorithm prefix that expectation named, e.g. "ML-KEM".
    expected: str = ""
    #: Set on `rescan` when the expectation this stage checked CANNOT BE FAILED by this
    #: asset. A rule lists every algorithm it can migrate; when none of them describes the
    #: asset in hand, the check asks whether some other algorithm is absent from the file —
    #: and it always is. The result is a `pass` that carries no information.
    #:
    #: Recorded rather than repaired, deliberately. Narrowing the fallback would change the
    #: acceptance rate mid-measurement and destroy comparability with everything already
    #: recorded; and the SIZE of this bucket is itself a finding — "N% of accepted patches
    #: were checked against a criterion their algorithm could not fail" says more about
    #: automated migration tooling than any acceptance rate does. It is countable now, which
    #: is the precondition for reporting it and then fixing it.
    vacuous: bool = False

    def as_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "status": self.status,
            "detail": self.detail[:4096],
            "duration_s": round(self.duration_s, 3),
        }
        if self.vacuous:
            # Only written when true, so the key's presence is the query: existing records
            # predate the flag and must not be read as "measured, and not vacuous".
            record["vacuous"] = True
        return record


#: The evidence ladder. Each rung is a strictly stronger statement than the one below it, and a
#: patch is recorded at the highest rung whose gates ACTUALLY RAN AND PASSED.
#:
#: This exists because `passed: bool` collapsed six very different states into one word, and that
#: is why the old headline number could not be defended: 216 of 216 accepted patches were flagged
#: `partial`, 20 were accepted with every stage skipped, and `tests` had never run on a single one
#: — 0 of 292. "74% passed validation" was a claim about a gate, not about a migration.
#:
#: Read the rungs as: L0 the diff is well formed and the result parses · L1 names resolve and the
#: module loads · L2 the SCANNER's opinion changed (compatible with a reused nonce or a dropped
#: auth tag) · L3 the primitive demonstrably works AND demonstrably fails when it should · L4
#: behaviour preserved on lines the project's own suite executes.
_EVIDENCE_LADDER: tuple[tuple[int, tuple[str, ...]], ...] = (
    (0, ("applies", "parses")),
    (1, ("symbols", "compiles")),
    (2, ("rescan",)),
    (3, ("behaves",)),
    (4, ("tests",)),
)

#: Nothing was established. Distinct from level 0, which is a real claim about the diff.
NO_EVIDENCE = -1


def evidence_level(stages: dict[str, StageResult]) -> int:
    """The highest ladder rung whose gates all passed, or `NO_EVIDENCE`.

    A `skipped` gate caps the level and never counts as a pass — that equivalence is the single
    assumption that produced every inflated number this project has had to retract. A gate that
    did not run has established nothing, and saying so costs a smaller number and buys a
    defensible one.
    """
    reached = NO_EVIDENCE
    for rung, names in _EVIDENCE_LADDER:
        gates = [stages.get(name, StageResult("skipped")) for name in names]
        # A vacuous gate is a pass that could not have been a fail, so it is worth exactly as
        # much as a skip. Admitting it here is how a criterion the asset satisfies by
        # construction turns into a claim that the migration was verified.
        if all(g.status == "pass" and not g.vacuous for g in gates):
            reached = rung
        else:
            break
    return reached


@dataclass
class ValidationReport:
    stages: dict[str, StageResult] = field(default_factory=dict)
    passed: bool = False
    partial: bool = False

    @property
    def evidence_level(self) -> int:
        """See `evidence_level`. Derived rather than stored so it can never disagree with the
        stages it is computed from."""
        return evidence_level(self.stages)

    def as_dict(self) -> dict[str, Any]:
        return {
            "stages": {k: v.as_dict() for k, v in self.stages.items()},
            "passed": self.passed,
            "partial": self.partial,
            # Reported alongside `passed`, not instead of it, so existing readers keep working
            # while the honest number becomes available. Anything reporting an acceptance RATE
            # should report the distribution of this instead.
            "evidence_level": self.evidence_level,
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
    # `x509` joins these for the same reason the others are here: a certificate is not source, has
    # no grammar to parse it, and nothing in the syntax or sandbox stages can say anything true
    # about it. cert-pqc-01 resolves to a guided path, never to a patch.
    {"nginx", "apache", "httpd", "sshd_config", "ssh_config", "config", "manifest", "x509", ""}
)

#: Non-code languages the SCANNER can still read, mapped to the extension it dispatches on.
#:
#: `parses` and `compiles` must skip these — there is no grammar and no single-file compiler. But
#: `rescan` needs neither: it needs a file the scanner will pick up. Conflating the two capabilities
#: cost real evidence. Measured on the live database: 11 nginx/apache TLS-config patches were
#: APPLIED having established nothing whatsoever, because `_stage_rescan` consulted
#: `LANGUAGE_TO_EXT` (a source-file map) and skipped when the language was not in it — even though
#: the scanner had found the weak TLS asset in that very file moments earlier.
#:
#: Config hardening is the highest-value transform QUBIT performs, since one `ssl_conf_command`
#: line turns on X25519MLKEM768 for all traffic. It was also the least verified.
_CONFIG_LANGUAGE_TO_EXT: dict[str, str] = {
    "nginx": ".conf",
    "apache": ".conf",
    "httpd": ".conf",
    "config": ".conf",
    "sshd_config": ".conf",
    "ssh_config": ".conf",
}

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


#: Every stage `validate_patch` reports, in the order it runs them.
#:
#: Declared once so anything describing the gate reads it from here rather than restating it. The
#: evidence pack's truth table enumerates 3**len(STAGE_NAMES) combinations and was hardcoded to five
#: stages, so it silently kept asserting soundness over 243 of the 729 that exist once `symbols` was
#: added — a documented "all combinations were evaluated" claim that had quietly stopped being true.
STAGE_NAMES: tuple[str, ...] = (
    "applies",
    "parses",
    "symbols",
    "compiles",
    # Between `compiles` and `tests` deliberately. `compiles` establishes that the module loads;
    # `behaves` asks whether the cryptography it loaded actually works. It sits BELOW `tests` on
    # the evidence ladder because a project suite is a stronger statement — and ABOVE it in build
    # order because `behaves` needs no project dependencies, no coverage and no maintainer-written
    # tests, so it is available for EVERY finding rather than the subset somebody happened to
    # exercise.
    "behaves",
    "tests",
    "rescan",
)

#: Languages whose compiler REFUSES a source file with an import it never uses. Everywhere else
#: this is a lint warning at most (Python F401, Java/Rust/C# warnings), so it must not fail a
#: patch — see `_stage_symbols`. A language property, deliberately not a judgement about style.
_UNUSED_IMPORT_IS_AN_ERROR = frozenset({"go"})


def _stage_symbols(
    patched_source: str,
    language: str = "python",
    original_source: str | None = None,
) -> StageResult:
    """Does the patch still resolve its own names? The semantic check that is not language-locked.

    `compiles` needs a toolchain in a Docker image, and `_COMPILE_SANDBOX` has five entries — so
    for Go, Java, Rust, C#, Kotlin, Swift, Scala, Dart and TypeScript it SKIPS, and a skipped
    stage counts as a pass. That left `parses` as the only real check for those languages, and
    tree-sitter answers a much weaker question than it appears to: `mldsa65.PublicKey` is
    syntactically perfect whether or not `mldsa65` is imported.

    Measured on the go-ethereum ML-DSA migration, which QUBIT reported as "31 changes prepared and
    validated": 23 of the 27 written files did not compile. The dominant failure was the model
    "removing ECDSA" by deleting the `ecdsa`/`elliptic`/`big` import lines while leaving every
    call that used them, plus imports it added and never referenced — in Go an unused import is a
    compile ERROR, not a warning. Every one of those passed `applies`, `parses` and `rescan`.

    Both halves are diffed against the ORIGINAL file rather than judged absolutely, which is what
    makes this safe to run on real code: `t.Run`, `err.Error` and `conn.Read` look exactly like
    package references to any regex, but they appear in both versions and cancel out. Only what
    the patch newly broke is reported.
    """
    t0 = time.monotonic()
    lang = (language or "").lower()
    if lang in _NON_CODE_LANGUAGES or lang not in TS_GRAMMAR:
        return StageResult(
            "skipped",
            f"{lang or 'unknown'} has no grammar to resolve symbols against",
            time.monotonic() - t0,
        )
    if original_source is None:
        # Without a baseline this cannot separate "the patch broke it" from "it was always so".
        return StageResult(
            "skipped", "no original source to compare against", time.monotonic() - t0
        )

    # Safety valve. If import extraction finds nothing in a file that plainly imports something,
    # this grammar's import nodes are not mapped well enough to judge it — and then EVERY newly
    # added qualifier looks unresolved, so a perfectly correct patch that adds a package and its
    # import would be rejected. Skipping is the honest answer; the alternative is a confident
    # wrong one.
    if not _import_names(original_source, lang) and not _import_names(patched_source, lang):
        return StageResult(
            "skipped",
            f"no imports could be read from this {lang} file, so symbol resolution cannot judge it",
            time.monotonic() - t0,
        )

    new_unresolved = sorted(
        unresolved_qualifiers(patched_source, lang) - unresolved_qualifiers(original_source, lang)
    )
    new_unused = sorted(
        unused_imports(patched_source, lang) - unused_imports(original_source, lang)
    )

    problems = []
    # An unresolved name is a hard error in EVERY language: the compiler, interpreter or runtime
    # has nothing to bind it to.
    if new_unresolved:
        problems.append(
            f"uses {', '.join(new_unresolved)} but the patch does not import "
            f"{'it' if len(new_unresolved) == 1 else 'them'} — if you replace an algorithm you "
            f"must add its import, and if you keep using one you must not delete its import"
        )
    # An unused import is NOT universally an error, and failing a working migration over a lint
    # nit is the same over-strict-gate mistake that wasted three model attempts per finding
    # elsewhere. Measured: the argon2 codemod correctly rewrites the only `hashlib.sha1` call and
    # leaves `import hashlib` behind — dead, untidy, and completely valid Python. Rejecting that
    # patch would throw away a correct migration. In Go the same leftover will not compile.
    if new_unused and lang in _UNUSED_IMPORT_IS_AN_ERROR:
        problems.append(
            f"imports {', '.join(new_unused)} without ever using "
            f"{'it' if len(new_unused) == 1 else 'them'}, which {lang} rejects at compile time"
        )
    if problems:
        return StageResult("fail", "; ".join(problems), time.monotonic() - t0)
    note = "every name the patch introduces resolves"
    if new_unused:
        note += f" (leaves {', '.join(new_unused)} imported but unused, which {lang} allows)"
    return StageResult("pass", note, time.monotonic() - t0)


def _scan_command(target: Path) -> list[str]:
    """The command that runs the scanner's public CLI over ``target``.

    Stage 5 deliberately goes through the ``qubit scan`` **CLI** rather than importing
    qubit-scanner, because doc 03 §2 forbids qubit-migrate from importing scanner internals — the
    CLI is the public interface. The argv-building itself lives in `scanner_cli`, shared with the
    target-shape lookup that asks the same CLI what a migrated state looks like.
    """
    return cli_command("scan", str(target), "--json")


def _scan_source(source: str, ext: str) -> list[dict[str, Any]]:
    """Scan one in-memory source through the scanner's public CLI. [] when it cannot be read."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_file = Path(tmpdir) / f"probe{ext}"
        # `newline="\n"` — every reader in this codebase uses `Path.read_text()`, whose universal
        # newline translation strips `\r`, so `source` is always LF-only here. Without pinning the
        # write side too, `write_text`'s default (`newline=None`) re-encodes those `\n` as
        # `os.linesep` — CRLF on Windows — which the scanner/tree-sitter would then read back
        # differently than the real repo file this probe is meant to stand in for.
        tmp_file.write_text(source, encoding="utf-8", newline="\n")
        try:
            result = subprocess.run(
                _scan_command(tmp_file),
                capture_output=True,
                timeout=60,
                cwd=str(Path(__file__).parents[6]),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return []
        raw = result.stdout.decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # exit code 3 means no assets found — an empty inventory, not a failure
            return []
    assets = data.get("assets", [])
    return [a for a in assets if isinstance(a, dict)]


def _occurrence_survived(
    *,
    still_present: list[dict[str, Any]],
    gone_prefix: str,
    patched_source: str,
    original_source: str | None,
    asset_line: int | None,
    ext: str,
) -> str | None:
    """Did THIS task's finding survive the patch? A detail string if so, None if it went away.

    Other findings of the same algorithm elsewhere in the file are other tasks, each with its own
    patch, and holding this one responsible for them makes every task in a mixed file unsatisfiable.
    """
    lines_preserved = original_source is not None and len(original_source.splitlines()) == len(
        patched_source.splitlines()
    )

    if asset_line is not None and lines_preserved:
        # Exact, when it applies: a token swap does not move code, so the flagged line is still the
        # flagged line.
        at_line = [a for a in still_present if a.get("location", {}).get("line") == asset_line]
        if at_line:
            return (
                f"Expected {gone_prefix!r} gone from line {asset_line}, but it is still there: "
                f"{sorted({str(a.get('algorithm', '')) for a in at_line})}"
            )

    if original_source is None:
        # No baseline to compare against: fall back to the original whole-file rule rather than
        # passing something unverified.
        return (
            f"Expected {gone_prefix!r} gone, but still found: "
            f"{sorted({str(a.get('algorithm', '')) for a in still_present})}"
        )

    # The line check alone is not enough, and the difference is a real one: a rewrite that MOVES the
    # algorithm to another line leaves the flagged line clean while changing nothing that matters.
    # The count has to fall as well — this patch is responsible for exactly one occurrence, and it
    # must have removed it.
    before = [
        a
        for a in _scan_source(original_source, ext)
        if str(a.get("algorithm", "")).startswith(gone_prefix)
    ]
    if len(still_present) < len(before):
        return None
    return (
        f"Expected {gone_prefix!r} gone, but the patch removed none of it: "
        f"{len(before)} occurrence(s) before, {len(still_present)} after "
        f"({sorted({str(a.get('algorithm', '')) for a in still_present})})"
    )


#: Image for the metamorphic harness. It needs the crypto library the target algorithm lives in,
#: which `python:3.12-slim` does not carry — so this is a separate image from `_COMPILE_SANDBOX`,
#: built from `qubit-v2/02-verification/Dockerfile.oracle`.
#:
#: Never pulled. QUBIT is offline by mandate, so the stage skips with the build command rather than
#: fetching anything, exactly as `compiles` does.
#: Environment override, so a corpus image can supply the imports the patched module needs.
_ORACLE_IMAGE_ENV = "QUBIT_MIGRATE_ORACLE_IMAGE"

#: A host directory mounted read-only and put on `PYTHONPATH` inside the oracle container.
#:
#: The harness writes the patched file to a temp dir and mounts only that, which is right for
#: exercising a primitive in isolation — but a patched module that imports its OWN package cannot
#: resolve it, and the stage skips with `ModuleNotFoundError: <the corpus>`. Measured on Flexget:
#: 6 of 8 patches skipped for exactly that reason once the third-party imports were satisfied.
#:
#: Pointing this at the corpus root lets those modules import, so the relations can actually run.
#: The tree is mounted READ-ONLY and the patched file still comes from the temp dir, so the thing
#: under test remains the patch rather than whatever is on disk.
_ORACLE_PYPATH_ENV = "QUBIT_MIGRATE_ORACLE_PYPATH"

_DEFAULT_ORACLE_IMAGE = "qubit-eval/oracle:py312"


def _oracle_image() -> str:
    """The image the metamorphic harness runs in. Overridable, and it has to be.

    The default carries the crypto library and nothing else, so a patched module importing anything
    of its own -- loguru, psutil, feedparser -- fails at import and the stage skips with
    `patched module did not import`.

    Measured across every arm on both corpora: `behaves` skipped on **39 of 39** patches, and 11 of
    those were exactly this, on Flexget patches whose SHA-1-to-SHA-256 transformation the relations
    DO cover. The oracle was never given the chance to answer. The env override points it at a
    corpus image that carries those imports.
    """
    return os.getenv(_ORACLE_IMAGE_ENV) or _DEFAULT_ORACLE_IMAGE


#: Families whose admission controls have been verified IN THIS PROCESS, and the report that says
#: so. Process-level because what is being established is a property of this image and this
#: installed library, neither of which can change mid-run.
#:
#: `None` means "not yet attempted". An empty frozenset AFTER an attempt means the controls ran and
#: did not behave -- a very different state, and one that must not be retried per patch: a broken
#: oracle does not become correct on the ninth attempt, and re-running ten container pairs for
#: every finding would cost more than the migrations do.
_verified_families: frozenset[str] | None = None
_control_report: ControlReport | None = None


def _oracle_pypath_args() -> list[str]:
    """Mount the corpus tree and expose it on `PYTHONPATH`, when one is configured.

    Returns nothing when unset, so the default behaviour — an isolated temp dir — is unchanged.
    """
    root = os.getenv(_ORACLE_PYPATH_ENV)
    if not root or not Path(root).is_dir():
        return []
    return ["-v", f"{Path(root).resolve()}:/src:ro", "-e", "PYTHONPATH=/src:/src/src"]


def _run_oracle(source: str, target: str, usage_context: str, construction: str) -> dict[str, Any]:
    """Render and execute the harness once. The single path both controls and patches take.

    Shared deliberately. A control that exercised a different code path from the thing it licenses
    would establish nothing about it, which is the same error as trusting a gate that never ran.
    """
    plan = build_harness(relations_for(usage_context, construction), source, target)
    if not plan.runnable:
        return {"status": "skipped", "reason": plan.skip_reason, "relations": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        work = Path(tmpdir)
        # `newline="\n"`: bind-mounted into a Linux container, and Python's default re-encoding to
        # CRLF on Windows breaks the harness exactly as it broke shell scripts in `_stage_compiles`.
        (work / "patched.py").write_text(source, encoding="utf-8", newline="\n")
        (work / "harness.py").write_text(plan.source, encoding="utf-8", newline="\n")
        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none",
                    "--memory=1g",
                    "--cpus=1",
                    "--pids-limit=128",
                    "-v",
                    f"{tmpdir}:/work:ro",
                    *_oracle_pypath_args(),
                    _oracle_image(),
                    "python",
                    "/work/harness.py",
                ],
                capture_output=True,
                timeout=90,
            )
        except subprocess.TimeoutExpired:
            # Not a behavioural difference. Inconclusive rather than `fail`, for the same reason a
            # slow-but-green test suite must not be scored as a patch failure.
            return {
                "status": "skipped",
                "reason": "the metamorphic harness timed out",
                "relations": [],
            }

    raw = result.stdout.decode("utf-8", errors="replace").strip().splitlines()
    if not raw:
        return {
            "status": "skipped",
            "reason": "the harness produced no verdict: "
            + result.stderr.decode("utf-8", errors="replace")[:300],
            "relations": [],
        }
    try:
        verdict: dict[str, Any] = json.loads(raw[-1])
    except json.JSONDecodeError:
        return {
            "status": "skipped",
            "reason": f"unreadable harness verdict: {raw[-1][:200]}",
            "relations": [],
        }
    return verdict


def verified_families() -> frozenset[str]:
    """Families the admission controls have licensed, running them once if needed.

    Until a family's two controls have both behaved, `behaves` reports `skipped` for it rather than
    `pass`. That is the whole point: an oracle nobody has proven can FAIL is indistinguishable from
    one that passes everything, and counting its verdicts as evidence is how a measurement becomes
    unfalsifiable. See `oracles/controls.py`.
    """
    global _verified_families, _control_report
    if _verified_families is not None:
        return _verified_families
    if not _docker_available() or not _image_present(_oracle_image()):
        # Not a control failure -- the oracle cannot run at all, which the stage reports on its own
        # with the build command. Left unset so it is retried if the image later appears.
        return frozenset()
    _control_report = run_controls(_run_oracle)
    _verified_families = _control_report.families
    return _verified_families


def control_report() -> ControlReport | None:
    """The published control artifact, or None if the controls have not been run.

    Published, not internal. Without it every `behaves` number in the paper is unfalsifiable: a
    reader has no way to tell a gate that discriminates from one that says yes to everything.
    """
    return _control_report


def _stage_behaves(
    patched_source: str,
    rule: Any | None,
    language: str,
    usage_context: str | None,
    construction: str = "pure",
) -> StageResult:
    """Does the migrated primitive actually work, and does it fail when it should?

    Every gate before this one asks a question about the TEXT of the patch. This one runs the
    cryptography the patch installed and checks metamorphic relations against it — a round trip
    that must hold, and rejections that must happen.

    The negatives are why this is an oracle rather than a smoke test. Measured on a deliberately
    broken patch that passes `applies`, `parses`, `symbols`, `compiles` and `rescan`: a signature
    scheme whose `verify` accepts anything and whose `sign` returns bytes of exactly the right
    length, so even the size advisory reads correct. Its round-trip relation PASSES. Only
    `sig-wrong-key`, `sig-tampered-message` and `sig-truncated` catch it.

    Runs in a container because it imports and executes model-generated code. Doing that on the
    host would be the one place QUBIT ran an LLM's output directly, which is exactly what the
    sandbox exists to prevent.
    """
    t0 = time.monotonic()

    if (language or "").lower() != "python":
        return StageResult(
            "skipped",
            f"the metamorphic harness has probed API shapes for Python only, not {language}",
            time.monotonic() - t0,
        )

    target = ""
    if rule is not None:
        target = str((getattr(rule, "target", None) or {}).get("algorithm") or "")
    if not target:
        return StageResult(
            "skipped", "the rule declares no target algorithm to exercise", time.monotonic() - t0
        )

    relation_set = relations_for(usage_context, construction)
    plan = build_harness(relation_set, patched_source, target)
    if not plan.runnable:
        # Never `pass`. An oracle that did not run has established nothing, and recording that as
        # success is the exact failure the admission controls exist to catch.
        return StageResult("skipped", plan.skip_reason, time.monotonic() - t0)

    if not _docker_available():
        return StageResult("skipped", "docker unavailable", time.monotonic() - t0)
    if not _image_present(_oracle_image()):
        return StageResult(
            "skipped",
            f"oracle image {_oracle_image()} is not built (QUBIT never pulls one itself) — run: "
            f"docker build -t {_oracle_image()} -f qubit-v2/02-verification/Dockerfile.oracle .",
            time.monotonic() - t0,
        )

    # THE ADMISSION GATE. A family whose controls have not both behaved cannot award evidence,
    # however green its own relations come back. An oracle that reports `pass` for everything looks
    # exactly like a working one from the outside; the controls are the only thing that tells the
    # two apart, and running them once per process costs ten containers against thousands of
    # findings.
    if relation_set.family not in verified_families():
        return StageResult(
            "skipped",
            f"the admission controls have not licensed the {relation_set.family!r} family, so its "
            "verdicts are not evidence — see oracles/controls.py",
            time.monotonic() - t0,
        )

    verdict = _run_oracle(patched_source, target, usage_context or "", construction)

    status = str(verdict.get("status", "skipped"))
    relations = verdict.get("relations") or []
    ran = ", ".join(f"{r.get('id')}={r.get('outcome')}" for r in relations)
    if status == "pass":
        detail = f"{len(relations)} relations held ({ran})"
    elif status == "fail":
        detail = f"{verdict.get('reason', '')} [{ran}]"
    else:
        detail = str(verdict.get("reason", ""))

    # Narrowed explicitly rather than cast: the harness is a subprocess and its status is whatever
    # JSON it printed. Anything this code does not recognise becomes `skipped`, never `pass` -- an
    # unrecognised verdict has established nothing.
    outcome: StageStatus = "skipped"
    if status == "pass":
        outcome = "pass"
    elif status == "fail":
        outcome = "fail"
    return StageResult(outcome, detail, time.monotonic() - t0)


def _stage_rescan(
    patched_source: str,
    rule: Any | None,
    language: str = "python",
    asset_algorithm: str | None = None,
    original_source: str | None = None,
    asset_line: int | None = None,
    target_rel_path: str | None = None,
) -> StageResult:
    """Run qubit scan --json on the patched source and check rescan_expect.

    ``asset_algorithm`` scopes the ``gone`` check to the algorithm this patch was migrating. Without
    it the check asserted that no listed weak algorithm appears anywhere in the file, which fails
    whenever a file mixes usages that different rules own — an MD5 digest beside an HMAC-SHA1 and a
    SHA-1 signature is ordinary code, and `code-weakhash-02` is responsible for exactly one of the
    three.

    ``asset_line`` and ``original_source`` narrow it the rest of the way, from "this algorithm" to
    "this occurrence of it". One file routinely holds several findings of the SAME algorithm — the
    polyglot corpus has three MD5 findings in one SQL file and two in one C# file — and each is a
    separate task. Requiring all of them to vanish made every one of those tasks fail, including the
    ones whose own occurrence the patch had migrated correctly. See ``_occurrence_survived``.
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
    ext = LANGUAGE_TO_EXT.get(language) or _CONFIG_LANGUAGE_TO_EXT.get(language)
    if ext is None:
        return StageResult(
            "skipped",
            f"no scanner file extension known for language {language!r} — cannot rescan safely",
            time.monotonic() - t0,
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        # The original BASENAME, not just the extension. The scanner's config dispatch is
        # name-sensitive — `options-ssl-apache.conf` routes to the Apache parser because "apache"
        # is in its name, and `sshd_config` to the OpenSSH one — so writing every patch to
        # `patched.conf` sends an Apache file to nginx's stricter grammar and loses detections that
        # the scan which produced the finding had made. Source languages are unaffected: their
        # dispatch is by suffix, and the suffix is preserved either way.
        name = Path(target_rel_path).name if target_rel_path else ""
        tmp_file = Path(tmpdir) / (name if name and Path(name).suffix == ext else f"patched{ext}")
        tmp_file.write_text(patched_source, encoding="utf-8", newline="\n")

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

            # A HYBRID TARGET INVERTS THE EXPECTATION FOR ITS CLASSICAL HALF.
            #
            # For a pure migration, "ECDSA is gone" is success. For `ML-DSA-65+ECDSA-P256` it is
            # the opposite: the classical component must SURVIVE, because a composite that keeps
            # only the lattice half protects against nothing an implementation flaw in that half
            # would expose -- which is the entire reason BSI and ANSSI require hybrid.
            #
            # Left unhandled, the gate rewarded exactly the wrong patch. A rewrite that dropped
            # the classical signature satisfied `gone: ECDSA` and was ACCEPTED, while the correct
            # composite -- which necessarily still contains ECDSA -- was REJECTED. The tool would
            # have driven every hybrid migration toward the non-compliant outcome, and reported
            # success for it.
            components = hybrid_components(
                str(((getattr(rule, "target", None) or {}).get("algorithm")) or "")
            )
            if components is not None:
                pqc, classical = components
                # Both halves must be detectable afterwards. Requiring only the PQC one would
                # accept the same broken patch by a different route.
                for half in (pqc, classical):
                    if not any(half.upper().startswith(p.upper()) for p in present_prefixes):
                        present_prefixes.append(half)
                # And the classical half is no longer something to be rid of.
                gone_prefixes = [
                    p for p in gone_prefixes if not classical.upper().startswith(p.upper())
                ]

            # Narrow `gone` to the prefixes that actually describe THIS patch's algorithm. A rule
            # lists every algorithm it can migrate; one patch migrates one of them, and the others
            # may legitimately still be in the file under a usage this rule does not own.
            # Set when the `gone` check cannot be failed by this asset — see StageResult.vacuous.
            vacuous = False
            if asset_algorithm and gone_prefixes:
                matching = [p for p in gone_prefixes if asset_algorithm.startswith(p)]
                if matching:
                    gone_prefixes = matching
                else:
                    # Falls through to the full list, unchanged. The asset satisfies it by
                    # construction — its algorithm is not among the ones being checked for.
                    vacuous = True

            for gone_prefix in gone_prefixes:
                surviving = [
                    a for a in assets if str(a.get("algorithm", "")).startswith(gone_prefix)
                ]
                if not surviving:
                    continue
                detail = _occurrence_survived(
                    still_present=surviving,
                    gone_prefix=gone_prefix,
                    patched_source=patched_source,
                    original_source=original_source,
                    asset_line=asset_line,
                    ext=ext,
                )
                if detail is not None:
                    return StageResult(
                        "fail",
                        detail,
                        time.monotonic() - t0,
                        expectation="gone",
                        expected=gone_prefix,
                    )
            # `weakness_gone`: the expectation for a rule whose finding is a property of the
            # CALL rather than the algorithm. An ECB migration leaves AES in the file - that is
            # the point, AES is not the problem - so neither `gone` nor `present` can express
            # "this is no longer ECB". Checking the weakness the scanner re-derives from the
            # patched source is the only expectation that actually verifies such a fix.
            for weakness_id in _prefixes(expect.get("weakness_gone", "")):
                surviving_weak = [
                    a
                    for a in assets
                    if weakness_id
                    in {
                        w.get("id")
                        for w in (
                            ((a.get("evidence") or {}).get("context") or {}).get("extra") or {}
                        ).get("weaknesses", [])
                        if isinstance(w, dict)
                    }
                ]
                if surviving_weak:
                    lines = sorted(
                        str((a.get("location") or {}).get("line")) for a in surviving_weak
                    )
                    return StageResult(
                        "fail",
                        f"Expected the {weakness_id!r} weakness to be gone, but it is still "
                        f"present at line(s) {', '.join(lines)}",
                        time.monotonic() - t0,
                        expectation="weakness_gone",
                        expected=weakness_id,
                    )
            if components is not None:
                # EVERY half, not any. The "any one satisfies it" rule below exists because a rule
                # may offer several ACCEPTABLE ALTERNATIVES; a composite's two halves are not
                # alternatives, they are both required, and reading them as alternatives accepts a
                # patch that shipped one of them.
                for half in components:
                    if not any(a.upper().startswith(half.upper()) for a in algos):
                        return StageResult(
                            "fail",
                            f"{half!r} is missing after a migration to a composite target. Both "
                            f"halves of {components[0]}+{components[1]} must be present — a "
                            f"composite carrying only one of them satisfies the hybrid mandate on "
                            f"paper and provides none of the defence in depth it exists for. "
                            f"Algorithms: {algos}",
                            time.monotonic() - t0,
                            expectation="present",
                            expected=half,
                        )
            # Any ONE of the listed prefixes satisfies the expectation: a rule may offer several
            # acceptable targets (ML-KEM or a hybrid group), and requiring all of them at once would
            # reject a correct migration that picked one.
            elif present_prefixes and not any(a.startswith(tuple(present_prefixes)) for a in algos):
                return StageResult(
                    "fail",
                    f"Expected one of {present_prefixes!r} present, but not found. "
                    f"Algorithms: {algos}",
                    time.monotonic() - t0,
                    expectation="present",
                    expected=present_prefixes[0],
                )
            # `vacuous` rides on the PASS, which is the only place it matters: a fail is
            # informative whatever the prefixes were, and a pass on an unfailable criterion
            # is the thing that must never be counted as evidence.
            return StageResult(
                "pass",
                (
                    f"rescan ok, but the 'gone' criterion does not name {asset_algorithm!r} "
                    f"so it could not have failed. algorithms: {algos}"
                    if vacuous
                    else f"rescan ok. algorithms: {algos}"
                ),
                time.monotonic() - t0,
                vacuous=vacuous,
            )

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
        # `newline="\n"` — without it, `write_text`'s default re-encodes `patched_source`'s `\n`
        # as `os.linesep` (CRLF on Windows) before this file is bind-mounted into the Linux
        # sandbox. A shell script then fails with a bogus syntax error on every `do`/`then`
        # keyword (`$'do\r''`) — the CRLF is an artifact of the HOST write, not a defect in the
        # patch. Found live on OpenSSL's `util/analyze-contention-log.sh`.
        (Path(tmpdir) / filename).write_text(patched_source, encoding="utf-8", newline="\n")
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


#: Filename the JSON report is written to inside the sandbox, then read back from the copy.
_REPORT_NAME = ".qubit-pytest-report.json"


@dataclass(frozen=True)
class _Baseline:
    """What the project's own suite does BEFORE any patch is applied.

    `passing` is the set of node ids that pass. It is what turns this stage from "did the exit code
    change" into "did anything that worked stop working", and that distinction is the whole game: a
    real repository almost always has a handful of tests that cannot run in an offline sandbox, and
    under a plain exit-code comparison one of those made the entire stage `skipped` and discarded
    the evidence from the other several thousand tests.
    """

    passing: frozenset[str]
    collected: int
    green: bool


#: Baseline per (image, repo_root). It is byte-identical for every patch in a run, and re-deriving
#: it per patch doubled the most expensive operation in the pipeline to re-learn the same fact --
#: at 150 findings across 5 experiment arms, 750 suite runs of pure waste.
_BASELINE_CACHE: dict[tuple[str, str], _Baseline | None] = {}

#: Directories that must never be copied into the sandbox. A stray local virtualenv turns a
#: per-patch tree copy into minutes of pure I/O, and this runs once per patch per arm.
_COPY_IGNORES = shutil.ignore_patterns(
    # `.git` is deliberately NOT ignored. A large share of Python projects derive their version
    # from git at import time -- `versioningit` and `setuptools_scm` between them cover most of it
    # -- and with the repository uninstalled from the image (which it must be, or the overlaid file
    # is never read) that derivation is the only thing left. Measured on streamlink: without the
    # git directory, `import streamlink` raised `ModuleNotFoundError: No module named
    # 'versioningit'` from its own `_version.py`, so the suite could not start and no patch could
    # ever be judged. The cost is bounded -- 756K for tornado, 1.2M for streamlink, 89M for the
    # largest repository in the corpus -- and it is paid once per patch against a container run
    # measured in minutes.
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "htmlcov",
    "*.egg-info",
)


def _kill_container(name: str) -> None:
    """`subprocess.run(timeout=)` kills the docker CLIENT, not the container it started.

    Without this a timed-out suite keeps running, holding its CPU reservation, and every later run
    on the machine looks slower than it is -- which silently corrupts any timing comparison
    between experiment arms.
    """
    with contextlib.suppress(subprocess.TimeoutExpired, OSError):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)


def _docker_run(work: Path, image: str, shell_cmd: str, timeout_s: float) -> tuple[int, str]:
    """One sandboxed command. Offline, resource-capped, and killable."""
    name = f"qubit-tests-{uuid.uuid4().hex[:12]}"
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        # The offline mandate. Also the reason a suite needing DNS shows up as a baseline failure
        # rather than as evidence against a patch.
        "--network=none",
        # Not paranoia: without a CPU cap the `duration_s` this stage reports is a function of
        # whatever else the machine is doing, and the timings stop being comparable across arms.
        "--memory=2g",
        "--cpus=2",
        "--pids-limit=512",
        # The image deliberately does NOT install the project -- if it did, `import pkg` would
        # resolve to site-packages and the overlaid file would never be read, so every patch would
        # score as behaviour-preserving. That makes the import path this stage's responsibility.
        #
        # `-w /work` alone only covers a FLAT layout, where `python -m pytest` puts the working
        # directory on `sys.path`. A `src/` layout has nothing importable at /work at all, and the
        # oracle controls said so plainly: on streamlink, `import streamlink` inside the sandbox
        # raised ModuleNotFoundError, so the suite could not run and not one patch was ever judged.
        # Both roots are listed because both layouts occur; a missing directory on PYTHONPATH is
        # ignored by the interpreter, so this is safe for either.
        "-e",
        "PYTHONPATH=/work/src:/work",
        "-v",
        f"{work}:/work",
        "-w",
        "/work",
        image,
        "sh",
        "-c",
        shell_cmd,
    ]
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_container(name)
        raise
    return result.returncode, result.stdout.decode("utf-8", errors="replace")


def _pytest_report(work: Path) -> tuple[frozenset[str], int] | None:
    """Passing node ids and the collected count from `--json-report`, or None if unavailable.

    None is not a failure -- it means the image cannot produce a per-test report (no pytest, or no
    `pytest-json-report`), and the caller falls back to comparing exit codes.
    """
    path = work / _REPORT_NAME
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    tests = data.get("tests")
    if not isinstance(tests, list):
        return None
    passing = frozenset(
        str(t.get("nodeid"))
        for t in tests
        if isinstance(t, dict) and t.get("outcome") == "passed" and t.get("nodeid")
    )
    return passing, len(tests)


def _run_suite(
    work: Path, image: str, command: str, timeout_s: float, *, fail_fast: bool = False
) -> tuple[int, str, tuple[frozenset[str], int] | None]:
    """Run the suite, preferring a per-test report and degrading gracefully when it is absent.

    `fail_fast` is for the BASELINE only, where the single bit "is it red" is all that is wanted.
    The patched run deliberately never uses `-x`: stopping at the first failure answers "something
    broke" but never "how much broke", and it cannot distinguish a patch that broke one test from
    one that broke the suite.
    """
    # `-p pytest_jsonreport` loads the plugin EXPLICITLY. Installing it is not enough: a
    # project that sets `--disable-plugin-autoload` in its own addopts -- streamlink does, and
    # it is a common choice for determinism -- leaves the plugin installed and unloaded, so
    # pytest answers "unrecognized arguments: --json-report" and the stage falls back to
    # comparing exit codes. That fallback then refuses any repository with a single
    # permanently-red test, which is exactly what the per-test set difference exists to
    # tolerate: streamlink has 7,228 passing tests and 4 that fail on the untouched tree.
    report_flag = f" -p pytest_jsonreport --json-report --json-report-file=/work/{_REPORT_NAME}"
    x_flag = " -x" if fail_fast else ""
    attempts = (
        f"{command}{x_flag}{report_flag} 2>&1",
        f"{command}{x_flag} 2>&1",
        "python -m unittest discover -s tests 2>&1",
    )
    code, out = 1, ""
    for index, shell_cmd in enumerate(attempts):
        (work / _REPORT_NAME).unlink(missing_ok=True)
        code, out = _docker_run(work, image, shell_cmd, timeout_s)
        parsed = _pytest_report(work)
        if parsed is not None:
            return code, out, parsed
        if "No module named pytest" in out:
            continue  # bare interpreter: fall through to the stdlib runner
        if index == 0 and "json-report" in out:
            continue  # pytest is there but the plugin is not: rerun without the flag
        return code, out, None
    return code, out, None


def _compute_baseline(
    repo_root: Path, image: str, command: str, timeout_s: float
) -> _Baseline | None:
    """What the untouched tree does. Computed once per (image, repo_root), then cached."""
    key = (image, str(repo_root))
    if key in _BASELINE_CACHE:
        return _BASELINE_CACHE[key]
    result: _Baseline | None = None
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            work = Path(tmpdir) / "repo"
            shutil.copytree(repo_root, work, ignore=_COPY_IGNORES)
            code, _out, parsed = _run_suite(work, image, command, timeout_s, fail_fast=False)
            if parsed is not None:
                passing, collected = parsed
                result = _Baseline(passing=passing, collected=collected, green=code == 0)
            else:
                result = _Baseline(passing=frozenset(), collected=0, green=code == 0)
    except (subprocess.TimeoutExpired, OSError, shutil.Error):
        result = None
    _BASELINE_CACHE[key] = result
    return result


#: Directories never worth walking when looking for tests -- vendored code and build output can
#: contain thousands of files and none of them are this repository's suite.
_TEST_SEARCH_SKIP = frozenset(
    {".git", ".tox", ".venv", "venv", "node_modules", "build", "dist", "__pycache__", ".mypy_cache"}
)


def _has_test_suite(repo_root: Path) -> bool:
    """Is there plausibly a suite here at all?

    A cheap pre-filter, not a verdict: it exists only to avoid paying for a container on a
    repository that obviously has no tests. Being slightly too generous costs one baseline run,
    which then finds nothing and skips honestly; being too strict costs the verdict entirely, with
    a message that reads as a property of the repository rather than of this function.

    It was too strict. Looking only at the repository ROOT missed wagtail -- a Django project whose
    tests live inside each app rather than in a top-level `tests/`, and which declares its runner in
    `tox.ini` -- and ansible, for the same reason. Measured on this installation: 16 of 84 patches
    were refused with "no test suite detected in repo" against repositories that unambiguously have
    one.
    """
    if (repo_root / "tests").is_dir() or (repo_root / "test").is_dir():
        return True
    for marker in ("pytest.ini", "setup.cfg", "tox.ini", "conftest.py", "pyproject.toml"):
        path = repo_root / marker
        if path.is_file() and (
            marker in ("pytest.ini", "conftest.py")
            or "pytest" in path.read_text(encoding="utf-8", errors="replace")
        ):
            return True
    # Nested suites: Django and Ansible both keep tests beside the code they cover. Bounded to three
    # levels and stopped at the first hit, so this stays a filter rather than a tree walk.
    for depth in range(1, 4):
        pattern = "/".join(["*"] * depth)
        for candidate in repo_root.glob(f"{pattern}/tests"):
            if candidate.is_dir() and not (_TEST_SEARCH_SKIP & set(candidate.parts)):
                return True
        for candidate in repo_root.glob(f"{pattern}/test_*.py"):
            if not (_TEST_SEARCH_SKIP & set(candidate.parts)):
                return True

    # Every marker above is a Python one, because this stage refused every other language outright
    # until the twins made that refusal measurable. The conventions below are each language's
    # standard location, so a project that follows its own ecosystem's layout is not told it has
    # "no test suite" on the strength of not being Python.
    for marker in ("pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Gemfile", "Rakefile"):
        if (repo_root / marker).is_file():
            return True
    for depth in range(0, 4):
        pattern = "/".join(["*"] * depth) + ("/" if depth else "")
        for glob in (f"{pattern}*_test.go", f"{pattern}*Test.java", f"{pattern}*_test.rb",
                     f"{pattern}test_*.rb"):
            for candidate in repo_root.glob(glob):
                if not (_TEST_SEARCH_SKIP & set(candidate.parts)):
                    return True
    return False


def _stage_tests(
    patched_source: str,
    repo_root: Path | None,
    target_rel_path: str | None,
    language: str = "python",
    original_source: str | None = None,
    image: str = _SANDBOX_IMAGE,
    command: str = "python -m pytest -q --continue-on-collection-errors",
    timeout_s: float = 300.0,
) -> StageResult:
    """Stage 4: copy the repo, overlay the patched file, run its own suite in the sandbox.

    This is the only stage in the pipeline that can tell you a migration PRESERVED BEHAVIOUR.
    Every other stage is syntactic: `rescan` says the scanner stopped seeing RSA and started
    seeing ML-KEM, which is equally true of a rewrite that reuses a nonce, drops an auth tag, or
    breaks every caller.

    Two things decide whether it is an oracle or theatre:

    * **The image.** A bare interpreter has no pytest and none of the repo's dependencies, so the
      suite dies on its own imports and this stage honestly declines to judge. Measured on this
      installation: 292 patches, 292 skips. `MigrateConfig.test_sandbox_image` points it at an
      image built from the target's pinned dependency spec.
    * **What the image must NOT contain: the project itself.** If it is installed, `import pkg`
      resolves to site-packages and the file overlaid into /work is never imported -- the stage
      then reports `pass` for every patch regardless of content. Verify with a mutation control
      before trusting a single number from it.

    The verdict is a per-test set difference, not an exit-code comparison: a patch fails when
    something that PASSED on the untouched tree stops passing. That is robust to the handful of
    tests a real repository cannot run offline, which under the old comparison made the whole
    stage `skipped` and discarded everything else.
    """
    t0 = time.monotonic()
    # This stage refused every non-Python language here, which made the strongest rung on the
    # evidence ladder unreachable for three of the four twins -- and, because a skipped rung still
    # counts as `passed`, patches were applied to Ruby, Go and Java on `parses` + `compiles` alone.
    # Measured on inkwell-esign: 6 of 14 findings were migrated against an explicit refusal, and
    # the twin's own suite went red. Nothing below this line is Python-specific: without a pytest
    # JSON report `parsed` is None and the verdict falls through to the exit-code comparison
    # against the untouched tree, which is language-agnostic and already implemented.
    if repo_root is None or target_rel_path is None or Path(target_rel_path).is_absolute():
        return StageResult("skipped", "no repo_root/relative target for test run", 0.0)
    if not _has_test_suite(repo_root):
        return StageResult("skipped", "no test suite detected in repo", 0.0)
    if not _docker_available():
        return StageResult("skipped", "docker unavailable", time.monotonic() - t0)
    # `_stage_compiles` has always guarded this; this stage did not, so `docker run` could silently
    # PULL -- from a tool whose stated promise is that your code never leaves the machine.
    if not _image_present(image):
        return StageResult(
            "skipped",
            f"sandbox image {image} is not pulled (QUBIT never downloads one itself) — "
            f"build or pull it first: docker pull {image}",
            time.monotonic() - t0,
        )

    baseline = _compute_baseline(repo_root, image, command, timeout_s)

    with tempfile.TemporaryDirectory() as tmpdir:
        work = Path(tmpdir) / "repo"
        shutil.copytree(repo_root, work, ignore=_COPY_IGNORES)
        target = work / target_rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(patched_source, encoding="utf-8", newline="\n")

        try:
            code, out, parsed = _run_suite(work, image, command, timeout_s)
        except subprocess.TimeoutExpired:
            # A timeout used to be scored `fail`, which called a slow-but-green suite a broken
            # patch. If the untouched tree cannot finish either, this says nothing about the patch.
            if baseline is None:
                return StageResult(
                    "skipped",
                    f"the suite did not finish within {timeout_s:.0f}s, and neither did the "
                    "untouched tree, so it says nothing about this change",
                    time.monotonic() - t0,
                )
            return StageResult(
                "fail", f"sandbox tests timed out after {timeout_s:.0f}s", time.monotonic() - t0
            )

        # ── The oracle proper: a per-test set difference against the untouched tree ──
        if parsed is not None and baseline is not None and baseline.collected > 0:
            patched_passing, collected = parsed
            regressions = sorted(baseline.passing - patched_passing)
            if regressions:
                shown = ", ".join(regressions[:10])
                more = f" (+{len(regressions) - 10} more)" if len(regressions) > 10 else ""
                return StageResult(
                    "fail",
                    f"{len(regressions)} test(s) that passed before this patch now do not: "
                    f"{shown}{more}",
                    time.monotonic() - t0,
                )
            if not baseline.passing:
                return StageResult(
                    "skipped",
                    "no test passes on the untouched tree in this sandbox, so the suite cannot "
                    "say anything about this change",
                    time.monotonic() - t0,
                )
            return StageResult(
                "pass",
                f"all {len(baseline.passing)} tests that passed before this patch still pass "
                f"({collected} collected)",
                time.monotonic() - t0,
            )

        # ── Fallback: no per-test report available, so compare exit codes ──
        if code == 0:
            return StageResult(
                "pass", out[:2048] or "tests green in sandbox", time.monotonic() - t0
            )
        # A red suite is only evidence against the PATCH if the same suite is green without it.
        # Measured on the real `requests` checkout: every test module failed with ImportError in a
        # bare offline sandbox and a perfectly good SHA-256 patch was rejected for it.
        if baseline is not None and not baseline.green:
            return StageResult(
                "skipped",
                "this suite does not run in the sandbox even before the patch "
                "(missing dependencies, no network), so it says nothing about this change",
                time.monotonic() - t0,
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
    asset_line: int | None = None,
    #: The finding's usage context and the plan's construction, which together select the
    #: metamorphic relation set. Optional so every existing caller keeps working: with no usage
    #: context no relation family claims the finding and `behaves` reports `skipped` — which is
    #: the honest answer, since an oracle that did not run has established nothing.
    usage_context: str | None = None,
    construction: str = "pure",
    test_sandbox_image: str = _SANDBOX_IMAGE,
    test_command: str = "python -m pytest -q --continue-on-collection-errors",
    test_timeout_s: float = 300.0,
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
    # Runs for EVERY language with a grammar, unlike `compiles` — which is what makes it the only
    # semantic check most languages ever get. See `_stage_symbols` for what it caught.
    stages["symbols"] = _stage_symbols(patched_source, language, original_source)
    if no_docker:
        stages["compiles"] = StageResult("skipped", "no_docker configured")
        stages["behaves"] = StageResult("skipped", "no_docker configured")
        stages["tests"] = StageResult("skipped", "no_docker configured")
    else:
        stages["compiles"] = _stage_compiles(patched_source, language)
        stages["behaves"] = _stage_behaves(
            patched_source, rule, language, usage_context, construction
        )
        stages["tests"] = _stage_tests(
            patched_source,
            repo_root,
            target_rel_path,
            language,
            original_source,
            image=test_sandbox_image,
            command=test_command,
            timeout_s=test_timeout_s,
        )
    stages["rescan"] = _stage_rescan(
        patched_source,
        rule,
        language,
        asset_algorithm,
        original_source=original_source,
        asset_line=asset_line,
        target_rel_path=target_rel_path,
    )

    # The gate's reported surface must match its declared one. Adding a stage without declaring it
    # is how the evidence pack's "all 243 combinations were evaluated" claim silently went stale.
    assert tuple(stages) == STAGE_NAMES, f"stages {tuple(stages)} != declared {STAGE_NAMES}"

    passed = all(v.status in ("pass", "skipped") for v in stages.values())
    partial = any(v.status == "skipped" for v in stages.values())

    return ValidationReport(stages=stages, passed=passed, partial=partial)


__all__ = ["STAGE_NAMES", "StageResult", "ValidationReport", "validate_patch"]
