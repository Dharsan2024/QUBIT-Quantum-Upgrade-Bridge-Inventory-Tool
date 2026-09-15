"""MigrationOrchestrator facade (doc 03 §5.2)."""

from __future__ import annotations

import contextlib
import functools
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Literal
from uuid import UUID

from qubit_core import CryptoAsset
from qubit_core.db import AssetRow, secrets_at_rest
from qubit_core.db.models import (
    DEFAULT_TENANT_ID,
    LearnedPatch,
    LlmEngine,
    LlmProviderConfig,
    ProjectRow,
    ScanRow,
)
from qubit_core.db.session import retry_write_on_lock
from qubit_core.mapping import row_to_asset
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from . import scheduling
from .config import MigrateConfig
from .graph import build_dependency_graph, migration_order
from .protocol_contract import external_contract
from .queue import rank_ready_frontier
from .regimes import load_regimes
from .state import (
    MigrationEvent,
    MigrationPlan,
    MigrationTask,
    MigrationUnit,
    PatchProposal,
    to_public_status,
    transition,
    write_event,
)
from .state.measurement import MigrationMeasurement
from .transform import (
    EditApplyError,
    ValidationReport,
    detect_line_ending,
    file_sha256,
    load_rules,
    match_rule,
    old_new_to_diff,
    restore_incidental_blank_lines,
    run_codemod,
    validate_patch,
)
from .transform.advise import generate_migration_advice
from .transform.languages import language_for_suffix
from .transform.llm import (
    _MAX_PREDICT,
    DEFAULT_BASE_URL,
    ExternalEndpoint,
    OllamaError,
    build_excerpt,
    current_ledger,
    generate_llm_source,
    start_ledger,
    unverifiable_reason,
)
from .transform.synthesized import recall_rule, remember_rule, synthesize_rule
from .transform.targets import target_availability

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Engine:
    """One generation engine QUBIT can route a finding to.

    `name` is the string patches and `LearnedOutcome.source_model` record, so the reliability
    lookup and the attribution written afterwards cannot drift apart.
    """

    name: str
    #: None for the local Ollama model; an endpoint for anything OpenAI-compatible.
    endpoint: ExternalEndpoint | None
    #: Tokens one request may use, prompt and answer together.
    budget_tokens: int
    #: Whether using it spends a quota. Free engines are tried first for exactly this reason.
    metered: bool


def _language_of_row(asset: Any) -> str:
    """The language of an `AssetRow`, from its recorded path.

    `AssetRow` has no `language` column. Reading one with `getattr(..., "language", "")` returned
    "" for every row, which is worse than an error: the column looked measured and was uniformly
    blank, so any per-language breakdown would have shown a single empty bucket.
    """
    if asset is None:
        return ""
    path = str((getattr(asset, "location", None) or {}).get("file_path") or "")
    return language_for_suffix(path) or ""


def _file_size(asset: Any, repo_root: Path | None) -> dict[str, int]:
    """`file_bytes` and `file_lines` for the asset's file, or zeros.

    Zeros when the file cannot be read — a deleted path, or a run with no repo root. Recorded as 0
    rather than omitted so the column stays present; a reader can tell "unmeasured" from "empty
    file" by the fact that no real source file is 0 lines AND 0 bytes while also having a patch.
    """
    if asset is None or repo_root is None:
        return {"file_bytes": 0, "file_lines": 0}
    rel = str((getattr(asset, "location", None) or {}).get("file_path") or "")
    if not rel:
        return {"file_bytes": 0, "file_lines": 0}
    try:
        raw = (repo_root / rel).read_bytes()
    except OSError:
        return {"file_bytes": 0, "file_lines": 0}
    return {"file_bytes": len(raw), "file_lines": raw.count(b"\n") + 1}


def _diff_lines(diff_text: str | None) -> tuple[int, int]:
    """`(changed, noise)` for a unified diff: added/removed lines, and how many are blank-only.

    Noise is tracked separately because it was a real failure mode — 12 of 18 patches in one run
    were majority whitespace — and a "changed lines" count that includes blank-line churn
    overstates how much work the tool did. Both numbers are covariates a reader needs to interpret
    the time: a 40-line rewrite and a one-line substitution are not the same task.
    """
    if not diff_text:
        return (0, 0)
    changed = noise = 0
    for line in diff_text.splitlines():
        # `+++`/`---` are file headers, not content. Counting them adds two phantom changed lines
        # to every patch, which matters most on the one-line substitutions that dominate.
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            changed += 1
            if not line[1:].strip():
                noise += 1
    return (changed, noise)


def _language_of(asset: CryptoAsset) -> str:
    """The language of the file an asset was found in, for the effort model's language modifier.

    `estimate_effort` defaults this to "python", and nothing ever overrode it — so the "Java
    toolchain (+2)" modifier was unreachable even for Java.
    """
    path = asset.location.file_path if asset.location else None
    return language_for_suffix(path) or "unknown"


def _neighbourhood(source: str, line: int | None, context: int = 6) -> str:
    """The lines around a finding, matching the window `learn.extract_hunk` stores.

    Compared against a stored `hunk_before` by token overlap, so the two sides have to be windows
    of the same size or the similarity is measuring the difference in how much was shown.
    """
    if line is None:
        return ""
    lines = source.splitlines()
    if not (1 <= line <= len(lines)):
        return ""
    window = lines[max(0, line - 1 - context) : line + context]
    return "\n".join(window)


def _relocate_finding_line(asset: CryptoAsset, source: str) -> int | None:
    """Locate a scanned finding in a file whose earlier plan patch moved lines.

    A location line belongs to the scan, not to the mutable working tree.  Reusing it after an
    earlier patch added or removed a line can make a line-scoped codemod edit a sibling finding.
    The scanner already records a small, redacted source window for code findings; use that window
    only when it still occurs exactly once.  Ambiguity is deliberately a failure to relocate: a
    rescan is safer than guessing which identical call site the task owns.
    """
    line = asset.location.line if asset.location else None
    snippet = (asset.evidence.snippet if asset.evidence else "") or ""
    if line is None or not snippet:
        return None

    window = snippet.splitlines()
    if not window:
        return None
    # CodeScanner records +/-2 lines, clipped only at the beginning/end of a file.
    offset = line - max(1, line - 2)
    if not 0 <= offset < len(window):
        return None

    lines = source.splitlines()
    starts = [
        start
        for start in range(len(lines) - len(window) + 1)
        if lines[start : start + len(window)] == window
    ]
    if len(starts) != 1:
        return None
    return starts[0] + offset + 1


def _flagged_line_untouched(orig: str, new: str, asset: CryptoAsset) -> str | None:
    """Why this codemod's edit does not address the flagged finding, or None if it does.

    A file often holds several findings of the same algorithm, each its own task. A token-swap
    codemod rewrites every occurrence it CAN express, which may not include this one — measured on
    `V3__hash_passwords.sql`, where MySQL's `MD5(password)` and `gen_salt('md5')` are both excluded
    by design while `digest(payload,'md5')` on another line is swapped. Both excluded tasks were
    recording the line-6 rewrite as their own patch.

    Only meaningful when the codemod preserved the line count, which a token swap does. If it did
    not, the line numbers no longer correspond and the rescan's occurrence check takes over.
    """
    line = asset.location.line if asset.location else None
    if line is None:
        return None
    before = orig.splitlines()
    after = new.splitlines()
    if len(before) != len(after) or not (1 <= line <= len(before)):
        return None
    if before[line - 1] != after[line - 1]:
        return None
    changed = [i for i, (a, b) in enumerate(zip(before, after, strict=True), 1) if a != b]
    if not changed:
        return None
    where = ", ".join(str(c) for c in changed[:6])
    return (
        f"the codemod cannot express the {asset.algorithm} usage on line {line}; it rewrote "
        f"line(s) {where} instead, which belong to other findings. This one needs migration "
        f"advice rather than a patch."
    )


def _contract_collateral(orig: str, new: str, asset: CryptoAsset) -> str | None:
    """A line this patch changes that is somebody else's contract, or None if it touches none.

    `external_contract` is consulted once per finding, before generation, and that is not enough.
    A codemod rewrites every occurrence in the FILE it can express, so a patch generated for
    finding A silently carries finding B along with it — including a B the guard has already
    refused. The refusal is recorded, the advice is written, and the change happens anyway.

    Measured on the MediVault twin: the guard refused `archive_entry_id` in `documents.py` on
    `sha1_hash = hashlib.sha1(`, and the codemod for `document_fingerprint` — a different task, in
    the same file — rewrote both. The second task then reported *"already migrated by an earlier
    py-weakhash-01 patch to this file"* and parked itself as satisfied. Every gate passed. The
    offsite archive's identifiers changed.

    So the guard is applied a second time, to what the patch actually DID: every changed line is
    re-examined with its own surrounding context, and a patch that edits a protocol-mandated line
    is rejected whole rather than trimmed. Trimming would be worse — a partial rewrite of a file
    is neither the old behaviour nor the new one.

    The finding's own line is NOT exempt, though an earlier draft of this exempted it on the
    reasoning that reaching here means the pre-generation guard already cleared it. That reasoning
    holds only while the two see the same text: the guard reads `asset.evidence.snippet`, recorded
    at scan time and redacted before storage, while this reads the file as it is now. Where they
    agree the exemption changes nothing, because the guard already refused and generation never
    started. Where they disagree — an empty snippet, a file an earlier task in the same plan has
    since edited — the exemption is the difference between catching that and not. So it is gone,
    and `test_a_patch_scoped_to_its_own_finding_is_allowed` covers the case it was there to protect.
    """
    before = orig.splitlines()
    after = new.splitlines()
    if len(before) != len(after):
        # Line numbers no longer correspond, so "the context around line N" is not answerable.
        # A structural rewrite is out of scope for this check rather than guessed at.
        return None

    own_line = asset.location.line if asset.location else None
    path = asset.location.file_path if asset.location else None

    for number, (old_line, new_line) in enumerate(zip(before, after, strict=True), 1):
        if old_line == new_line:
            continue
        # The same +/-2 line window the scanner records, so the guard sees what it was written
        # against rather than a single line stripped of its context.
        window = "\n".join(before[max(0, number - 3) : number + 2])
        verdict = external_contract(asset.algorithm, path, window)
        if verdict is not None:
            return (
                f"this patch also rewrites line {number}, which is not this finding and is not "
                f"this repository's to change — {verdict.reason}. Detected from: {verdict.signal}. "
                f"A file-scoped edit cannot carry a refused finding along with an accepted one; "
                f"line {own_line} needs a change scoped to itself."
            )
    return None


#: Why a task is parked in `deferred`.
#:
#: The FSM has one state for two different outcomes, because its terminal states all mean "a patch
#: was applied and verified" and no such patch exists in either case. But "I could not migrate this"
#: and "there was nothing here to migrate" are opposite facts about the codebase, and reporting the
#: second as the first tells an operator to go and fix something already correct.
RESOLUTION_UNRESOLVED = "unresolved"
#: The finding is already handled: an earlier patch in this plan covered it, or the dependency pin
#: already meets the PQC-capable floor. Not a failure, and counted separately from one.
RESOLUTION_SATISFIED = "satisfied"
#: The finding has a concrete remediation that is not an edit QUBIT can make: a certificate must be
#: re-issued, an ecosystem has no provider trustworthy enough to install automatically, a shell
#: script generates a key whose post-quantum answer lives in configuration.
#:
#: This is a RESULT, and the third one this field exists to keep apart from the other two. Before
#: it, all three arrived at `deferred` and read identically to an operator: "could not migrate".
#: A guided task carries a full remediation plan in `advice_text` — steps, commands, sources — and
#: reporting that as a failure is what made the app look like it shrugs.
RESOLUTION_GUIDED = "guided"
#: A patch was GENERATABLE and QUBIT declined to write it: the algorithm is fixed by a party
#: outside this repository (a remote's own format, an established KDF, a protocol both ends must
#: agree on). Distinct from `RESOLUTION_GUIDED` -- which also carries a written plan, for the
#: opposite reason, "no patch was on offer at all" -- so that a later pass over `deferred` findings
#: (advising, re-generating) can tell "this already has the complete, correct answer" apart from
#: "this genuinely has nothing yet and a model's file-specific read would still help". Conflating
#: the two meant a correct ownership refusal's advice_text got overwritten with a generic
#: algorithm-migration plan the very next time anything re-visited the task.
RESOLUTION_REFUSED = "refused"


class AlreadySatisfied(ValueError):
    """Nothing left to do for this finding, and that is the outcome the rule exists to reach.

    Raised where a codemod reports no change because an earlier patch in the same plan already
    rewrote the file, or because the dependency pin already meets the PQC-capable floor. Both park
    the task with `RESOLUTION_SATISFIED` before raising.

    It needs its own type because the generic `except Exception` around the codemod branch used to
    catch it and re-park the task with the DEFAULT resolution — overwriting `satisfied` with
    `unresolved` and prefixing the message with "Codemod error:". Measured on the demo corpus: 19
    findings in one run, every one of them finished work, all reported as failures. Subclasses
    ValueError so callers that already treat a failed generation as a ValueError still catch it.
    """


class GuidedRemediation(Exception):
    """Raised instead of returning a patch when a finding resolves to a guided path.

    An exception rather than a second return type because every caller and every test treats
    `generate_patch` as returning a `PatchProposal`, and a union return would silently degrade to
    "falsy, so it failed" in the callers that do not know about it yet. The guidance is already
    persisted on the task by the time this is raised; the exception only tells the caller which
    outcome it got.

    `refusal` splits the two very different reasons this is raised. Most sites mean "QUBIT has no
    patch to offer here" — no rule matches, the target primitive is not installable on this
    machine, the file will not fit the model. One means the opposite: a patch is perfectly
    generatable and writing it would be WRONG, because the algorithm belongs to a party outside
    this repository (a Gravatar URL keyed by MD5, a webhook field the remote names `sha1=`, an
    established KDF). Measured on medivault-emr: 6 of 24 findings were refused on those grounds and
    the run reported them in the same breath as findings no engine could handle, so a report of
    "18 failed" described a tool that had been right 6 times.

    A flag on the exception rather than a phrase the caller matches on: the string test that
    predates this recognised two of the four `AlreadySatisfied` wordings and miscounted 19 findings
    of finished work as failures. The classification belongs where the decision is made.
    """

    def __init__(self, task_id: UUID, guidance: str, *, refusal: bool = False) -> None:
        super().__init__(f"task {task_id} resolves to a guided remediation path")
        self.task_id = task_id
        self.guidance = guidance
        self.refusal = refusal


def _validation_payload(
    report: ValidationReport, notes: list[str], caveats: list[str]
) -> dict[str, Any]:
    """The stored validation record, plus the model's reasoning when there is any.

    Both fields are optional and additive: a template patch has neither, and a patch is not worse
    for lacking them. They are stored together because they are read together — the UI shows the
    reasoning above the diff and the caveats as the warnings on it.
    """
    payload: dict[str, Any] = dict(report.as_dict())
    if notes:
        payload["security_notes"] = notes[-1]
    if caveats:
        payload["security_caveats"] = caveats
    return payload


def _first_failure(report: ValidationReport) -> tuple[str, str]:
    """The stage that rejected this patch and what it said, as ``(stage_name, detail)``.

    One source for both audiences: the operator reads it as the task's `last_error`, and the model
    is handed the same words as repair feedback. They must not drift apart — a reviewer chasing a
    failure the model was never actually told about is the confusing case this avoids.
    """
    name = next((n for n, s in report.stages.items() if s.status == "fail"), "validation")
    stage = report.stages.get(name)
    return name, stage.detail if stage else "see validation_json"


def _porcelain_paths(stdout: bytes, root: Path) -> list[Path]:
    """Absolute paths reported by ``git status --porcelain -z``.

    ``-z`` because the default format QUOTES any path containing a space or a non-ASCII byte, and
    a path the caller misreads is a file the dirty-tree guard cannot recognise as QUBIT's own -
    which would make it refuse a migration it had itself caused. Each record is ``XY <path>``;
    a rename or copy appends the ORIGINAL path as a second record, consumed here so it is never
    mistaken for a status line of its own.

    Paths are relative to the repository root, not to the working directory the command ran in,
    which is why ``root`` is `git rev-parse --show-toplevel` rather than the scan target.
    """
    fields = stdout.decode("utf-8", "replace").split("\0")
    paths: list[Path] = []
    index = 0
    while index < len(fields):
        record = fields[index]
        index += 1
        if len(record) < 4:
            continue
        if record[0] in ("R", "C"):
            index += 1  # the source path of the rename/copy, not a status of its own
        with contextlib.suppress(OSError, ValueError):
            paths.append((root / record[3:]).resolve())
    return paths


#: The sandbox image and suite command each ecosystem uses when nothing more specific is
#: configured. Before this table existed, `_stage_tests` refused every non-Python language outright
#: and the `tests` rung -- the only one that can falsify a patch behaviourally -- was unreachable
#: outside Python. Measured on the Ruby twin: every patch was applied on `parses` + `compiles`
#: alone, 6 of 14 findings were migrated against an explicit refusal, and the twin's suite went red.
#:
#: A guess here is safe by construction: a command that cannot make the UNTOUCHED tree green makes
#: `_stage_tests` skip rather than judge, so a wrong entry costs one container run, never a false
#: verdict. The images are stock upstream ones because QUBIT never pulls (see `_image_present`) --
#: an entry only takes effect where that image is already present, and the stage names it when not.
_LANGUAGE_SANDBOX: dict[str, tuple[str, str]] = {
    "java": ("maven:3.9-eclipse-temurin-21", "mvn -B -o test"),
    "go": ("golang:1.23-alpine", "go test ./..."),
    "ruby": ("ruby:3.3-alpine", "rake test"),
}


def _documented_constraint_for(asset: CryptoAsset) -> Any:
    """The contract verdict written down NEAR this finding, if any.

    Two checks, both looking outside the +/-2 line snippet the scanner records, because that window
    can show a call and nothing about what constrains it:

    1. the enclosing function stating in a string literal that the algorithm is required — the
       strongest code-level evidence there is, and usually in the catch clause BELOW the call;
    2. the enclosing documentation describing the value as one that outlives the call.

    Reads the file, so it is guarded: a finding whose file has moved or cannot be decoded produces
    no verdict rather than an error. Absence of documentation is not evidence of a free choice.
    """
    from .protocol_contract import (
        _ALGORITHM_REQUIRED,
        _VERSIONED_OUTPUT,
        ContractVerdict,
        digest_names_stored_state,
        documented_constraint,
        enclosing_documentation,
        inherited_from_signing_counterpart,
        module_declares_no_third_party,
        required_algorithm_in_body,
    )

    location = asset.location
    if location is None or not location.file_path or not location.line:
        return None
    try:
        source = Path(location.file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # The code SAYING the algorithm is required, anywhere in the enclosing function.
    #
    # Checked before the prose rule because it is the stronger evidence: a docstring describes the
    # value, this is the authors recording a constraint. And it is checked over the function body
    # rather than the snippet because that is where such a statement actually sits — usually in the
    # catch clause, BELOW the call, outside the +/-2 window the scanner records. `PM-02` was
    # migrated in every run for exactly that reason, with its constraint four lines away.
    body = required_algorithm_in_body(source, location.line)
    required = _ALGORITHM_REQUIRED.search(body)
    if required is not None:
        return ContractVerdict(
            reason="the code states that this algorithm is required, so it is a constraint the "
            "authors recorded rather than a choice this codebase is free to make",
            signal=f"the enclosing function says {required.group(0).strip()!r}",
        )

    # The code STAMPING its own format version onto the digest it returns. Read over the same
    # function body and for the same reason: the tell sits BELOW the call, in the return, where
    # neither the +/-2 snippet nor the docstring above can see it. See `_VERSIONED_OUTPUT`.
    versioned = _VERSIONED_OUTPUT.search(body)
    if versioned is not None:
        return ContractVerdict(
            reason="the code stamps a format version onto this digest before returning it, which "
            "is the shape of a value something outside this repository has stored and will read "
            "back — re-deriving it under a different algorithm silently invalidates every copy "
            "already issued",
            signal=f"the enclosing function returns {versioned.group(0).strip()!r}",
        )

    own = documented_constraint(
        enclosing_documentation(source, location.line),
        module_declares_no_third_party=module_declares_no_third_party(source),
    )
    if own is not None:
        return own

    # Then the constraint written on the other half of a signature pair. A verifier cannot change
    # algorithm independently of the signer it checks, so a documented refusal on one binds both.
    # Asked after the finding's own documentation so that a finding which speaks for itself is
    # never overruled by its neighbour.
    inherited = inherited_from_signing_counterpart(source, location.line)
    if inherited is not None:
        return inherited

    # Last: the constraint nobody wrote down. Every check above reads PROSE, which works on code
    # documented with an eye to what must not change and fails on ordinary repositories that
    # simply name the function after what it returns. Measured on scrapy, chosen for round 4
    # precisely because nothing in it was written for this tool: all five of its persisted-digest
    # sites -- the dupefilter fingerprint, two stored filenames, a thumbnail path and the
    # scheduler's queue directory -- produced NO verdict from any prose rule, and every one of
    # them is a value the project stores and reads back. Asked last because it is the weakest
    # evidence of the set: a name, not a sentence.
    return digest_names_stored_state(source, location.line)


class MigrationOrchestrator:
    """Facade wiring all qubit-migrate components (the only import surface for api/cli)."""

    def __init__(
        self,
        session: Session,
        config: MigrateConfig | None = None,
        pinned_engine: str | None = None,
    ) -> None:
        self.session = session
        self.config = config or MigrateConfig()
        self._rules = load_rules()
        #: Restrict this instance to one engine, by `_Engine.name`.
        #:
        #: A bulk run works several findings at once, one worker per engine, so that the whole pool
        #: is busy instead of one engine at a time with the rest -- including the local GPU -- idle.
        #: Without a pin every worker would independently run the same cost policy, reach the same
        #: conclusion, and pile onto the same cheapest engine: six workers, one engine, six times
        #: the rate-limit pressure and no more throughput.
        #:
        #: The pin narrows the CHOICE, never the safety checks. Fit, the reliability gate and the
        #: rescan all still apply, and when the pinned engine cannot take a finding the router says
        #: so exactly as it would have for a single engine -- the finding is then left for a worker
        #: whose engine can, rather than forced through this one.
        self.pinned_engine = pinned_engine

    # Effort inputs derived from the asset and its matched rule. Kept as a method rather than
    # inlined so `test_effort.py` can exercise the mapping directly — the bug it guards against is
    # not that the numbers are wrong but that they were never computed at all.
    _RULE_KIND_BY_PREFIX: ClassVar[dict[str, str]] = {
        "cfg-": "config",
        "dep-": "config",
    }

    def _effort_inputs(self, asset: CryptoAsset, rule: Any | None) -> dict[str, Any]:
        """Build the ``estimate_effort`` kwargs for one asset."""
        if rule is None:
            # Genuinely unmatched: no codemod, no LLM constraints, someone reads the code. That is
            # what the +8 base is for, and now it means it.
            return {
                "language": _language_of(asset),
                "cross_service": asset.usage_context.value in ("tls", "kex"),
            }

        rule_id = rule.id or ""
        kind = next(
            (k for prefix, k in self._RULE_KIND_BY_PREFIX.items() if rule_id.startswith(prefix)),
            None,
        )
        if kind is None:
            # Derive from what the rule is about, which is encoded in its id: `-signature-`,
            # `-kex-`, `-weakhash-`, `-mac-`, `-tls-`, `-weakcipher-`.
            if "signature" in rule_id or "sign" in rule_id:
                kind = "signature"
            elif "tls" in rule_id:
                kind = "config"
            else:
                kind = "kex"

        return {
            "rule_kind": kind,
            "language": _language_of(asset),
            "data_compat": getattr(rule, "data_compat", None),
            "library_pinned": asset.library is not None and bool(asset.library.version),
            "cross_service": asset.usage_context.value in ("tls", "kex"),
        }

    def advise_task(self, task_id: UUID, *, force: bool = False) -> MigrationTask:
        """Generate migration advice for one task, and store it on the task.

        This is what a task with no patch is left with, so it has to be worth reading: the model is
        given the real file, the real finding and — when a patch was attempted — the real reason it
        was rejected, and asked to explain the change for THIS code. Nothing is templated; two
        findings of the same algorithm in different files produce different advice because the code
        around them differs.

        Cached on the task. `force=True` regenerates.
        """
        task = self.session.get(MigrationTask, task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        if task.advice_text and not force:
            return task

        row = self.session.get(AssetRow, task.asset_id)
        if row is None:
            raise ValueError("the asset this task was built from no longer exists")
        asset = row_to_asset(row)

        path = asset.location.file_path if asset.location else None
        source = ""
        if path:
            candidate = Path(path)
            if candidate.is_file():
                source = candidate.read_text(encoding="utf-8", errors="replace")
        if not source:
            # No file to read means no MODEL advice — a certificate, a binary, a path that has
            # moved. It does not mean no advice: the deterministic plan needs the finding, not the
            # source, and for a certificate it is the only correct answer anyway.
            return self.resolve_guided(task_id, force=force)

        rule = match_rule(asset, self._rules)

        # The deterministic plan first, and unconditionally. It carries the facts QUBIT is
        # authoritative about — the target, the verified provider and its version floor, the
        # artefact sizes, the weakness authorities, the rule's own engineering constraints — none
        # of which a 7B model should be recalling. Building it first also means the guidance
        # exists before the model is contacted, so an Ollama outage costs detail, not the answer.
        from .transform.guidance import build_guided_plan

        base = build_guided_plan(asset, rule, failure_reason=task.last_error).to_markdown()

        # Advice is routed through the same pool a PATCH is, for the same reason: it is the only
        # output a guided finding has, so producing it on whichever engine is cheapest-by-default
        # spends the least and delivers the least. `_route` applies fit, quota and the reliability
        # gate exactly as it does for generation.
        # Tasks carry no tenant column of their own -- `_tenant_of` reads it one hop up, through
        # the plan, exactly as every other tenant-scoped lookup in this class does.
        routed, decision = self._route(rule, source, _language_of(asset), self._tenant_of(task))
        chosen = routed or _Engine(
            name=self.config.model,
            endpoint=None,
            budget_tokens=self.config.llm_context_tokens,
            metered=False,
        )
        by_name = {e.name: e for e in self._engines()}
        advice_pool = tuple(
            engine.endpoint
            for name in decision.alternatives
            if (engine := by_name.get(name)) is not None and engine.endpoint is not None
        )
        logger.debug("advice for %s routed to %s: %s", task_id, chosen.name, decision.reason)

        try:
            advice = generate_migration_advice(
                source,
                asset,
                rule,
                model=(chosen.endpoint.model if chosen.endpoint else self.config.model),
                base_url=(chosen.endpoint.base_url if chosen.endpoint else DEFAULT_BASE_URL),
                timeout=self.config.llm_timeout,
                # The rejection reason, when there is one, is the most useful single fact: it says
                # what the automated attempt could not do, which is exactly what the human has to.
                failure_reason=task.last_error,
                provider="openai-compatible" if chosen.endpoint is not None else "ollama",
                api_key=chosen.endpoint.api_key if chosen.endpoint else None,
                backup=advice_pool[0] if advice_pool else None,
                backups=advice_pool[1:],
                budget_tokens=chosen.endpoint.budget_tokens if chosen.endpoint else None,
            )
        except (OSError, OllamaError) as exc:
            logger.info(
                "advice model unavailable for task %s (%s); using the plan alone", task_id, exc
            )

            def _store_plan_only() -> None:
                task.advice_text = base
                task.advice_model = "qubit-guided"
                task.advice_at = datetime.now(UTC)
                task.resolution = RESOLUTION_GUIDED
                self.session.commit()

            # `retry_write_on_lock`, not `commit_with_retry` -- these mutate an existing row, and
            # rollback reverts such changes, so retrying the commit alone would silently store
            # nothing. See `resume_task` for the full reasoning.
            retry_write_on_lock(self.session, _store_plan_only)
            self.session.refresh(task)
            return task

        # The model's contribution is what it is genuinely good at: reading THIS file. It goes
        # after the plan, under its own heading, so a reader can tell which half is a verified fact
        # and which half is a model's reading of their code.
        advice = f"{base}\n---\n\n## This file, read by {chosen.name}\n\n{advice}"

        def _store_advice() -> None:
            task.advice_text = advice
            task.advice_model = chosen.name
            task.advice_at = datetime.now(UTC)
            self.session.commit()

        retry_write_on_lock(self.session, _store_advice)
        self.session.refresh(task)
        return task

    def resolve_guided(
        self, task_id: UUID, *, force: bool = False, claim_resolved: bool = True
    ) -> MigrationTask:
        """Give a task a concrete remediation path and park it as guided rather than failed.

        Runs for two kinds of finding:

        * a rule that declares `remediation: guided` — a certificate, a Dart or Ruby manifest, a
          shell script generating a key. There is no edit QUBIT can correctly make, and pretending
          otherwise costs three model attempts and produces nothing.
        * a finding no rule matches at all, which previously reached the queue as "no rule matched"
          and stopped there.

        The plan is built from shipped data — the rule pack, the migration knowledge base, the
        weakness catalogue and the verified provider playbook — so it works with Ollama stopped and
        states facts rather than recalling them. `advise_task` layers the model's file-specific
        reading on top when it is available; this is what guarantees something useful underneath.
        """
        task = self.session.get(MigrationTask, task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        if task.advice_text and not force:
            return task

        asset = self._load_asset(task.asset_id)
        if asset is None:
            raise ValueError("the asset this task was built from no longer exists")

        from .transform.guidance import build_guided_plan

        plan = build_guided_plan(
            asset,
            match_rule(asset, self._rules),
            # The reason a patch attempt failed is the most useful single fact a reader can have:
            # it says what the automation could not do, which is exactly what they now have to.
            failure_reason=task.last_error,
        )
        task.advice_text = plan.to_markdown()
        task.advice_model = "qubit-guided"
        task.advice_at = datetime.now(UTC)

        # `claim_resolved=False` is the failure fallback: a generation that could not be produced
        # still deserves a written path, but it is NOT a resolved finding. Marking it `guided`
        # there conflated two different things - a rule saying "no edit is ever right here" and
        # the model failing today - and the second one must stay retryable, because the engine
        # that failed it is not the engine the next run will use.
        #
        # EXPLICITLY `RESOLUTION_UNRESOLVED`, not left at whatever `resolution` already was.
        # `handlers.py`'s bulk-retry query and `routers/migrate.py`'s resume query both filter
        # `resolution == RESOLUTION_UNRESOLVED` -- a task this leaves at `None` is invisible to
        # both, and every rejected or failed finding parked through this path (every caller of
        # `park_for_retry`) was silently unretryable forever, not merely until the next run.
        def _park_as_guided() -> None:
            task.resolution = RESOLUTION_GUIDED if claim_resolved else RESOLUTION_UNRESOLVED
            if task.state != "deferred":
                self._transition(task, "defer", detail={"resolution": task.resolution})
            self.session.commit()

        retry_write_on_lock(self.session, _park_as_guided)
        self.session.refresh(task)
        return task

    def resolve_refused(self, task_id: UUID, guidance: str) -> MigrationTask:
        """Park a task QUBIT declined to patch on OWNERSHIP grounds, with the reason on the record.

        Deliberately NOT `resolve_guided`. That method rebuilds a plan from the RULE via
        `build_guided_plan` — the right thing for "no rule matches" or "no edit is possible here" —
        but a `GuidedRemediation(refusal=True)` already carries the one fact that matters and
        `build_guided_plan` does not know it: WHY this specific algorithm is not QUBIT's to change.
        Routing a refusal through `resolve_guided` discards that reason and replaces it with a
        generic "here is how one would migrate this algorithm" plan — measured live: a Gravatar-MD5
        refusal came back advising "re-hash any existing MD5 hashes using SHA-256", which is exactly
        the migration the refusal exists to refuse.

        `guidance` is the exception's own message, so the stored explanation is the one QUBIT
        actually reasoned through, not a rebuilt approximation of it.
        """
        task = self.session.get(MigrationTask, task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")

        task.advice_text = (
            f"## Why no edit was made\n\nThis algorithm is fixed by a party outside this "
            f"repository, so changing it here would be wrong rather than merely unfinished:\n\n"
            f"{guidance}"
        )
        task.advice_model = "qubit-guided"
        task.advice_at = datetime.now(UTC)

        def _park_as_refused() -> None:
            task.resolution = RESOLUTION_REFUSED
            if task.state != "deferred":
                self._transition(task, "defer", detail={"resolution": RESOLUTION_REFUSED})
            self.session.commit()

        retry_write_on_lock(self.session, _park_as_refused)
        self.session.refresh(task)
        return task

    def resume_task(self, task_id: UUID) -> MigrationTask:
        """Put a task that a previous run FAILED back on the ready queue.

        The engine learns between runs: a rewrite validated on one file grounds the next attempt
        at the same shape, and a rejection is retained so it is not walked into blind. None of
        that reached the findings that most needed it, because a failed task parks in `deferred`
        and every bulk run selected only `ready`. Measured on this corpus, 9 findings sat at
        `deferred/unresolved` across three subsequent runs - each with a better engine than the
        one that failed them - and not one was tried again.

        Only `unresolved` and a reviewer-rejected patch are resumable. `satisfied` is finished
        work and `guided` is a written remediation; re-running either would undo the distinction
        the resolution field exists to draw, and would overwrite a plan the user may already be
        following.

        A task STRANDED in `generating` is also resumed here -- see `_stranded_generating`.
        """
        task = self.session.get(MigrationTask, task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")

        # A generation whose caller went away leaves the task at `generating` forever. The FSM has
        # no `generate` event from `generating`, so every later click answers
        # "No transition 'generate' from state 'generating'" and the row is a permanent dead end.
        # `JobRunner._recover_orphaned_tasks` already repairs exactly this -- but only on server
        # RESTART, which does not help a user who simply navigated away mid-generation and came
        # back. Recovering it on the retry click is the same repair at the moment it is needed.
        # `retry_write_on_lock`, NOT `commit_with_retry`. The distinction is load-bearing and cost
        # a wrong fix to find: `commit_with_retry` re-adds freshly-constructed rows, but these
        # writes MUTATE an existing row, and `Session.rollback()` reverts attribute changes on a
        # persistent object. Retrying only the commit therefore committed nothing and returned
        # success with the task still `deferred` -- a silent no-op, strictly worse than the HTTP 500
        # it was meant to fix. Re-running the whole mutation is what this helper is for.
        if task.state == "generating" and self._stranded_generating(task):

            def _reclaim() -> None:
                self._transition(
                    task, "defer", detail={"reason": "previous generation was interrupted"}
                )
                task.resolution = RESOLUTION_UNRESOLVED
                task.last_error = "the previous generation was interrupted before it finished"
                self.session.commit()

            retry_write_on_lock(self.session, _reclaim)
            self.session.refresh(task)

        # A reviewer rejection deliberately has a transition of its own: it is not a failure of
        # the finding, only of this proposed diff.  The FSM has supported `rejected -> ready`
        # since its first version, but this convenience method ignored it.  Both the single-row
        # Generate action and bulk preparation call `resume_task`, so that omission made a
        # rejected proposal a permanent dead end even though the state machine said it could be
        # regenerated.
        if task.state == "rejected":

            def _regenerate() -> None:
                self._transition(
                    task,
                    "regenerate",
                    detail={"reason": "regenerating after reviewer rejection"},
                )
                self.session.commit()

            retry_write_on_lock(self.session, _regenerate)
            self.session.refresh(task)

        if task.state != "deferred" or task.resolution != RESOLUTION_UNRESOLVED:
            return task

        def _resume() -> None:
            self._transition(task, "resume", detail={"reason": "retrying with the current engine"})
            # The previous rejection stays on the row until this attempt produces its own outcome:
            # it is what `build_guided_plan` opens with if this attempt fails too, and clearing it
            # early would lose the only record of what has already been tried.
            task.resolution = None
            self.session.commit()

        retry_write_on_lock(self.session, _resume)
        self.session.refresh(task)
        return task

    def reopen_task(
        self, task_id: UUID, *, reason: str = "reopening for a fresh proposal"
    ) -> MigrationTask:
        """Explicitly reopen a rejected proposal without rewriting its review history.

        Rejection is a reviewer verdict on one immutable proposal, not a verdict that the finding
        can never be migrated.  A source change (or a stale proposal discovered during review)
        needs a fresh diff against current bytes.  Keep the rejected row as audit evidence and
        move only the task back to ``ready``; callers must request this deliberately so a manual
        rejection is never silently retried.
        """
        task = self.session.get(MigrationTask, task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        if task.state != "rejected":
            raise ValueError(
                f"Task {task_id} is {task.state}, not rejected; only rejected proposals can "
                "be reopened"
            )

        def _reopen() -> None:
            self._transition(task, "regenerate", detail={"reason": reason})
            task.resolution = None
            task.last_error = None
            self.session.commit()

        retry_write_on_lock(self.session, _reopen)
        self.session.refresh(task)
        return task

    #: How many model calls one `generate_patch` can legitimately make, worst case, before it is
    #: certain that a task still sitting at `generating` is orphaned rather than working.
    #:
    #: The arithmetic, from `generate_llm_source`: one planning pass, then up to `_MAX_ATTEMPTS`
    #: (3) rounds of [generate + self-review] = 7 calls; the orchestrator's outer feedback retry
    #: can run that whole budget a second time = 14. Rounded up to 16 to leave room for the
    #: validation stages (docker build, test run) that are not model calls but are not free either.
    #:
    #: Deliberately generous. Reclaiming a task that is genuinely still in flight would let two
    #: generations write to the same row, which is a worse failure than waiting: the honest cost of
    #: not being able to ask "is that request still alive?" across a process boundary.
    _MAX_GENERATION_CALLS = 16

    def _stranded_generating(self, task: MigrationTask) -> bool:
        """Whether a `generating` task has been there longer than any real generation could take.

        Time-based because there is no other signal available: the request that owns a generation
        runs in a worker thread with no handle the next request can ask about, and after a client
        disconnect FastAPI keeps that thread running to completion regardless. So "is it still
        working?" can only be answered by "could it possibly still be working?".

        The clock comes from the task's own `generating` event rather than a column, because
        `MigrationTask` has no updated-at and the event log already records every transition with
        its timestamp. A task with no such event recorded (possible for rows written before the
        event log, or if the write was lost) is treated as NOT stranded -- refusing to reclaim is
        always the safe direction.
        """
        entered = self.session.scalar(
            select(MigrationEvent.at)
            .where(MigrationEvent.task_id == task.id, MigrationEvent.to_state == "generating")
            .order_by(MigrationEvent.at.desc())
            .limit(1)
        )
        if entered is None:
            return False
        # SQLite hands back naive datetimes (it has no timezone type) while `utcnow()` is aware;
        # comparing the two raises. Everything QUBIT stores is UTC, so attach it rather than
        # converting -- see `qubit_api.schemas._ensure_utc` for the same fix on the way out.
        if entered.tzinfo is None:
            entered = entered.replace(tzinfo=UTC)
        limit = timedelta(seconds=self.config.llm_timeout * self._MAX_GENERATION_CALLS)
        return datetime.now(UTC) - entered > limit

    def _engines(self) -> list[_Engine]:
        """Every engine available to this install, CHEAPEST FIRST.

        "Cheapest" is not a guess about pricing -- it is the order that spends the least scarce
        resource for the same outcome:

        * **Local Ollama first.** It costs nothing and has no daily quota, so any finding it can
          genuinely handle should never reach a metered endpoint.
        * **Then externals by ascending allowance.** A bigger allowance is not better here, it is
          the thing you need only when the file demands it -- and measured, it is exactly the slow
          one. `openai/gpt-oss-120b` on Groq answers a whole-file rewrite in ~3.6s with an
          8,000-token allowance; `gemma-4-31b-it` needs 64,000 to take the same file and one real
          patch through the app took **899 seconds**. Picking the SMALLEST engine that fits is
          therefore both the cheapest and the fastest choice, not a trade-off between them.
        """
        engines = [
            _Engine(
                name=self.config.model,
                endpoint=None,
                budget_tokens=self.config.llm_context_tokens,
                metered=False,
            )
        ]
        if self.config.single_engine_only:
            return engines
        # Merely storing a provider credential must never make repository source leave the
        # machine.  Generation prompts include the target file, so external routing requires an
        # explicit, separately auditable opt-in rather than being an automatic fallback.
        if not self.config.allow_external_source_processing:
            return engines
        row = self.session.get(LlmProviderConfig, 1)
        if row is None or row.provider != "openai-compatible":
            return engines

        external: list[_Engine] = []
        for base_url, model, blob, budget in (
            (row.base_url, row.model, row.api_key_encrypted, row.context_tokens),
            (
                row.backup_base_url,
                row.backup_model,
                row.backup_api_key_encrypted,
                row.backup_context_tokens,
            ),
        ):
            if not (base_url and model and blob):
                continue
            with contextlib.suppress(Exception):
                external.append(
                    _Engine(
                        name=f"openai-compatible:{model}",
                        endpoint=ExternalEndpoint(
                            base_url=base_url,
                            model=model,
                            api_key=secrets_at_rest.decrypt(blob),
                            budget_tokens=budget,
                        ),
                        budget_tokens=budget or self.config.llm_context_tokens,
                        metered=True,
                    )
                )
        external.extend(self._pooled_engines())
        external.sort(key=lambda e: e.budget_tokens)
        # `external-first` inverts the head of the list and keeps local as the FALLBACK rather
        # than dropping it: an install with a metered pool should be able to spend it, and an
        # exhausted quota should still degrade to something that works rather than to nothing.
        # Off by default, because it spends a rationed allowance — see `MigrateConfig.engine_order`.
        if self.config.engine_order == "external-first" and external:
            return external + engines
        return engines + external

    def engine_names(self) -> list[str]:
        """Every engine this install can use, cheapest first — the pins a bulk run divides work by.

        Public because the caller that decides how much to run at once is the bulk handler, and the
        honest width of a pool is a property of the pool, not a number to configure. Local Ollama
        is first, so a run with one worker still behaves exactly as it did before.
        """
        return [engine.name for engine in self._engines()]

    def _pooled_engines(self) -> list[_Engine]:
        """Engines attached to the pool, beyond the primary and backup slots.

        Two slots was a ceiling on the only thing that actually adds capacity here. A hosted free
        tier is rationed per PROJECT -- Groq allows 1,000 requests/day; two Google keys in one
        project share a quota while a different model on the same key gets its own -- so more
        capacity means MORE INDEPENDENT TIERS, not a better model. A third key previously had
        nowhere to go.

        A row that cannot be decrypted is skipped rather than raised on: one unreadable key must
        not take the whole pool, and the rest of the engines are still perfectly usable.
        """
        pooled: list[_Engine] = []
        for row in self.session.scalars(select(LlmEngine).where(LlmEngine.enabled.is_(True))):
            if not (row.base_url and row.model and row.api_key_encrypted):
                continue
            with contextlib.suppress(Exception):
                pooled.append(
                    _Engine(
                        # The key suffix is part of the identity, not decoration. Two keys for the
                        # same model are two INDEPENDENT quotas -- which is the entire reason the
                        # pool exists -- and both `learn.reliability` and the call ledger key on
                        # this name. Without the suffix they would share one success record and one
                        # cost total, so a quota-exhausted key would look like a failing model and
                        # drag its healthy twin down with it.
                        name=f"openai-compatible:{row.model}#{row.api_key_last4}",
                        endpoint=ExternalEndpoint(
                            base_url=row.base_url,
                            model=row.model,
                            api_key=secrets_at_rest.decrypt(row.api_key_encrypted),
                            budget_tokens=row.context_tokens,
                        ),
                        budget_tokens=row.context_tokens or self.config.llm_context_tokens,
                        metered=True,
                    )
                )
        return pooled

    def _select_engine(
        self, rule: Any, source: str, language: str, tenant_id: UUID | None = None
    ) -> _Engine | None:
        """The cheapest engine that can plausibly migrate THIS finding, or None for guided advice.

        Two independent questions, asked per engine:

        1. **Can it hold the file?** The window has to fit prompt AND answer, so the prompt may use
           `llm_max_prompt_fraction` of it.
        2. **Has it been shown to fail this exact work?** `learn.reliability` records pass/fail per
           (rule, language, engine). A pairing an engine has failed `llm_skip_after_failures` times
           with no success is skipped -- for THAT engine only.

        The second question is what makes this worth doing rather than always reaching for the
        biggest engine. Measured on this installation: the local 7B has passed
        `code-signature-01`/go 518 times, so sending that to a metered endpoint would buy nothing
        and spend quota for it. The same
        model has failed `code-kex-01` in c, go and ruby **every** time it has tried -- and until
        now those were routed to written advice, which is exactly the "why am I getting guidance
        instead of a patch" complaint. Escalating them to an engine that can actually do the work
        both removes the wasted local attempts (three tries at ~23s each) and produces a patch.
        """
        engine, _ = self._route(rule, source, language, tenant_id)
        return engine

    def _route(
        self, rule: Any, source: str, language: str, tenant_id: UUID | None = None
    ) -> tuple[_Engine | None, scheduling.Decision]:
        """`_select_engine`, plus the reasoning -- so a route can be explained, not just observed.

        The two answers are wanted in different places. `generate_patch` needs the engine AND the
        wait the provider asked for; the pre-flight probe only needs to know whether anything at
        all could take the finding. Returning both from one function keeps them from drifting.

        The policy itself lives in `qubit_migrate.scheduling`, which is pure. Everything this method
        does is gather what is known -- fit, this installation's own outcome history, the budget the
        provider last reported, and how long each engine has actually taken -- and hand it over.
        """
        from .transform import learn, llm

        estimated = len(source) // 3
        tid = tenant_id if tenant_id is not None else DEFAULT_TENANT_ID
        # `rule` is None for a finding no rule matched at all -- `advise_task` is the one caller
        # that reaches `_route` with that case, for exactly the reason `resolve_guided` exists:
        # "no rule matched" used to dead-end at the queue with nothing further to say. Every other
        # caller builds a rule by construction before generating, so this was unreachable until
        # advice started going through the same routing a patch does. "" groups every ruleless
        # finding under one reliability record rather than raising -- there is no per-rule history
        # to be more specific than that, and the record is at worst uninformative, never wrong.
        rule_id = rule.id if rule is not None else ""
        by_name: dict[str, _Engine] = {}
        offers: list[scheduling.EngineOffer] = []
        for engine in self._engines():
            by_name[engine.name] = engine
            passed, failed = learn.reliability(
                self.session,
                rule_id=rule_id,
                language=language,
                tenant_id=tid,
                source_model=engine.name,
                include_unattributed=not engine.metered,
            )
            # The budget is keyed by ENDPOINT, because that is what the provider rations; the
            # engine name carries a key suffix so two keys for one model stay distinct in the
            # outcome history. The two identities are deliberately different and must be mapped.
            budget: dict[str, Any] = {}
            if engine.endpoint is not None:
                budget = llm.rate_budget(f"{engine.endpoint.base_url}::{engine.endpoint.model}")
            offers.append(
                scheduling.EngineOffer(
                    name=engine.name,
                    metered=engine.metered,
                    budget_tokens=engine.budget_tokens,
                    passed=passed,
                    failed=failed,
                    remaining_requests=budget.get("remaining_requests"),
                    remaining_tokens=budget.get("remaining_tokens"),
                    reset_tokens_s=float(budget.get("reset_tokens_seconds") or 0.0),
                    seconds_per_call=llm.observed_seconds_per_call(engine.name),
                )
            )

        decision = scheduling.choose(
            offers,
            prompt_tokens=estimated,
            max_prompt_fraction=self.config.llm_max_prompt_fraction,
            skip_after_failures=self.config.llm_skip_after_failures,
        )
        decision = self._apply_pin(decision)
        return (by_name.get(decision.engine) if decision.engine else None), decision

    def _apply_pin(self, decision: scheduling.Decision) -> scheduling.Decision:
        """Move this worker's own engine to the front, if the policy judged it able to take the job.

        Applied AFTER `scheduling.choose`, not by hiding the other engines from it, and that
        ordering is the whole point. The policy still evaluates the entire pool, so the pinned
        engine is only promoted from among the ones it found ELIGIBLE -- fit, the reliability gate
        and the reported rate budget all still decide -- and the engines it displaces stay on as
        alternatives, so a worker whose engine answers 503 still has somewhere to go.

        Filtering the offers instead would have looked simpler and been worse twice over: a pinned
        engine would bypass no checks but would arrive with an empty alternatives list, so one 503
        would drop the finding to the local model; and an engine the policy had ruled out for this
        file would be used anyway.
        """
        pin = self.pinned_engine
        if pin is None or decision.engine == pin:
            return decision
        eligible = (decision.engine, *decision.alternatives)
        if pin not in eligible:
            # Not a failure and not worth a warning: the pool is heterogeneous, so a file that does
            # not fit this worker's engine is ordinary. The finding is routed as the policy asked.
            return decision
        others = tuple(name for name in eligible if name != pin and name is not None)
        return replace(
            decision,
            engine=pin,
            reason=f"{decision.reason}; pinned to {pin} so the whole pool runs at once",
            alternatives=others,
        )

    def _effective_context_tokens(self) -> int:
        """The largest window any configured engine offers.

        Used by the size half of `_llm_detour_reason`, which asks "could ANY engine hold this
        file" -- so the answer must come from the most capable one, not whichever happens to be
        marked primary. `_select_engine` then picks the cheapest one that actually fits.
        """
        return max(e.budget_tokens for e in self._engines())

    def _oversize_reason(self, source: str) -> str | None:
        """Why this file cannot be sent whole, or None if it fits.

        Split out of `_llm_detour_reason` so `generate_patch` can tell the SIZE refusal apart from
        the other two. Size is the only one an excerpt can answer: a pairing the engine has never
        completed, or a rescan that cannot confirm the result, is exactly as true of an excerpt as
        of the whole file, and overriding either would just spend quota to reach the same verdict.
        """
        context_tokens = self._effective_context_tokens()
        budget = int(context_tokens * self.config.llm_max_prompt_fraction)
        # ~3 characters per token deliberately under-estimates for code, matching
        # `llm._output_budget`, so the estimate errs toward letting a borderline file through.
        estimated = len(source) // 3
        # The ANSWER has to fit too, and only the prompt was ever checked. A whole-file rewrite
        # must emit the entire file, so a file needing more than `_MAX_PREDICT` tokens to reproduce
        # cannot be returned however well the model behaves -- the generation is truncated at the
        # ceiling, the repair loop reads unbalanced brackets as the model getting it wrong, and
        # three attempts are spent proving something arithmetic said in advance.
        #
        # Measured on this installation: 324 of 1,019 files in the corpus (32%) are in this state,
        # and four tasks failed with "unbalanced brackets" against files needing up to 19,951
        # tokens. Windowing answers it -- an excerpt is a fraction of the file -- which is exactly
        # what the prompt-side refusal already routes to.
        if estimated > budget:
            return (
                f"this file is too large for the configured model: about {estimated:,} tokens "
                f"against a {context_tokens:,}-token context window, which must hold the "
                f"rewritten file as well as the original. Sending it would truncate the file "
                f"before the model saw it. A larger-context model, or splitting the change by "
                f"hand, is what this needs."
            )
        if estimated > _MAX_PREDICT:
            return (
                f"this file needs about {estimated:,} tokens to return in full, against an answer "
                f"ceiling of {_MAX_PREDICT:,}. The model can read it but cannot write it back, so "
                f"a whole-file rewrite would be truncated no matter how well it went."
            )
        return None

    def _llm_detour_reason(
        self, rule: Any, source: str, language: str, tenant_id: UUID | None = None
    ) -> str | None:
        """Why the model should be skipped for this finding, or None to go ahead.

        Both tiers of the hybrid cost real time — three attempts at several minutes each — and
        both were being spent on findings where the outcome was decided before the first token.
        Routing them straight to the guided path is not giving up: the plan is built from the
        rule pack, the knowledge base and the verified provider playbook, so the operator gets
        steps, commands and sources instead of a fifteen-minute wait for a rejection.

        Neither check is permanent. The task is parked with `claim_resolved=False`, so it returns
        to the queue on the next build, and an explicit `generator="llm"` bypasses this entirely.

        1. **The file cannot fit the model's context.** The window holds prompt AND answer, and a
           whole-file rewrite answers at about the length of its input. Measured on node-forge:
           `pkcs1.js` needs ~27,400 tokens and `rsa.js` ~20,900 against an 8,192 window. Ollama
           silently truncates the prompt, so the model was being shown a fragment of a file and
           asked to return all of it — it could not have succeeded once, and it was asked
           three times.

           This one no longer ends in guidance by itself. `generate_patch` overrides it, and ONLY
           it, where the finding has a line to build an `llm.Excerpt` around: the model is shown
           the imports plus the neighbourhood of the flagged line, and the answer is spliced back
           into the full file. The reason is still returned from here, because whether an excerpt
           can stand in depends on the finding, which this method is not given.

        2. **This (rule, language) pair has never once succeeded here.** The experience base
           already records pass/fail per rule and language; `reliability` reads it and, until
           now, was called by nothing. `code-kex-01` is the case that motivates it: replacing RSA
           key transport with a KEM restructures the protocol, and across two measured runs and
           eleven languages the local 7B model completed 0 of them. That is a ceiling on this
           model, not a property of the task — which is exactly why this reads measured evidence
           from THIS installation rather than a hardcoded blocklist.
        """
        # The window of the engine ACTUALLY configured, not the local default. An external
        # provider routinely offers 16x the local model's window (measured: gpt-oss-120b reports
        # 131,072 against the shipped 7B model's 8,192), and gating on the local number while an
        # external model is selected sends files to guided advice that the configured engine could
        # rewrite comfortably -- the exact "why is it giving me advice instead of a patch" failure
        # this method is supposed to be avoiding, inverted.
        oversize = self._oversize_reason(source)
        if oversize is not None:
            return oversize

        # 3. The rescan cannot confirm the answer in this language, so no rewrite can pass.
        #
        # A rule with `rescan_expect.present: [X]` is only satisfiable where the SCANNER can
        # recognise X. Where it cannot, the task is unwinnable by construction: the model can
        # produce a flawless migration and stage 5 still reports "expected ML-DSA, not found",
        # so three attempts are spent proving something that was decided before the first token.
        #
        # This is a QUBIT gap, not a model failure, and it is the honest thing to say. It was
        # costing whole languages silently: go-ethereum's 107 signature findings could not have
        # passed even in principle, because Go had ML-KEM detection and no ML-DSA rule at all
        # (now fixed — GO-CIRCL-MLDSA). php, ruby and dart remain in exactly that position for
        # both algorithms, and asking here means the answer stays correct as coverage changes,
        # instead of a hardcoded language list that silently rots.
        expect = getattr(rule, "rescan_expect", None)
        wanted = ((expect or {}).get("present") or {}).get("algorithm_prefix") or []
        if wanted and language:
            from .transform.target_shapes import verified_target_shapes

            if all(not verified_target_shapes(language, prefix) for prefix in wanted):
                targets = " or ".join(wanted)
                return (
                    f"QUBIT cannot yet confirm a {targets} rewrite in {language}: its scanner "
                    f"ships no rule that recognises {targets} in this language, so the rescan "
                    f"that decides whether a patch worked could never pass — no matter how good "
                    f"the rewrite is. Spending model attempts on it would prove nothing. The "
                    f"remediation path below is the real answer until {language} detection lands."
                )

        from .transform import learn

        # Ask whether ANY configured engine can do this, not just whichever is marked primary.
        # `_select_engine` walks them cheapest-first and applies the same per-engine reliability
        # test this branch used to apply to one engine -- so a pairing the local model has failed
        # every time now ESCALATES to an engine that might succeed instead of going to written
        # advice. Only when no engine is left is guidance the honest answer.
        if self._select_engine(rule, source, language, tenant_id) is not None:
            return None

        engine = self._active_model_name()
        _, failed = learn.reliability(
            self.session,
            rule_id=rule.id,
            language=language,
            tenant_id=tenant_id if tenant_id is not None else DEFAULT_TENANT_ID,
            source_model=engine,
            include_unattributed=engine == self.config.model,
        )
        return (
            f"no configured engine has completed a {rule.id} migration in {language} on this "
            f"machine — {failed} attempts on {engine}, none validated, and no other configured "
            f"engine can hold this file. Rather than spend three more, here is the remediation "
            f"path. Configuring another engine, or re-running after a model upgrade, will try "
            f"again automatically."
        )

    def _active_model_name(self) -> str:
        """The engine that generation will actually use, named the way patches record it.

        Must agree with `generate_patch`'s own `_current_model_name`, because the reliability
        gate compares against `LearnedOutcome.source_model` — which those patches wrote. A
        mismatch would silently make the gate count nothing and never fire.
        """
        with contextlib.suppress(Exception):
            row = self.session.get(LlmProviderConfig, 1)
            if (
                row is not None
                and row.provider == "openai-compatible"
                and row.model
                and row.api_key_encrypted
            ):
                return f"openai-compatible:{row.model}"
        return self.config.model

    def _rescan_verifier(
        self, rule: Any, asset: CryptoAsset, rel_path: str, *, original_source: str | None = None
    ) -> Callable[[str], str | None] | None:
        """A closure the repair loop can call to ask "is the finding gone?".

        Returns None when the rule declares no `rescan_expect`, so nothing is verified that the rule
        did not ask for.

        This runs the SAME stage the validator runs, rather than a second approximation of it — a
        check that exists twice is a check that will disagree with itself. It costs one scanner
        subprocess per attempt, against a model call of several seconds, and it converts a rejected
        patch into a correctable one.

        `original_source` is what makes "the same stage" actually the same. `_stage_rescan` narrows
        its `gone` check from "this algorithm appears nowhere in the file" to "THIS task's
        occurrence of it went away" — but only when given a baseline to diff against; without one
        it falls back to the whole-file rule (see `_occurrence_survived`). The repair loop passed
        no baseline, so the loop judged every candidate by a STRICTER rule than the validator that
        would ultimately accept it.

        Measured on five real repositories: 18 of 22 `code-kex-01` rejections were
        `Expected 'RSA' gone, but still found: ['RSA']` — the whole-file fallback firing on files
        where the flagged call site HAD been migrated. Worse, `code-kex-01`'s own
        `prompt_constraints` tell the model to "keep the old decrypt path so already-encrypted data
        can still be read", so the loop spent all three attempts ordering the model to delete the
        very compatibility path the rule asks for, then reported a real migration as a failure.
        """
        if not getattr(rule, "rescan_expect", None) or not self.config.llm_verify_rescan:
            return None

        from .transform.languages import language_for_suffix
        from .transform.target_shapes import verified_target_shapes
        from .transform.validate import _stage_rescan

        language = language_for_suffix(rel_path) or rule.language
        asset_line = asset.location.line if asset.location else None

        def verify(candidate: str) -> str | None:
            result = _stage_rescan(
                candidate,
                rule,
                language,
                asset.algorithm,
                original_source=original_source,
                asset_line=asset_line,
            )
            # Recorded on the closure so callers can tell a real pass from an unfailable one. The
            # repair loop is right to ignore this -- it only ever asks "is there still something to
            # correct", and a criterion that cannot fail cannot answer yes. The PRE-FLIGHT probe is
            # a different question: "has this already been migrated", and there a vacuous pass is
            # the wrong answer, because the criterion never mentioned this asset's algorithm.
            verify.last_vacuous = bool(getattr(result, "vacuous", False))  # type: ignore[attr-defined]
            if result.status != "fail":
                return None
            # There are two ways to fail this stage and they need opposite advice. Appending one
            # fixed sentence to both told the model "your rewrite still leaves RSA in the file"
            # when RSA was gone and the real problem was that the replacement could not be found —
            # so the repair loop spent every remaining attempt correcting something that was
            # already correct. The rescan reports which expectation failed; use it.
            if result.expectation == "present":
                shapes = verified_target_shapes(language, result.expected or "")
                hint = ""
                if shapes:
                    hint = (
                        " QUBIT recognises it from code shaped like this:\n```"
                        f"{language}\n{shapes[0].source}\n```"
                    )
                return (
                    f"{result.detail}. You removed {asset.algorithm}, but the replacement is not "
                    f"one QUBIT can detect — check the module path and the call names."
                    f"{hint}"
                )
            return (
                f"{result.detail}. Your rewrite still leaves {asset.algorithm} in the file — check "
                "for an import, use-statement or include that you no longer call, and for another "
                "call site further down."
            )

        verify.last_vacuous = False  # type: ignore[attr-defined]
        return verify

    def _tenant_of(self, task: MigrationTask) -> UUID:
        """The team that owns a task, read from its plan one hop up.

        Tasks carry no tenant column of their own — same one-join boundary the API uses. Falls back
        to the default tenant only if the plan has vanished, which a foreign key makes impossible;
        the fallback exists so a lookup failure can never silently produce a NULL insert.
        """
        plan = self.session.get(MigrationPlan, task.plan_id)
        return plan.tenant_id if plan is not None else DEFAULT_TENANT_ID

    def build_plan(
        self,
        *,
        min_risk: float = 0.0,
        project_id: UUID | None = None,
        scan_id: UUID | None = None,
        tenant_id: UUID | None = None,
    ) -> MigrationPlan:
        """Build graph+queue from risk-annotated assets -> saves plan.

        `project_id` / `scan_id` bound the plan to one project (optionally to one scan within it).
        Without them the plan spans every asset in the database, which is what every plan did
        before scoping existed: the Migration Hub showed the newest plan, that plan had been
        assembled from whatever else had ever been scanned, and the project you had just scanned
        had no plan of its own to show. Both are recorded on the row AND in `scope_json`, so a plan
        can always say what it was built from.

        `tenant_id` is a HARD boundary, unlike those two: it always filters, and omitting it means
        the default tenant rather than "every team". A plan assembled across two teams' findings
        would put one team's file paths in the other's queue.
        """
        tenant_id = tenant_id if tenant_id is not None else DEFAULT_TENANT_ID
        # Domain assets live as flattened AssetRow rows; hydrate back to the schema the
        # graph/queue components expect.
        #
        # The scope filter runs in SQL. This used to `select(AssetRow)` with NO predicate at all —
        # every asset in the entire database, across every project and every historical scan —
        # convert each one through `row_to_asset` (pydantic validation per asset), and only then
        # discard the ones that are safe or unscored. A plan only ever concerns vulnerable,
        # risk-scored assets, so the rest was work done purely to be thrown away, and it grew with
        # total scan history rather than with the size of the plan. `qv_vulnerable`, `risk_score`,
        # `project_id` and `scan_id` are all indexed.
        # Quantum-vulnerable findings, PLUS hardcoded secrets.
        #
        # A key committed to a repository is not quantum-vulnerable in any interesting sense - it
        # is already compromised, today, by anyone with read access. The scanner has always
        # reported them and the plan has never included them, so the one class of finding with the
        # most urgent remediation in the whole inventory had no entry in the migration queue at
        # all. `secret_rotation` in the playbook is what to do about it; this is what routes them
        # there. They resolve to a guided path, because rotating a credential at its issuer is not
        # an edit and deleting the literal without rotating leaves a live key in the git history.
        predicates = [
            or_(
                and_(
                    AssetRow.qv_vulnerable.is_(True),
                    AssetRow.risk_score.is_not(None),
                    AssetRow.risk_score >= min_risk,
                ),
                AssetRow.asset_type == "secret",
            ),
            AssetRow.tenant_id == tenant_id,
        ]
        if project_id is not None:
            predicates.append(AssetRow.project_id == project_id)
        if scan_id is not None:
            predicates.append(AssetRow.scan_id == scan_id)
        rows = self.session.scalars(select(AssetRow).where(*predicates)).all()
        scope = {
            "project_id": str(project_id) if project_id else None,
            "scan_id": str(scan_id) if scan_id else None,
            "min_risk": min_risk,
        }
        in_scope = [row_to_asset(r) for r in rows]
        if not in_scope:
            plan = MigrationPlan(
                status="completed",
                tenant_id=tenant_id,
                project_id=project_id,
                scan_id=scan_id,
                scope_json=scope,
                stats_json={"message": "No vulnerable assets in scope"},
                regime=self.config.regime,
            )
            self.session.add(plan)
            self.session.commit()
            return plan

        plan = MigrationPlan(
            status="active",
            tenant_id=tenant_id,
            project_id=project_id,
            scan_id=scan_id,
            scope_json=scope,
            # Stamped at creation, so the plan explains its own targets. `ML-KEM-1024` and
            # `X25519MLKEM768` are each correct in one jurisdiction and rejected in another;
            # without this a reviewer cannot tell a deliberate choice from a mistake.
            regime=self.config.regime,
            config_json=self.config.model_dump(),
        )
        self.session.add(plan)
        self.session.flush()

        g = build_dependency_graph(in_scope, min_confidence=self.config.min_confidence)
        id_to_asset = {a.id: a for a in in_scope}
        units = migration_order(g, id_to_asset=id_to_asset)

        # Match rules FIRST, so the effort estimator can see them.
        #
        # This used to happen further down, once per unit member, which meant `rank_ready_frontier`
        # was called with no `effort_kwargs_map` at all: `estimate_effort` then ran with
        # `rule_kind=None` and `language="python"` for every asset, scored every task 8 points /
        # 4-12 h with the driver "no rule matched (+8)" — even on tasks whose matched rule id was
        # written to the very same row — and, because WSJF is `risk / effort.points`, reduced the
        # priority ranking to a rescaled risk score. The additive table in doc 03 §6.2 had never
        # run against real inputs.
        rules_by_asset = {a.id: match_rule(a, self._rules) for a in in_scope}
        effort_kwargs = {a.id: self._effort_inputs(a, rules_by_asset[a.id]) for a in in_scope}

        # Ranked tasks (ignoring prerequisites for the initial rank snapshot)
        ranked = rank_ready_frontier(in_scope, effort_kwargs_map=effort_kwargs)
        rank_map = {rt.asset.id: rt for rt in ranked}

        for info in units:
            unit_db = MigrationUnit(
                plan_id=plan.id,
                order_index=info.order_index,
                label=info.label,
                member_ids_json=[str(uid) for uid in info.member_ids],
            )
            self.session.add(unit_db)
            self.session.flush()

            for asset_id in info.member_ids:
                rt = rank_map[asset_id]
                rule = rules_by_asset[asset_id]
                task = MigrationTask(
                    plan_id=plan.id,
                    unit_id=unit_db.id,
                    asset_id=asset_id,
                    state="ready",  # M1: all start ready (edge prerequisites don't block yet)
                    rule_id=rule.id if rule else None,
                    effort_points=rt.effort.points,
                    effort_json={
                        "hours_low": rt.effort.hours_low,
                        "hours_high": rt.effort.hours_high,
                        "drivers": rt.effort.drivers,
                    },
                    priority=rt.priority,
                    rank=rt.rank,
                )
                self.session.add(task)
                self.session.flush()

                # Sync back to Asset.migration
                self._sync_public_status(task)
                write_event(
                    self.session,
                    task,
                    from_state=None,
                    to_state="ready",
                    detail={"rule": task.rule_id},
                )

        # Rollups the Migration Hub would otherwise recompute by walking every task on every
        # render. `automatable` is the one that matters operationally: a task with no codemod rule
        # cannot be patched from the app at all, and a plan that is mostly unautomatable is a very
        # different piece of work from one that is mostly not.
        by_algorithm: dict[str, int] = {}
        for rt in ranked:
            by_algorithm[rt.asset.algorithm] = by_algorithm.get(rt.asset.algorithm, 0) + 1
        tasks_built = list(plan.tasks)
        # Three states, not one "automatable" count. Only 5 of the 14 rules carry a deterministic
        # codemod; the rest route to a local LLM, which needs Ollama running and produces a patch a
        # human has to read. Reporting both as "codemod available" overstated what the app can do
        # offline by more than 2x on a real polyglot project (110 claimed vs 46 actual).
        codemod_rules = {r.id for r in self._rules if r.codemod}
        # Guided rules are a fourth category and have to be subtracted from the LLM count, not
        # left in it. A `dep-legacy-01` finding has a rule and no codemod, so the old arithmetic
        # called it LLM-assisted while its only control in the queue said GET GUIDANCE — the badge
        # and the button describing different products.
        guided_rules = {r.id for r in self._rules if r.remediation == "guided"}
        with_codemod = sum(1 for t in tasks_built if t.rule_id in codemod_rules)
        with_rule = sum(1 for t in tasks_built if t.rule_id)
        guided = sum(1 for t in tasks_built if t.rule_id is None or t.rule_id in guided_rules)
        plan.stats_json = {
            "tasks": len(in_scope),
            "units": len(units),
            "with_codemod": with_codemod,
            "with_llm_rule": max(0, with_rule - with_codemod - guided),
            # Kept under the key the API and dashboard already read. It no longer means "no rule
            # matched": every finding has a path, and this counts the ones whose path is a written
            # procedure rather than an edit.
            "manual": guided,
            # Retained under its old name for anything reading the previous shape; it means "has a
            # rule of any kind", which is what it always actually counted.
            "automatable": with_rule,
            "effort_points": sum(t.effort_points for t in tasks_built),
            "effort_hours_low": round(
                sum(float(t.effort_json.get("hours_low", 0.0)) for t in tasks_built), 1
            ),
            "effort_hours_high": round(
                sum(float(t.effort_json.get("hours_high", 0.0)) for t in tasks_built), 1
            ),
            "by_algorithm": dict(sorted(by_algorithm.items(), key=lambda kv: (-kv[1], kv[0]))),
        }
        self.session.commit()
        return plan

    def get_queue(self, plan_id: UUID, limit: int = 50) -> list[MigrationTask]:
        """Ready frontier, ranked."""
        stmt = (
            select(MigrationTask)
            .where(MigrationTask.plan_id == plan_id)
            .where(MigrationTask.state == "ready")
            .order_by(MigrationTask.rank)
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def generate_patch(
        self,
        task_id: UUID,
        *,
        generator: Literal["auto", "llm", "template"] = "auto",
        repo_root: Path | None = None,
    ) -> PatchProposal:
        """Generate a patch for a task, and record how long it took and what came of it.

        The measurement is the point of the wrapper. `Y` -- time to complete a migration -- is an
        input to every quantum risk model in the literature and every one of them ESTIMATES it,
        because completed migrations do not exist to measure. QUBIT performs them, with timestamps,
        per finding, and was discarding that as a log line.

        Wrapped here rather than instrumented at each exit because there are many exits and they
        must ALL be counted. A row is written whether the attempt was accepted, rejected, routed to
        guidance, found already satisfied, or failed outright: excluding the unsuccessful ones
        biases `Y` downward, which is the direction that flatters the tool and therefore the
        direction to be most careful about.

        Recording never changes the outcome. A measurement failure that swallowed a patch, or
        turned a working migration into an error, would be a instrumentation defect masquerading as
        a tool defect -- so every failure here is suppressed and the original result or exception
        propagates untouched.
        """
        queued_at = datetime.now(UTC)
        started = time.monotonic()
        record = functools.partial(
            self._record_measurement,
            task_id,
            queued_at=queued_at,
            started=started,
            repo_root=repo_root,
        )
        try:
            patch = self._generate_patch(task_id, generator=generator, repo_root=repo_root)
        except AlreadySatisfied as exc:
            # A verdict, not a failure: an earlier patch already did this work. It still consumed
            # scanner time, and a `satisfied` finding that goes unrecorded is a migration the
            # dataset claims never happened.
            # `suppress` at the CALL SITE, not only inside the recorder. These handlers end in
            # `raise`, so a recorder that threw would REPLACE the migration's own exception with a
            # measurement error — an instrumentation defect wearing a tool defect's costume, and
            # the hardest kind to diagnose. Making the guarantee structural here means it survives
            # any future edit to `_record_measurement` that escapes its own try block.
            with contextlib.suppress(Exception):
                record("satisfied", "satisfied", detail=str(exc))
            raise
        except GuidedRemediation as exc:
            # Also a verdict. The tool decided this finding needs a human and wrote the procedure;
            # scoring that as a failure understates the tool, and scoring it as an acceptance
            # overstates it, so it is its own path.
            with contextlib.suppress(Exception):
                record("guided", "guided", detail=str(exc), human=True)
            raise
        except Exception:
            with contextlib.suppress(Exception):
                record("model", "failed")
            raise
        # And on the success path for the mirror reason: a measurement failure must not discard a
        # patch that was generated and validated correctly.
        with contextlib.suppress(Exception):
            record(
                "model" if patch.generator == "llm" else "codemod",
                "accepted" if patch.status == "proposed" else "rejected",
                patch=patch,
            )
        return patch

    def _record_measurement(
        self,
        task_id: UUID,
        path: str,
        outcome: str,
        *,
        queued_at: datetime,
        started: float,
        repo_root: Path | None = None,
        patch: PatchProposal | None = None,
        detail: str = "",
        human: bool = False,
    ) -> None:
        """Write one row. Never raises, and never alters the outcome it is describing."""
        try:
            task = self.session.get(MigrationTask, task_id)
            asset = self.session.get(AssetRow, task.asset_id) if task else None
            spend = (task.spend_json or {}) if task else {}
            stages = ((patch.validation_json or {}).get("stages") or {}) if patch else {}
            rescan = stages.get("rescan") or {}
            row = MigrationMeasurement(
                task_id=task_id,
                plan_id=task.plan_id if task else None,
                corpus=self._corpus_label(),
                rule_id=(task.rule_id if task else "") or "",
                # A synthesised rule is a different experimental condition; pooling the two hides
                # which one the tool is actually good at.
                synthesised=bool(task and (task.rule_id or "").startswith("synth-")),
                # Derived from the path: `AssetRow` has no language column, and `getattr(asset,
                # "language", "")` silently returned "" for every row — a covariate that looked
                # measured and was always blank.
                language=_language_of_row(asset) or "",
                algorithm=str(getattr(asset, "algorithm", "") or ""),
                # `AssetRow` stores these as plain strings, not enums — reading `.value`
                # off a str silently yields "" and every row would lose its usage context.
                usage_context=str(getattr(asset, "usage_context", "") or ""),
                regime=self.config.regime,
                # From the rule's TARGET, not the file path — a path containing "+" is not a
                # hybrid migration, and `file_path` was the wrong field to read entirely.
                construction=self._construction_of(task),
                path=path,
                engine=(patch.model_name if patch else None),
                from_cache=bool(spend.get("from_cache")),
                queued_at=queued_at,
                started_at=queued_at,
                total_s=time.monotonic() - started,
                attempts=int(task.attempts or 0) if task else 0,
                model_seconds=float(spend.get("seconds") or 0.0),
                outcome=outcome,
                evidence_level=(patch.evidence_level if patch else None),
                stage_outcomes={k: v.get("status") for k, v in stages.items()},
                # Only meaningful on the rescan stage, and only written there when true -- so its
                # absence means "not measured", not "measured and clean".
                vacuous=bool(rescan.get("vacuous")),
                human_needed=human or outcome == "guided",
                diff_changed_lines=_diff_lines(patch.diff_text)[0] if patch else 0,
                # Blank-line-only changes. Tracked because it was a real failure mode — 12 of 18
                # patches in one run were majority whitespace — and a "changed lines" count that
                # includes them overstates how much work the tool did.
                diff_noise_lines=_diff_lines(patch.diff_text)[1] if patch else 0,
                # Size covariates. A 40 kB file and a 400-byte one are not the same task, so a
                # median over both is partly a median over the file-size distribution rather than
                # over the tool's behaviour.
                **_file_size(asset, repo_root),
            )
            if detail:
                row.stage_outcomes = {**row.stage_outcomes, "detail": detail[:400]}
            self.session.add(row)
            self.session.commit()
        except Exception:
            with contextlib.suppress(Exception):
                self.session.rollback()

    def _construction_of(self, task: MigrationTask | None) -> str:
        """`hybrid` when this task targets a composite, else `pure`.

        Read from what was ASKED FOR, not from the patch that came back. A patch that failed still
        attempted a hybrid migration, and filing it under `pure` would put it in the wrong
        distribution — hybrid is the more expensive treatment, so the error would flatter it.

        A synthesised rule is not in the catalog and its target cannot be read back here, so the
        fallback is the regime, which is what produced that target in the first place.
        """
        rule_id = task.rule_id if task else None
        rule = next((r for r in self._rules if r.id == rule_id), None)
        if rule is not None:
            return "hybrid" if "+" in str((rule.target or {}).get("algorithm") or "") else "pure"
        regime = load_regimes().get(self.config.regime)
        return "hybrid" if regime is not None and regime.requires_hybrid else "pure"

    def _corpus_label(self) -> str:
        """`owner/repo@commit` for the plan under way, or "".

        Denormalised onto every row so an exported CSV identifies its own corpus without a join
        into a database the reader does not have.
        """
        return str(getattr(self.config, "corpus", "") or "")

    def _generate_patch(
        self,
        task_id: UUID,
        *,
        generator: Literal["auto", "llm", "template"] = "auto",
        repo_root: Path | None = None,
    ) -> PatchProposal:
        """Generate a patch for a task.

        M1 only supports generator="template".
        """
        # Start counting what this patch costs the attached model. Deliberately not a context
        # manager: wrapping this body would re-indent several hundred lines to measure
        # something none of them are about.
        spend = start_ledger()
        task = self.session.get(MigrationTask, task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        # The team this work belongs to, read from the plan the task hangs off. Everything the
        # learning store reads or writes below is filtered by it, so one team's stored source is
        # never replayed into another team's prompt.
        tenant_id = self._tenant_of(task)

        # A task that FAILED a previous attempt is `deferred`/`unresolved`, not `ready`, and the
        # FSM has no `generate` event from `deferred` — so calling this on a failed task raised
        # `InvalidTransition`, which the API surfaced as "this task already has a generated patch,
        # review or reject it" (see `routers/migrate.py::generate_patch`'s 409 handler). That
        # message is simply wrong for this task: it has no patch at all, only a rejection. The
        # bulk path already resumes every `deferred`/`unresolved` task before generating for it
        # (`jobs/handlers.py::migrate_handler`); a single retry click deserves the same courtesy
        # rather than a dead end that can only be worked around by rebuilding the whole plan.
        # `resume_task` no-ops on any other state (satisfied, guided, already ready), so this is
        # safe to call unconditionally.
        self.resume_task(task_id)

        # Fall back to the project's own recorded root when the caller did not name one. The
        # dashboard does not send `repo_root` -- there is nowhere in the UI to type it -- so every
        # patch generated through the app arrived here with None, and two validation stages are
        # gated on it: `applies` needs a root to run `git apply` from, and `tests` needs one to
        # mount into the sandbox. Measured on this installation before the fix: of 84 patches, 58
        # skipped BOTH stages with "no repo_root/relative target", while `projects.root_path` held
        # a correct, existing directory for every one of them. The information was there and simply
        # never reached the validator.
        #
        # A supplied root always wins, so nothing about the CLI or the evidence scripts changes,
        # and a root that no longer exists on disk is ignored rather than raised on -- a project
        # whose checkout has moved should still produce a patch, just an unvalidated one, exactly
        # as it does today.
        if repo_root is None:
            recorded = self._project_root_of(task)
            if recorded is not None:
                repo_root = recorded

        asset = self._load_asset(task.asset_id)
        if not asset or not asset.location or not asset.location.file_path:
            raise ValueError(f"Asset {task.asset_id} has no file_path")

        file_path = Path(asset.location.file_path)
        if repo_root:
            # `Path.__truediv__` is a documented no-op when the right side is already absolute:
            # `repo_root / file_path` silently returns `file_path` UNCHANGED, discarding
            # `repo_root` entirely. `asset.location.file_path` is always absolute -- the scanner
            # records real filesystem paths -- so this line never actually re-anchored anything;
            # it only happened to look correct because `repo_root` and the asset's own path have,
            # so far, always agreed (both derived from the same scan).
            #
            # They stop agreeing the moment a project's `root_path` is changed via
            # `PATCH /projects/{id}` (reachable today over the API; not yet wired to a dashboard
            # control) without a fresh scan to refresh its assets' paths. When that happens, this
            # silently fell through to a WORSE failure than a clear error: `diff_path` below
            # raises `ValueError` on `.relative_to()` and the exception is swallowed, so
            # `diff_path` becomes the STALE absolute path instead of a repo-relative one --
            # and `apply_patch` re-anchors `patch.file_path` the same no-op way, so the write
            # lands at the OLD location, not `repo_root`, with nothing to say so. `repo_root` was
            # bypassed end to end, silently, in both directions.
            #
            # Failing loudly here (NFR-7) turns that into an error the operator can act on instead
            # of a migration written to a location they did not choose.
            resolved = file_path.resolve()
            if not resolved.is_relative_to(repo_root.resolve()):
                raise ValueError(
                    f"{asset.location.file_path} is not inside {repo_root} — this project's "
                    "root path has changed since the finding was scanned. Rescan the project to "
                    "refresh its asset paths before migrating."
                )
            file_path = resolved

        # Diff headers + the stored patch path are repo-relative (posix) whenever the file
        # sits under repo_root — required for `git apply` to work from the repo root.
        # Absolute paths only remain for repo-less generation (no apply possible there).
        diff_path = str(file_path)
        if repo_root:
            diff_path = file_path.relative_to(repo_root.resolve()).as_posix()

        rule = match_rule(asset, self._rules)
        if not rule:
            # No rule in the pack is not the same as nothing to do. QUBIT already knows what this
            # family and usage should become -- the knowledge base and the agility policy are what
            # `/assets/{id}/recommendation` has always answered with -- so a rule is synthesised
            # from that and the model is asked to write the change. The target comes from QUBIT's
            # own knowledge, never from the model's imagination, and the patch faces every gate a
            # hand-written rule's patch faces, the rescan included.
            #
            # Guidance is still the answer when synthesis returns None: a hash is not a Shor
            # problem, a certificate cannot be rewritten, and an ecosystem with no trustworthy PQC
            # provider should not have one installed on the operator's behalf.
            # From the file's own suffix rather than `file_language`, which is not computed until
            # the LLM branch far below -- and a synthesised rule has to exist before there is a
            # branch to take.
            # NOT defaulted to Python. A synthesised rule tells the model to rewrite this file in
            # this language, so guessing the language means asking for a Python rewrite of a file
            # that is not Python -- and `notes.txt` mentioning RSA would be handed to a model as
            # Python source. A suffix QUBIT has no grammar for gets guidance, exactly as before:
            # there is no rescan that could check the answer anyway.
            # The PATH, not the suffix: `language_for_suffix` takes the whole path and reads the
            # suffix itself, and `Path(".py").suffix` is "" -- a leading dot makes it a hidden file
            # with no extension. Passing the suffix meant the lookup returned None every single
            # time, which the previous `or "python"` then covered up, so every file of every kind
            # was being called Python.
            synth_language = language_for_suffix(file_path)
            # A rule QUBIT already derived AND proved comes first. Not for speed -- deriving costs
            # nothing -- but for consistency: a stored rule is one whose patch passed the gates, so
            # the second occurrence of a finding is answered by the derivation that worked rather
            # than by whatever the knowledge base happens to resolve to now.
            if synth_language is not None:
                rule = recall_rule(self.session, asset, synth_language, tenant_id)
                if rule is None:
                    rule = synthesize_rule(asset, synth_language, regime=self.config.regime)
            if rule is None:
                task.last_error = "no migration rule covers this finding"
                self.resolve_guided(task.id, force=True)
                raise GuidedRemediation(task.id, task.advice_text or "")
            logger.info(
                "no rule for %s/%s; using %s targeting %s",
                asset.algorithm,
                synth_language,
                rule.id,
                rule.target.get("algorithm"),
            )

        # A rule can declare that no edit is the right answer. That is a verdict about the
        # finding, not a limitation to be worked around: a certificate is a signed object, and an
        # ecosystem whose only PQC package comes from an unverified publisher should not have it
        # installed on the user's behalf. Deciding this BEFORE `generate` means the model is never
        # asked for something structurally impossible.
        if rule.remediation == "guided":
            self.resolve_guided(task.id, force=True)
            raise GuidedRemediation(task.id, task.advice_text or "")

        # The algorithm may not be this repository's to change.
        #
        # Checked HERE, before any generator runs, because the downstream gates provably cannot
        # catch it: eleven patches on `pyload` passed `applies`, `parses`, `symbols`, `compiles`
        # and `rescan` while breaking authentication against three different services, because
        # each rewrote crypto whose format is fixed by a remote party. `rescan` passes precisely
        # BECAUSE the algorithm changed. See `qubit-v2/08-evaluation/RESULTS-B0-arm.md`.
        #
        # Guided rather than skipped: the risk is real and the operator still needs it on the
        # report. What is not available is a source edit.
        contract = external_contract(
            asset.algorithm,
            (asset.location.file_path if asset.location else None),
            ((asset.evidence.snippet if asset.evidence else None) or None),
        )
        # The snippet is a +/-2 line window, which can show a call and nothing about what happens
        # to its result. The reason a digest must not change is almost never on the call line: it
        # is in the docstring above it. Measured across the four twins, refusals whose evidence
        # class is `prose` were 4 of the 9 false migrations in the first complete run, and every
        # one had the constraint written down two lines up.
        #
        # Consulted only when the snippet-level rules found nothing, so it can add refusals and
        # never override a verdict reached on stronger evidence.
        if contract is None:
            contract = _documented_constraint_for(asset)
        if contract is not None:
            task.last_error = contract.reason
            # `resolve_guided` regenerates `advice_text` from the playbook, so the contract's own
            # advice is APPENDED afterwards rather than set before — assigning first silently lost
            # it, and the operator saw the generic "migrate this hash" guidance for a finding whose
            # whole point is that it must not be migrated.
            self.resolve_guided(task.id, force=True)
            contract_advice = contract.advice(asset.algorithm or "This algorithm")
            task.advice_text = "\n\n".join(
                part for part in (task.advice_text, contract_advice) if part
            ).strip()
            self.session.commit()
            # `refusal=True`: this is the one guided path where a patch was available and declining
            # to write it IS the correct migration decision. The caller counts it apart from the
            # findings QUBIT simply could not answer.
            raise GuidedRemediation(task.id, task.advice_text, refusal=True)

        def _mark_generating() -> None:
            self._transition(task, "generate", detail={"generator": generator})
            self.session.commit()

        # Commit the transition BEFORE any generation starts, and specifically before the model is
        # called. SQLite allows one writer at a time even under WAL, and `_transition` writes
        # (the task's new state, plus an event row) without committing — so the write lock was
        # taken at the next autoflush and then held for the entire duration of the LLM call.
        #
        # A `code-kex-01` attempt is three model calls at up to `llm_timeout` (180s default) each,
        # so the lock could be held for minutes. Every other writer in the process — most visibly
        # a click on "Build plan" for a DIFFERENT project trying to INSERT its job row — waited on
        # `busy_timeout` and failed. That is what `commit_with_retry` was written for, and it is
        # why retrying could not fix it: no retry budget outlasts a five-minute lock. Measured
        # during a five-repository stress run: 3 of 5 build-plan clicks produced no job at all.
        #
        # Committing here is also just correct on its own terms. "This task is generating" is a
        # durable fact worth surviving a crash, and holding it uncommitted bought nothing.
        #
        # RETRIED, and the paragraph above is why that is now the right answer where it once was
        # not. "No retry budget outlasts a five-minute lock" was true while the lock was held
        # ACROSS the model call; committing before generation is exactly what stopped that. What
        # remains is brief contention between generations that overlap -- one client's request
        # finishing server-side while the next starts -- and brief contention is precisely what a
        # jittered retry is for. Measured: without it this line answered HTTP 500 at ~25.7s (just
        # past `PRAGMA busy_timeout`'s 20s) whenever a previous generation was still writing.
        #
        # `retry_write_on_lock`, not `commit_with_retry`: the transition MUTATES an existing row,
        # and `rollback()` reverts that, so retrying the commit alone would commit an empty
        # transaction and report success with the task never moved to `generating` -- the exact
        # "silently commits an EMPTY transaction" failure `commit_with_retry`'s own docstring
        # warns about. The whole transition has to be redone.
        retry_write_on_lock(self.session, _mark_generating)

        # auto prefers the deterministic codemod; LLM is used when forced or when the
        # rule has no codemod. Either way the same validation pipeline gates the result.
        use_llm = generator == "llm" or (generator == "auto" and not rule.codemod)
        # Some codemods are the authority for their transform and outrank an explicit
        # `--generator llm` (see MigrationRule.codemod_authoritative): the correct output is a
        # constant, so a model can only lose information. This is what kept X25519MLKEM768 out of
        # LLM-generated configs.
        if use_llm and rule.codemod and rule.codemod_authoritative:
            use_llm = False
        model_name: str | None = None
        # Only the LLM branch populates these; the codemod branch leaves them at their defaults so
        # the shared validation/record code below can read them unconditionally.
        learned: LearnedPatch | None = None
        finding_line: int | None = None
        file_language = ""
        # Hoisted with the other shared locals: the outcome recorder below the branch reads them,
        # and only the LLM branch sets them.
        shape: str | None = None
        flagged_line = ""
        security_notes: list[str] = []
        # The lines of the model's own notes that admit something is unfinished. Kept beside the
        # diff so a reviewer sees what the patch does NOT do before approving it, and deliberately
        # never a rejection — see `llm.check_reasoning`.
        security_caveats: list[str] = []

        # A prior patch for ANY rule can move this finding too (for example, deleting a Go import
        # shifts every later hash call).  Do not classify a task as satisfied by comparing
        # scan-time line numbers: a shifted sibling can land on an earlier task's historic line.
        # The codemod and occurrence-aware rescan below are the authority after a write.
        prior_write_to_file = bool(
            self.session.scalar(
                select(PatchProposal.id)
                .join(MigrationTask, PatchProposal.task_id == MigrationTask.id)
                .where(PatchProposal.file_path == diff_path)
                .where(PatchProposal.status == "applied")
                .where(MigrationTask.plan_id == task.plan_id)
                .where(MigrationTask.id != task.id)
                .limit(1)
            )
        )

        this_line = asset.location.line if asset.location else None
        if prior_write_to_file:
            try:
                current_source = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self._fail_task(task, f"cannot re-anchor finding after an earlier patch: {exc}")
                raise ValueError(task.last_error) from exc
            relocated_line = _relocate_finding_line(asset, current_source)
            if relocated_line is None:
                detail = (
                    "an earlier patch changed this file and QUBIT cannot uniquely re-anchor this "
                    "finding from its scan evidence. Rescan the project before retrying; no patch "
                    "was generated from the stale line location."
                )
                self._fail_task(task, detail)
                raise ValueError(detail)
            if relocated_line != this_line:
                asset = asset.model_copy(deep=True)
                assert asset.location is not None
                asset.location.line = relocated_line

        # CAN THIS ENVIRONMENT ACTUALLY BUILD THE TARGET?
        #
        # Asked before any model time is spent, and before a codemod writes a rewrite that cannot
        # import. A migration to a primitive the machine does not have is worse than no migration:
        # the patch applies, it parses, its names look right, and then every later gate blames the
        # PATCH for what is an environment problem.
        #
        # Live example rather than a hypothetical: `cryptography` 49.0.0 ships no `slhdsa` module
        # at all, while BSI TR-02102 approves SLH-DSA and a rule may legitimately target it.
        # Routed to guidance rather than failed — the finding is real and a human can still act on
        # it, so refusing to write a patch is the correct answer, not a defeat.
        availability = target_availability(str((rule.target or {}).get("algorithm") or ""))
        if not availability.available:
            # `last_error` first: `resolve_guided` writes the advice, and the operator needs
            # to see WHY a real finding produced a procedure instead of a diff.
            task.last_error = availability.advisory
            self.resolve_guided(task.id, force=True)
            raise GuidedRemediation(task.id, task.advice_text or availability.advisory)

        # The file's OWN line-ending convention, re-injected only into the diff (see
        # `old_new_to_diff`) — `orig`/`new` themselves stay LF-normalized for every codemod, LLM
        # prompt and validation stage downstream (both branches below read the file with
        # `read_text()`, whose universal newline translation strips `\r` either way), none of
        # which cares about the difference. Computed once, here, since both branches need it.
        line_ending = detect_line_ending(file_path)

        if use_llm:
            # Several assets routinely share one file — a weak sshd_config yields a finding per
            # algorithm in every list — so whichever task runs first remediates the file for all of
            # them. The rest then have nothing to do. The deterministic codemod is the cheapest
            # authority on that: it reports "no change" exactly when its target pattern is gone.
            # Probing it first turns three wasted 7B-model attempts and a misleading "LLM rewrite
            # rejected" into an immediate, accurate skip. The probe result is DISCARDED — an
            # explicit `--generator llm` still gets its rewrite from the model when work remains.
            if rule.codemod:
                probe_found_work = True
                with contextlib.suppress(Exception):  # a probe failure must not block generation
                    probe_found_work = run_codemod(rule.codemod, asset, file_path) is not None
                if not probe_found_work:
                    self._fail_task(
                        task,
                        "already remediated by an earlier task in this plan",
                        resolution=RESOLUTION_SATISFIED,
                    )
                    raise AlreadySatisfied("already remediated by an earlier task in this plan")
            from .transform import learn
            from .transform.llm import _prompt_language

            file_language = _prompt_language(rule, asset)
            orig = file_path.read_text(encoding="utf-8")
            finding_line = asset.location.line if asset.location else None

            # Does the file ALREADY meet this rule's success criterion? The rescan verifier is
            # the rule's own definition of "migrated"; running it against the unmodified source
            # answers the question before a single token is generated.
            #
            # This is not an optimisation bolted on for speed, though it is a large one. On a
            # partially-migrated codebase the model was being handed files that were already
            # correct - `code-weakcipher-01` matches bare `AES`, and a file rewritten to
            # AES-256-GCM still reports bare `AES` because the key length lives in the key
            # variable, not the call. The model did the right thing and returned the file
            # unchanged; the engine called that a rejection, tried twice more, and recorded a
            # failure. Measured on a run over an already-migrated corpus: three model calls each,
            # on tasks whose honest answer was "already done".
            already = self._rescan_verifier(rule, asset, diff_path)
            satisfied = False
            if already is not None:
                with contextlib.suppress(Exception):  # a probe failure must not block generation
                    # NOTE: a vacuous pass is accepted here, deliberately, and it costs real
                    # migrations. `_stage_rescan` narrows its `gone` prefixes to the ones describing
                    # THIS asset's algorithm and falls through to the full list when none match, so
                    # the criterion is satisfied by construction. The closure records that
                    # (`last_vacuous`), and rejecting it here looks like the obvious fix.
                    #
                    # It is not, because the two cases are indistinguishable to the RULE.
                    # `code-weakcipher-01` declares `gone: [DES, 3DES, RC4, ...]` and
                    # `present: [AES]`, so for any AES asset the `gone` half is vacuous and the
                    # `present` half passes. That is correct for a file already using AES-256-GCM --
                    # `test_a_file_that_already_meets_the_rule_is_not_sent_to_the_model` pins that,
                    # and sending such a file to a model wastes three calls to reach "already done".
                    # It is wrong for inkwell-esign's `encrypt_draft`, which is AES-128-CBC and
                    # genuinely needs migrating; two of that twin's five migratable findings are
                    # lost here.
                    #
                    # Same code path, opposite correct answers, and nothing at this level can tell
                    # them apart. The fix belongs in the RULE: `code-weakcipher-01` needs a
                    # criterion its own findings can fail -- a `weakness_gone` naming the mode or
                    # key size it flagged -- rather than one satisfied by the algorithm family it
                    # already matched. Recorded as a measured limitation instead of patched here,
                    # because changing the probe trades a correct skip for a correct call at a
                    # one-for-one rate.
                    satisfied = already(orig) is None
            if satisfied:
                # Raised OUTSIDE the suppress block. `AlreadySatisfied` subclasses ValueError, so
                # raising it inside `contextlib.suppress(Exception)` was swallowed and the task
                # went on to call the model anyway - the probe ran, answered correctly, and the
                # answer went nowhere.
                detail = (
                    f"{Path(diff_path).name} already meets what {rule.id} asks for - the flagged "
                    "algorithm is gone from this occurrence and the target is present. Nothing "
                    "left to generate."
                )
                self._fail_task(task, detail, resolution=RESOLUTION_SATISFIED)
                raise AlreadySatisfied(detail)

            # What this project already knows about migrating code of this SHAPE.
            #
            # The older grounding asked for "any two verified line pairs for this rule", which is
            # weak evidence and, in this installation, mostly unreachable evidence: 17 of the 21
            # cached rows carried the rule's `multi` as their language while the lookup passes the
            # file's, so they could never be returned at all. This asks a sharper question - has
            # anything structurally identical been migrated before, and did it work - and gets
            # back hunks, the reasoning that went with them, and the rejections to avoid.
            flagged_line = ""
            if finding_line is not None:
                source_lines = orig.splitlines()
                if 1 <= finding_line <= len(source_lines):
                    flagged_line = source_lines[finding_line - 1]
            shape = learn.shape_key(rule.id, file_language, flagged_line) if flagged_line else None
            experience = learn.experience_for(
                self.session,
                rule_id=rule.id,
                language=file_language,
                shape=shape,
                # The flagged neighbourhood, for the near-miss tier: an exact shape key cannot
                # match code that differs by an added or removed statement, and that is the
                # common case in a real repository.
                text=_neighbourhood(orig, finding_line),
                tenant_id=tenant_id,
            )

            learned = learn.lookup(
                self.session,
                rule_id=rule.id,
                orig=orig,
                line=finding_line,
                tenant_id=tenant_id,
            )
            reused = (
                learn.apply(orig, finding_line, learned)
                if learned is not None and finding_line is not None
                else None
            )

            def _capture_notes(text: str) -> None:
                security_notes.append(text)

            def _capture_caveats(lines: list[str]) -> None:
                security_caveats.extend(lines)

            # Which engine actually generates: the DB-backed config a user sets in Settings, read
            # fresh here rather than cached anywhere, so a key changed mid-session takes effect on
            # the very next finding without restarting the process. Falls back to plain Ollama
            # (today's only behaviour) whenever nothing is configured, the row is missing, or no
            # key has been saved for the external provider yet — an unconfigured install is
            # byte-for-byte what it was before this existed.
            # The CHEAPEST engine that can actually do this finding, not simply whichever is
            # configured as primary. Free local first, then externals by ascending allowance —
            # see `_engines` for why smallest-that-fits is both the cheapest and the fastest.
            # Falls back to the local model when nothing is configured, which is what an install
            # with no keys has always done.
            #
            # Decide what will actually be SENT before choosing an engine to send it to. A file
            # that will be windowed is sized by its EXCERPT, because that is all the engine ever
            # receives. Sized by the whole file, `_select_engine` returns None for every oversize
            # finding and the fallback below hands the work to a hardcoded local engine -- which
            # skips the reliability gate entirely, giving the job to the one engine this
            # installation may already have measured as unable to do it. Sized by the excerpt the
            # gate applies again and the finding escalates to an engine with no such record.
            windowed = False
            routing_source = orig
            if self._oversize_reason(orig) is not None:
                excerpt = build_excerpt(orig, asset.location.line if asset.location else None)
                # The excerpt has to actually FIT. A file with a 300-line import block produces a
                # large one, and windowing it anyway would clear the size refusal and then hand a
                # still-oversize prompt to a model that truncates it silently -- strictly worse
                # than the guidance the refusal would have produced. Measured across the 27
                # oversize findings here the excerpt fits every time, worst case 2,527 tokens
                # against a 28,800 budget, but "every time so far" is not a guarantee.
                if excerpt is not None and self._oversize_reason(excerpt.text) is None:
                    windowed, routing_source = True, excerpt.text
            routed, decision = self._route(rule, routing_source, file_language, tenant_id)
            chosen = routed or _Engine(
                name=self.config.model,
                endpoint=None,
                budget_tokens=self.config.llm_context_tokens,
                metered=False,
            )
            if routed is not None and decision.wait_seconds:
                # A token-per-minute window REFILLS; a daily request quota does not. Groq's own 429
                # says *"Please try again in 4.86s"*, and the scheduler only proposes a wait it has
                # already judged shorter than routing elsewhere would cost -- against a local engine
                # measured in minutes per finding, a few seconds is the cheap answer. Waits longer
                # than `MAX_WAIT_SECONDS` never reach here; they are rejected as a route.
                logger.info(
                    "waiting %.1fs for %s: %s",
                    decision.wait_seconds,
                    chosen.name,
                    decision.reason,
                )
                time.sleep(decision.wait_seconds)
            logger.debug("routing %s/%s: %s", rule.id, file_language, decision.reason)
            for name, why in decision.rejected:
                logger.debug("  not %s: %s", name, why)
            use_external = chosen.endpoint is not None
            if use_external:
                logger.info(
                    "routing %s/%s to %s (allowance %s tokens)",
                    rule.id,
                    file_language,
                    chosen.name,
                    f"{chosen.budget_tokens:,}",
                )
            # Everything else the scheduler ranked stays available BENEATH the choice: if the
            # selected engine is unreachable, overloaded or rate-limited mid-run, `_generate`
            # walks on to the next one rather than failing the finding. Degrade, never stop.
            #
            # Taken from the routing decision rather than from `_engines()` order, which is what
            # it used to be. That order is by context size, so the "backup" was whichever engine
            # happened to have the next-smallest window -- possibly one already rejected for this
            # finding as out of quota, too small, or measured as unable to do this pairing. The
            # ranked alternatives are the engines that passed every one of those checks.
            by_name = {e.name: e for e in self._engines()}
            fallback_chain = [
                engine.endpoint
                for name in decision.alternatives
                if (engine := by_name.get(name)) is not None and engine.endpoint is not None
            ]
            backup_endpoint = fallback_chain[0] if fallback_chain else None

            # Set by `on_fallback` the moment generation drops off the primary — so the patch is
            # attributed to whichever engine actually produced it, not the one merely configured.
            # The reliability gate counts against these exact strings, so blaming the wrong engine
            # would both poison its record and leave the real one's artificially clean.
            actually_ran: str | None = None

            def _mark_fallback(engine: str) -> None:
                nonlocal actually_ran
                actually_ran = engine

            def _current_model_name() -> str:
                # The engine ROUTING picked, not whichever is configured primary -- otherwise a
                # finding sent to the local model to save quota would be recorded against an
                # external one, and the reliability gate would learn the wrong engine's record.
                # `actually_ran` overrides it when the chain fell through to a different engine.
                if actually_ran is not None:
                    return actually_ran
                return chosen.name

            # `windowed` was decided above, alongside the engine it is routed to. `_generate_fresh`
            # reads it, so the retry paths window exactly as the first attempt did -- a file does
            # not become smaller because the validator rejected the last candidate.
            def _generate_fresh(source: str, feedback: str | None = None) -> str:
                try:
                    generated = generate_llm_source(
                        source,
                        rule,
                        asset,
                        model=(chosen.endpoint.model if chosen.endpoint else self.config.model),
                        base_url=(
                            chosen.endpoint.base_url if chosen.endpoint else DEFAULT_BASE_URL
                        ),
                        fallback_model=self.config.fallback_model,
                        timeout=self.config.llm_timeout,
                        # The baseline the repair loop judges against. Without it the loop
                        # applies the whole-file `gone` rule while the validator that
                        # accepts the result applies the per-occurrence one.
                        verify=self._rescan_verifier(rule, asset, diff_path, original_source=orig),
                        experience=experience,
                        # Set only on a re-attempt, carrying the validator's own words about what
                        # was wrong with the previous candidate. `_build_prompt` renders it as the
                        # "your previous attempt was REJECTED for this reason" block.
                        feedback=feedback,
                        on_notes=_capture_notes,
                        on_caveats=_capture_caveats,
                        self_review_pass=self.config.llm_self_review,
                        plan_first=self.config.llm_plan_first,
                        provider="openai-compatible" if use_external else "ollama",
                        api_key=chosen.endpoint.api_key if chosen.endpoint else None,
                        # Keep Ollama as a backup (§2 of the LLM-provider plan): if the external
                        # call can't connect or the key is rejected, fall back to the SAME local
                        # model this install already runs when no external provider is configured
                        # at all, rather than failing the task over an outage of a service QUBIT
                        # doesn't control.
                        fallback_ollama_model=self.config.model,
                        on_fallback=_mark_fallback,
                        backup=backup_endpoint,
                        # The rest of the ranked pool, so a finding survives more than one engine
                        # failing. Engines fail independently, which is why pooling free tiers is
                        # worth doing at all.
                        backups=tuple(fallback_chain[1:]),
                        # The provider's EFFECTIVE per-request token allowance, which on a free
                        # tier is a rate limit far below the model's context window. Without it
                        # `max_tokens` was sized from the model's ceiling and the whole request
                        # was refused with 413 — see `_external_output_budget`.
                        budget_tokens=(chosen.endpoint.budget_tokens if chosen.endpoint else None),
                        # Show an excerpt rather than the whole file. Set only where the whole
                        # file provably does not fit, so this never narrows what the model sees
                        # on a file it could have read completely.
                        windowed=windowed,
                    )
                    # Blank lines the model dropped are put back before ANYTHING sees this
                    # candidate — the validator, the repair loop's feedback, the stored diff. No
                    # gate can object to reformatting, because no parse, symbol, compilation or
                    # rescan result depends on a blank line; so without this a patch that was
                    # right about the cryptography still reached the operator as a diff full of
                    # edits nobody asked for, with the migration the hard part to find in it.
                    return restore_incidental_blank_lines(source, generated)
                except (OSError, OllamaError) as e:
                    # A rejection is evidence. Recorded against the SHAPE so the next attempt at
                    # structurally identical code is told what was tried and why it failed,
                    # instead of rediscovering it over three more model calls. Nothing about this
                    # refuses future work - a ceiling measured on one model is not a property of
                    # the task.
                    if shape:
                        with contextlib.suppress(Exception):
                            learn.record_outcome(
                                self.session,
                                rule_id=rule.id,
                                language=file_language,
                                algorithm=asset.algorithm,
                                shape=shape,
                                tenant_id=tenant_id,
                                passed=False,
                                hunk_before=flagged_line,
                                failure_reason=str(e),
                                # The engine that actually ran, NOT `self.config.model`. This row
                                # is what the reliability gate counts against a (rule, language,
                                # engine) triple, so attributing an external provider's failure to
                                # the local model would blame Ollama for work it never did — and
                                # leave the external engine's record artificially clean, so it
                                # would never be gated even when it should be.
                                model_name=_current_model_name(),
                                # `generate_llm_source` appends `unverifiable_reason`'s explanation
                                # when the rescan could not be satisfied by any output in this
                                # language. Asking it directly beats matching its wording later.
                                unwinnable=unverifiable_reason(rule, file_language) is not None,
                            )
                            self.session.commit()
                    self._fail_task(task, f"LLM generation failed: {e}")
                    raise ValueError(f"LLM generation failed: {e}") from e

            if reused is not None and learned is not None:
                # An identical finding was already fixed and validated — replay it and skip the
                # model. This still passes the same validation gate below before it can be
                # proposed; only the LLM round-trip is skipped, never the validator.
                new = reused.new_source
                model_name = f"cache:{learned.source_model or self.config.model}"
            else:
                # Nothing cached for this finding, so the model is the next tier — but only where
                # the model can actually deliver. Checked AFTER the cache, so a free replay is
                # never given up, and skipped entirely when the caller explicitly asked for the
                # model rather than letting `auto` decide.
                if generator != "llm":
                    detour = self._llm_detour_reason(rule, orig, file_language, tenant_id)
                    # Size alone is no longer a reason to give up. When the ONLY thing wrong is
                    # that the file will not fit, and the finding has a line to centre on, the
                    # model is shown an excerpt instead -- the imports plus the neighbourhood of
                    # the flagged line -- and `Excerpt.splice` puts its answer back into the full
                    # file before anything inspects it.
                    #
                    # Measured on this installation: 27 findings are refused here today, and
                    # an excerpt of every single one fits (median 1,800 tokens against a whole-file
                    # median of 35,279, worst case 2,527 against 115,994 -- a 96.3% reduction).
                    # The message this used to produce said "splitting the change by hand is what
                    # this needs"; this is QUBIT doing that splitting itself.
                    if windowed and detour == self._oversize_reason(orig):
                        detour = None
                    if detour is not None:
                        # `_fail_task` first, exactly as the post-failure fallback in
                        # `jobs/handlers.py` does. It is what sets `resolution=unresolved`, and
                        # that value is load-bearing twice over: `resume_task` and the bulk run's
                        # retry query both select ONLY `unresolved`, and the Migration Hub's
                        # progress split reads it to tell handled work from outstanding work.
                        #
                        # Setting `last_error` alone left resolution NULL, which silently made a
                        # detoured finding the worst of both: never retried when a better engine
                        # arrived, and counted as outstanding forever so the plan could never read
                        # complete. `claim_resolved=False` then attaches the plan without claiming
                        # the finding is settled: the remediation is real, the retry still owed.
                        self._fail_task(task, detour)
                        self.resolve_guided(task.id, force=True, claim_resolved=False)
                        raise GuidedRemediation(task.id, task.advice_text or "")
                new = _generate_fresh(orig)
                model_name = _current_model_name()
                learned = None
        else:
            if not rule.codemod:
                self._fail_task(task, "Rule has no codemod")
                raise ValueError(f"Rule {rule.id} has no codemod fallback")
            try:
                result = run_codemod(rule.codemod, asset, file_path)
                if not result and rule.codemod == "bump_crypto_dependency":
                    # A version bump with nothing to raise means the pin is ALREADY at or above the
                    # PQC-capable floor — the outcome the rule exists to reach, reported as a
                    # generic "produced no change" failure. Measured on the polyglot corpus, whose
                    # requirements.txt pins cryptography==49.0.0 against a 48.0.0 floor.
                    #
                    # The task is still parked rather than completed: the FSM's terminal states all
                    # mean "a patch was applied and verified", and claiming that for a file nothing
                    # touched would be worse than an accurate message.
                    detail = (
                        "no bump needed - this dependency already pins a version that provides "
                        "PQC primitives"
                    )
                    self._fail_task(task, detail, resolution=RESOLUTION_SATISFIED)
                    raise AlreadySatisfied(detail)
                if not result:
                    # "Produced no change" is true but unhelpful, and for a dependency bump it is
                    # actively misleading: the usual cause is that the pin is ALREADY at or above
                    # the PQC-capable floor, which is a success condition, not a failure. The other
                    # cause is that an earlier task in the same plan already remediated this file —
                    # several assets routinely share one.
                    detail = (
                        f"nothing left for {rule.codemod} to change in "
                        f"{Path(diff_path).name} — either this file was already remediated by an "
                        "earlier task in this plan, or it already meets the target."
                    )
                    self._fail_task(task, detail, resolution=RESOLUTION_SATISFIED)
                    raise AlreadySatisfied(detail)
                orig, new = result
                untouched = _flagged_line_untouched(orig, new, asset)
                if untouched is not None:
                    self._fail_task(task, untouched)
                    raise ValueError(untouched)
            except AlreadySatisfied:
                # Already parked as satisfied by the branch that raised it. Re-parking here would
                # overwrite that with `unresolved` and rename finished work "Codemod error".
                raise
            except Exception as e:
                self._fail_task(task, f"Codemod error: {e}")
                raise

        # Applied to BOTH generators, and after generation rather than before, because the question
        # is what the patch does — not what the finding looked like. A model asked to fix one hash
        # in a file rewrites its neighbours just as readily as a codemod does.
        collateral = _contract_collateral(orig, new, asset)
        if collateral is not None:
            self.resolve_guided(task.id, force=True)
            task.advice_text = "\n\n".join(
                part for part in (task.advice_text, collateral) if part
            ).strip()
            self.session.commit()
            # The same verdict as the pre-generation contract check, reached after the fact: the
            # rewrite touched crypto a remote party owns. Counted as a refusal for the same reason.
            raise GuidedRemediation(task.id, task.advice_text, refusal=True)

        def _validate(candidate: str) -> ValidationReport:
            return validate_patch(
                diff_text=old_new_to_diff(diff_path, orig, candidate, line_ending=line_ending),
                patched_source=candidate,
                rule=rule,
                repo_root=repo_root,
                language=rule.language,
                # ALWAYS pass the path, not only when a repo root was supplied. `target_rel_path`
                # is used by `_effective_language` purely to read the file's SUFFIX, which needs no
                # repo — but it was gated on `repo_root`, and generating from the app supplies none.
                # So for every cross-language rule (`language: multi`) the validator fell back to
                # "multi", found no grammar for it, and skipped BOTH the syntax check and the
                # rescan. Measured across 20 generated patches: only the one Python patch was
                # validated at all; the other 18 were accepted with every stage `skipped`.
                # `repo_root` still gates the `applies` stage on its own, which is the stage that
                # genuinely needs a git repo.
                target_rel_path=diff_path,
                no_docker=self.config.no_docker,
                # The sandbox the `tests` stage runs in. Default is a bare interpreter, which is
                # why that stage has never once run here; point it at an image carrying the target
                # repo's pinned dependencies and it becomes a real behaviour-preservation oracle.
                test_sandbox_image=self._sandbox_image_for(repo_root, rule.language),
                test_command=self._test_command_for(task, repo_root, rule.language),
                test_timeout_s=self.config.test_timeout_s,
                asset_algorithm=asset.algorithm,
                original_source=orig,
                # This task owns ONE finding. Other occurrences of the same algorithm in the
                # same file are other tasks; judging this patch on theirs made every task in a
                # mixed file fail. Measured: 3 MD5 findings in one SQL file, 2 in one C# file.
                asset_line=asset.location.line if asset.location else None,
                # Selects the metamorphic relation family for `behaves`. Without these the
                # stage has nothing to choose and skips every finding — which is how a gate
                # that exists in the code contributes nothing to the measurement.
                usage_context=asset.usage_context.value if asset.usage_context else None,
                # A hybrid target must be exercised as a COMPOSITE: both halves, not one.
                # Read from the rule's own target, so a regime that mandates hybrid gets the
                # relations that can tell a real composite from a decorative half.
                construction=(
                    "hybrid" if "+" in str((rule.target or {}).get("algorithm") or "") else "pure"
                ),
            )

        report = _validate(new)

        if use_llm and not report.passed and learned is not None:
            # The replayed fix did not generalise to this occurrence — fall back to a real
            # generation, grounded in the same validated experience the store entry came from,
            # rather than failing a finding the model could still solve. Reuse is an
            # optimisation; it must never cost coverage.
            new = _generate_fresh(orig)
            model_name = _current_model_name()
            learned = None
            report = _validate(new)

        if use_llm and not report.passed:
            # One more attempt, told exactly what the validator objected to.
            #
            # `generate_llm_source` already runs a repair loop, but the only verdict it can see is
            # the rescan — the `applies`, `parses`, `symbols`, `compiles` and `tests` stages all run
            # out here, AFTER it has returned, and their failures used to be discarded. So a rewrite
            # rejected for something as answerable as "uses mldsa65.PublicKey but the patch does not
            # import it" was thrown away without the model ever being told, while a truncated answer
            # got three tries. Feeding the real stage detail back is the single cheapest source of
            # accepted patches available: the same generate-test-refine shape that the repair
            # literature measures in double-digit percentage-point gains.
            #
            # Capped at exactly one extra attempt, not a second full budget. The inner loop is
            # already 3 attempts, so an uncapped outer loop multiplies into 9+ model calls for one
            # finding, and the measured gains are overwhelmingly in the FIRST refinement round.
            stage_name, stage_detail = _first_failure(report)
            try:
                retried = _generate_fresh(orig, feedback=f"{stage_name} failed: {stage_detail}")
            except ValueError:
                # The re-attempt could not produce anything at all. Keep the first candidate and
                # its report: a failed patch a reviewer can read beats an exception, and this path
                # is reached only when the finding was already going to fail.
                pass
            else:
                retried_report = _validate(retried)
                if retried_report.passed:
                    new, report, model_name = retried, retried_report, _current_model_name()

        diff = old_new_to_diff(diff_path, orig, new, line_ending=line_ending)

        patch = PatchProposal(
            task_id=task.id,
            generator="llm" if use_llm else "template",
            model_name=model_name,
            file_path=diff_path,
            base_sha256=file_sha256(file_path),
            diff_text=diff,
            validation_json=_validation_payload(report, security_notes, security_caveats),
            # Written from the same report the JSON came from, so the column and the blob can
            # never disagree. This is the number to report, not `status`.
            evidence_level=report.evidence_level,
            # Denormalised from the plan on purpose: a plan's regime can be changed and its
            # patches regenerated, and a patch carrying only a foreign key would then claim to
            # have been built under a policy it never saw.
            regime=self.config.regime,
            # Empty when no model was involved, which is the majority: a deterministic
            # codemod or a cache replay costs nothing and should be visible as costing
            # nothing.
            cost_json=spend.summary(),
            status="proposed" if report.passed else "failed",
        )
        # The successful path spends too, and the task-level total has to include it or
        # the two records disagree about the same work.
        self._accumulate_spend(task)
        self.session.add(patch)
        self.session.flush()

        if report.passed:
            # A derived rule that produced an ACCEPTED patch has earned persistence. Storing it
            # here rather than at derivation time is the whole safety argument: a rule whose patch
            # the gates rejected is a bad derivation, and keeping it would hand the same mistake to
            # every later finding it matches.
            remember_rule(self.session, rule, asset, model_name, tenant_id)
            if use_llm and finding_line is not None:
                if learned is not None:
                    # A replayed fix passed validation again on a new file — it has now earned
                    # its place, which is what ranks it for future prompt grounding.
                    learn.touch(self.session, learned)
                else:
                    # A fresh model call passed the gate: remember this line's fix so the next
                    # identical occurrence — any file, any project, any later scan — skips the
                    # model, and so this rule's grounding gets one more verified example.
                    learn.record(
                        self.session,
                        rule_id=rule.id,
                        language=file_language,
                        algorithm=asset.algorithm,
                        orig=orig,
                        new=new,
                        line=finding_line,
                        model_name=model_name,
                        tenant_id=tenant_id,
                    )
            # Recorded for EVERY validated rewrite, single-line or not. `learn.record` above only
            # keeps a change whose line count did not move, which is the one shape it can replay
            # verbatim onto another file — and that filter discarded roughly two thirds of
            # everything the model got right, the multi-statement rewrites most of all. This keeps
            # the hunk and the model's own reasoning, which is what a later call actually needs.
            if use_llm and shape:
                hunk_before, hunk_after = learn.extract_hunk(orig, new, finding_line)
                with contextlib.suppress(Exception):
                    learn.record_outcome(
                        self.session,
                        rule_id=rule.id,
                        language=file_language,
                        algorithm=asset.algorithm,
                        shape=shape,
                        passed=True,
                        hunk_before=hunk_before,
                        hunk_after=hunk_after,
                        reasoning=security_notes[-1] if security_notes else "",
                        model_name=model_name,
                        tenant_id=tenant_id,
                    )
            # The transition is applied in `_store` below, so a retried write re-applies it
            # rather than losing it to the rollback.
        else:
            # `last_error` and `resolution` were never set on this path — only `_transition` was
            # called, so `task.resolution` stayed NULL forever. `patch.status` DOES correctly read
            # "failed" here, which is why this was never visible as a silently-accepted bad patch:
            # `migrate_handler` checks it, raises, and lands in its own generic exception handler
            # -- which calls `resolve_guided(..., claim_resolved=False)` specifically BECAUSE this
            # is a genuine unresolved failure, not a guided-by-design one. But that call only sets
            # `resolution` when `claim_resolved` is True; it assumes a baseline of UNRESOLVED is
            # already in place from a normal `_fail_task` call, which this branch never made.
            #
            # Found on a real OpenSSL migration: a `code-weakhash-02` codemod produced a patch
            # whose `applies` stage failed (a SECOND finding's earlier patch had already changed
            # `apps/passwd.c`, moving the context lines this one's diff was written against) --
            # exactly the shape `_fail_task`'s docstring on `RESOLUTION_UNRESOLVED` describes, yet
            # the task ended up `deferred` with `resolution=None`: neither retryable (the bulk
            # retry query selects only `unresolved`) nor countable as handled (the Migration Hub's
            # progress split reads the same field). The same failure mode as the router's own
            # detour bug, reached by a different, older path that predates the router entirely.
            failing_stage, failing_detail = _first_failure(report)

            # A rejection here is evidence too, and it used to be thrown away entirely.
            # `record_outcome` was only ever reached from `_generate_fresh`'s exception handler —
            # i.e. only when generation itself gave up — so a rewrite that generated cleanly and
            # then failed `compiles`, `tests` or `symbols` left NO trace anywhere. The next attempt
            # at structurally identical code started from nothing and made the same mistake again.
            if use_llm and shape:
                hunk_before, hunk_after = learn.extract_hunk(orig, new, finding_line)
                with contextlib.suppress(Exception):
                    learn.record_outcome(
                        self.session,
                        rule_id=rule.id,
                        language=file_language,
                        algorithm=asset.algorithm,
                        shape=shape,
                        passed=False,
                        hunk_before=hunk_before,
                        hunk_after=hunk_after,
                        failure_reason=f"{failing_stage} failed: {failing_detail}",
                        model_name=model_name,
                        # The validator ran and objected to the rewrite on its merits. That is the
                        # model's ceiling, not a QUBIT gap, so it counts.
                        unwinnable=False,
                        tenant_id=tenant_id,
                    )

            def _park_failure() -> None:
                self._fail_task(task, f"{failing_stage} failed: {failing_detail}")
                self.session.commit()

            retry_write_on_lock(self.session, _park_failure)
            return patch

        # Retried, not a bare commit. The `generate` transition is already committed before the
        # model is called (see above) so the write lock is not held across generation -- but the
        # writes DOWN HERE still land while another generation may be finishing its own. SQLite
        # allows one writer at a time even under WAL, and `PRAGMA busy_timeout=20000` gives up
        # after 20s.
        #
        # Measured, reproducibly: with two generations in flight (the second started after the
        # first client had gone away, which leaves the server-side work running), this commit
        # raised `sqlite3.OperationalError: database is locked` at ~21.9s and the API answered a
        # bare HTTP 500. With the other generation cleared, the identical request answered in 4.5s.
        # Reachable in ordinary use by clicking Generate on two rows in quick succession.
        #
        # `commit_with_retry` takes the patch EXPLICITLY. `rollback()` expunges a pending row, so a
        # bare retried commit would write an empty transaction and report success with no patch
        # stored -- the failure its own docstring describes. Passing `patch` is what makes the
        # retry re-add it. No model call is repeated; only the write is retried, with jittered
        # backoff.
        #
        # The `validation_passed` transition above is re-applied here for the same reason: rollback
        # reverts attribute changes on a persistent row, so re-adding the patch alone would leave
        # the task stuck in `generating` with a patch attached to it.
        def _store() -> None:
            if task.state == "generating":
                self._transition(task, "validation_passed", detail={"patch_id": str(patch.id)})
            # `last_error` is only ever written, never cleared, so a task that failed and then
            # succeeded kept showing the old failure beside its accepted patch. Observed live:
            # `evp_pkey_provided_test.c` reached `proposed` while still displaying "LLM rewrite
            # rejected after 3 attempt(s): the returned file has unbalanced '{}' brackets" from
            # the previous run -- a reviewer reads that as "this patch failed". The retry that
            # produced this patch is the current truth about the task.
            task.last_error = None
            self.session.add(patch)
            self.session.commit()

        retry_write_on_lock(self.session, _store)
        return patch

    def review_patch(
        self,
        patch_id: UUID,
        *,
        approve: bool,
        note: str = "",
        actor: str = "cli",
    ) -> PatchProposal:
        """Approve or reject a proposed patch."""
        patch = self.session.get(PatchProposal, patch_id)
        if not patch or patch.status != "proposed":
            raise ValueError(f"Patch {patch_id} not found or not proposed")

        task = self.session.get(MigrationTask, patch.task_id)
        if not task:
            raise ValueError("Task not found")

        patch.status = "approved" if approve else "rejected"
        patch.review_note = note
        # Recorded ONLY on approval: a rejection is not a vote toward the multi-approval gate,
        # and overwriting it on rejection would erase who genuinely did approve if a patch is
        # later re-reviewed after being superseded.
        if approve:
            patch.approved_by = actor
        from datetime import datetime

        patch.reviewed_at = datetime.now(UTC)

        self._transition(task, "approve" if approve else "reject", actor=actor)
        self.session.commit()
        return patch

    #: Per-repository sandbox images already resolved in this process, keyed by (root, commit).
    #: `docker image inspect` is a subprocess, and this runs once per patch on a bulk run of
    #: thousands.
    _IMAGE_CACHE: ClassVar[dict[tuple[str, str], str]] = {}

    def _sandbox_image_for(self, repo_root: Path | None, language: str | None = None) -> str:
        """The image whose site-packages match THIS repository, or the configured default.

        `_stage_tests` runs the project's own suite `--network=none`. Against a bare
        `python:3.12-slim` that suite dies on its own imports, the baseline is red before any patch
        is applied, and the stage honestly reports `skipped` -- measured on this installation: 84
        patches, 84 skips, and not one behaviour verdict in the whole database.

        `build_sandbox_image.py` already produces the image that fixes it, tagged
        `qubit-eval/<owner>-<repo>:<commit12>` and carrying the repository's dependencies but
        deliberately NOT the repository itself. Nothing selected it, so those images sat on disk
        while every patch was validated against the bare one. This closes that gap by deriving the
        tag the builder would have written and using it only if it is actually present locally.

        An explicitly configured image always wins: an operator who set one meant it, and silently
        substituting a different one would make the sandbox unauditable.
        """
        # Imported here, matching `apply_patch` below: the module is only needed on the two paths
        # that shell out, and neither runs on an ordinary template migration.
        import subprocess

        configured = self.config.test_sandbox_image
        # `MigrateConfig` is a pydantic model, so the default lives in `model_fields`, not on the
        # class -- reading it as a class attribute raises AttributeError and took down generation
        # for every task until it was caught.
        default_image = MigrateConfig.model_fields["test_sandbox_image"].default
        if configured != default_image:
            return configured
        if repo_root is None:
            by_language = _LANGUAGE_SANDBOX.get((language or "").lower())
            return by_language[0] if by_language is not None else configured
        try:
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(repo_root),
                capture_output=True,
                check=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return configured
        commit = head.stdout.decode("utf-8", "replace").strip()[:12]
        if not commit:
            return configured
        key = (str(repo_root), commit)
        if key in self._IMAGE_CACHE:
            return self._IMAGE_CACHE[key]
        # The builder is invoked with `<owner>/<repo>` and lowercases it with `/` -> `-`; the corpus
        # checkout for that repository is usually the directory `<owner>__<repo>`. Desktop imports
        # are deliberately named by the user instead (for example, `validator-...-paymesh-gateway`),
        # so get the canonical repository name from origin when it is available. Falling back to
        # the directory keeps manually copied, offline repositories working exactly as before.
        repo_name = repo_root.name.replace("__", "-").lower()
        image_name = repo_name
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            origin = (
                subprocess.run(
                    ["git", "remote", "get-url", "origin"],
                    cwd=str(repo_root),
                    capture_output=True,
                    check=True,
                    timeout=30,
                )
                .stdout.decode("utf-8", "replace")
                .strip()
            )
            origin = origin.removesuffix("/").removesuffix(".git")
            # Handles both https://host/owner/repo and git@host:owner/repo. The owner is useful
            # only for the commit-pinned builder convention; the final component is also used for
            # a locally built shorthand image such as `qubit-eval/paymesh:sandbox`.
            parts = [part for part in origin.replace(":", "/").split("/") if part]
            if parts:
                repo_name = parts[-1].lower()
                if len(parts) >= 2:
                    image_name = "-".join(parts[-2:]).lower()

        candidate = f"qubit-eval/{image_name}:{commit}"
        found = configured
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            probe = subprocess.run(
                ["docker", "image", "inspect", candidate],
                capture_output=True,
                timeout=60,
            )
            if probe.returncode == 0:
                logger.info("validating against the per-repository sandbox image %s", candidate)
                found = candidate
        # A committed, dependency-only image is preferred above, but older desktop evaluations
        # have already built local shorthand images (`qubit-eval/paymesh:sandbox`, etc.). These
        # must be considered before a generic Maven/Go/Ruby image: the generic image has the right
        # executable but not the repository's pinned dependencies, so the baseline is red and the
        # test gate is skipped. This is local discovery only -- Docker is never asked to pull.
        #
        # Match the full repository slug first, then its leading component. The latter covers the
        # historical names above while keeping the choice deterministic; exactly one local image
        # must match, so an ambiguous machine configuration falls back to the generic image.
        if found == configured:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                stems = [repo_name]
                if "-" in repo_name:
                    stems.append(repo_name.split("-", 1)[0])
                for stem in stems:
                    listing = subprocess.run(
                        [
                            "docker",
                            "image",
                            "ls",
                            "--format",
                            "{{.Repository}}:{{.Tag}}",
                            f"qubit-eval/{stem}",
                        ],
                        capture_output=True,
                        timeout=60,
                    )
                    matches = sorted(
                        {
                            line.strip()
                            for line in listing.stdout.decode("utf-8", "replace").splitlines()
                            if line.strip().startswith(f"qubit-eval/{stem}:")
                        }
                    )
                    if len(matches) == 1:
                        found = matches[0]
                        logger.info("validating against the local sandbox image %s", found)
                        break
                    if len(matches) > 1:
                        logger.warning(
                            "multiple local sandbox images match %s; "
                            "configure test_sandbox_image explicitly",
                            stem,
                        )
        self._IMAGE_CACHE[key] = found
        if found != configured:
            return found
        # No repository-specific image was available. A stock image can still provide a valid
        # baseline for dependency-free projects, but it must be the final fallback, never the
        # reason the repository image above was ignored.
        by_language = _LANGUAGE_SANDBOX.get((language or "").lower())
        return by_language[0] if by_language is not None else configured

    def _test_command_for(
        self, task: MigrationTask, repo_root: Path | None, language: str | None = None
    ) -> str:
        """How to run THIS repository's suite.

        One global command cannot cover a corpus. `python -m pytest` is right for most Python
        projects and wrong for a Django one: wagtail's tests are Django `TestCase`s that need a
        settings module and a database, and bare pytest collects them and then errors on every one,
        so the baseline is red and the stage reports `skipped` -- a verdict about QUBIT's
        configuration, worded as a fact about the repository.

        Three sources, most specific first:

        1. `projects.settings["test_command"]`, for a repository whose runner nothing can guess.
        2. A `runtests.py` at the root, which is the near-universal convention for a Django project
           that ships its own runner (wagtail and django itself both do).
        3. `MigrateConfig.test_command`.

        A command found this way still has to satisfy the baseline before it counts for anything:
        if it cannot make the untouched tree green, `_stage_tests` still refuses to judge a patch
        with it. So a wrong guess costs a container run, never a false verdict.
        """
        with contextlib.suppress(Exception):
            plan = self.session.get(MigrationPlan, task.plan_id)
            project_id = plan.project_id if plan is not None else None
            if project_id is None and plan is not None and plan.scan_id is not None:
                scan = self.session.get(ScanRow, plan.scan_id)
                project_id = scan.project_id if scan is not None else None
            if project_id is not None:
                project = self.session.get(ProjectRow, project_id)
                configured = (project.settings or {}).get("test_command") if project else None
                if isinstance(configured, str) and configured.strip():
                    return configured.strip()
        if repo_root is not None and (repo_root / "runtests.py").is_file():
            return "python runtests.py"
        # Ruby projects do not all ship a Rakefile. The former generic `rake test` fallback
        # therefore made a dependency-complete sandbox look broken for a perfectly conventional
        # Minitest repository containing only `test/**/*_test.rb`. Prefer Rake when the repository
        # actually declares it; otherwise run the discovered Minitest files through Ruby with the
        # usual local load paths. Multiple test files are loaded in stable order so their minitest
        # registrations share one process, while a single file retains a compact, auditable command.
        if repo_root is not None and (language or "").lower() == "ruby":
            if (repo_root / "Rakefile").is_file():
                return "rake test"
            ruby_tests = sorted(repo_root.glob("test/**/*_test.rb"))
            if len(ruby_tests) == 1:
                return f"ruby -Ilib -Itest {ruby_tests[0].relative_to(repo_root).as_posix()}"
            if ruby_tests:
                return (
                    "ruby -Ilib -Itest -e "
                    '\'Dir["test/**/*_test.rb"].sort.each '
                    "{ |path| require File.expand_path(path) }'"
                )
        if self.config.test_command == MigrateConfig.model_fields["test_command"].default:
            by_language = _LANGUAGE_SANDBOX.get((language or "").lower())
            if by_language is not None:
                return by_language[1]
        return self.config.test_command

    def _project_root_of(self, task: MigrationTask) -> Path | None:
        """The checkout this task's project points at, or None if there isn't a usable one.

        A plan reaches its project either directly (`project_id`) or through the scan it was built
        from, and both spellings occur in the wild -- a plan created from a scan carries `scan_id`,
        one created for a project carries `project_id`. Trying both is why this is a method rather
        than a join at the call site.

        Never raises: this is a convenience for a caller that did not supply a root, so every
        failure mode -- no plan, no project, a null or stale `root_path` -- returns None and leaves
        the caller exactly where it would have been.
        """
        with contextlib.suppress(Exception):
            plan = self.session.get(MigrationPlan, task.plan_id)
            if plan is None:
                return None
            project_id = plan.project_id
            if project_id is None and plan.scan_id is not None:
                scan = self.session.get(ScanRow, plan.scan_id)
                project_id = scan.project_id if scan is not None else None
            if project_id is None:
                return None
            project = self.session.get(ProjectRow, project_id)
            root = Path(project.root_path) if project and project.root_path else None
            # `is_dir` and not merely truthiness: a recorded path whose checkout has been moved or
            # deleted would send `git apply` and the sandbox mount at a directory that is not
            # there, turning a clean "skipped" into a stage failure that blames the patch.
            if root is not None and root.is_dir():
                return root
        return None

    def _paths_this_plan_wrote(self, task: MigrationTask, repo_root: Path) -> set[Path]:
        """Absolute paths already written to disk by patches belonging to ``task``'s plan.

        Read from the database rather than accumulated by the caller, so it is correct no matter
        how the applies were sequenced - a bulk run, several single-task applies, or a bulk run
        resumed after one.
        """
        written: set[Path] = set()
        rows = self.session.scalars(
            select(PatchProposal.file_path)
            .join(MigrationTask, PatchProposal.task_id == MigrationTask.id)
            .where(MigrationTask.plan_id == task.plan_id)
            .where(PatchProposal.status == "applied")
        ).all()
        for relative in rows:
            with contextlib.suppress(OSError, ValueError):
                written.add((repo_root / relative).resolve())
        return written

    def apply_patch(
        self,
        patch_id: UUID,
        *,
        repo_root: Path,
        branch: str | None = None,
        actor: str = "cli",
    ) -> PatchProposal:
        """Apply an approved patch to the git repo using git apply."""
        patch = self.session.get(PatchProposal, patch_id)
        if not patch or patch.status != "approved":
            raise ValueError(f"Patch {patch_id} not approved")

        task = self.session.get(MigrationTask, patch.task_id)
        if not task:
            raise ValueError("Task not found")

        # 0. Guard: Governance Policy Gate
        from qubit_migrate.governance import check_governance

        check_governance(task.id, self.session)

        # 1. Guard: Check git repo is clean
        import subprocess

        try:
            # `-- .` restricts the report to `repo_root`, not the whole repository it sits in.
            # Without it, a `repo_root` that is a SUBDIRECTORY of a larger git working tree (any
            # scan target that is not its own repo — a copied folder, an extracted archive, a
            # subproject) had that OUTER repo's unrelated dirty state reported as this migration's
            # own. Measured: migrating a plain copy of the 21-app demo corpus that happened to sit
            # inside this monorepo's working tree failed 246 of 250 real findings with "Dirty git
            # tree", entirely because of edits elsewhere in the monorepo that `repo_root` had
            # nothing to do with. Pinned by
            # `test_apply_e2e.py::test_apply_ignores_dirty_state_outside_repo_root`.
            r = subprocess.run(
                ["git", "status", "--porcelain", "-z", "--", "."],
                capture_output=True,
                cwd=str(repo_root),
            )
            top = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                cwd=str(repo_root),
            )
        except FileNotFoundError as e:
            raise ValueError("git not found") from e
        # Dirt THIS PLAN created is not a reason to stop. The guard exists to catch edits QUBIT
        # has not seen, so that its work stays separable from the operator's; a file QUBIT itself
        # wrote earlier in the same plan is neither.
        #
        # Without this the guard made bulk apply impossible in a real repository: the first patch
        # lands, the tree is now dirty by QUBIT's own hand, and every subsequent patch in the run
        # fails with "commit or stash changes before applying". It went unnoticed because the
        # demo corpus is not a git repository, where both git guards are inert.
        #
        # Guard 2 below is what actually protects the file being written, and it is stricter than
        # this one: it compares the file's sha256 against the hash recorded when the patch was
        # generated, so a file edited under QUBIT's feet is refused whether or not git tracks it.
        root = Path(top.stdout.decode("utf-8", "replace").strip() or repo_root)
        expected = self._paths_this_plan_wrote(task, repo_root)

        # Scoped to the files THIS patch writes, not the whole tree. The wide version made QUBIT
        # unusable on any repository with work in progress, which is the normal state of one: a
        # single unrelated edit anywhere under `repo_root` refused every patch in the run with
        # "Dirty git tree", and the operator had no way to tell which file was the problem or why
        # it mattered. Measured on this installation: a migration reported one patch written and
        # twenty refused, all twenty for edits in files no patch would have touched.
        #
        # Nothing is given up by narrowing it. Guard 2 below hashes the file being written against
        # the hash recorded at generation time and refuses on any mismatch, so the file this patch
        # edits is protected more strictly than a porcelain check could manage. What this guard
        # still adds is the case guard 2 cannot see: a file the patch CREATES that already exists
        # with uncommitted content, which `git apply` would overwrite.
        touched = {(repo_root / patch.file_path).resolve()}
        for created in patch.new_files_json or {}:
            touched.add((repo_root / created).resolve())
        unexpected = [
            p for p in _porcelain_paths(r.stdout, root) if p in touched and p not in expected
        ]
        if unexpected:
            shown = ", ".join(sorted(str(p.name) for p in unexpected)[:5])
            raise ValueError(
                f"This change writes {shown}, which has uncommitted edits QUBIT did not make. "
                "Commit or stash that file before applying."
            )

        # 2. Guard: File hasn't changed since generation
        file_path = repo_root / patch.file_path
        if not file_path.exists():
            patch.status = "superseded"
            self.session.commit()
            raise ValueError(f"File {patch.file_path} deleted")
        if file_sha256(file_path) != patch.base_sha256:
            patch.status = "superseded"
            self._transition(task, "defer", actor=actor)  # Back to ready via resume later
            self._transition(task, "resume", actor=actor)
            self.session.commit()
            raise ValueError(f"File {patch.file_path} changed since generation. Patch superseded.")

        # 3. Create branch (if requested)
        applied_branch = None
        if branch:
            subprocess.run(["git", "checkout", "-b", branch], cwd=str(repo_root), check=True)
            applied_branch = branch

        # 4. Apply diff
        p = subprocess.run(
            ["git", "apply", "-"], input=patch.diff_text.encode("utf-8"), cwd=str(repo_root)
        )
        if p.returncode != 0:
            if applied_branch:
                subprocess.run(["git", "checkout", "-"], cwd=str(repo_root))
                if branch:
                    subprocess.run(["git", "branch", "-D", branch], cwd=str(repo_root))
            raise EditApplyError(f"git apply failed with code {p.returncode}")

        # 4b. Guard: what landed on disk is what this patch describes.
        #
        # Everything up to here establishes that the patch was VALIDATED and that `git apply`
        # returned 0. Neither says the bytes in the file are the bytes the gates judged: the
        # stages run on an in-memory `patched_source`, the diff is derived from it, and what
        # reaches disk is `git apply`'s reconstruction of that diff. Those three agreed on every
        # patch audited on this installation -- 6 of 6 files byte-identical to HEAD plus their
        # stored diffs -- but nothing MADE them agree, and a patch write is the one step where
        # being wrong silently corrupts a user's source file.
        #
        # Reversing the diff is the check that needs no new state: if the hunks this patch adds
        # are all present in the file exactly as written, they can be taken back out again, and
        # if any of them landed fuzzily, partially, or not at all, they cannot. `--check` makes it
        # a dry run, so the file is never touched.
        reverse = subprocess.run(
            ["git", "apply", "-R", "--check", "-"],
            input=patch.diff_text.encode("utf-8"),
            cwd=str(repo_root),
            capture_output=True,
        )
        if reverse.returncode != 0:
            # Put the file back before reporting: a half-written patch left on disk is worse than
            # no patch, and the operator cannot tell the difference by looking.
            subprocess.run(
                ["git", "checkout", "--", patch.file_path],
                cwd=str(repo_root),
                capture_output=True,
            )
            if applied_branch:
                subprocess.run(["git", "checkout", "-"], cwd=str(repo_root))
                if branch:
                    subprocess.run(["git", "branch", "-D", branch], cwd=str(repo_root))
            detail = reverse.stderr.decode("utf-8", "replace").strip()
            raise EditApplyError(
                f"{patch.file_path} was written but does not match the change that was "
                f"validated, so it has been reverted: {detail}"
            )

        # 5. Commit (if branch requested)
        applied_commit = None
        if branch:
            subprocess.run(["git", "add", patch.file_path], cwd=str(repo_root), check=True)
            msg = f"QUBIT: migrate {patch.file_path}\n\nTask: {task.id}\nRule: {task.rule_id}"
            subprocess.run(["git", "commit", "-m", msg], cwd=str(repo_root), check=True)
            c = subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, cwd=str(repo_root)
            )
            applied_commit = c.stdout.decode().strip()

        patch.status = "applied"
        patch.applied_branch = applied_branch
        patch.applied_commit = applied_commit
        self._transition(task, "apply", actor=actor)
        self.session.commit()
        return patch

    def verify_task(self, task_id: UUID) -> ValidationReport | None:
        """Re-scan to prove remediation."""
        task = self.session.get(MigrationTask, task_id)
        if not task or task.state not in ("applied", "verifying"):
            raise ValueError(f"Task {task_id} not applied")

        patch = self.session.scalars(
            select(PatchProposal).where(
                PatchProposal.task_id == task.id, PatchProposal.status == "applied"
            )
        ).first()
        if not patch:
            raise ValueError("No applied patch found")

        asset = self._load_asset(task.asset_id)
        if not asset or not asset.location or not asset.location.file_path:
            raise ValueError("Asset lost")

        # Re-scan the file AS IT NOW SITS ON DISK, and require the finding to be gone.
        #
        # This used to transition straight to `verify_pass` and return
        # `ValidationReport(passed=True)`
        # unconditionally, with a comment saying real verification would come later. It never did.
        # The result was a method whose entire job is to answer "did the migration hold?" and which
        # answered yes without looking -- including for a patch whose file had since been reverted,
        # re-edited, or written by something else. It reports on the CURRENT file rather than on
        # the in-memory string the gates saw at generation time, because that is the only thing
        # `verify` can add over what `validate_patch` already established.
        from .transform.languages import language_for_suffix
        from .transform.validate import StageResult, _stage_rescan

        file_path = Path(asset.location.file_path)
        try:
            current = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._transition(task, "verify_fail", actor="system")
            self.session.commit()
            return ValidationReport(
                stages={"rescan": StageResult("fail", f"cannot read {file_path}: {exc}", 0.0)},
                passed=False,
            )

        # `self._rules` is a list, matching every other lookup in this class.
        rule = (
            next((r for r in self._rules if r.id == task.rule_id), None) if task.rule_id else None
        )
        language = language_for_suffix(file_path.suffix) or "python"
        result = _stage_rescan(
            current,
            rule,
            language,
            asset_algorithm=asset.algorithm,
            asset_line=asset.location.line,
            target_rel_path=patch.file_path,
        )
        # A rule with nothing to check cannot refute the migration, and refusing to verify on that
        # basis would park a correct patch forever. `skipped` is recorded in the notes so the
        # difference between "checked and clean" and "nothing to check" stays visible.
        passed = result.status in ("pass", "skipped")
        self._transition(task, "verify_pass" if passed else "verify_fail", actor="system")
        self.session.commit()
        return ValidationReport(stages={"rescan": result}, passed=passed)

    def _accumulate_spend(self, task: MigrationTask) -> None:
        """Add what the current attempt cost to this task's running total.

        Accumulated rather than replaced: a task can be retried, and the question the paper asks --
        how many requests did this finding cost in total -- is not answered by the last attempt
        alone.
        """
        book = current_ledger()
        if book is None:
            return
        spent = book.summary()
        if not spent.get("calls"):
            return
        running = dict(task.spend_json or {})
        for key in ("calls", "failed_calls", "prompt_tokens", "completion_tokens"):
            running[key] = int(running.get(key, 0)) + int(spent.get(key, 0))
        running["seconds"] = round(float(running.get("seconds", 0)) + spent["seconds"], 2)
        engines = dict(running.get("by_engine") or {})
        for engine, count in (spent.get("by_engine") or {}).items():
            engines[engine] = engines.get(engine, 0) + count
        running["by_engine"] = engines
        running["attempts"] = int(running.get("attempts", 0)) + 1
        task.spend_json = running

    def _fail_task(
        self, task: MigrationTask, reason: str, *, resolution: str = RESOLUTION_UNRESOLVED
    ) -> None:
        # Before anything else: a failed attempt still spent the quota. This is the only
        # place that spend can be recorded, because a task that exhausts its repair
        # budget produces no patch to attach a cost to.
        self._accumulate_spend(task)
        task.last_error = reason
        # Why the task is parked, not just that it is. `deferred` is reached both by "QUBIT could
        # not migrate this" and by "there was nothing left to migrate", and conflating them made a
        # plan report finished work as broken -- 6 of 18 apparent failures on the polyglot corpus.
        task.resolution = resolution
        # `deferred` only accepts `resume`, so a SECOND failure on an already-deferred task made
        # transition() raise and the real reason was replaced by a confusing FSM error surfacing as
        # "skipped one asset: No transition 'defer' from state 'deferred'". This happens in ordinary
        # use: when one file contains two findings, the first patch fixes both, and the second task
        # then fails with nothing to change. Recording a failure must be idempotent — the task is
        # already parked in exactly the state we wanted, so keep the newest reason and move on.
        if task.state == "deferred":
            write_event(
                self.session,
                task,
                from_state="deferred",
                to_state="deferred",
                actor="system",
                detail={"error": reason, "note": "already deferred"},
            )
            self._commit_failure()
            return
        self._transition(task, "defer", detail={"error": reason})  # fail -> pending basically
        self._commit_failure()

    def _commit_failure(self) -> None:
        """Persist the parking, because every caller of `_fail_task` raises immediately after it.

        Nothing else commits on this path. `_transition` only mutates and writes an event, the API
        turns the exception into a 422, and `get_session` closes the session in a `finally` with no
        commit -- so the deferral, `last_error` and `resolution` were all discarded the moment the
        request ended. Observed against the running app: a task whose asset matched no rule returned
        422, and came back from the queue still `ready`, with `last_error` null, ready to fail
        identically forever.

        Why a commit and not a caller-side one: recording WHY a task could not be migrated is a
        durable fact about the codebase, not part of the work being rolled back. The only pending
        changes at this point are the task's own state and its event, which is exactly what should
        survive.
        """
        try:
            self.session.commit()
        except Exception:
            # The caller is about to raise the reason this task failed. Losing that behind a
            # database error would replace a useful message with a confusing one.
            logger.exception("could not persist the failure state for a migration task")
            self.session.rollback()

    def _transition(
        self,
        task: MigrationTask,
        event: str,
        actor: str = "system",
        detail: dict[str, Any] | None = None,
    ) -> None:
        from_state = task.state
        task.state = transition(from_state, event)
        self._sync_public_status(task)
        write_event(
            self.session,
            task,
            from_state=from_state,
            to_state=task.state,
            actor=actor,
            detail=detail,
        )

    def _load_asset(self, asset_id: UUID) -> CryptoAsset | None:
        """Hydrate the domain CryptoAsset for an asset id (rows are flattened AssetRow)."""
        row = self.session.get(AssetRow, asset_id)
        return row_to_asset(row) if row else None

    def _sync_public_status(self, task: MigrationTask) -> None:
        row = self.session.get(AssetRow, task.asset_id)
        if row:
            status = to_public_status(task.state)
            migration = dict(row.migration_json or {})
            migration["status"] = status
            # MigrationAnnotation requires a recommendation — always write one so the row
            # stays hydratable via row_to_asset.
            if task.rule_id:
                migration["recommendation"] = f"Migrate using {task.rule_id}"
            else:
                migration.setdefault("recommendation", "Manual migration required (no rule)")
            row.migration_status = status
            row.migration_json = migration
            flag_modified(row, "migration_json")


__all__ = ["MigrationOrchestrator"]
