"""Learned-patch store: the local model earns its keep once per distinct code shape.

Every crypto codebase repeats itself — the same `hashlib.md5(payload).hexdigest()` one-liner, the
same `MessageDigest.getInstance("MD5")` call, appears in dozens of files across one repo and across
unrelated repos scanned later. When a rule with no deterministic codemod fixes one of those lines
and the fix PASSES the full validation gate, that (rule, line) -> replacement pair is recorded here.

Two things then get cheaper, and they are deliberately separate:

* :func:`lookup` + :func:`apply` — **exact reuse**. A later finding whose flagged line is character
  -identical (after stripping) is answered from the store, skipping the model entirely. The reused
  result still goes through the same `validate_patch` gate as a fresh generation before it can be
  proposed; this skips the LLM call, never the validator.
* :func:`experience_for_rule` — **grounding**. Most real findings are *not* character-identical, so
  exact reuse misses. Those still benefit: the best-proven fixes for the same rule are replayed
  into the generator prompt as worked examples, conditioning a fresh call on work this project has
  already had verified instead of on prose alone.

Everything here is local. Migration must keep working with no network — and a scan target's rule
ids and languages are exactly the kind of thing that must never leave the machine — so nothing in
this module reaches the internet.
"""

from __future__ import annotations

from dataclasses import dataclass

from qubit_core.db.models import LearnedPatch
from qubit_core.schemas import utcnow
from sqlalchemy import select
from sqlalchemy.orm import Session

from .diffing import sha256_of


def _leading_ws(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _line_key(rule_id: str, stripped_line: str) -> str:
    return sha256_of(f"{rule_id}\n{stripped_line}")


@dataclass
class ReuseResult:
    """A cached fix successfully replayed onto a new file."""

    new_source: str
    learned_id: str
    hit_count: int


def lookup(session: Session, *, rule_id: str, orig: str, line: int | None) -> LearnedPatch | None:
    """A previously-validated fix for the exact line this finding flags, if one exists."""
    if line is None:
        return None
    lines = orig.splitlines()
    if not (1 <= line <= len(lines)):
        return None
    key = _line_key(rule_id, lines[line - 1].strip())
    return session.scalar(
        select(LearnedPatch)
        .where(LearnedPatch.rule_id == rule_id)
        .where(LearnedPatch.snippet_key == key)
        .limit(1)
    )


def apply(orig: str, line: int, learned: LearnedPatch) -> ReuseResult | None:
    """Replay a learned line-fix at ``line`` in ``orig``, keeping THIS file's indentation.

    Returns None when the line no longer matches what was learned — the file drifted since the
    entry was written, so the caller falls back to a fresh generation rather than forcing a
    replacement that no longer fits.
    """
    lines = orig.splitlines(keepends=True)
    if not (1 <= line <= len(lines)):
        return None
    raw = lines[line - 1]
    newline = "\n" if raw.endswith("\n") else ""
    body = raw[: len(raw) - len(newline)] if newline else raw
    if body.strip() != learned.snippet_before.strip():
        return None
    lines[line - 1] = _leading_ws(body) + learned.snippet_after.strip() + newline
    return ReuseResult(
        new_source="".join(lines),
        learned_id=str(learned.id),
        hit_count=learned.hit_count,
    )


def record(
    session: Session,
    *,
    rule_id: str,
    language: str,
    algorithm: str | None,
    orig: str,
    new: str,
    line: int,
    model_name: str | None,
) -> None:
    """Remember a freshly-validated fix so the next identical line skips the model.

    Only a single-line change is stored, and only when the rewrite preserved the file's line count
    — the same precondition `orchestrator._flagged_line_untouched` uses to attribute a line-scoped
    edit to its finding. A whole-file restructure has no safe one-line snippet to extract, and
    guessing one would produce an entry that corrupts the next file it is replayed onto.
    """
    before_lines = orig.splitlines()
    after_lines = new.splitlines()
    if len(before_lines) != len(after_lines) or not (1 <= line <= len(before_lines)):
        return
    before = before_lines[line - 1].strip()
    after = after_lines[line - 1].strip()
    if before == after or not before or not after:
        return
    key = _line_key(rule_id, before)
    existing = session.scalar(
        select(LearnedPatch)
        .where(LearnedPatch.rule_id == rule_id)
        .where(LearnedPatch.snippet_key == key)
        .limit(1)
    )
    if existing is not None:
        return  # already known — a reuse bumps hit_count via touch(), not a second insert
    session.add(
        LearnedPatch(
            rule_id=rule_id,
            language=language,
            algorithm=algorithm,
            snippet_key=key,
            snippet_before=before,
            snippet_after=after,
            source_model=model_name,
        )
    )


def touch(learned: LearnedPatch) -> None:
    """Record a reuse against an entry already loaded into the session."""
    learned.hit_count += 1
    learned.last_used_at = utcnow()


def get_experience_for_rule(
    session: Session, rule_id: str, language: str, limit: int = 2
) -> list[tuple[str, str]]:
    """The best-proven (before, after) fixes for ``rule_id`` in ``language``, for prompt grounding.

    Ordered by how often each has already been reused, then by recency: a pattern the store has
    answered several times is better evidence than one seen once, and among equals the newest
    reflects the model's current behaviour.

    Filtered by language, which matters for a cross-language rule (`language: multi`) — one rule id
    covers 21 file suffixes, and replaying a Go fix at a Rust file is the exact failure
    `llm._worked_examples` documents: measured there, the 7B model returned the example's language
    verbatim for 3 of 4 files. Grounding has to be in the language being edited or it misleads.

    ``limit`` is small on purpose. A rule migrated a hundred times would otherwise push the actual
    task further down the prompt, diluting the strongest signal with volume — the same reason
    `_worked_examples` shows one demonstration rather than a rule's whole example library.
    """
    rows = session.scalars(
        select(LearnedPatch)
        .where(LearnedPatch.rule_id == rule_id)
        .where(LearnedPatch.language == language)
        .order_by(LearnedPatch.hit_count.desc(), LearnedPatch.created_at.desc())
        .limit(limit)
    ).all()
    return [(r.snippet_before, r.snippet_after) for r in rows]


__all__ = [
    "ReuseResult",
    "apply",
    "get_experience_for_rule",
    "lookup",
    "record",
    "touch",
]
