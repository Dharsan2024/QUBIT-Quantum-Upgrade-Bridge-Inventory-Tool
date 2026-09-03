"""What QUBIT has learned from its own validated migrations, and how a fresh call reads it.

Two stores, doing two different jobs.

**The cache** (`LearnedPatch`, :func:`lookup` / :func:`apply` / :func:`record`) remembers a proven
single-line replacement so an identical line in another file, project or scan skips the model
entirely. It is cheap and exact, and the replayed result still passes the same validation gate as
a fresh generation - this skips the LLM round trip, never the validator.

**The experience base** (`LearnedOutcome`, :func:`record_outcome` / :func:`experience_for` /
:func:`known_failures`) is what the cache could not be. Measured on this project's own store, the
cache held 21 rows against 59 accepted LLM patches: `record` refuses anything whose line count
changed, so roughly two thirds of everything the model got right was discarded, and the harder the
rewrite the more certain it was to be thrown away. The experience base keeps:

* **hunks**, so a rewritten function is retained rather than skipped;
* **failures**, so a shape that has already defeated the model is known before three more attempts
  are spent on it;
* the model's own **reasoning** for a patch that passed, which is the strongest few-shot content
  available - a verified explanation of a verified change;
* a **structural shape key**, so `hashlib.md5(payload)` and `hashlib.md5(data)` are recognised as
  the same problem instead of two unrelated ones.

Everything here is local. Migration must keep working with no network, and a scan target's rule
ids, languages and source lines are exactly the kind of thing that must never leave the machine,
so nothing in this module reaches the internet.
"""

from __future__ import annotations

import contextlib
import difflib
import logging
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field

from qubit_core.db.models import DEFAULT_TENANT_ID, LearnedOutcome, LearnedPatch
from qubit_core.db.session import retry_write_on_lock
from qubit_core.schemas import utcnow
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .diffing import sha256_of

logger = logging.getLogger(__name__)

# --- exact line cache -------------------------------------------------------------------------


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


def lookup(
    session: Session,
    *,
    rule_id: str,
    orig: str,
    line: int | None,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
) -> LearnedPatch | None:
    """A previously-validated fix for the exact line this finding flags, if one exists."""
    if line is None:
        return None
    lines = orig.splitlines()
    if not (1 <= line <= len(lines)):
        return None
    key = _line_key(rule_id, lines[line - 1].strip())
    return session.scalar(
        select(LearnedPatch)
        .where(LearnedPatch.tenant_id == tenant_id)
        .where(LearnedPatch.rule_id == rule_id)
        .where(LearnedPatch.snippet_key == key)
        .limit(1)
    )


def apply(orig: str, line: int, learned: LearnedPatch) -> ReuseResult | None:
    """Replay a learned line-fix at ``line`` in ``orig``, keeping THIS file's indentation.

    Returns None when the line no longer matches what was learned - the file drifted since the
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


def _counterpart(before_lines: list[str], after_lines: list[str], index: int) -> str | None:
    """What the line at `index` became, or None when there is no single-line answer.

    Positional lookup (`after_lines[index]`) is only correct when the rewrite preserved the line
    count, and the most ordinary successful migration does not: replacing a primitive usually adds
    an import, which shifts every line below it by one. The old code required equal line counts and
    so DISCARDED those fixes entirely -- measured on this installation, 11 of 17 validated
    successes, none of which could ever be replayed or used to ground a later prompt.

    Aligning the two files first recovers them. A line that was replaced one-for-one has a
    counterpart whatever happened elsewhere in the file; a line that was deleted, or absorbed into
    a block of a different size, genuinely has no single-line answer and still returns None rather
    than a guess. Guessing is what would corrupt the next file the entry lands on.
    """
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if not i1 <= index < i2:
            continue
        if tag != "replace" or (i2 - i1) != (j2 - j1):
            # `equal` means the flagged line was not touched; an uneven `replace`, an `insert` or a
            # `delete` means it has no one-line counterpart to record.
            return None
        return after_lines[j1 + (index - i1)]
    return None


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
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
) -> None:
    """Remember a freshly-validated single-line fix so the next identical line skips the model.

    Still narrow, and deliberately so: only a line-scoped change, because that is the only shape
    :func:`apply` can replay onto another file without knowing anything about it. A whole-file
    restructure has no safe one-line snippet to extract, and guessing one produces an entry that
    corrupts the next file it lands on. Those go to :func:`record_outcome` instead.

    It used to be narrower than that, and wrongly. The line count had to be UNCHANGED, which
    excluded the most ordinary successful migration there is: replacing a primitive and adding the
    import it needs. Measured on this installation, that shape was 11 of 17 validated successes --
    so nearly two thirds of everything the local model got right was thrown away, could never be
    replayed without a model call, and never grounded a later prompt. `_counterpart` aligns the two
    files instead of indexing into them, which recovers exactly those and still returns None where
    there is genuinely no single-line answer.
    """
    before_lines = orig.splitlines()
    after_lines = new.splitlines()
    if not 1 <= line <= len(before_lines):
        return
    counterpart = _counterpart(before_lines, after_lines, line - 1)
    if counterpart is None:
        return
    before = before_lines[line - 1].strip()
    after = counterpart.strip()
    if before == after or not before or not after:
        return
    key = _line_key(rule_id, before)
    existing = session.scalar(
        select(LearnedPatch)
        .where(LearnedPatch.tenant_id == tenant_id)
        .where(LearnedPatch.rule_id == rule_id)
        .where(LearnedPatch.snippet_key == key)
        .limit(1)
    )
    if existing is not None:
        return  # already known - a reuse bumps hit_count via touch(), not a second insert
    session.add(
        LearnedPatch(
            tenant_id=tenant_id,
            rule_id=rule_id,
            language=_safe_language(language),
            algorithm=algorithm,
            snippet_key=key,
            snippet_before=before,
            snippet_after=after,
            source_model=model_name,
        )
    )


def touch(session: Session, learned: LearnedPatch | LearnedOutcome) -> None:
    """Record a reuse against an entry already loaded into the session, and never fail.

    Written immediately rather than left pending, and that is the whole point of taking a session.
    A dirty attribute sits in the Session until SQLAlchemy autoflushes it -- at whatever query comes
    next, deep inside `generate_patch` or the validator -- and if THAT write loses a race the
    Session is poisoned for everything after it, with an error naming a table the caller never
    touched.

    Measured once parallel workers made write contention real: a bump on `learned_outcomes` hit
    "database is locked", the failure surfaced on the next unrelated query, and a run that had
    already prepared 133 of 143 findings was reported as failed at 93%. The migration work was
    finished and correct; it was discarded over a counter.

    So the write is attempted here, briefly retried, and then given up on. Learning is a side
    benefit of work that already succeeded -- losing one hit count costs a slightly worse ranking
    hint next time, which is nothing beside losing the run that earned it.
    """
    # The READ is inside the guard too, and that is not defensive padding. After a commit every
    # attribute is expired, so `learned.hit_count` is itself a query -- which autoflushes any
    # pending change first, and can therefore fail with the very lock error this function exists to
    # survive. A guard that started one line lower let the failure out of the first bump on a
    # freshly committed session, which is the common case.
    try:
        learned.hit_count += 1
        learned.last_used_at = utcnow()
        retry_write_on_lock(session, session.flush, attempts=4)
    except Exception as exc:
        # `expire` discards the pending change and leaves the object attached and usable, which
        # `rollback` (too broad -- it would undo the caller's real work) and `expunge` (detaches,
        # breaking the caller's reference) both fail to do.
        # `expire` discards the pending change and leaves the object attached and usable, which
        # `rollback` (too broad -- it would undo the caller's real work) and `expunge` (detaches,
        # breaking the caller's reference) both fail to do. Suppressed in turn, because a session
        # that is already unhappy can refuse this too, and by here there is nothing left worth
        # raising about.
        with contextlib.suppress(Exception):
            session.expire(learned)
        logger.warning("learning: hit-count bump skipped (%s)", type(exc).__name__)


# --- structural shape -------------------------------------------------------------------------

#: Tokens that carry the MEANING of a crypto call site and must survive normalisation. Everything
#: else is folded away, so two findings that differ only in the names their author chose collapse
#: to one shape.
#:
#: Deliberately excludes the single generic verbs a first draft of this kept - `digest`, `hash`,
#: `cipher`, `sign`, `verify`, `new`, `create`, `update`, `final`. They read as cryptographic and
#: are ordinary variable names: `digest = hashlib.md5(payload)` kept `digest` as a meaningful
#: token purely because the author named the result after what it is, so it no longer matched
#: `checksum = hashlib.md5(data)` - the exact collision this key exists to make. What survives is
#: either an algorithm, a mode, a padding, a protocol version, or a compound API name no one
#: reaches for as a local.
#: Registry aliases that are also ordinary words in ordinary code. `dh` and `seed` are kept in the
#: hand-written set above where they are unambiguous in context; here they would match any local
#: named `seed` or a Diffie-Hellman mention in prose.
_ALIAS_STOPWORDS = frozenset({"null", "none", "seed", "new", "key", "data", "mode", "type"})


def _registry_primitive_words() -> set[str]:
    """Every algorithm name and alias the canonical registry knows, as bare lowercase words.

    Derived rather than typed out. A hand-kept list of primitives is a list that falls behind the
    registry the first time an algorithm is added to it, and a shape key that does not recognise
    an algorithm silently folds it to `_` - which makes two DIFFERENT algorithms hash to the same
    shape, the one failure this key must never have.

    Split on separators so `ML-KEM-768` contributes `ml`, `kem` and the joined `mlkem`: a shape
    key tokenises identifiers, and `MLKem768` in real code arrives as those words.
    """
    from qubit_core import algorithms

    words: set[str] = set()
    for entry in algorithms.ALGORITHMS:
        for name in (entry.canonical, *entry.aliases):
            lowered = name.lower()
            words.add(re.sub(r"[^a-z0-9]", "", lowered))
            words.update(part for part in re.split(r"[^a-z0-9]+", lowered) if len(part) > 1)
    # Bare numbers are parameter sizes, and `shape_key` already folds every number to `#`.
    #
    # `_ALIAS_STOPWORDS` is the price of deriving from aliases: a few registry entries carry
    # aliases that are also ordinary words in ordinary code. `null` arrived that way and promptly
    # broke a shape match, because `createCipheriv("aes-256-ecb", key, null)` and the same call
    # with a real IV stopped being the same shape - the JavaScript literal had become a
    # cryptographic token. Better to drop three words than to fold every `null` into the key.
    return {w for w in words if w and not w.isdigit() and w not in _ALIAS_STOPWORDS}


_KEEP = frozenset(
    {
        # primitives
        "md5",
        "md4",
        "md2",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3",
        "ripemd160",
        "des",
        "des3",
        "desede",
        "tripledes",
        "rc2",
        "rc4",
        "arc4",
        "blowfish",
        "cast5",
        "idea",
        "seed",
        "aes",
        "chacha20",
        "poly1305",
        "salsa20",
        "rsa",
        "dsa",
        "dh",
        "ecdh",
        "ecdsa",
        "ed25519",
        "ed448",
        "x25519",
        "x448",
        "hmac",
        "cmac",
        "gmac",
        "pbkdf2",
        "scrypt",
        "bcrypt",
        "argon2",
        "argon2id",
        "hkdf",
        "mlkem",
        "mldsa",
        "slhdsa",
        # modes, paddings, protocol versions
        "ecb",
        "cbc",
        "gcm",
        "ccm",
        "ctr",
        "cfb",
        "ofb",
        "xts",
        "siv",
        "ocb",
        "eax",
        "pkcs1",
        "pkcs5",
        "pkcs7",
        "oaep",
        "pss",
        "nopadding",
        "sslv2",
        "sslv3",
        "tlsv1",
        "tlsv11",
        "tlsv12",
        "tlsv13",
        # compound API names - unambiguous, and they say what the call DOES
        "getinstance",
        "generatekey",
        "generatekeypair",
        "newcipher",
        "createcipheriv",
        "createcipher",
        "createhash",
        "createhmac",
        "messagedigest",
        "secretkeyfactory",
        "pbekeyspec",
        "keypairgenerator",
        "signpkcs1v15",
        "verifypkcs1v15",
        "encryptoaep",
        "decryptoaep",
        "signpss",
        "verifypss",
        "pbkdf2hmac",
        "pbkdf2_hmac",
        "hexdigest",
    }
)

#: The hand-kept set above, widened with every algorithm the registry knows. Written this way so a
#: primitive added to the registry becomes shape-significant without anyone remembering to add it
#: here twice.
_KEEP = _KEEP | _registry_primitive_words()


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+")
#: Split an identifier into its words: `MODE_ECB` -> mode, ecb; `createCipheriv` -> create,
#: cipheriv; `SignPKCS1v15` -> sign, pkcs1v15.
_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")


def _meaning(token: str) -> list[str]:
    """The cryptographically meaningful words in one identifier, or [] if it carries none.

    The whole token is tried first, because the compound API names are only unambiguous whole:
    `getInstance` means something, `get` and `instance` do not. Only then is it split, which is
    what rescues the constants that carry the mode: `AES.MODE_ECB` is one token to the tokenizer,
    matched nothing as a whole, and folded away entirely - so an ECB call and a GCM call hashed
    to the same shape, which is the one distinction this key exists to preserve.
    """
    whole = token.lower()
    if whole in _KEEP:
        return [whole]
    words = [w.lower() for w in _WORD_RE.findall(token)]
    return [w for w in words if w in _KEEP]


def shape_key(rule_id: str, language: str, text: str) -> str:
    """A fingerprint of what this code DOES, insensitive to what its author called things.

    `digest = hashlib.md5(payload).hexdigest()` and `checksum = hashlib.md5(data).hexdigest()` are
    the same migration problem and hash to the same key here, where the exact-line cache treats
    them as two unrelated findings. That difference is why the cache answered only 13 reuses
    across a corpus that repeats itself constantly.

    Identifiers carrying no cryptographic word fold to `_`, numbers fold to `#`, and runs of
    folded tokens collapse - so two call sites differing only in how many locals the author used
    still match. The rule id and language are part of the key so a Go shape and a Java shape can
    never collide.
    """
    tokens: list[str] = []
    for match in _TOKEN_RE.finditer(text or ""):
        token = match.group(0)
        if token.isdigit():
            tokens.append("#")
            continue
        meaning = _meaning(token)
        tokens.extend(meaning if meaning else ["_"])
    collapsed: list[str] = []
    for piece in tokens:
        if piece == "_" and collapsed and collapsed[-1] == "_":
            continue
        collapsed.append(piece)
    signature = " ".join(collapsed)
    return sha256_of(f"{rule_id}\n{_safe_language(language)}\n{signature}")


#: SourcererCC's default similarity threshold at function granularity. Adopted rather than tuned:
#: it is the published operating point for near-miss detection, and this store has nowhere near
#: enough rows to justify fitting one of our own.
NEAR_MISS_THRESHOLD = 0.7


def token_bag(rule_id: str, language: str, text: str) -> Counter[str]:
    """The normalised tokens of ``text`` as a MULTISET, for near-miss comparison.

    `shape_key` hashes an ORDERED token sequence, which is exact-match by construction: it finds
    what the clone-detection literature calls Type-1 and Type-2 clones - identical code, and code
    differing only in identifiers and literals. It cannot find a Type-3 near-miss, where a
    statement has been added, removed or modified, because one extra token changes the hash
    entirely.

    SourcererCC's insight is that a bag of tokens is agnostic to position, and therefore resilient
    to exactly those edits. Same normalisation as `shape_key`, thrown into a multiset instead of a
    sequence, so token FREQUENCY still counts - two AES calls in a hunk is different evidence from
    one.
    """
    bag: Counter[str] = Counter()
    for match in _TOKEN_RE.finditer(text or ""):
        token = match.group(0)
        if token.isdigit():
            bag["#"] += 1
            continue
        meaning = _meaning(token)
        for word in meaning or ["_"]:
            bag[word] += 1
    # `_` is whatever the author called things and says nothing about what the code does. Left in,
    # a hunk full of locals would look similar to any other hunk full of locals.
    bag.pop("_", None)
    return bag


def overlap_similarity(left: Counter[str], right: Counter[str]) -> float:
    """SourcererCC's ``S(M1, M2) = |M1 ∩ M2| / max(|M1|, |M2|)`` over token multisets.

    Multiset intersection, so a token appearing twice on one side and once on the other
    contributes one - which is what makes the measure sensitive to a repeated call rather than
    treating presence as binary.
    """
    if not left or not right:
        return 0.0
    shared = sum((left & right).values())
    return shared / max(sum(left.values()), sum(right.values()))


#: A language value the retrieval side can never ask for is a row that can never be read. The
#: older table is full of them: 17 of 21 rows carry the rule's `multi`, while lookups pass the
#: FILE's language, so those rows were dead for grounding from the moment they were written.
_UNUSABLE_LANGUAGES = frozenset({"", "multi", "none", "unknown"})


def _safe_language(language: str) -> str:
    return "unknown" if (language or "").strip().lower() in _UNUSABLE_LANGUAGES else language


# --- the experience base ----------------------------------------------------------------------


def extract_hunk(before: str, after: str, line: int | None, context: int = 6) -> tuple[str, str]:
    """The changed region of a rewrite, with a little context - not the whole file.

    A whole file is too much to put several of into a 7B model's prompt, and the unchanged parts
    of it teach nothing. The region between the first and last differing line, padded by
    ``context``, is what a later call actually needs to see.

    Falls back to the neighbourhood of the flagged line when the two sides differ everywhere (a
    reformat, or a rewrite so complete there is no common prefix), because a hunk covering the
    entire file is the same problem as sending the file.
    """
    old = before.splitlines()
    new = after.splitlines()
    first = 0
    while first < len(old) and first < len(new) and old[first] == new[first]:
        first += 1
    last_old, last_new = len(old) - 1, len(new) - 1
    while last_old > first and last_new > first and old[last_old] == new[last_new]:
        last_old -= 1
        last_new -= 1

    span = max(last_old - first, last_new - first) + 1
    if span > 60 and line is not None and 1 <= line <= len(old):
        # No usable common region. Anchor on the finding instead.
        first = max(0, line - 1 - context)
        last_old = min(len(old) - 1, line - 1 + context)
        last_new = min(len(new) - 1, line - 1 + context)

    lo = max(0, first - context)
    return (
        "\n".join(old[lo : last_old + 1 + context]).strip("\n"),
        "\n".join(new[lo : last_new + 1 + context]).strip("\n"),
    )


#: Rejection wordings that say the CHECK could not be satisfied, not that the rewrite was wrong.
#:
#: `llm.unverifiable_reason` already diagnoses this: a `present` expectation fails when QUBIT
#: ships no verified target shape for that language, so the rescan cannot be satisfied by any
#: output at all. Storing one of those as "this shape defeats the model" is a FALSE NEGATIVE, and
#: the in-context-learning literature is specific that a bad negative example misleads rather than
#: teaches - the risk it names as the price of showing failures directly.
_UNWINNABLE_MARKERS = (
    "ships no verified",
    "may be unsatisfiable",
    "candidate for migration advice",
)


def is_false_negative(failure_reason: str) -> bool:
    """True when a rejection says more about the checker than about the rewrite.

    LEGACY CLASSIFIER, kept for rows written before `LearnedOutcome.is_unwinnable` existed.
    Matching free text for three substrings is fragile by construction, and it was already
    provably incomplete: the router's own detour message says "ships no rule that recognises",
    which none of the markers match, so that path's failures were never recognised as
    self-inflicted. New writes pass `unwinnable=` explicitly instead — the callers that produce
    these rejections know exactly why they are failing, so nothing needs to be re-derived from a
    string afterwards. See :func:`record_outcome` and :func:`reliability`.
    """
    lowered = (failure_reason or "").lower()
    return any(marker in lowered for marker in _UNWINNABLE_MARKERS)


def was_unwinnable(row: LearnedOutcome) -> bool:
    """Whether a stored failure was QUBIT's own gap rather than the model's ceiling.

    Reads the explicit flag when the row carries one, and falls back to the legacy text match
    only for rows written before that column existed (NULL). Both paths are needed: dropping the
    fallback would silently re-admit every historical self-inflicted failure into the reliability
    gate, which is exactly the trap that once blocked go-ethereum from being retried at all.
    """
    if row.is_unwinnable is not None:
        return row.is_unwinnable
    return is_false_negative(row.failure_reason or "")


def record_outcome(
    session: Session,
    *,
    rule_id: str,
    language: str,
    algorithm: str | None,
    shape: str,
    passed: bool,
    hunk_before: str,
    hunk_after: str = "",
    reasoning: str = "",
    failure_reason: str = "",
    model_name: str | None = None,
    unwinnable: bool | None = None,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
) -> None:
    """Record what happened to this shape, whether it worked or not.

    Both halves matter and for different reasons. A success is grounding: the next call for the
    same shape sees a verified before/after and the reasoning that went with it. A failure is a
    warning: the next call is told what was tried and why it was rejected, which is the single
    most useful thing to know before attempting the same thing again.

    De-duplicated per (rule, language, shape, outcome) - a corpus repeats itself, and fifty copies
    of one lesson crowd the prompt without adding to it. A repeat bumps `hit_count` instead, which
    is what ranks the strongest evidence first.

    `unwinnable=True` marks a rejection that QUBIT inflicted on itself (it ships no verified target
    shape for this language, so the rescan cannot be satisfied by ANY output). Those are dropped
    rather than stored: replaying one would warn the next attempt away from a rewrite that may have
    been perfectly good. Callers state it explicitly; `None` means "not stated", which falls back
    to the legacy text match for compatibility with existing call sites.
    """
    if not passed:
        self_inflicted = unwinnable if unwinnable is not None else is_false_negative(failure_reason)
        if self_inflicted:
            # Not recorded at all - this rejection is the rescan being unsatisfiable in this
            # language, which says nothing about whether the rewrite was right.
            return
    lang = _safe_language(language)
    existing = session.scalar(
        select(LearnedOutcome)
        .where(LearnedOutcome.tenant_id == tenant_id)
        .where(LearnedOutcome.rule_id == rule_id)
        .where(LearnedOutcome.language == lang)
        .where(LearnedOutcome.shape_key == shape)
        .where(LearnedOutcome.outcome == ("passed" if passed else "failed"))
        .limit(1)
    )
    if existing is not None:
        touch(session, existing)
        # A later run may have produced better evidence for the same lesson: keep the reasoning
        # if the first attempt had none, and keep the newest failure reason, which reflects the
        # current prompt rather than one two versions ago.
        if passed and reasoning and not existing.reasoning:
            existing.reasoning = reasoning
        if not passed and failure_reason:
            existing.failure_reason = failure_reason
        return
    session.add(
        LearnedOutcome(
            tenant_id=tenant_id,
            rule_id=rule_id,
            language=lang,
            algorithm=algorithm,
            shape_key=shape,
            outcome="passed" if passed else "failed",
            hunk_before=hunk_before.strip(),
            hunk_after=hunk_after.strip(),
            reasoning=reasoning.strip(),
            failure_reason=failure_reason.strip(),
            source_model=model_name,
            # False, not None, for a stored failure: reaching here means it was judged and found
            # genuine, so a later reader must not re-run the legacy text match over it.
            is_unwinnable=None if passed else False,
        )
    )


@dataclass
class Experience:
    """What this project already knows about migrating a shape like the one in hand."""

    #: Verified (before, after, reasoning) rewrites, strongest evidence first.
    proven: list[tuple[str, str, str]] = field(default_factory=list)
    #: Rejection reasons from attempts at this same shape, newest first.
    failures: list[str] = field(default_factory=list)
    #: True when `proven` contains a rewrite of the SAME shape rather than merely the same rule.
    exact_shape: bool = False
    #: True when the strongest evidence came from a NEAR-MISS match rather than an exact one - the
    #: stored code differs by an added, removed or modified statement but shares enough tokens to
    #: clear `NEAR_MISS_THRESHOLD`. Reported separately so the prompt can say "very close" instead
    #: of claiming "exactly this shape", which would be a slightly false claim.
    near_miss: bool = False

    def __bool__(self) -> bool:
        return bool(self.proven or self.failures)


def experience_for(
    session: Session,
    *,
    rule_id: str,
    language: str,
    shape: str | None = None,
    text: str | None = None,
    limit: int = 3,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
) -> Experience:
    """Everything worth telling a fresh call about this rule, this language and this shape.

    Ranked deliberately: a rewrite of the SAME shape is the strongest possible evidence and comes
    first, then the most-reused rewrites for the same rule and language. Failures are attached
    separately rather than mixed in, because "here is a fix that worked" and "here is what was
    rejected last time" have to be said differently or the model copies the wrong one.

    ``limit`` stays small on purpose. A rule migrated a hundred times would otherwise push the
    actual task down the prompt and dilute the strongest signal with volume.
    """
    lang = _safe_language(language)
    result = Experience()

    if shape:
        same_shape = session.scalars(
            select(LearnedOutcome)
            .where(LearnedOutcome.tenant_id == tenant_id)
            .where(LearnedOutcome.rule_id == rule_id)
            .where(LearnedOutcome.language == lang)
            .where(LearnedOutcome.shape_key == shape)
            .where(LearnedOutcome.outcome == "passed")
            .order_by(LearnedOutcome.hit_count.desc(), LearnedOutcome.created_at.desc())
            .limit(limit)
        ).all()
        for row in same_shape:
            result.proven.append((row.hunk_before, row.hunk_after, row.reasoning))
            touch(session, row)
        result.exact_shape = bool(same_shape)

    # Tier two: NEAR-MISS. The exact key is a hash of an ordered token sequence, so it finds only
    # what the clone-detection literature calls Type-1 and Type-2 clones - identical code, and
    # code differing only in names. A statement added, removed or modified changes the hash
    # completely, and that is the common case in real repositories: the same call wrapped in a
    # try/except, or with one extra argument, missed entirely. Comparing token MULTISETS instead
    # is position-agnostic and therefore survives those edits (SourcererCC,
    # `S = |M1 ∩ M2| / max(|M1|, |M2|)`, threshold 0.7).
    if text and len(result.proven) < limit:
        query_bag = token_bag(rule_id, lang, text)
        candidates = session.scalars(
            select(LearnedOutcome)
            .where(LearnedOutcome.tenant_id == tenant_id)
            .where(LearnedOutcome.rule_id == rule_id)
            .where(LearnedOutcome.language == lang)
            .where(LearnedOutcome.outcome == "passed")
            .where(LearnedOutcome.shape_key != (shape or ""))
        ).all()
        # The stored hunk can be wider than the query window (it spans first-to-last change plus
        # context, the query is a fixed window round the finding). Dividing by `max` means the
        # wider side lowers the score, so the asymmetry biases towards a MISS rather than a false
        # hit - the safe direction for something that ends up in a prompt as "follow this".
        scored = [
            (overlap_similarity(query_bag, token_bag(rule_id, lang, row.hunk_before)), row)
            for row in candidates
        ]
        for score, row in sorted(scored, key=lambda pair: -pair[0]):
            if len(result.proven) >= limit or score < NEAR_MISS_THRESHOLD:
                break
            result.proven.append((row.hunk_before, row.hunk_after, row.reasoning))
            # Only claimed when the near-miss tier is what ANSWERED. It also runs to top up an
            # exact hit with more evidence, and flagging that as a near miss would understate what
            # was found - the prompt reads these two fields to decide whether to say "exactly this
            # shape" or "very close".
            result.near_miss = result.near_miss or not result.exact_shape
            touch(session, row)

    # Tier three: anything verified for this rule and language, most-reused first. Weaker
    # evidence - it shares the migration, not the code - but far better than starting cold.
    if len(result.proven) < limit:
        seen = {before for before, _, _ in result.proven}
        stmt = (
            select(LearnedOutcome)
            .where(LearnedOutcome.tenant_id == tenant_id)
            .where(LearnedOutcome.rule_id == rule_id)
            .where(LearnedOutcome.language == lang)
            .where(LearnedOutcome.outcome == "passed")
            .order_by(LearnedOutcome.hit_count.desc(), LearnedOutcome.created_at.desc())
            .limit(limit)
        )
        if shape:
            stmt = stmt.where(LearnedOutcome.shape_key != shape)
        for row in session.scalars(stmt).all():
            if len(result.proven) >= limit:
                break
            if row.hunk_before in seen:
                continue
            result.proven.append((row.hunk_before, row.hunk_after, row.reasoning))
            touch(session, row)

    result.failures = known_failures(
        session, rule_id=rule_id, language=language, shape=shape, tenant_id=tenant_id
    )
    return result


def known_failures(
    session: Session,
    *,
    rule_id: str,
    language: str,
    shape: str | None = None,
    limit: int = 2,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
) -> list[str]:
    """Rejection reasons recorded against this shape, or this rule and language.

    Told to the model BEFORE it writes, so it does not spend an attempt rediscovering a rejection
    this project has already paid for.
    """
    lang = _safe_language(language)
    stmt = (
        select(LearnedOutcome)
        .where(LearnedOutcome.tenant_id == tenant_id)
        .where(LearnedOutcome.rule_id == rule_id)
        .where(LearnedOutcome.language == lang)
        .where(LearnedOutcome.outcome == "failed")
        .order_by(LearnedOutcome.hit_count.desc(), LearnedOutcome.created_at.desc())
        .limit(limit)
    )
    if shape:
        stmt = stmt.where(LearnedOutcome.shape_key == shape)
    return [row.failure_reason for row in session.scalars(stmt).all() if row.failure_reason]


def reliability(
    session: Session,
    *,
    rule_id: str,
    language: str,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
    source_model: str | None = None,
    include_unattributed: bool = False,
) -> tuple[int, int]:
    """``(passed, failed)`` recorded for this rule in this language.

    ``source_model``: count only outcomes produced by THIS engine. See the second trap below --
    without it, switching to a stronger model inherits the weaker one's failures and the new
    engine is refused work it may well be able to do.

    ``include_unattributed``: also count rows with no ``source_model``. Set by the caller when the
    active engine is the LOCAL one, because a row written before attribution existed was produced
    by the local model -- that is a fact about when the column was added, not a guess. Attaching
    that history to an external engine instead would be wrong in the harmful direction.

    Counts only failures the MODEL is answerable for. A rejection produced by an expectation
    nothing could satisfy - QUBIT shipping no verified target shape for the language, so the
    rescan's `present` check can never pass - says nothing about the model and must not be
    counted against it. `was_unwinnable` draws that line for the grounding examples too, and the
    two must agree about what a failure means.

    Not filtering here was a real, self-inflicted trap. `_llm_detour_reason` refuses to call the
    model once a (rule, language) pair has failed `llm_skip_after_failures` times with no
    success, so unwinnable failures became permanent evidence against the model - and the moment
    the underlying QUBIT gap was FIXED, the pairing stayed blocked by the very failures that gap
    had caused, reporting "the local model has not completed this" about a model that had never
    been given a fair attempt. Measured: go-ethereum's `code-signature-01`/go recorded 4 failures,
    every one of them caused by Go having no ML-DSA detection rule; after that rule was added the
    pairing was still skipped, citing those same four.

    The SECOND form of the same trap, and the reason `source_model` exists: a ceiling measured on
    one model is not a property of the task. Counting every engine's failures together meant
    configuring a stronger model inherited the weaker one's record and was refused before its
    first attempt -- `_llm_detour_reason` sent the finding to written advice citing failures the
    new engine had no part in. Measured live: `py-signature-01`/python carried enough local-7B
    failures to trip `llm_skip_after_failures`, and a freshly configured 120B model was skipped on
    that evidence. Scoping the count to the engine that will actually run restores the property
    the docstring above already claimed.
    """
    lang = _safe_language(language)
    stmt = (
        select(LearnedOutcome)
        .where(LearnedOutcome.tenant_id == tenant_id)
        .where(LearnedOutcome.rule_id == rule_id)
        .where(LearnedOutcome.language == lang)
    )
    if source_model is not None:
        match = LearnedOutcome.source_model == source_model
        if include_unattributed:
            match = or_(match, LearnedOutcome.source_model.is_(None))
        stmt = stmt.where(match)
    rows = session.scalars(stmt).all()
    passed = sum(1 + row.hit_count for row in rows if row.outcome == "passed")
    failed = sum(
        1 + row.hit_count for row in rows if row.outcome == "failed" and not was_unwinnable(row)
    )
    return passed, failed


def engine_record(
    session: Session,
    *,
    source_model: str,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
    include_unattributed: bool = False,
) -> tuple[int, int]:
    """``(passed, failed)`` for this engine across EVERY rule and language.

    `reliability` answers "has this engine done this exact pairing", which is the right question
    for gating one finding and the wrong one for deciding who gets first attempt. A pairing has to
    fail `llm_skip_after_failures` times before it is gated, so an engine that cannot do the work at
    all pays that toll separately on every new pairing it meets -- and each toll is several model
    calls plus the repair loop.

    Measured on this installation: the local 7B is **0 for 22** on the current patch set, spread
    across enough distinct pairings that the per-pairing gate had barely begun to fire, while the
    hosted engines are 10 for 13. That is not a fact about any one rule; it is a fact about the
    engine, and it takes a question at this scope to see it.

    Same "answerable" filter as `reliability`: a rejection produced by an expectation nothing could
    satisfy says nothing about the model, so `was_unwinnable` rows are not counted against it.
    """
    stmt = select(LearnedOutcome).where(LearnedOutcome.tenant_id == tenant_id)
    match = LearnedOutcome.source_model == source_model
    if include_unattributed:
        match = or_(match, LearnedOutcome.source_model.is_(None))
    rows = session.scalars(stmt.where(match)).all()
    passed = sum(1 + row.hit_count for row in rows if row.outcome == "passed")
    failed = sum(
        1 + row.hit_count for row in rows if row.outcome == "failed" and not was_unwinnable(row)
    )
    return passed, failed


def get_experience_for_rule(
    session: Session, rule_id: str, language: str, limit: int = 2
) -> list[tuple[str, str]]:
    """The older (before, after) line-pair grounding, kept for the callers that still want it.

    Superseded by :func:`experience_for`, which carries hunks, reasoning and failures instead of
    bare line pairs. Retained because it reads the line CACHE, which is still the right source for
    "what one-liner did we swap this to".
    """
    rows = session.scalars(
        select(LearnedPatch)
        .where(LearnedPatch.rule_id == rule_id)
        .where(LearnedPatch.language == _safe_language(language))
        .order_by(LearnedPatch.hit_count.desc(), LearnedPatch.created_at.desc())
        .limit(limit)
    ).all()
    return [(r.snippet_before, r.snippet_after) for r in rows]


__all__ = [
    "NEAR_MISS_THRESHOLD",
    "Experience",
    "ReuseResult",
    "apply",
    "experience_for",
    "extract_hunk",
    "get_experience_for_rule",
    "is_false_negative",
    "known_failures",
    "lookup",
    "overlap_similarity",
    "record",
    "record_outcome",
    "reliability",
    "shape_key",
    "token_bag",
    "touch",
]
