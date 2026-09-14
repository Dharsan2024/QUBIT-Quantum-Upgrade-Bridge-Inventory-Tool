"""Rules for findings the hand-written pack does not cover.

A finding with no rule used to go straight to written guidance. That is the right answer when no
edit QUBIT can make is correct -- a signed certificate, an ecosystem with no trustworthy PQC
provider -- but it was also the answer for findings that are perfectly migratable and simply had no
YAML entry yet. The queue then said "no migration rule covers this finding", which reads as a
refusal rather than as the gap it actually is.

**The target is not invented.** QUBIT already knows what a given algorithm and usage context should
become: `kb.lookup_kb` holds the vetted family -> PQC mapping with its library, and `agility`
resolves a policy target when the KB is silent. That is the same cascade
`/assets/{id}/recommendation` has always used to tell the operator what to migrate TO; the only
thing missing was using it to actually generate the change. So a synthesised rule is assembled from
QUBIT's own knowledge, the model writes the code, and every gate that judges a hand-written rule's
patch judges this one identically -- including the rescan, which is what stops a plausible-looking
rewrite that did not migrate anything.

What a synthesised rule deliberately does NOT get is a codemod. A codemod is a known-correct
constant edit, and there is no way to derive one for a transform nobody has written yet.
"""

from __future__ import annotations

import contextlib
import logging
import re
import uuid

from qubit_core import CryptoAsset
from qubit_core.db.models import DEFAULT_TENANT_ID, LearnedRule
from qubit_core.schemas import SourceScanner, utcnow
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agility import resolve_target
from ..kb import lookup_kb
from .rules import MigrationRule
from .targets import library_exists

logger = logging.getLogger(__name__)

#: Algorithms whose migration is a judgement call about surrounding code rather than a substitution,
#: so a synthesised rule is worth attempting. Everything Shor breaks belongs here: replacing RSA or
#: ECDSA is a new key type, a new call shape and new imports, which is exactly the work a model can
#: do and a codemod cannot.
_WORTH_SYNTHESISING = re.compile(
    r"^(RSA|DSA|ECDSA|ECDH|DH|X25519|X448|ED25519|ED448|ELGAMAL)", re.IGNORECASE
)


def _family(algorithm: str) -> str:
    """`RSA-2048` -> `RSA`, matching how the KB indexes its entries."""
    return algorithm.split("-")[0].upper() if algorithm else "UNKNOWN"


def synthesize_rule(
    asset: CryptoAsset, language: str, regime: str | None = None
) -> MigrationRule | None:
    """A rule for this finding derived from the KB and the agility policy, or None.

    None means QUBIT genuinely has nothing to say -- no KB entry, no policy target -- and the
    caller should fall through to guided remediation, which is still the honest answer there.
    """
    algorithm = asset.algorithm or ""
    if not algorithm or not _WORTH_SYNTHESISING.match(algorithm):
        return None
    # A synthesised rule authorises a SOURCE REWRITE, so it may only be derived for a finding in
    # source code. The other scanners find things no edit to a file can fix: a certificate is a
    # signed object that has to be re-issued, a TLS endpoint's suite is chosen by whatever serves
    # it, a dependency's algorithm belongs to the dependency. Written guidance is the right answer
    # for those, and it always was -- what changed is only that findings in code stopped getting it
    # by default.
    if asset.source_scanner is not None and asset.source_scanner != SourceScanner.code:
        return None

    family = _family(algorithm)
    usage = asset.usage_context.value if asset.usage_context else "unknown"

    target_algorithm = ""
    library = ""
    rationale = ""

    entry = lookup_kb(family, usage)
    if entry is not None:
        target_algorithm = entry.target.parameter_set or entry.target.algorithm
        python_lib = entry.library.python
        library = python_lib.name if python_lib else ""
        rationale = entry.guidance

    if regime:
        # A REGIME OUTRANKS THE KNOWLEDGE BASE. The KB holds generic guidance — good defaults for
        # an install that has not said where it operates. A regime is a regulator's requirement,
        # and an install that named one has said exactly that. Letting the KB win would mean a
        # deployment under CNSA 2.0 silently receiving ML-KEM-768, which that regime rejects.
        #
        # The KB's LIBRARY advice survives, because which package implements a primitive is a
        # fact about the ecosystem rather than a policy question, and the regime has no opinion
        # on it.
        governed = resolve_target(asset, regime=regime)
        if governed is not None:
            # `hybrid_group` is deliberately NOT consulted: `resolve_target` sets it FROM
            # `parameter_set`, so the two can never differ and a `hybrid_group or ...` branch is
            # dead code wearing the costume of a safeguard. The hybrid signal that downstream
            # code needs travels in the target STRING (`X25519MLKEM768`, or a `+` for a
            # composite), which is what `hybrid_components` and the composite shape both read.
            target_algorithm = governed.parameter_set or governed.target
            rationale = governed.rationale
    elif entry is None:
        policy = resolve_target(asset)
        if policy is not None:
            target_algorithm = policy.parameter_set or policy.target
            rationale = policy.rationale

    if not target_algorithm:
        return None

    # ONLY NAME A LIBRARY THAT EXISTS HERE.
    #
    # The knowledge base recommends a package per (family, usage), and that recommendation goes
    # straight into the prompt as a concrete instruction. When the package is not installed, the
    # model is being told to import something the environment does not have — and it complies.
    # Measured on this installation: four patches named `pqcrypto`, which is not a dependency of
    # this project at all, and `symbols` caught them one gate after the model time was spent.
    #
    # Dropped rather than substituted. Inventing a replacement would be the same failure with a
    # different author: the model then writes against whatever QUBIT guessed. With no library
    # named, the prompt falls back to the target ALGORITHM, which the rescan and the metamorphic
    # oracle both verify independently.
    if library and not library_exists(library):
        logger.info(
            "knowledge base recommends %r for %s/%s, which is not importable here; "
            "omitting it from the rule rather than instructing the model to import it",
            library,
            family,
            usage,
        )
        library = ""

    return MigrationRule(
        # Namespaced so a synthesised rule is never mistaken for a hand-written one, in the queue
        # or in the outcome history the reliability gate reads.
        id=f"synth-{family.lower()}-{usage}-{language}",
        language=language,
        title=f"Replace {family} ({usage}) with {target_algorithm}",
        matches={
            "algorithm": [algorithm, family],
            "usage_context": [usage],
            "source_scanner": ["code"],
        },
        target={
            "algorithm": target_algorithm,
            "pqc_target": target_algorithm,
            **({"library": {"name": library}} if library else {}),
        },
        semantic_note=(
            rationale
            or f"{family} is broken by Shor's algorithm; {target_algorithm} is the PQC replacement."
        ),
        # No codemod: there is no known-correct constant edit for a transform nobody has written.
        codemod=None,
        prompt_constraints=[
            f"Replace the {family} usage on the flagged line with {target_algorithm}.",
            "Add every import the replacement needs; a name used but not "
            "imported is a broken file.",
            "Change nothing else. Preserve all unrelated code, comments and formatting exactly.",
            "If the old algorithm must stay readable for existing data, keep that path and add the "
            "new one alongside it rather than deleting it.",
        ],
        # The gate that makes this safe. A synthesised rule is a hypothesis, and the rescan is what
        # decides whether the model's answer actually removed the finding -- without it a
        # confident-looking rewrite that migrated nothing would be indistinguishable from a
        # real one.
        # The shape the validator reads: `{gone: {algorithm_prefix: [...]}}`. A flat list here
        # crashed `_stage_rescan` with `'list' object has no attribute 'get'` on the first
        # synthesised patch that reached the stage -- every one of them, since the rescan is what
        # makes a derived rule safe to use at all.
        rescan_expect={
            "gone": {"algorithm_prefix": [family]},
            "present": {"algorithm_prefix": [target_algorithm]},
        },
        remediation="auto",
        # Recorded so the queue, and anything reading the plan later, can tell where this came from.
        data_compat="in_place",
    )


def provenance(rule: MigrationRule) -> str:
    """Human-readable note for a synthesised rule, or "" for a hand-written one."""
    if not rule.id.startswith("synth-"):
        return ""
    return (
        "This rule was derived from QUBIT's migration knowledge base rather than hand-written, "
        "because no rule in the pack covered this finding. The target algorithm is QUBIT's own "
        "recommendation for this family and usage; the change was written by the attached model "
        "and passed the same validation gates as any other patch."
    )


def recall_rule(
    session: Session,
    asset: CryptoAsset,
    language: str,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
) -> MigrationRule | None:
    """A rule QUBIT derived earlier and already proved, or None.

    Checked before deriving a fresh one. Not an optimisation -- deriving is cheap -- but a
    consistency guarantee: a stored rule is one whose patch passed the gates, so the second
    occurrence of a finding is answered by the derivation that worked rather than by whatever the
    knowledge base resolves to today. It also makes the learning visible: `hit_count` is the count
    of findings a self-derived rule has since handled.
    """
    algorithm = asset.algorithm or ""
    if not algorithm:
        return None
    family = _family(algorithm)
    usage = asset.usage_context.value if asset.usage_context else "unknown"
    rule_id = f"synth-{family.lower()}-{usage}-{language}"

    with contextlib.suppress(Exception):
        row = session.scalars(
            select(LearnedRule)
            .where(LearnedRule.tenant_id == tenant_id)
            .where(LearnedRule.rule_id == rule_id)
        ).first()
        if row is not None and row.rule_json:
            rule = MigrationRule.model_validate(row.rule_json)
            row.hit_count += 1
            row.last_used_at = utcnow()
            session.commit()
            return rule
    return None


def remember_rule(
    session: Session,
    rule: MigrationRule,
    asset: CryptoAsset,
    source_model: str | None = None,
    tenant_id: uuid.UUID = DEFAULT_TENANT_ID,
) -> None:
    """Store a synthesised rule whose patch passed validation.

    Called only from the success path, and that placement is the whole safety argument: a rule that
    produced a patch the gates rejected is a bad derivation, and persisting it would hand the same
    mistake to every later finding it matches. Storing only proven ones means the table can be
    trusted without re-checking it.

    Hand-written rules are ignored -- they already live in the pack, and copying them here would
    create a second definition that nobody updates.

    Never raises. Learning is a side benefit of a migration that already succeeded, and losing a
    lesson is a far smaller cost than failing the patch that taught it.
    """
    if not rule.id.startswith("synth-"):
        return
    with contextlib.suppress(Exception):
        existing = session.scalars(
            select(LearnedRule)
            .where(LearnedRule.tenant_id == tenant_id)
            .where(LearnedRule.rule_id == rule.id)
        ).first()
        if existing is not None:
            return
        session.add(
            LearnedRule(
                tenant_id=tenant_id,
                rule_id=rule.id,
                language=rule.language,
                family=_family(asset.algorithm or ""),
                usage_context=(asset.usage_context.value if asset.usage_context else "unknown"),
                target_algorithm=str(rule.target.get("algorithm", "")),
                rule_json=rule.model_dump(mode="json"),
                source_model=source_model,
            )
        )
        session.commit()
        logger.info("learned a new rule %s targeting %s", rule.id, rule.target.get("algorithm"))
