"""Regulatory regimes: the target algorithm is a function of jurisdiction, not a constant.

Every automated migration tool surveyed picks ONE target per finding, and every one of them is
wrong somewhere. The frameworks genuinely disagree, and the disagreement is not the one people
expect:

* **BSI TR-02102 REQUIRES hybrid.** Pure standalone ML-KEM is not sufficient for new deployments.
* **ANSSI requires hybrid too**, but raises a standalone PQC KEM as an ADVISORY — strongly
  recommended rather than mandatory. Same rule, different severity, and a tool that cannot express
  the difference must either over-block or under-warn.
* **CNSA 2.0 does not forbid hybrid.** It forbids a hybrid whose ML-KEM component is below the
  1024 grade. `X25519MLKEM768`, the industry default and the thing browsers actually ship, fails
  CNSA 2.0 **on the 768, not on the hybrid**.

That last point is the finding. A tool that models the axis as "hybrid vs pure" — which is how it
is usually described — gets CNSA 2.0 backwards and cannot explain why the default configuration
fails. The real axis is PARAMETER GRADE.

Sourced from `vendor/open-quantum-secure/pkg/compliance/{cnsa2,anssi,bsi_tr_02102}.go`, executable
encodings of each framework. That source CORRECTED two entries this project had recorded from
prose: BSI was written down as "warns against default hybrid" (it requires it) and CNSA 2.0 as
"against hybrid by default" (it objects to the grade). Both are marked `verified-secondary` — read
from an executable encoding, not from the primary standard — and `asd-ism` remains `secondary`,
unverified, because it is in neither.

**An install that configures no regime is unchanged.** Regimes add a lens; they do not move the
default. See `resolve_target`'s contract in `agility.py`.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

_PARAMS_DIR = Path(__file__).parent / "params"
_REGIMES_PATH = _PARAMS_DIR / "regimes.yaml"

#: How a regime treats the pure/hybrid choice.
#:
#: `either` is not a synonym for "unspecified" — NIST IR 8547 sets deprecation dates without
#: mandating a construction, which is a deliberate position and the reason it is the safe default.
Construction = Literal["hybrid", "pure_or_hybrid_at_grade", "either"]

#: What a regime would RATHER see, which is not the same question as what it permits.
#:
#: CNSA 2.0 permits a hybrid at the 1024 grade and prefers a pure target; ASD permits one for
#: legacy interoperability and prefers pure. `Construction` cannot express that — its members
#: describe permission, and "pure" is not among them precisely because no regime here forbids a
#: hybrid outright. Two types because they are two different questions.
Preference = Literal["pure", "hybrid"]
#: What KIND of thing is being migrated, in ANSSI's own two-way split.
#:
#: ANSSI's follow-up position paper (21 Dec 2023, §4) makes the hybrid mandate depend on this and
#: on nothing else: an `end` product "shall implement hybridation", while an `intermediate` product
#: -- "platform products that provide raw cryptographic functionalities to an upper (applicative)
#: layer" -- may ship pure PQC, because the hybridisation "will be part of upper user-oriented
#: layers".
#:
#: This is not a detail. A cryptographic LIBRARY is an intermediate product, and libraries are the
#: bulk of what this tool migrates.
ProductClass = Literal["end", "intermediate"]

#: A regime's objection to a target. `violation` blocks; `advisory` warns.
#:
#: The split exists because ANSSI and BSI impose the SAME hybrid requirement at different
#: strengths: BSI's is a requirement, ANSSI's reference implementation raises it as an advisory.
#: Collapsing them would either block French deployments that are actually compliant or let German
#: ones through that are not.
#: `notice` is informational: the target is permitted and will not be blocked, but the regime
#: prefers something else. CNSA 2.0 and ASD both permit a hybrid at grade while recommending
#: against it, and collapsing that into "ok" hides a fact an operator choosing an architecture
#: needs — while raising it to `advisory` would imply an action they are not required to take.
Severity = Literal["violation", "advisory", "notice"]

#: Pulls the numeric grade out of a parameter set: `ML-KEM-768` -> 768, `ML-DSA-87` -> 87.
#: Also matches the grade embedded in a hybrid group name — `X25519MLKEM768` -> 768 — which is what
#: makes the CNSA 2.0 sub-1024 rule expressible at all.
_GRADE = re.compile(r"(\d{2,4})(?!.*\d)")


class RegimeTarget(BaseModel):
    """A regime's default for one usage bucket."""

    algorithm: str
    parameter_set: str | None = None
    #: The classical component, when the regime's construction is hybrid.
    hybrid_with: str | None = None


class Regime(BaseModel):
    """One regulatory framework's position."""

    authority: str = ""
    source: str = ""
    #: `primary` read from the standard, `verified-secondary` from an executable encoding of it,
    #: `secondary` from prose. Carried into the record so a reader can weigh the claim; a tool that
    #: presents all three as equally settled is overstating what it knows.
    confidence: str = "secondary"
    applies_to: str = ""
    construction: Construction = "either"
    #: Severity of a construction objection, DECLARED rather than inferred. This was previously
    #: derived by grepping `rationale` for the word "advisory", so an editorial edit to the prose
    #: would silently flip a regime between warning and blocking — a policy change made by a
    #: typo. ANSSI and BSI impose the SAME hybrid requirement and differ only here.
    hybrid_severity: Severity = "violation"
    #: Severity under the regime's REGULATORY role, where it differs from its advisory one.
    #:
    #: ANSSI states it has "a twofold role... advisory and regulatory". For general industry it
    #: encourages hybrid; for French state certification its Phase 2 says post-quantum algorithms
    #: "SHALL continue to be systematically included inside hybrid mechanisms". Those are two
    #: different answers and an installation seeking certification needs the strict one.
    hybrid_severity_certified: Severity | None = None
    #: Families exempt from this regime's hybrid requirement.
    #:
    #: BSI and ANSSI both carve out hash-based signatures: collision resistance rests on no
    #: structured-lattice assumption, so there is nothing for a classical half to hedge. Without
    #: this the engine reported a standalone SLH-DSA as a BSI VIOLATION — against the regime that
    #: most explicitly approves it.
    standalone_exempt: list[str] = Field(default_factory=list)
    #: Severity for a standalone PQC target in a PLATFORM product, under the certified track.
    #:
    #: ANSSI §4 permits it where the end product will hybridise, so this downgrades the mandate --
    #: but only against two obligations, carried in `intermediate_product_conditions`. A downgrade
    #: that dropped them would turn a conditional permission into an unconditional pass, which is
    #: the same defect as a success criterion that cannot fail.
    intermediate_product_severity: Severity | None = None
    #: What the evaluator requires in exchange for that downgrade. Reported verbatim in the
    #: conflict detail, because an obligation nobody is told about is not an obligation.
    intermediate_product_conditions: list[str] = Field(default_factory=list)
    #: What the regime would rather see, when that differs from what it permits.
    preferred_construction: Preference | None = None
    #: The regime's own control identifier, where it has one (e.g. ASD's `ISM-1917`).
    control_reference: str = ""
    #: Which section of the primary document an entry was read from.
    #:
    #: Recorded only for entries at `confidence: primary`, and it is what makes that claim
    #: checkable: "we read the standard" is an assertion, "§2.2 of TR-02102-1 Version 2026-01" is
    #: an address a reviewer can go to.
    source_section: str = ""
    rationale: str = ""
    defaults: dict[str, RegimeTarget] = Field(default_factory=dict)
    #: Family -> minimum numeric grade. `{"ML-KEM": 1024}` rejects ML-KEM-512 and ML-KEM-768.
    minimum_grade: dict[str, int] = Field(default_factory=dict)
    #: Algorithms this regime does not approve, whatever their grade. CNSA 2.0 excludes SLH-DSA
    #: **despite FIPS 205 approval**, which is the kind of rule that only an explicit list can
    #: express — no amount of reasoning from "is it standardised" produces it.
    excluded: list[str] = Field(default_factory=list)
    approved_hybrid_kex: list[str] = Field(default_factory=list)
    also_approved: list[str] = Field(default_factory=list)
    deadlines: dict[str, Any] = Field(default_factory=dict)
    #: Protocol-version horizons, where the regime publishes them separately from algorithm ones.
    #:
    #: BSI puts these in TR-02102-*2* (the TLS profile) rather than -1, and the reason it gives for
    #: ending TLS 1.2's recommendation is post-quantum: no PQC key agreement will be standardised
    #: for it. That makes a TLS 1.2 listener a migration blocker rather than a weak-protocol
    #: finding, which is a different thing to tell an operator.
    protocol_deadlines: dict[str, Any] = Field(default_factory=dict)
    #: Minimum SYMMETRIC strength, where the regime sets one above the general recommendation.
    #:
    #: ANSSI does, and says so explicitly: AES-256 for block ciphers and SHA2-384 for hashes,
    #: "slightly more conservative than NIST's and BSI's current recommendation". It is the one
    #: place a target can satisfy every PQC rule here and still fail a regime on a primitive that
    #: has nothing to do with post-quantum key agreement.
    #:
    #: DATA ONLY — `check_target` does not enforce it, deliberately. ANSSI frames the floor as
    #: dimensioning "symmetric primitives as to ensure a conjectured post-quantum security", which
    #: is about collision and preimage resistance where those matter. `code-weakhash-02` targets
    #: SHA-256, below ANSSI's SHA2-384, and for an MD5 cache key that is entirely fine. Enforcing
    #: the floor without knowing the usage context would emit an advisory on every incidental hash
    #: in the corpus -- a criterion that fires regardless of whether anything is wrong, which is
    #: the same defect as one that cannot fire at all. `check_target` receives no usage context,
    #: so the honest state is recorded-and-not-enforced rather than half-enforced.
    symmetric_floor: dict[str, str] = Field(default_factory=dict)
    #: What the regime has SAID it will recommend, once a standard exists. Not approved, and not
    #: to be reported as such.
    #:
    #: BSI names two SSH hybrid KEX algorithms it intends to recommend "sobald der zugehörige RFC
    #: verabschiedet wurde" — once the RFC is adopted. Treating that as current would have QUBIT
    #: emit a configuration no shipped SSH server negotiates.
    intended_recommendations: dict[str, Any] = Field(default_factory=dict)
    hybrid_rule: str = ""

    @property
    def requires_hybrid(self) -> bool:
        return self.construction == "hybrid"


class RegimeCatalog(BaseModel):
    version: str
    default_regime: str
    regimes: dict[str, Regime]
    known_conflicts: list[dict[str, Any]] = Field(default_factory=list)

    def get(self, name: str | None) -> Regime | None:
        return self.regimes.get(name) if name else None


class PolicyConflict(BaseModel):
    """One regime's objection to a proposed target.

    Deliberately not an exception. A conflict is a RESULT — the same patch can satisfy BSI and
    violate CNSA 2.0, and both facts belong in the record. Raising on the first objection would
    discard the rest and make multi-regime reporting impossible.
    """

    regime: str
    severity: Severity
    rule: str
    detail: str

    @property
    def blocking(self) -> bool:
        return self.severity == "violation"


@lru_cache(maxsize=1)
def load_regimes(path: Path | None = None) -> RegimeCatalog:
    """Load and validate the regime catalog. Cached; call `.cache_clear()` in tests."""
    raw: dict[str, Any] = yaml.safe_load((path or _REGIMES_PATH).read_text(encoding="utf-8"))
    return RegimeCatalog.model_validate(raw)


def grade_of(parameter_set: str | None) -> int | None:
    """The numeric grade in a parameter set or hybrid group name, or None.

    `ML-KEM-1024` -> 1024. `X25519MLKEM768` -> 768. `SecP384r1MLKEM1024` -> 1024 — note the LAST
    number wins, because the classical curve's own number (384) comes first and reading that one
    would judge the hybrid on its classical half.
    """
    if not parameter_set:
        return None
    match = _GRADE.search(parameter_set)
    return int(match.group(1)) if match else None


def family_of(algorithm: str | None) -> str | None:
    """`ML-KEM-768` -> `ML-KEM`; `X25519MLKEM768` -> `ML-KEM`.

    Hybrid group names are spelled without separators, so a prefix match on the canonical family
    name fails and the grade minimum silently never applies — which would let X25519MLKEM768
    through CNSA 2.0, the exact case the whole regime engine exists to catch.
    """
    if not algorithm:
        return None
    compact = algorithm.replace("-", "").replace("_", "").upper()
    for family in ("MLKEM", "MLDSA", "SLHDSA", "FALCON", "HQC", "FRODOKEM"):
        if family in compact:
            return {
                "MLKEM": "ML-KEM",
                "MLDSA": "ML-DSA",
                "SLHDSA": "SLH-DSA",
                "FALCON": "FALCON",
                "HQC": "HQC",
                "FRODOKEM": "FrodoKEM",
            }[family]
    return None


def hybrid_components(target_algorithm: str | None) -> tuple[str, str] | None:
    """`ML-DSA-65+ECDSA-P256` -> `("ML-DSA-65", "ECDSA-P256")`, else None.

    The PQC half first, whichever order the target was written in, because the callers care which
    half is which: one must APPEAR after the migration and the other must SURVIVE it.
    """
    if not target_algorithm or "+" not in target_algorithm:
        return None
    parts = [p.strip() for p in target_algorithm.split("+", 1)]
    if len(parts) != 2 or not all(parts):
        return None
    first, second = parts
    # `family_of` recognises exactly the post-quantum families, so it doubles as the test for
    # which half is the lattice one.
    if family_of(first) is not None:
        return first, second
    if family_of(second) is not None:
        return second, first
    return None


def _is_hybrid(algorithm: str, hybrid_group: str | None, mode: str | None) -> bool:
    """Whether a proposed target is a hybrid construction.

    Three signals because the callers disagree on how they express it: `AgilityTarget` carries an
    explicit `mode`, rules carry `+` in the algorithm, and the policy file names a `hybrid_group`.
    Reading only one of them mislabels the other two.
    """
    if (mode or "").lower() == "hybrid" or hybrid_group:
        return True
    if "+" in algorithm:
        return True
    # `X25519MLKEM768` and `SecP256r1MLKEM768` are hybrids whose names say so only by carrying a
    # classical curve alongside the lattice family.
    compact = algorithm.replace("-", "").replace("_", "").upper()
    return any(c in compact for c in ("X25519", "SECP256R1", "SECP384R1", "P256", "P384"))


def is_hybrid(
    algorithm: str,
    hybrid_group: str | None = None,
    mode: str | None = None,
) -> bool:
    """Is this target a hybrid construction? The public form of the structural check.

    Exported because the question is asked outside this module. The API's recommendation endpoint
    used to answer it by searching the algorithm's NAME for the word "hybrid", which no hybrid is
    named with -- `X25519MLKEM768` is the industry standard and contains no such word -- so every
    key-exchange rule reported a hybrid target as `pure`.
    """
    return _is_hybrid(algorithm, hybrid_group, mode)


def _hybrid_severity(
    regime: Regime,
    *,
    certified: bool,
    product_class: ProductClass | None,
) -> Severity:
    """How hard the hybrid requirement bites, given who is asking and about what.

    Three inputs, checked most-specific first. The platform carve-out is narrower than the
    certified mandate, so it has to be tested before it — the other order makes it dead code.
    """
    if not certified:
        return regime.hybrid_severity
    if product_class == "intermediate" and regime.intermediate_product_severity is not None:
        return regime.intermediate_product_severity
    return regime.hybrid_severity_certified or regime.hybrid_severity


def check_target(
    regime: Regime,
    regime_name: str,
    algorithm: str,
    parameter_set: str | None = None,
    hybrid_group: str | None = None,
    mode: str | None = None,
    *,
    certified: bool = False,
    product_class: ProductClass | None = None,
) -> list[PolicyConflict]:
    """Every objection `regime` has to this target, in reporting order.

    A list, never a raise: one target can satisfy one regime and violate another, and both belong
    in the record. Returning early on the first objection would make a multi-regime report a
    report about whichever regime happened to be checked first.
    """
    conflicts: list[PolicyConflict] = []
    hybrid = _is_hybrid(algorithm, hybrid_group, mode)
    subject = hybrid_group or parameter_set or algorithm

    # 1. Excluded algorithms. Checked first because an excluded algorithm's grade is irrelevant,
    #    and reporting "ML-KEM-512 is below grade" for an algorithm the regime does not accept at
    #    ANY grade sends the reader to fix the wrong thing.
    family = family_of(algorithm) or algorithm
    for banned in regime.excluded:
        if banned.upper() in (family.upper(), algorithm.upper()):
            conflicts.append(
                PolicyConflict(
                    regime=regime_name,
                    severity="violation",
                    rule="excluded-algorithm",
                    detail=(
                        f"{regime.authority or regime_name} does not approve {banned} at any "
                        f"parameter set"
                        + (
                            " — note this exclusion stands DESPITE FIPS 205 approval"
                            if banned.upper() == "SLH-DSA"
                            else ""
                        )
                    ),
                )
            )

    if conflicts:
        # Stop here. Everything below asks "is this target good enough", which presumes the regime
        # would accept it at SOME setting — and it will not. Reporting "ML-KEM-512 is below grade"
        # for an algorithm banned outright sends the reader to raise a parameter that was never
        # the problem, and reporting "hybrid required" for it invites them to build a hybrid out
        # of something the regime does not approve.
        return conflicts

    # 2. Grade minimum. This is the rule the "hybrid vs pure" framing hides: CNSA 2.0's objection
    #    to X25519MLKEM768 lands HERE, not on the construction.
    minimum = regime.minimum_grade.get(family or "")
    grade = grade_of(subject)
    if minimum is not None and grade is not None and grade < minimum:
        # One rule id for one rule. `cnsa2-hybrid-sub-1024` is the id in CNSA 2.0's OWN reference
        # implementation, and attaching it to ASD-ISM's objection — which is a different authority
        # citing a different document — misattributes the finding to a framework that did not
        # raise it. The regime's own `hybrid_rule` reference is appended to the detail instead.
        conflicts.append(
            PolicyConflict(
                regime=regime_name,
                severity="violation",
                rule="below-minimum-grade",
                detail=(
                    f"{subject} has a {family} grade of {grade}; {regime_name} requires at least "
                    f"{minimum}"
                    + (
                        f". The objection is to the {grade}, NOT to the hybrid construction — "
                        f"{subject} would be acceptable with a {minimum}-grade component"
                        if hybrid
                        else ""
                    )
                    + (f" [{regime.hybrid_rule.strip()}]" if hybrid and regime.hybrid_rule else "")
                ),
            )
        )

    # 3. Construction. ANSSI and BSI impose the same requirement at different strengths, which is
    #    why severity is a property of the regime rather than of the rule.
    # A family the regime exempts is not subject to its hybrid requirement at all.
    exempt = any(
        (family or algorithm).upper().startswith(e.upper()) for e in regime.standalone_exempt
    )
    if regime.requires_hybrid and not hybrid and not exempt:
        severity = _hybrid_severity(regime, certified=certified, product_class=product_class)
        # The platform carve-out is CONDITIONAL, and the conditions travel with it.
        carve_out = (
            certified
            and product_class == "intermediate"
            and regime.intermediate_product_severity is not None
        )
        conflicts.append(
            PolicyConflict(
                regime=regime_name,
                severity=severity,
                # Named for what the regime actually does. BSI's §2.2 says `empfiehlt`
                # (recommends); ANSSI's Phase 2 says `shall` for certified products. Calling both
                # "required" misreports the German guideline as stricter than it is, which is the
                # same class of error as calling a criterion "verified" when it could not fail.
                rule=("hybrid-required" if severity == "violation" else "hybrid-recommended"),
                detail=(
                    f"{regime_name} "
                    f"{'requires' if severity == 'violation' else 'recommends'} a hybrid "
                    f"construction during the transition; {subject} is a standalone PQC target"
                    + (
                        " — permitted here only as a platform product whose caller hybridises,"
                        " and only against: " + "; ".join(regime.intermediate_product_conditions)
                        if carve_out and regime.intermediate_product_conditions
                        else ""
                    )
                ),
            )
        )
    # Permitted, but not what the regime would choose. Emitted last and non-blocking, so it never
    # changes a verdict — it only tells the operator that a compliant target is still not the
    # recommended architecture.
    if (
        not conflicts
        and regime.preferred_construction
        and regime.preferred_construction == "pure"
        and hybrid
    ):
        conflicts.append(
            PolicyConflict(
                regime=regime_name,
                severity="notice",
                rule="construction-not-preferred",
                detail=(
                    f"{subject} is permitted by {regime_name} at this grade, but the regime "
                    f"prefers a pure post-quantum target and tolerates a hybrid only as a "
                    f"temporary bridge (protocol standardisation, product availability, "
                    f"interoperability)"
                ),
            )
        )
    return conflicts


def resolve_all_regimes(
    algorithm: str,
    parameter_set: str | None = None,
    hybrid_group: str | None = None,
    mode: str | None = None,
    catalog: RegimeCatalog | None = None,
    *,
    certified: bool = False,
    product_class: ProductClass | None = None,
) -> dict[str, list[PolicyConflict]]:
    """What EVERY regime thinks of this target, keyed by regime name.

    The comparison is the point. A single-regime answer hides that the industry-default hybrid is
    simultaneously required by BSI and rejected by CNSA 2.0, which is the most useful thing this
    engine can tell an operator and the thing no surveyed tool reports.
    """
    cat = catalog or load_regimes()
    return {
        name: check_target(
            regime,
            name,
            algorithm,
            parameter_set,
            hybrid_group,
            mode,
            certified=certified,
            product_class=product_class,
        )
        for name, regime in cat.regimes.items()
    }


__all__ = [
    "Construction",
    "PolicyConflict",
    "Preference",
    "Regime",
    "RegimeCatalog",
    "RegimeTarget",
    "Severity",
    "check_target",
    "family_of",
    "grade_of",
    "hybrid_components",
    "is_hybrid",
    "load_regimes",
    "resolve_all_regimes",
]
