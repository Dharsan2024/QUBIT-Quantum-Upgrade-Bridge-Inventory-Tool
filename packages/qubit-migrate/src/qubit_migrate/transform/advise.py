"""Migration advice for a finding no patch can be produced for.

A queue entry that says "manual change" and nothing else is a dead end. It names an algorithm and a
line number and leaves the reader to work out what the code is doing, why that is a problem, what it
should become, and what breaks on the way. For the findings QUBIT cannot patch — a structural
protocol change, a language with no codemod, a dialect the token swap cannot express — that gap is
where the work actually stops.

This asks the local model for the missing half: read *this* file, and explain how to migrate *this*
finding.

Deliberately not a template. There is no per-algorithm text to fill in and no canned paragraph
keyed off the rule id: the advice is generated from the real file, the real finding, the real
surrounding code and — when a patch was attempted — the real reason it was rejected. Two RSA
findings in different files get different advice, because the code around them differs.

What the rules DO contribute is fact, not prose: the target algorithm, the parameter set, the
data-compatibility class and the library floor are constants QUBIT is authoritative about, so they
are stated to the model rather than left for it to guess. The model's job is to apply them to the
code in front of it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .languages import language_for_suffix
from .llm import DEFAULT_BASE_URL, OllamaError, _ollama_generate

if TYPE_CHECKING:
    from qubit_core import CryptoAsset

    from .rules import MigrationRule

#: How much of the file to show. The finding's own neighbourhood is what makes the advice specific;
#: a whole 2 000-line file mostly costs context the 7B model spends badly.
_CONTEXT_LINES = 40

_SECTIONS = (
    "WHAT THIS CODE DOES",
    "WHY IT IS A PROBLEM",
    "WHAT TO CHANGE",
    "WHAT THIS BREAKS",
    "HOW TO VERIFY",
)


def _excerpt(source: str, line: int | None) -> tuple[str, int]:
    """The finding's neighbourhood, and the line number the excerpt starts at."""
    lines = source.splitlines()
    if not lines:
        return "", 1
    if line is None or line < 1:
        return "\n".join(lines[:_CONTEXT_LINES]), 1
    half = _CONTEXT_LINES // 2
    start = max(0, line - 1 - half)
    end = min(len(lines), start + _CONTEXT_LINES)
    return "\n".join(lines[start:end]), start + 1


def _kb_facts(asset: CryptoAsset) -> str | None:
    """The knowledge base's target for this finding, when no rule covers it.

    `params/migration_kb.yaml` is the project's single source of truth for
    vulnerable-family + usage-context -> PQC target, and the advice path was not consulting it. A
    finding with no *codemod* rule still has a known target; without this the model was asked to
    invent one, and for a shell script generating an RSA key it answered "use RSA-2048 or
    ECDSA-P256" — both Shor-breakable, and the exact opposite of the point.
    """
    from ..kb import lookup_kb

    family = asset.algorithm.split("-")[0]
    entry = lookup_kb(family, asset.usage_context.value)
    if entry is None:
        return None
    target = entry.target
    facts = [f"- Target algorithm: {target.algorithm}"]
    if target.mode:
        facts.append(f"- Mode: {target.mode}")
    if getattr(target, "parameter_set", None):
        facts.append(f"- Parameter set: {target.parameter_set}")
    if getattr(target, "hybrid_group", None):
        facts.append(f"- Hybrid group: {target.hybrid_group}")
    if getattr(target, "fips", None):
        facts.append(f"- Standard: {target.fips}")
    if entry.guidance:
        facts.append(f"- Knowledge-base guidance: {' '.join(entry.guidance.split())}")
    return "\n".join(facts)


def _known_facts(rule: MigrationRule | None, asset: CryptoAsset | None = None) -> str:
    """The things QUBIT is authoritative about, stated rather than left to the model.

    A local 7B model will invent a plausible parameter set or library version if it has to. These
    come from the rule pack and the migration knowledge base, which is where the verified values
    live, so the model is applying facts instead of recalling them.
    """
    if rule is None:
        kb = _kb_facts(asset) if asset is not None else None
        if kb:
            return kb
        return (
            "QUBIT has no migration rule or knowledge-base entry for this finding. Recommend a "
            "target from the NIST post-quantum standards (FIPS-203 ML-KEM, FIPS-204 ML-DSA, "
            "FIPS-205 SLH-DSA) or a quantum-resistant symmetric/hash algorithm, and say why it "
            "fits this usage. Do NOT recommend RSA, DSA, DH, ECDH or ECDSA at any key size: they "
            "are all broken by Shor's algorithm, so a larger key is not a migration."
        )
    target = rule.target or {}
    facts: list[str] = []
    if target.get("algorithm"):
        facts.append(f"- Target algorithm: {target['algorithm']}")
    if target.get("mode"):
        facts.append(f"- Mode: {target['mode']}")
    if target.get("parameter_set"):
        facts.append(f"- Parameter set: {target['parameter_set']}")
    if target.get("hybrid_group"):
        facts.append(f"- Hybrid group: {target['hybrid_group']}")
    if target.get("fips"):
        facts.append(f"- Standard: {target['fips']}")
    library = getattr(rule, "target", {}).get("library") or {}
    if isinstance(library, dict) and library.get("name"):
        floor = f" >= {library['min_version']}" if library.get("min_version") else ""
        facts.append(f"- Library that provides it: {library['name']}{floor}")
    if rule.data_compat:
        facts.append(f"- Data-compatibility class: {rule.data_compat}")
    if rule.semantic_note:
        facts.append(f"- Rule guidance: {' '.join(rule.semantic_note.split())}")
    return "\n".join(facts) or "(no target recorded on the rule)"


def _exposure_phrase(asset: CryptoAsset) -> str:
    """Shor breaks a public-key algorithm outright; Grover halves a symmetric one's margin.

    Spelled out because "shor" and "grover" mean nothing to a reader who is not already in this
    field, and the advice is written for the engineer who owns the file, not for a cryptographer.
    """
    return (
        "breaks the algorithm outright"
        if asset.quantum_vulnerable.attack.value == "shor"
        else "halves its effective strength"
    )


def build_advice_prompt(
    source: str,
    asset: CryptoAsset,
    rule: MigrationRule | None,
    *,
    failure_reason: str | None = None,
) -> str:
    """The prompt. Separated from the call so a test can assert on it without a model."""
    path = asset.location.file_path if asset.location else None
    line = asset.location.line if asset.location else None
    language = language_for_suffix(path) or "unknown"
    excerpt, first_line = _excerpt(source, line)

    why_no_patch = (
        "An automated patch was attempted and rejected. The exact reason was:\n"
        f"  {failure_reason}\n"
        "Take that into account: explain what a person has to do that the automated attempt could "
        "not.\n\n"
        if failure_reason
        else "QUBIT cannot patch this automatically, so a person has to make the change.\n\n"
    )

    return (
        "You are a post-quantum cryptography migration engineer. A scanner has flagged one finding "
        "in a real codebase. Explain how to migrate it.\n\n"
        "Write for the engineer who owns this file. Be concrete and specific to the code shown — "
        "refer to the actual functions, variables and call sites in front of you, not to generic "
        "examples. Do not output a patch or a diff; explain the change.\n\n"
        f"FINDING\n"
        f"- Algorithm: {asset.algorithm}"
        f"{f' ({asset.key_size}-bit)' if asset.key_size else ''}\n"
        f"- Used for: {asset.usage_context.value}\n"
        f"- Quantum exposure: {asset.quantum_vulnerable.attack.value} "
        f"({_exposure_phrase(asset)})\n"
        f"- File: {path or 'unknown'} (line {line or '?'}, {language})\n"
        f"- Data sensitivity: {asset.sensitivity.value}\n\n"
        f"WHAT QUBIT KNOWS ABOUT THE TARGET\n{_known_facts(rule, asset)}\n\n"
        f"{why_no_patch}"
        f"THE CODE (from line {first_line})\n```{language}\n{excerpt}\n```\n\n"
        "Answer under exactly these five headings, in this order, with no preamble:\n"
        + "\n".join(f"{name}" for name in _SECTIONS)
        + "\n\nKeep each section to a few sentences. Under WHAT TO CHANGE give concrete steps for "
        "this file. Under WHAT THIS BREAKS say what happens to data already encrypted, hashed or "
        "signed with the old algorithm, and to anything on the other side of the wire. Under HOW "
        "TO VERIFY say what to re-scan or test to prove the finding is gone."
    )


#: Words that read as an algorithm name in prose. Resolved through the canonical registry rather
#: than matched against a list, so the check knows exactly what the scanner knows.
_ALGO_TOKEN_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*\b")


def _recommended_vulnerable_algorithms(advice: str, current: str | None = None) -> list[str]:
    """Algorithms the advice recommends that the registry itself rates quantum-vulnerable.

    Only the WHAT TO CHANGE section is examined: the earlier sections legitimately name the broken
    algorithm, because describing it is their job.

    `current` is the algorithm being migrated, and two spellings of it are excluded — the exact
    name and its bare family — because "Replace RSA-1024…" and "the RSA key" are both the *old*
    thing, not a recommendation. A DIFFERENT member of the same family is not excluded: recommending
    RSA-2048 in place of RSA-1024 is precisely the failure this exists to catch, since it answers
    "this key is short" rather than "this key is quantum-vulnerable".

    The registry is the same one the scanner uses to decide a finding is vulnerable at all, so
    advice that recommends a vulnerable target contradicts the finding that produced it — and a
    contradiction is something to catch rather than ship.
    """
    from qubit_core.algorithms import resolve

    match = re.search(
        r"^\W*WHAT TO CHANGE\b(.*?)(?=^\W*WHAT THIS BREAKS\b|\Z)",
        advice,
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    if match is None:
        return []
    section = match.group(1)

    allowed = set()
    if current:
        allowed.add(current.upper())
        allowed.add(current.split("-")[0].upper())

    bad: list[str] = []
    for token in _ALGO_TOKEN_RE.findall(section):
        if token.upper() in allowed:
            continue
        spec = resolve(token)
        # The registry field is `vulnerable`. Reading a name that does not exist here would
        # have made the guard flag ML-KEM-768 as broken, which is the opposite of its job.
        if spec is None or not spec.vulnerable:
            continue
        if token.upper() not in {b.upper() for b in bad}:
            bad.append(token)
    return bad


def _looks_complete(text: str) -> bool:
    """Did the model answer under the headings it was given?

    A local model sometimes returns two sections and stops. Checking is cheap and the repair loop
    can re-ask, which is better than storing half an answer as though it were guidance.
    """
    found = sum(1 for name in _SECTIONS if re.search(rf"^\W*{name}\b", text, re.MULTILINE | re.I))
    return found >= 4


def generate_migration_advice(
    source: str,
    asset: CryptoAsset,
    rule: MigrationRule | None,
    *,
    model: str,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = 180.0,
    failure_reason: str | None = None,
    max_attempts: int = 3,
) -> str:
    """Ask the local model how to migrate this specific finding by hand.

    Raises :class:`OllamaError` if no usable answer comes back, so the caller can report that
    instead of storing an empty or truncated one.
    """
    prompt = build_advice_prompt(source, asset, rule, failure_reason=failure_reason)
    last = ""
    prompt_suffix = ""
    for _attempt in range(max(1, max_attempts)):
        text = _ollama_generate(
            prompt + prompt_suffix, model=model, base_url=base_url, timeout=timeout
        ).strip()
        # Strip a wrapping code fence if the model added one despite being asked for prose.
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z0-9_+-]*\n", "", text)
            text = re.sub(r"\n```\s*$", "", text)
        if not _looks_complete(text):
            last = text
            prompt_suffix = (
                "\n\nYour previous answer was incomplete. Answer under ALL five headings."
            )
            continue
        vulnerable = _recommended_vulnerable_algorithms(text, asset.algorithm)
        if vulnerable:
            # The failure that made this check necessary: asked about a 1024-bit RSA key, the model
            # recommended RSA-2048 and ECDSA-P256. Both are Shor-breakable, so the advice answers
            # "this key is short" instead of "this key is quantum-vulnerable".
            last = text
            prompt_suffix = (
                "\n\nYour previous answer recommended "
                + ", ".join(vulnerable)
                + ". Every one of those is broken by Shor's algorithm — a larger key is not a "
                "post-quantum migration. Recommend a NIST post-quantum algorithm instead and "
                "rewrite WHAT TO CHANGE."
            )
            continue
        return text
    raise OllamaError(
        "the model did not produce usable advice"
        + (f" (last answer was {len(last.splitlines())} lines)" if last else "")
    )


def advice_context(asset: CryptoAsset, rule: Any | None) -> dict[str, Any]:
    """The non-prose facts, returned alongside the advice so the UI can show them as data."""
    target = (getattr(rule, "target", None) or {}) if rule else {}
    return {
        "algorithm": asset.algorithm,
        "key_size": asset.key_size,
        "usage_context": asset.usage_context.value,
        "attack": asset.quantum_vulnerable.attack.value,
        "target_algorithm": target.get("algorithm"),
        "parameter_set": target.get("parameter_set"),
        "data_compat": getattr(rule, "data_compat", None) if rule else None,
        "rule_id": getattr(rule, "id", None) if rule else None,
    }


__all__ = [
    "advice_context",
    "build_advice_prompt",
    "generate_migration_advice",
    "recommended_vulnerable_algorithms",
]

#: Public alias — the guard is worth testing directly.
recommended_vulnerable_algorithms = _recommended_vulnerable_algorithms
