"""A concrete remediation path for every finding, built without a model.

`advise.py` asks the local LLM to explain a finding in its own file, and that is the better answer
when it works. This is what has to exist underneath it, for three reasons measured on real runs:

* **Ollama is optional.** `advise_task` raised `could not generate advice` when the server was
  down, so the app's answer to "what do I do about this?" depended on a service the user may not
  be running. A migration tool that shrugs when a side-car is missing is a migration tool nobody
  trusts.
* **Some findings have no file to reason about.** A certificate cannot be rewritten; a `.pem` is a
  signed object and editing the bytes invalidates the CA signature. Handing that to a code model
  produces confident nonsense.
* **Facts should not be generated.** The provider, its version floor, its adoption number, the
  size of an ML-DSA-65 signature and the CNSA 2.0 deadline are all things QUBIT knows exactly.
  Asking a 7B model to recall them is how an earlier version of this project recommended
  "RSA-2048 or ECDSA-P256" as the fix for an RSA finding.

So the plan is assembled from the rule pack, the migration knowledge base, the weakness catalogue
and the verified provider playbook - all shipped data, all offline. The model's contribution, when
it is available, is the part it is actually good at: applying those facts to this file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..kb import lookup_impact, lookup_kb
from ..playbook import Playbook, Provider, load_playbook

if TYPE_CHECKING:
    from qubit_core import CryptoAsset

    from .rules import MigrationRule


@dataclass(frozen=True)
class GuidedStep:
    title: str
    detail: str = ""
    #: A copy-pasteable command or code sketch. Rendered as a fenced block.
    command: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"title": self.title, "detail": self.detail, "command": self.command}


@dataclass
class GuidedPlan:
    """What to do about one finding, in the order to do it."""

    headline: str
    why: str
    target: str
    steps: list[GuidedStep] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    #: Stated when full automation is genuinely impossible, with the reason. Never omitted to make
    #: the plan look stronger than it is.
    honest_note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "why": self.why,
            "target": self.target,
            "steps": [s.as_dict() for s in self.steps],
            "sources": self.sources,
            "honest_note": self.honest_note,
        }

    def to_markdown(self) -> str:
        out: list[str] = [f"## {self.headline}", ""]
        if self.why:
            out += [self.why, ""]
        if self.target:
            out += [f"**Target:** {self.target}", ""]
        if self.honest_note:
            out += [f"> {self.honest_note}", ""]
        if self.steps:
            out += ["### Steps", ""]
            for i, step in enumerate(self.steps, 1):
                out.append(f"{i}. **{step.title}**")
                if step.detail:
                    out.append(f"   {step.detail}")
                if step.command:
                    out += [
                        "",
                        "   ```",
                        *[f"   {ln}" for ln in step.command.strip().splitlines()],
                        "   ```",
                    ]
                out.append("")
        if self.sources:
            out += ["### Sources", ""]
            out += [f"- {s}" for s in self.sources]
            out.append("")
        return "\n".join(out).rstrip() + "\n"


# --- the pieces a plan is assembled from -----------------------------------------------------


#: Target families that require a post-quantum implementation the ecosystem may not have. A target
#: outside this set - SHA-256, SHA3-256, AES-256-GCM, Argon2id - is available in every mainstream
#: standard library, so no provider question arises and none should be raised.
_PQC_TARGET_PREFIXES = ("ML-KEM", "ML-DSA", "SLH-DSA", "X25519MLKEM768", "FN-DSA", "sntrup761")


def _needs_pqc_provider(target: str) -> bool:
    return any(prefix.lower() in target.lower() for prefix in _PQC_TARGET_PREFIXES)


def _where(asset: CryptoAsset) -> str:
    loc = asset.location
    if loc is None or not loc.file_path:
        return ""
    name = Path(loc.file_path).name
    return f"{name}:{loc.line}" if loc.line else name


def _headline(asset: CryptoAsset) -> str:
    bits = [asset.algorithm]
    if asset.key_size:
        bits.append(f"{asset.key_size}-bit")
    place = _where(asset)
    where = f" in {place}" if place else ""
    return f"{' '.join(bits)} used for {asset.usage_context.value}{where}"


def _weaknesses(asset: CryptoAsset) -> list[dict[str, Any]]:
    """The classical weaknesses the scanner recorded on this finding, if any."""
    if asset.evidence is None or asset.evidence.context is None:
        return []
    raw = asset.evidence.context.extra.get("weaknesses")
    return [w for w in raw if isinstance(w, dict)] if isinstance(raw, list) else []


def _why(asset: CryptoAsset, found: list[dict[str, Any]]) -> str:
    """Why this finding matters, in the terms that actually apply to it."""
    parts: list[str] = []
    attack = getattr(asset.quantum_vulnerable, "attack", None)
    attack_value = getattr(attack, "value", attack)
    if attack_value == "shor":
        parts.append(
            f"{asset.algorithm} is broken outright by Shor's algorithm - a larger key is not a "
            "migration. NIST IR 8547 deprecates RSA, ECDSA, ECDH and finite-field DH after 2030 "
            "and disallows them after 2035."
        )
        if asset.usage_context.value in {"kex", "tls"}:
            parts.append(
                "Because this is key exchange, the exposure is immediate rather than future: "
                "traffic recorded today becomes readable the day the key exchange breaks "
                "(harvest-now-decrypt-later)."
            )
    elif attack_value == "grover":
        parts.append(
            f"{asset.algorithm} is below the bar this project holds: either it is already broken "
            "classically, or Grover's algorithm halves its effective strength to under 128 bits."
        )
    for w in found:
        parts.append(f"{w.get('title', '')} ({w.get('cwe', '')}). {w.get('remedy', '')}".strip())
    return " ".join(p for p in parts if p)


def _target_text(rule: MigrationRule | None, asset: CryptoAsset) -> str:
    """The target QUBIT is authoritative about, from the rule or the knowledge base."""
    target: dict[str, Any] | None = dict(rule.target) if rule and rule.target else None
    if target is None:
        entry = lookup_kb(asset.algorithm.split("-")[0], asset.usage_context.value)
        if entry is not None:
            target = entry.target.model_dump()
    if not target:
        return ""
    bits = [str(target.get("algorithm", ""))]
    if target.get("parameter_set") and target["parameter_set"] != target.get("algorithm"):
        bits.append(f"({target['parameter_set']})")
    if target.get("hybrid_group"):
        bits.append(f"- hybrid group {target['hybrid_group']}")
    if target.get("fips"):
        bits.append(f"[{target['fips']}]")
    return " ".join(b for b in bits if b)


def _impact_step(rule: MigrationRule | None, asset: CryptoAsset) -> GuidedStep | None:
    """What the migration does to sizes and stored formats - the part the flagged line hides."""
    algorithm = ""
    if rule and rule.target:
        algorithm = str(rule.target.get("algorithm", ""))
    if not algorithm:
        entry = lookup_kb(asset.algorithm.split("-")[0], asset.usage_context.value)
        algorithm = entry.target.algorithm if entry else ""
    impact = lookup_impact(algorithm) if algorithm else None
    if impact is None:
        return None
    lines: list[str] = []
    if impact.sizes:
        sizes = ", ".join(f"{k} {v:,} bytes" for k, v in impact.sizes.items())
        lines.append(f"{algorithm} artefact sizes: {sizes}.")
    for classical, note in (impact.replaces or {}).items():
        lines.append(f"Replaces {classical}: {note}.")
    for breakage in getattr(impact, "breaks", None) or []:
        lines.append(str(breakage))
    if not lines:
        return None
    return GuidedStep(
        title="Size the change before you write it",
        detail=" ".join(lines),
    )


def _provider_step(provider: Provider, *, for_manifest: str | None = None) -> GuidedStep:
    detail = [
        f"{provider.package} {provider.constraint} provides "
        f"{', '.join(provider.provides) or 'the target primitives'}.",
        provider.citation() + ".",
    ]
    if provider.license:
        detail.append(f"Licensed {provider.license}.")
    if provider.caveat:
        detail.append(provider.caveat)
    if provider.note:
        detail.append(provider.note)
    if provider.alternative:
        detail.append(provider.alternative)
    title = (
        f"Make the primitives available in {Path(for_manifest).name}"
        if for_manifest
        else "Make the primitives available"
    )
    return GuidedStep(
        title=title,
        detail=" ".join(d for d in detail if d),
        command=provider.install or "",
    )


def _usage_step(provider: Provider) -> GuidedStep | None:
    if not provider.usage:
        return None
    return GuidedStep(
        title=f"Call it the way {provider.package} expects",
        detail="The shape of the replacement, from the library's own documented API.",
        command=provider.usage,
    )


def _constraint_steps(rule: MigrationRule | None) -> list[GuidedStep]:
    """The rule's own engineering constraints, which are the substance of a correct fix.

    These are not decoration: `code-weakcipher-01` says the key length changes, the nonce must be
    fresh per message, the tag has to be stored, and the old decrypt path has to survive the
    re-encryption window. A guided path that omits them is the "swap one line" advice this tool
    exists to be better than.

    Skipped for `remediation: guided` rules, whose constraints are written for the MODEL rather
    than for a person — "Never propose adding a post-quantum package as the fix for a broken
    hash" is an instruction to a generator, and rendering it as a step told the reader not to do
    something they were never going to do. Observed in the running app on `dep-legacy-01`.
    """
    if rule is None or not rule.prompt_constraints or rule.remediation == "guided":
        return []
    return [
        GuidedStep(
            title="Get the details right",
            detail=" ".join(f"({i}) {c}" for i, c in enumerate(rule.prompt_constraints, 1)),
        )
    ]


def _compat_step(rule: MigrationRule | None) -> GuidedStep | None:
    """What happens to data already written under the old algorithm."""
    if rule is None:
        return None
    if rule.data_compat == "reencrypt_required":
        return GuidedStep(
            title="Plan for the data already encrypted",
            detail=(
                "Existing ciphertext cannot be read by the new algorithm or key length. Keep the "
                "old decrypt path alongside the new encrypt path, re-encrypt records as they are "
                "touched, and only remove the legacy reader once nothing decrypts with it."
            ),
        )
    if rule.data_compat == "dual_read":
        return GuidedStep(
            title="Read both formats during the transition",
            detail=(
                "Verify against the old and the new format while stored values are mixed, and "
                "write only the new one. Drop the old reader when no stored value still uses it."
            ),
        )
    return None


def _change_step(rule: MigrationRule | None, asset: CryptoAsset) -> GuidedStep | None:
    """What the change itself is, in QUBIT's own words rather than the model's.

    A rule's `semantic_note` is the substance of the migration - what changes, what it costs and
    what stops working. The knowledge base carries the same for findings no rule covers. Without
    this a guided path for a finding needing no new library was one step long: "confirm it".
    """
    note = (rule.semantic_note or "").strip() if rule is not None else ""
    if not note:
        entry = lookup_kb(asset.algorithm.split("-")[0], asset.usage_context.value)
        note = (entry.guidance or "").strip() if entry is not None else ""
    if not note:
        return None
    return GuidedStep(title="Make the change", detail=" ".join(note.split()))


def _dependency_step(asset: CryptoAsset, path: str) -> GuidedStep:
    """A manifest finding says a DECLARED library offers this algorithm, not that it is called.

    The dependency scanner reads manifests, so the location is `pubspec.yaml`, not the line that
    uses MD5. Saying "edit pubspec.yaml" would be wrong; the manifest is evidence of capability
    and the remediation is at the call sites, or in dropping the package.
    """
    library = asset.library.name if asset.library else "this dependency"
    return GuidedStep(
        title=f"Locate where {asset.algorithm} is actually used",
        detail=(
            f"{Path(path).name} declares {library}, which provides {asset.algorithm}. The manifest "
            "records the capability, not a call - so the fix is at the call sites that use it, or "
            "in removing the dependency if nothing does. Scan results for this project list those "
            "call sites as their own findings."
        ),
    )


def _verify_step(rule: MigrationRule | None, asset: CryptoAsset) -> GuidedStep:
    expect = getattr(rule, "rescan_expect", None) if rule else None
    detail = (
        f"Re-scan this project. The finding is resolved when {asset.algorithm} is no longer "
        "detected at this location"
    )
    if isinstance(expect, dict) and expect.get("present"):
        present = expect["present"]
        present = ", ".join(present) if isinstance(present, list) else str(present)
        detail += f" and {present} is detected in its place"
    return GuidedStep(title="Confirm it", detail=detail + ".")


def _default_source_keys(target: str) -> list[str]:
    """The authorities that actually back THIS target.

    Citing FIPS 203 and 204 under an MD5-to-SHA3 recommendation is noise at best: the reader
    checks the source, finds it says nothing about hashes, and trusts the next citation less.
    """
    lowered = target.lower()
    keys: list[str] = []
    if "ml-kem" in lowered or "mlkem" in lowered:
        keys.append("fips_203")
    if "ml-dsa" in lowered or "mldsa" in lowered:
        keys.append("fips_204")
    if "slh-dsa" in lowered:
        keys.append("fips_205")
    return keys


def _sources(
    playbook: Playbook, asset: CryptoAsset, found: list[dict[str, Any]], keys: list[str]
) -> list[str]:
    out: list[str] = []
    for key in keys:
        text = playbook.authorities.get(key)
        if text and text not in out:
            out.append(text)
    for w in found:
        authority = str(w.get("authority", "")).strip()
        if authority and authority not in out:
            out.append(authority)
    return out


# --- assembly ---------------------------------------------------------------------------------


def build_guided_plan(
    asset: CryptoAsset,
    rule: MigrationRule | None,
    *,
    failure_reason: str | None = None,
    playbook: Playbook | None = None,
) -> GuidedPlan:
    """A concrete, sourced remediation path for ``asset``. Never raises, never returns nothing."""
    pb = playbook or load_playbook()
    found = _weaknesses(asset)
    plan = GuidedPlan(
        headline=_headline(asset),
        why=_why(asset, found),
        target=_target_text(rule, asset),
    )
    source_keys: list[str] = []
    attack_value = getattr(getattr(asset.quantum_vulnerable, "attack", None), "value", None)
    if attack_value == "shor":
        source_keys += ["ir_8547", "cnsa_2"]

    path = asset.location.file_path if asset.location else None
    scanner = asset.source_scanner.value

    if failure_reason:
        plan.steps.append(
            GuidedStep(
                title="What the automated attempt could not do",
                detail=failure_reason,
            )
        )

    # --- certificates: a signed object, so the remediation is re-issuance, not an edit ---
    if scanner == "cert":
        procedure = pb.procedures.get("x509_certificate")
        if procedure is not None:
            plan.honest_note = procedure.honest_note
            plan.steps += [
                GuidedStep(title=s.title, detail=s.detail, command=s.command)
                for s in procedure.steps
            ]
            plan.sources = _sources(pb, asset, found, [*source_keys, "fips_204", "openssl_35"])
            return plan

    # --- hardcoded secrets: rotation at the issuer, not a text edit ---
    if asset.asset_type.value == "secret":
        procedure = pb.procedures.get("secret_rotation")
        if procedure is not None:
            plan.honest_note = procedure.honest_note
            plan.steps += [
                GuidedStep(title=s.title, detail=s.detail, command=s.command)
                for s in procedure.steps
            ]
            plan.sources = _sources(pb, asset, found, source_keys)
            return plan

    # --- manifests: either a verified provider, or an honest statement that there is none ---
    #
    # Gated on whether the TARGET actually needs a post-quantum provider. Without this, an MD5
    # finding in a `pubspec.yaml` was answered with Dart's missing-ML-KEM-provider notice - three
    # options about FFI and platform crypto, for a digest that migrates to SHA3-256 using
    # facilities the language has shipped for years. Naming a blocker that does not apply is its
    # own kind of dead end.
    if path and scanner == "config" and _needs_pqc_provider(plan.target):
        blocked = pb.unavailable_for_manifest(path)
        provider = pb.provider_for_manifest(path)
        if blocked is not None:
            plan.honest_note = blocked.reason
            plan.steps += [
                GuidedStep(title=f"Option {i}", detail=option)
                for i, option in enumerate(blocked.options, 1)
            ]
            plan.steps.append(_verify_step(rule, asset))
            plan.sources = _sources(pb, asset, found, source_keys) + list(blocked.sources)
            return plan
        if provider is not None:
            # A JOSE finding in package.json needs the JOSE library, not the raw KEM package.
            if asset.usage_context.value == "token" and "jose" in pb.providers:
                provider = pb.providers["jose"]
                source_keys.append("rfc_9964")
            plan.steps.append(_provider_step(provider, for_manifest=path))
            usage = _usage_step(provider)
            if usage is not None:
                plan.steps.append(usage)
            plan.steps.append(_verify_step(rule, asset))
            plan.sources = _sources(
                pb, asset, found, source_keys + _default_source_keys(plan.target)
            )
            return plan

    # A manifest finding whose target needs no new provider still deserves a real answer: say
    # what the manifest actually proves and where the fix lives.
    manifest_step_added = False
    if path and scanner == "config" and not _needs_pqc_provider(plan.target):
        plan.steps.append(_dependency_step(asset, path))
        manifest_step_added = True

    # --- code: install the provider, then make the change the rule describes ---
    if _needs_pqc_provider(plan.target):
        language_provider = _provider_for_source_file(pb, path, asset)
        if language_provider is not None:
            plan.steps.append(_provider_step(language_provider))
            usage = _usage_step(language_provider)
            if usage is not None:
                plan.steps.append(usage)
        elif path and Path(path).suffix.lower() == ".dart":
            blocked = pb.unavailable.get("dart")
            if blocked is not None:
                plan.honest_note = blocked.reason
                plan.steps += [
                    GuidedStep(title=f"Option {i}", detail=option)
                    for i, option in enumerate(blocked.options, 1)
                ]
                plan.sources += list(blocked.sources)
        elif path and Path(path).suffix.lower() == ".py" and asset.usage_context.value == "token":
            blocked = pb.unavailable.get("python_jose")
            if blocked is not None:
                plan.honest_note = blocked.reason
                plan.steps += [
                    GuidedStep(title=f"Option {i}", detail=option)
                    for i, option in enumerate(blocked.options, 1)
                ]
                plan.sources += list(blocked.sources)

    # `_dependency_step` already explains a manifest finding in the terms that apply to it, and
    # `dep-legacy-01`'s semantic_note says the same thing at greater length — so a plan for one
    # ended up with two steps making the same point back to back. Observed in the running app.
    if not manifest_step_added:
        change = _change_step(rule, asset)
        if change is not None:
            plan.steps.append(change)
    for weakness in found:
        plan.steps.append(
            GuidedStep(
                title=str(weakness.get("title", "Fix the weakness")),
                detail=str(weakness.get("remedy", "")),
            )
        )
    plan.steps += _constraint_steps(rule)
    impact = _impact_step(rule, asset)
    if impact is not None:
        plan.steps.append(impact)
    compat = _compat_step(rule)
    if compat is not None:
        plan.steps.append(compat)
    plan.steps.append(_verify_step(rule, asset))
    plan.sources = (
        _sources(pb, asset, found, source_keys + _default_source_keys(plan.target)) + plan.sources
    )
    return plan


#: Source-file suffix -> the playbook provider whose ecosystem owns it.
_SUFFIX_PROVIDER: dict[str, str] = {
    ".js": "npm",
    ".mjs": "npm",
    ".cjs": "npm",
    ".ts": "npm",
    ".tsx": "npm",
    ".rs": "cargo",
    ".php": "composer",
    ".py": "pip",
    ".java": "maven",
    ".kt": "maven",
    ".kts": "maven",
    ".scala": "maven",
    ".cs": "nuget",
    ".go": "go",
    ".swift": "swiftpm",
}


def _provider_for_source_file(
    playbook: Playbook, path: str | None, asset: CryptoAsset
) -> Provider | None:
    """The provider a source file in this language would install.

    Token findings in a JavaScript file resolve to `jose` rather than the raw KEM package, because
    RFC 9964 gives JOSE its own registered algorithm identifiers and swapping in a bare ML-DSA
    implementation would produce tokens no standard verifier accepts.
    """
    if not path:
        return None
    suffix = Path(path).suffix.lower()
    key = _SUFFIX_PROVIDER.get(suffix)
    if key is None:
        return None
    if asset.usage_context.value == "token" and key == "npm" and "jose" in playbook.providers:
        return playbook.providers["jose"]
    if asset.usage_context.value == "token" and key == "pip":
        return None  # see playbook.unavailable.python_jose - handled by the caller's weakness path
    return playbook.providers.get(key)


__all__ = ["GuidedPlan", "GuidedStep", "build_guided_plan"]
