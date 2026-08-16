"""SARIF 2.1.0 export — the format that puts QUBIT's findings into an analyst's existing tooling.

Chosen over inventing another JSON shape because SARIF is an **OASIS standard** (2.1.0, ratified
2020) and is the interchange format code-scanning platforms already consume: GitHub Advanced
Security turns an uploaded SARIF file into annotated code-scanning alerts, and VS Code and Azure
DevOps read the same schema. A crypto finding is a static-analysis result with a file and a line, so
it fits the schema natively — no adapter, no bespoke ingestion script.

Why this and not only a PDF: a PDF is read once by a human, while SARIF lands the finding on the
line of code that caused it, inside the review the developer is already doing. The two are
complements —
see `pdf.py` for the compliance/exec artifact, and `qubit_core.cbom` for the CycloneDX 1.7
(ECMA-424) inventory that US EO 14412 and OMB M-26-15 actually name.

The one non-obvious mapping is `partialFingerprints`. GitHub uses it to decide when two results are
"logically identical" across commits, which is what makes an alert persist rather than being closed
and reopened as new on every push. QUBIT already computes a stable, cross-platform asset fingerprint
for exactly that purpose, so it is passed straight through instead of letting the platform fall back
to line-number matching (which churns on every unrelated edit above the finding).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qubit_core.schemas import CryptoAsset

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema.json"

# SARIF `level` is a fixed vocabulary: none | note | warning | error. Mapping is by what the finding
# means for a migration deadline, not by a raw score:
#   error   — Shor-breakable public-key crypto. Harvested traffic is retroactively decryptable, so
#             the exposure has already begun and the fix has a hard federal deadline.
#   warning — Grover-affected or classically broken symmetric/hash material. Real, but it does not
#             hand an adversary recorded traffic the way a broken key exchange does.
#   note    — quantum-safe today; recorded for inventory completeness (a CBOM needs the safe assets
#             too, and "we checked and it is fine" is itself a reportable result).
_LEVEL_BY_ATTACK = {"shor": "error", "grover": "warning", "none": "note"}


def _level_for(asset: CryptoAsset) -> str:
    if not asset.quantum_vulnerable.vulnerable:
        return "note"
    return _LEVEL_BY_ATTACK.get(asset.quantum_vulnerable.attack.value, "warning")


def _uri_for(asset: CryptoAsset, repo_root: str | None = None) -> tuple[str | None, bool]:
    """Return ``(uri, is_relative_to_repo_root)`` — forward-slashed, as SARIF consumers expect.

    An absolute path (especially a Windows one) is not portable, and when `uriBaseId` is set the
    spec requires the uri to be RELATIVE to that base — an absolute value there uploads fine and
    then annotates nothing, because the platform cannot match it to a file in the repository.

    The relative-ness is RETURNED rather than re-derived by the caller from the string, because
    `Path.is_absolute()` is platform-dependent in exactly the way that matters here: on Windows,
    `Path("/etc/nginx/nginx.conf").is_absolute()` is False (no drive letter), so a POSIX absolute
    path was being tagged with `uriBaseId: SRCROOT` when a scan ran on Windows. Only the code that
    attempted the relativization actually knows whether it succeeded.
    """
    location = asset.location
    path = getattr(location, "file_path", None) if location else None
    if not path:
        return None, False
    if repo_root:
        try:
            return Path(path).resolve().relative_to(Path(repo_root).resolve()).as_posix(), True
        except (ValueError, OSError):
            # Outside the declared root (a system config, an absolute include) — keep it absolute
            # rather than emitting a misleading `../..` chain.
            return Path(path).as_posix(), False
    return Path(path).as_posix(), False


def _message_for(asset: CryptoAsset) -> str:
    qv = asset.quantum_vulnerable
    usage = asset.usage_context.value
    if not qv.vulnerable:
        return f"{asset.algorithm} ({usage}) is quantum-safe. Recorded for inventory completeness."

    if qv.attack.value == "shor":
        why = (
            "Shor's algorithm breaks this outright. Traffic or data protected by it that is "
            "recorded today can be decrypted once a CRQC exists (harvest-now-decrypt-later), so "
            "the exposure starts now rather than on the day the machine arrives."
        )
    else:
        why = (
            "Grover's algorithm halves the effective strength, and this primitive is already at or "
            "below the 128-bit post-quantum bar (or is classically broken)."
        )

    risk = ""
    if asset.risk is not None:
        risk = (
            f" HNDL risk score {asset.risk.score:.2f}; Mosca margin "
            f"{asset.risk.mosca_margin_years:+.1f} years"
            + (" — already negative, i.e. past due." if asset.risk.mosca_margin_years < 0 else ".")
        )
    return f"{asset.algorithm} used for {usage}. {why}{risk}"


def _rules_from(assets: list[CryptoAsset]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One SARIF `rule` per distinct detection rule, plus ruleId -> index for `ruleIndex`.

    Findings are grouped by the DETECTION rule that produced them (`QUBIT.PY-HASHLIB-MD5`, …) rather
    than one rule per algorithm: that is what lets a platform show "12 alerts from this rule" and
    lets a team dismiss or configure a whole class at once.
    """
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for asset in assets:
        rule_id = f"QUBIT.{asset.rule_id or 'UNKNOWN-RULE'}"
        if rule_id in index:
            continue
        index[rule_id] = len(rules)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace(".", "_"),
                "shortDescription": {"text": f"Quantum-vulnerable cryptography: {asset.algorithm}"},
                "fullDescription": {
                    "text": (
                        "Detected by QUBIT's cryptographic inventory scan. Public-key cryptography "
                        "is broken by Shor's algorithm and must migrate to a NIST PQC standard "
                        "(ML-KEM / FIPS 203 for key establishment, ML-DSA / FIPS 204 for "
                        "signatures); undersized symmetric and broken hash primitives must move to "
                        "AES-256 and SHA-256 or better."
                    )
                },
                "defaultConfiguration": {"level": _level_for(asset)},
                "properties": {
                    "tags": ["cryptography", "post-quantum", "security"],
                    "problem": {"severity": _level_for(asset)},
                },
            }
        )
    return rules, index


def export_sarif(
    assets: list[CryptoAsset],
    *,
    tool_version: str = "0.1.0",
    include_safe: bool = False,
    repo_root: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log for ``assets``.

    ``include_safe`` off by default: an analyst opening code-scanning alerts wants the problems, and
    a `note` for every healthy SHA-256 call would bury them. The full inventory — safe assets
    included — is the CBOM's job, and that is the artifact compliance asks for.
    """
    selected = [a for a in assets if include_safe or a.quantum_vulnerable.vulnerable]
    rules, rule_index = _rules_from(selected)

    results: list[dict[str, Any]] = []
    for asset in selected:
        rule_id = f"QUBIT.{asset.rule_id or 'UNKNOWN-RULE'}"
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _level_for(asset),
            "message": {"text": _message_for(asset)},
            # GitHub matches results across commits on this rather than on line numbers, so an alert
            # persists instead of closing and reopening whenever code shifts above it.
            "partialFingerprints": {"qubitAssetFingerprint": asset.fingerprint or ""},
            "properties": {
                "algorithm": asset.algorithm,
                "usage_context": asset.usage_context.value,
                "source_scanner": asset.source_scanner.value,
                "quantum_attack": asset.quantum_vulnerable.attack.value,
                "confidence": asset.confidence.value,
            },
        }
        if asset.key_size is not None:
            result["properties"]["key_size"] = asset.key_size
        if asset.risk is not None:
            result["properties"]["hndl_risk_score"] = asset.risk.score
            result["properties"]["mosca_margin_years"] = asset.risk.mosca_margin_years

        uri, uri_is_relative = _uri_for(asset, repo_root)
        if uri:
            region: dict[str, Any] = {}
            line = getattr(asset.location, "line", None)
            if line:
                region["startLine"] = line
            physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
            # Only claim SRCROOT when the path really was made relative to it. Tagging an absolute
            # path with a base id is exactly what makes a consumer fail to locate the file.
            if uri_is_relative:
                physical["artifactLocation"]["uriBaseId"] = "SRCROOT"
            if region:
                physical["region"] = region
            result["locations"] = [{"physicalLocation": physical}]
        else:
            # A network, cert or Vault finding has no file. SARIF requires SOMETHING locatable, and
            # omitting `locations` entirely makes GitHub reject the whole run, so the logical
            # location carries the host/service instead of a fabricated file path.
            result["locations"] = [
                {"logicalLocations": [{"name": _logical_name(asset), "kind": "resource"}]}
            ]
        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "QUBIT",
                "fullName": "QUBIT — Quantum Upgrade Bridge & Inventory Tool",
                "version": tool_version,
                "semanticVersion": tool_version,
                "informationUri": "https://github.com/Dharsan2024/QUBIT-Quantum-Upgrade-Bridge-Inventory-Tool",
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ],
    }
    if repo_root:
        run["originalUriBaseIds"] = {
            "SRCROOT": {"uri": Path(repo_root).as_posix().rstrip("/") + "/"}
        }

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def _logical_name(asset: CryptoAsset) -> str:
    location = asset.location
    host = getattr(location, "host", None) if location else None
    service = getattr(location, "service", None) if location else None
    if host and service:
        return f"{host} ({service})"
    return host or asset.algorithm


def validate_sarif_structure(doc: dict[str, Any]) -> list[str]:
    """Structural checks for the subset code-scanning platforms actually require.

    Deliberately not a full JSON-Schema validation: the point is to catch the mistakes that make an
    upload fail — a wrong version, a missing driver, a result with no location — at export time
    rather than in someone's CI log.
    """
    errors: list[str] = []
    if doc.get("version") != SARIF_VERSION:
        errors.append(f"version must be {SARIF_VERSION!r}, got {doc.get('version')!r}")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty list")
        return errors
    for i, run in enumerate(runs):
        driver = (run.get("tool") or {}).get("driver")
        if not driver or not driver.get("name"):
            errors.append(f"runs[{i}].tool.driver.name is required")
        rule_count = len(driver.get("rules", []) if driver else [])
        for j, result in enumerate(run.get("results", [])):
            if not result.get("ruleId"):
                errors.append(f"runs[{i}].results[{j}].ruleId is required")
            if not (result.get("message") or {}).get("text"):
                errors.append(f"runs[{i}].results[{j}].message.text is required")
            if result.get("level") not in {"none", "note", "warning", "error"}:
                errors.append(f"runs[{i}].results[{j}].level is not a valid SARIF level")
            if not result.get("locations"):
                errors.append(f"runs[{i}].results[{j}] has no locations — uploads are rejected")
            idx = result.get("ruleIndex")
            if idx is not None and not (0 <= idx < rule_count):
                errors.append(f"runs[{i}].results[{j}].ruleIndex {idx} is out of range")
    return errors


__all__ = ["SARIF_SCHEMA", "SARIF_VERSION", "export_sarif", "validate_sarif_structure"]
