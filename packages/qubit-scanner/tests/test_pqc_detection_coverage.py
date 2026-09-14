"""Every language that can be TOLD to migrate must be able to have the result CONFIRMED.

`code-signature-01` and `code-kex-01` are `language: multi` and assert `present: ML-DSA` /
`present: ML-KEM` at the rescan stage. So for any language whose rule pack emits `signature` or
`kex` findings, a missing PQC detection shape does not merely under-count adoption -- it makes the
migration **unwinnable by construction**. A perfectly correct rewrite reports no post-quantum
algorithm, the gate rejects it, and the repair loop spends all three attempts correcting a file that
is already right.

Measured, as the recorded failure reason on `inkwell-esign` through the desktop app:

    QUBIT cannot yet confirm a ML-DSA rewrite in ruby:
    its scanner ships no rule that recognises ML-...

Ruby had no PQC rule at all; C++, PHP, Dart and Bash had none either, and PowerShell recognised only
the certificate form and not the .NET type literal. Each was verified by scanning a probe file
containing the code a real migration emits, which reported nothing before the rule existed.

`sql` is the one language deliberately exempt: its pack emits `hash`, `kdf`, `mac` and
`encryption-at-rest` only, with no asymmetric cryptography anywhere, so neither of the two rules
above can ever target it. Adding a PQC shape there would be coverage theatre.
"""

from __future__ import annotations

import pytest
import yaml
from qubit_scanner.api import scan_paths

RULES = None


def _rules_root():
    from pathlib import Path

    import qubit_scanner.catalog as catalog

    return Path(catalog.__file__).parent / "rules"


#: Languages whose packs emit no asymmetric cryptography, so no PQC migration can target them.
EXEMPT = {"sql"}


def _language_contexts() -> dict[str, set[str]]:
    contexts: dict[str, set[str]] = {}
    for lang_dir in sorted(p for p in _rules_root().iterdir() if p.is_dir()):
        found: set[str] = set()
        for path in lang_dir.rglob("*.yaml"):
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for rule in doc.get("rules", []) or []:
                context = (rule.get("asset") or {}).get("usage_context")
                if context:
                    found.add(context)
        contexts[lang_dir.name] = found
    return contexts


def _pqc_rule_ids(language: str) -> set[str]:
    import re

    pqc = re.compile(r"ml[-_ ]?dsa|ml[-_ ]?kem|dilithium|kyber|slh[-_ ]?dsa|sphincs", re.I)
    found: set[str] = set()
    for path in (_rules_root() / language).rglob("*.yaml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in doc.get("rules", []) or []:
            if pqc.search(str(rule)):
                found.add(rule["id"])
    return found


LANGUAGES = sorted(p.name for p in _rules_root().iterdir() if p.is_dir())


@pytest.mark.parametrize("language", LANGUAGES)
def test_a_language_that_can_be_migrated_can_be_confirmed(language: str) -> None:
    contexts = _language_contexts()[language]
    targeted = bool({"signature", "kex", "tls", "unknown"} & contexts)
    if not targeted or language in EXEMPT:
        pytest.skip(f"{language} emits {sorted(contexts)}; no PQC migration targets it")
    hit = sorted(contexts & {"signature", "kex", "tls", "unknown"})
    assert _pqc_rule_ids(language), (
        f"{language} emits {hit} findings that `code-signature-01`/`code-kex-01` will target, but "
        f"ships no rule recognising ML-DSA or ML-KEM — so a correct migration of this language can "
        f"never pass the rescan gate"
    )


#: One probe per language, in the shape a real migration emits. These are the exact files used to
#: verify each gap; keeping them here means a rule that stops matching is caught by a test rather
#: than by a run that quietly rejects every patch.
PROBES: dict[str, tuple[str, str]] = {
    "ruby": (".rb", 'require "openssl"\ndef k = OpenSSL::PKey.generate_key("ML-DSA-65")\n'),
    "cpp": (".cpp", '#include <oqs/oqs.h>\nvoid f() { oqs::Signature s{"ML-DSA-65"}; }\n'),
    "php": (".php", "<?php\n$k = openssl_pkey_new(['algorithm' => 'ML-KEM-768']);\n"),
    "dart": (".dart", "void f() { final s = Signature('ML-DSA-65'); }\n"),
    "bash": (".sh", "openssl genpkey -algorithm ML-KEM-768 -out kem.key\n"),
    "powershell": (
        ".ps1",
        "$k = [System.Security.Cryptography.MLKem]::GenerateKey("
        "[System.Security.Cryptography.MLKemAlgorithm]::MLKem768)\n",
    ),
    "go": (".go", 'package x\nimport "crypto/mlkem"\nfunc f() { mlkem.GenerateKey768() }\n'),
    "python": (
        ".py",
        "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "def k(): return mldsa.MLDSA65PrivateKey.generate()\n",
    ),
}


@pytest.mark.parametrize("language", sorted(PROBES))
def test_the_probe_for_each_language_is_detected_as_post_quantum(language, tmp_path) -> None:
    suffix, source = PROBES[language]
    probe = tmp_path / f"probe{suffix}"
    probe.write_text(source, encoding="utf-8")

    result = scan_paths([probe], scanners={"code"})
    assets = result.assets if hasattr(result, "assets") else result
    algorithms = {a.algorithm for a in assets}

    assert any("ML-" in a for a in algorithms), (
        f"{language}: a migrated file reported {sorted(algorithms) or 'nothing'}. "
        "`present: ML-DSA`/`ML-KEM` cannot be satisfied, so every migration in this language "
        "is rejected however correct it is."
    )
    assert not any(a.quantum_vulnerable.vulnerable for a in assets if "ML-" in a.algorithm), (
        f"{language}: a post-quantum algorithm was reported as quantum-vulnerable"
    )
