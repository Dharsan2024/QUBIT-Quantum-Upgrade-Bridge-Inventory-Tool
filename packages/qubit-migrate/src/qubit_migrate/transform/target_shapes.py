"""What the checker will accept — asked of the scanner, not assumed.

A patch is only kept if the rescan finds the target algorithm in the rewritten file. So the set of
rewrites that can possibly pass is exactly the set the scanner can recognise, and until now nothing
told the generator what that set was. The measured consequence, on a Rust file:

    rule `code-kex-01` carries per-language API guidance for Go, Java, JS/TS and C, and claims 21
    file suffixes. Nothing scoped those lines to their language, so a `.rs` file arrived with
    "Go: use crypto/mlkem ... mlkem.GenerateKey768()" as its only concrete instruction. The model
    followed it exactly and emitted `mlkem::GenerateKey768(&mut rng)` — Go's standard-library API
    transliterated into Rust. It is not a Rust crate, the scanner does not detect it, and the
    migration was rejected with "Expected one of ['ML-KEM'] present, but not found" three times
    over. The failure was read as the model being too small for a structural rewrite. It was not:
    given the shape below, the same 7B model landed the same migration on its second attempt.

The shapes come from the scanner's own rule examples, which its test suite already proves are
detected (`test_rule_examples.py`), and are re-verified by the CLI before being emitted. So the
generator is told what to write by the same authority that decides whether it worked, and the two
cannot drift apart: adding a crate spelling to a detection rule updates this automatically.
"""

from __future__ import annotations

from dataclasses import dataclass

from .scanner_cli import run_cli_json

__all__ = ["TargetShape", "verified_target_shapes"]


@dataclass(frozen=True)
class TargetShape:
    """One code shape the scanner is verified to recognise as ``algorithms``."""

    rule_id: str
    language: str
    algorithms: tuple[str, ...]
    source: str


# Asking the CLI costs a subprocess, and a plan re-asks the same (language, prefix) pair for every
# task in it. The answer only changes when the rule catalog does, which cannot happen inside a run.
_cache: dict[tuple[str, str], tuple[TargetShape, ...]] = {}


def verified_target_shapes(language: str, algorithm_prefix: str) -> tuple[TargetShape, ...] | None:
    """Shapes in ``language`` the scanner detects as ``algorithm_prefix``\u2011something.

    An empty tuple is meaningful, not merely unlucky: the scanner answered, and it has no rule that
    recognises that algorithm here, so no rewrite in this language can be confirmed to have
    migrated. Callers use that to avoid spending model time on a check that cannot pass.

    ``None`` means something different and must not be confused with it — the scanner could not be
    asked at all. Treating that as "nothing is verifiable" would refuse every LLM task the moment
    the CLI became unreachable, turning a packaging problem into a silent capability loss.
    """
    lang = (language or "").strip().lower()
    prefix = (algorithm_prefix or "").strip().upper()
    if not lang or not prefix:
        return ()
    key = (lang, prefix)
    if key in _cache:
        return _cache[key]

    payload = run_cli_json(
        "rules", "examples", "--language", lang, "--algorithm-prefix", prefix, timeout=90.0
    )
    if not isinstance(payload, list):
        # Not cached: the next caller should get a real answer if the CLI comes back.
        return None
    shapes: tuple[TargetShape, ...] = tuple(
        TargetShape(
            rule_id=str(entry.get("rule_id", "")),
            language=str(entry.get("language", lang)),
            algorithms=tuple(str(a) for a in entry.get("algorithms", [])),
            source=str(entry.get("source", "")).strip(),
        )
        for entry in payload
        if isinstance(entry, dict) and str(entry.get("source", "")).strip()
    )
    _cache[key] = shapes
    return shapes
