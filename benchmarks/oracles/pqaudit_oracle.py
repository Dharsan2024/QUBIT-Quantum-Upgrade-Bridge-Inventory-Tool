"""pqaudit wrapped in the common `Detector` shape.

The engine is unchanged — `benchmarks/recall/oracle.py` still owns the pattern loading and the
comment filtering, and its docstring records why the patterns are applied verbatim rather than
reinterpreted. This module only adapts its output to `base.Finding` so pqaudit can sit alongside
semgrep and cryptoscan in one comparison.

Kept as a thin adapter rather than merged: the original harness (`benchmarks/recall/run.py`)
produced the published 0%-94.1% figures, and rewriting the code underneath those numbers would
invalidate them for no gain.

Provenance: git help/pqaudit @ 5e389b2 (PQCWorld, MIT).
"""

from __future__ import annotations

import sys
from pathlib import Path

from base import Finding

_RECALL_DIR = Path(__file__).resolve().parents[1] / "recall"
if str(_RECALL_DIR) not in sys.path:
    sys.path.insert(0, str(_RECALL_DIR))

from oracle import load_rules, scan_tree  # noqa: E402

PATTERNS = (
    Path(__file__).resolve().parents[2] / "git help" / "pqaudit" / "rules" / "crypto-patterns.yaml"
)


class PqauditDetector:
    """Applies pqaudit's 178 regular expressions to a tree."""

    name = "pqaudit"
    provenance = "PQCWorld/pqaudit @ 5e389b2 (MIT), rules/crypto-patterns.yaml applied verbatim"

    def available(self) -> tuple[bool, str]:
        if not PATTERNS.exists():
            return False, f"patterns not found at {PATTERNS} — clone pqaudit into 'git help/'"
        return True, "ok"

    def scan(self, root: Path) -> list[Finding]:
        rules = load_rules(PATTERNS)
        return [
            Finding(
                detector=self.name,
                path=hit.path,
                line=hit.line,
                algorithm=hit.algorithm,
                rule_id=hit.rule_id,
                text=hit.text,
            )
            for hit in scan_tree(root.resolve(), rules)
        ]


__all__ = ["PATTERNS", "PqauditDetector"]
