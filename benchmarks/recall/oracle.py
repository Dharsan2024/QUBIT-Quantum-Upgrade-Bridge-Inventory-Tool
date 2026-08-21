"""An independent detector, so QUBIT's recall is measured against something it did not write.

QUBIT's own rule pack cannot be its own ground truth: a rule that fails to match something also
fails to notice that it should have. Every detection gap found in this project so far surfaced by
accident from the migration side — a Swift rule whose title advertised `AES.GCM.seal` while its
query could not match it, both Swift rules blind to `try!`, every strong .NET class invisible to the
PowerShell rules. None was caught by a test, because the tests were written from the same
understanding as the rules.

So the oracle here is somebody else's. `pqaudit` (PQCWorld, MIT) ships `rules/crypto-patterns.yaml`:
28 rules and 178 regular expressions naming the crypto APIs a different team, working independently,
decided were worth detecting. Applying those patterns to real source gives a set of findings derived
with no knowledge of QUBIT's rules at all.

It is an *oracle*, not a gold standard. A regex over source text cannot tell a call from a comment,
a live import from a vendored test fixture, or `RSA` the algorithm from `RSA` in a variable name, so
its output contains false positives of its own. The obvious ones are filtered here — comments,
blank lines, files no scanner reads — and the rest are adjudicated in `run.py`, which reports what
each side found alone rather than declaring either correct.

Provenance: git help/pqaudit @ 5e389b2 — https://github.com/PQCWorld/pqaudit
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

#: Line prefixes that begin a comment in the languages this corpus covers. A regex oracle has no
#: parser, so a commented-out `rsa.GenerateKey` reads exactly like a live one — the single largest
#: source of spurious oracle findings, and cheap to remove.
_COMMENT_PREFIXES = ("//", "#", "--", "*", "/*", '"""', "'''", "%", ";")

#: Suffix -> the language label to report. Only what QUBIT's scanner also reads: comparing on files
#: one side never looks at measures nothing.
SUFFIXES: dict[str, str] = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".swift": "swift",
    ".dart": "dart",
    ".sh": "bash",
    ".ps1": "powershell",
    ".sql": "sql",
}


@dataclass(frozen=True)
class OracleFinding:
    """One pattern hit: a file, a line, and the algorithm the independent rule assigns it."""

    path: str
    line: int
    algorithm: str
    rule_id: str
    severity: str
    text: str


@dataclass
class OracleRule:
    rule_id: str
    algorithm: str
    severity: str
    patterns: list[re.Pattern[str]]


def load_rules(patterns_yaml: Path) -> list[OracleRule]:
    """Compile pqaudit's patterns. Anything that will not compile under Python `re` is dropped.

    The two dialects agree on everything these rules use; dropping rather than rewriting keeps the
    oracle honestly *theirs* — a pattern QUBIT's author had to reinterpret is no longer independent.
    """
    raw: list[dict[str, Any]] = yaml.safe_load(patterns_yaml.read_text(encoding="utf-8"))
    rules: list[OracleRule] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        compiled: list[re.Pattern[str]] = []
        for pattern in entry.get("patterns") or []:
            try:
                compiled.append(re.compile(str(pattern)))
            except re.error:
                continue
        if not compiled:
            continue
        rules.append(
            OracleRule(
                rule_id=str(entry.get("id", "?")),
                algorithm=str(entry.get("algorithm", "?")),
                severity=str(entry.get("severity", "?")),
                patterns=compiled,
            )
        )
    return rules


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith(_COMMENT_PREFIXES)


def scan_file(path: Path, rules: list[OracleRule], root: Path) -> list[OracleFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = path.relative_to(root).as_posix()
    findings: list[OracleFinding] = []
    for number, line in enumerate(text.splitlines(), 1):
        if _is_comment(line):
            continue
        for rule in rules:
            if any(p.search(line) for p in rule.patterns):
                findings.append(
                    OracleFinding(
                        path=rel,
                        line=number,
                        algorithm=rule.algorithm,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        text=line.strip()[:160],
                    )
                )
                break  # one finding per line, matching how both tools report
    return findings


def scan_tree(root: Path, rules: list[OracleRule], limit: int | None = None) -> list[OracleFinding]:
    findings: list[OracleFinding] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUFFIXES:
            continue
        if any(
            part in {".git", "node_modules", ".venv", "vendor", "dist", "build"}
            for part in path.parts
        ):
            continue
        findings.extend(scan_file(path, rules, root))
        if limit is not None and len(findings) >= limit:
            break
    return findings


__all__ = ["SUFFIXES", "OracleFinding", "OracleRule", "load_rules", "scan_file", "scan_tree"]
