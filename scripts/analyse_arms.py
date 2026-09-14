"""Phase 8.3 — run the pre-registered analysis over the arm databases.

The statistics module was written and mutation-tested long before there was anything to run it on.
This is the part that runs it, so the denominator ladder and the intervals are measured output
rather than an implementation nobody exercised.

## What it will and will not report on this corpus

`verified_accept` — accepted, non-vacuous, `tests == pass` (not skipped), on a covered line —
is **0 by construction here**, and that is established independently of any arm:
`RESULTS-G5-oracle.md` measures pyload's suite covering exactly 1 of its 34 crypto findings, and
that one is a PBKDF2 site rather than a migration target. So the primary endpoint cannot be reached
and the paired comparisons in `COMPARISONS` would rank arms on an endpoint none of them can attain.

Reporting the ladder anyway is the point. **The interesting rows are the ones before `accepted`**:
how many findings had no rule, how many were refused as somebody else's contract, how many reached
each rung. A study that could only report its primary endpoint would have nothing to say here, and
that would be a property of the report rather than of the evidence.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any


def _arm_rows(workdir: Path) -> list[dict[str, Any]]:
    """One row per task across every database this arm used."""
    rows: list[dict[str, Any]] = []
    for db in sorted(workdir.glob("*.db")):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            con.row_factory = sqlite3.Row
        except sqlite3.Error:
            continue
        patches = {}
        for p in con.execute("SELECT * FROM migration_patches"):
            patches[str(p["task_id"])] = p
        for t in con.execute("SELECT * FROM migration_tasks"):
            patch = patches.get(str(t["id"]))
            report = json.loads(patch["validation_json"] or "{}") if patch else {}
            stages = {
                k: (v.get("status") if isinstance(v, dict) else v)
                for k, v in (report.get("stages") or {}).items()
            }
            vacuous = any(
                isinstance(v, dict) and v.get("vacuous")
                for v in (report.get("stages") or {}).values()
            )
            rows.append(
                {
                    "task_id": str(t["id"]),
                    "rule_id": str(t["rule_id"] or ""),
                    "state": str(t["state"]),
                    "last_error": str(t["last_error"] or ""),
                    "advised": bool((t["advice_text"] or "").strip()),
                    "has_patch": patch is not None,
                    "evidence_level": (patch["evidence_level"] if patch else None),
                    "passed": bool(report.get("passed")),
                    "vacuous": vacuous,
                    "stages": stages,
                }
            )
        con.close()
    return rows


#: Why a finding produced no patch. Each is a different fact about the tool, and pooling them into
#: "not attempted" is exactly the collapse the denominator ladder exists to prevent.
_REASONS = (
    (
        "refused_as_contract",
        (
            "plain digest over a credential",
            "established key-derivation",
            "protocol path",
            "identifier holding",
            "remote names",
            "outbound request under a key",
        ),
    ),
    ("vacuous_rule_already_satisfied", ("already meets what",)),
    ("codemod_had_nothing_to_change", ("nothing left for",)),
    ("rule_has_no_codemod", ("no codemod",)),
    ("model_attempted_and_failed", ("llm generation failed", "rejected after")),
)


def _reason(last_error: str) -> str:
    low = (last_error or "").lower()
    for name, markers in _REASONS:
        if any(m.lower() in low for m in markers):
            return name
    return "other" if low else "unexplained"


def ladder(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The denominator ladder, spelled out. Collapsing these is how the old harness went wrong."""
    total = len(rows)
    no_rule = sum(1 for r in rows if not r["rule_id"])
    refused = sum(1 for r in rows if r["advised"] and not r["has_patch"])
    attempted = sum(1 for r in rows if r["has_patch"])
    vacuous = sum(1 for r in rows if r["vacuous"])
    accepted = sum(1 for r in rows if r["passed"])
    verified = sum(
        1 for r in rows if r["passed"] and not r["vacuous"] and r["stages"].get("tests") == "pass"
    )
    return {
        "total_findings": total,
        "minus_no_rule": total - no_rule,
        "minus_refused_as_contract": total - no_rule - refused,
        "attempted": attempted,
        "of_which_vacuous": vacuous,
        "accepted": accepted,
        "verified_accept": verified,
        "_refused_as_contract": refused,
        "_no_rule": no_rule,
        "why_no_patch": dict(
            Counter(
                _reason(r.get("last_error", "")) for r in rows if not r["has_patch"]
            ).most_common()
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workdir", type=Path, required=True, help="the arms working directory")
    ap.add_argument("--out", type=Path, default=Path("qubit-v2/08-evaluation"))
    args = ap.parse_args()

    report: dict[str, Any] = {"arms": {}}
    for arm_dir in sorted(p for p in args.workdir.iterdir() if p.is_dir()):
        rows = _arm_rows(arm_dir)
        if not rows:
            continue
        lad = ladder(rows)
        levels = Counter(r["evidence_level"] for r in rows if r["has_patch"])
        stage_counts: Counter[str] = Counter()
        for r in rows:
            for name, status in r["stages"].items():
                stage_counts[f"{name}:{status}"] += 1
        report["arms"][arm_dir.name] = {
            "denominator_ladder": lad,
            "evidence_levels": {
                str(k): v for k, v in sorted(levels.items(), key=lambda x: str(x[0]))
            },
            "stages": dict(sorted(stage_counts.items())),
            "rules_refused": dict(
                Counter(r["rule_id"] for r in rows if r["advised"] and not r["has_patch"])
            ),
        }

    report["primary_endpoint_note"] = (
        "verified_accept is 0 for every arm, and that is established independently of the arms: "
        "pyload's suite covers 1 of its 34 crypto findings (RESULTS-G5-oracle.md), so the `tests` "
        "stage cannot falsify any migration on this corpus. The paired comparisons in COMPARISONS "
        "are NOT run, because ranking arms on an endpoint none can reach would be a ranking of "
        "noise."
    )

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "analysis.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"\nwritten: {args.out / 'analysis.json'}")


if __name__ == "__main__":
    main()
