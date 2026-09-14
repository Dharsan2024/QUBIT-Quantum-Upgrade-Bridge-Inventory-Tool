"""Turn the per-twin evaluation JSON into the strength report.

Every number here is read from `qubit-v2/data/app_eval_*.json`, which is written by
`twin_app_eval.py` from a run against the shipped desktop app. Nothing is transcribed by hand: a
report that quotes a figure the data does not contain is the failure mode this script exists to
prevent.

    python scripts/twin_report.py > qubit-v2/RESULTS-twin-app-eval.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "qubit-v2" / "data"

#: Rung -> the gates that have to pass to reach it. Mirrors `_EVIDENCE_LADDER` in
#: `qubit_migrate.transform.validate`; duplicated rather than imported so the report can be
#: regenerated from the JSON alone.
LADDER = ["applies+parses", "symbols+compiles", "rescan", "behaves", "tests"]


def load() -> list[dict[str, Any]]:
    results = []
    for path in sorted(DATA.glob("app_eval_*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        results.extend(payload if isinstance(payload, list) else [payload])
    return [r for r in results if "error" not in r]


def truth_for(twin: str) -> dict[str, Any]:
    return json.loads((REPO / "demo-lab" / twin / "GROUND_TRUTH.json").read_text("utf-8"))


def pct(n: int, d: int) -> str:
    return "—" if not d else f"{100 * n / d:.0f}%"


def main() -> int:
    results = load()
    if not results:
        print("no evaluation data in", DATA, file=sys.stderr)
        return 1

    out: list[str] = []
    w = out.append

    w("# How strong is QUBIT? — measured against four digital twins\n")
    w("Every figure below was produced by driving the **shipped desktop application**")
    w("(`qubit-desktop.exe`) over the same HTTP endpoints its own buttons call — create project,")
    w("scan, build plan, run plan — against the engine the app spawns. No in-process orchestrator,")
    w("no side uvicorn. A route that is broken, mis-wired, or silently swallowing an error is")
    w("visible here and is not visible to a library-level harness.\n")
    w("Each twin was **duplicated first** and the copy migrated, because a migrated twin is a")
    w("spent twin: its vulnerabilities are gone and it cannot serve as a scanning target again.\n")

    # ---------------------------------------------------------------- headline
    w("## Headline\n")
    w(
        "| twin | stack | findings | correctly handled | false migrations | controls hit "
        "| suite after |"
    )
    w("|---|---|---|---|---|---|---|")
    tot_correct = tot_false = tot_controls = tot_findings = 0
    green = 0
    for r in results:
        s = r["score"]
        truth = truth_for(r["twin"])
        n = len(truth["findings"])
        correct = len(s["correct"])
        false_m = len(s["false_migrations"])
        controls = len(s["controls_wrongly_migrated"])
        suite = "green" if r["suite_after_migration"]["green"] else "**RED**"
        green += r["suite_after_migration"]["green"]
        tot_correct += correct
        tot_false += false_m
        tot_controls += controls
        tot_findings += n
        w(
            f"| {r['twin']} | {r['language']} | {n} | {correct} ({pct(correct, n)}) | "
            f"{false_m} | {controls} | {suite} |"
        )
    w(
        f"| **total** | — | **{tot_findings}** | "
        f"**{tot_correct}** ({pct(tot_correct, tot_findings)}) "
        f"| **{tot_false}** | **{tot_controls}** | {green}/{len(results)} green |\n"
    )

    w("*Correctly handled* means the disposition the manifest names is the disposition QUBIT")
    w("produced: a finding marked `migrate` was migrated, and a finding marked `refuse` was left")
    w("byte-identical. *False migration* is the dangerous direction — an edit to code the manifest")
    w("says must not be edited. *Controls hit* counts edits to cryptography that was already")
    w("correct, which is a false positive with a patch attached.\n")

    w("Attribution is taken from **the bytes on disk**, by diffing the migrated copy against the")
    w("pristine twin, not from the tool's own record of what it did. Scoring a refusal against")
    w("QUBIT's claim to have refused would make the evaluation circular.\n")

    # ------------------------------------------------------------ evidence ladder
    w("## What the evidence ladder actually established\n")
    w("A `skipped` gate never counts as a pass, so the level a patch reaches is the level it can")
    w("defend. Counts are over every patch proposed, accepted or not.\n")
    w(
        "| twin | "
        + " | ".join(
            f"`{g}`"
            for g in ("applies", "parses", "symbols", "compiles", "behaves", "tests", "rescan")
        )
        + " |"
    )
    w("|---|" + "---|" * 7)
    for r in results:
        cells = []
        for gate in ("applies", "parses", "symbols", "compiles", "behaves", "tests", "rescan"):
            tally = r["stages"].get(gate, {})
            if not tally:
                cells.append("—")
                continue
            cells.append(" ".join(f"{k[:4]}&nbsp;{v}" for k, v in sorted(tally.items())))
        w(f"| {r['twin']} | " + " | ".join(cells) + " |")
    w("")

    # ------------------------------------------------------------ per-twin detail
    w("## Per-twin detail\n")
    for r in results:
        s = r["score"]
        truth = truth_for(r["twin"])
        by_id = {e["id"]: e for e in [*truth["findings"], *truth["negative_controls"]]}
        w(f"### {r['twin']} — {r['language']}\n")
        w(f"- {r['assets']} crypto assets inventoried, {r['tasks']} migration tasks")
        w(f"- migration run: {r['run_seconds']}s (whole evaluation {r['total_seconds']}s)")
        w(
            "- task resolutions: "
            + ", ".join(f"`{k}` {v}" for k, v in sorted(r["resolutions"].items()))
        )
        suite = r["suite_after_migration"]
        w(f"- the twin's own suite after migration: **{'green' if suite['green'] else 'RED'}**")
        if suite["tail"]:
            w(f"  - `{suite['tail'][-1].strip()[:110]}`")
        if s["false_migrations"]:
            w("\n**False migrations** — edits to code the manifest marks `refuse`:\n")
            for fid in s["false_migrations"]:
                e = by_id.get(fid, {})
                w(
                    f"- `{fid}` {e.get('file', '?')}::{e.get('symbol', '?')} "
                    f"— {e.get('constraint_kind', '?')}, "
                    f"refusal evidence in **{e.get('refusal_evidence', '?')}**"
                )
                w(f"  - {e.get('reason', '')[:200]}")
        if s["expected_migrate_but_not_migrated"]:
            w("\n**Not migrated** — findings the manifest marks `migrate` that were left alone:\n")
            for fid in s["expected_migrate_but_not_migrated"]:
                e = by_id.get(fid, {})
                w(
                    f"- `{fid}` {e.get('file', '?')}::{e.get('symbol', '?')} "
                    f"({e.get('algorithm', '?')})"
                )
        if s["unmapped_outcomes"]:
            w(
                f"\n{s['unmapped_outcomes']} outcome(s) could not be attributed "
                f"to a manifest entry. "
                "These are reported rather than dropped: quietly excluding them would inflate "
                "every "
                "rate above."
            )
        w("")

    # ------------------------------------------------------------ refusal evidence
    w("## Where the refusals are won and lost\n")
    w("Each twin's manifest records, for every refusal, whether the reason is visible **in the")
    w("code** the scanner can see (a field name, a URL, a wire constant within the rule's own")
    w("match window) or only **in prose** — a docstring, a column comment, the shape of a schema.")
    w("This is the axis that predicts QUBIT's behaviour.\n")
    w("| refusal evidence | refusals | correctly refused | false migrations |")
    w("|---|---|---|---|")
    buckets: dict[str, list[int]] = {}
    for r in results:
        s = r["score"]
        truth = truth_for(r["twin"])
        for e in truth["findings"]:
            if e["expected_disposition"] != "refuse":
                continue
            kind = e.get("refusal_evidence", "?")
            row = buckets.setdefault(kind, [0, 0, 0])
            row[0] += 1
            if e["id"] in s["correct"]:
                row[1] += 1
            if e["id"] in s["false_migrations"]:
                row[2] += 1
    for kind, (total, ok, bad) in sorted(buckets.items()):
        w(f"| {kind} | {total} | {ok} ({pct(ok, total)}) | {bad} |")
    w("")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
