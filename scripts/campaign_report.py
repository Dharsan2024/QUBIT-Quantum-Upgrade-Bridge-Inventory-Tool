"""Aggregate the evaluation campaign into the report the paper quotes.

One pass is an anecdote. The generator is a language model, so the same finding can be handled
differently on two runs; a single-run percentage is not a measurement. This reads every pass under
`qubit-v2/data/campaign/pass-*/` and reports, per twin and overall, the mean with its observed range.

Every number is read from the JSON. Nothing is transcribed by hand.

    python scripts/campaign_report.py > qubit-v2/RESULTS-twin-app-eval.md
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CAMPAIGN = REPO / "qubit-v2" / "data" / "campaign"

GATES = ("applies", "parses", "symbols", "compiles", "behaves", "tests", "rescan")


def load() -> dict[str, list[dict[str, Any]]]:
    """`{twin: [result per pass]}`, skipping passes that errored."""
    by_twin: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pass_dir in sorted(CAMPAIGN.glob("pass-*")):
        for path in sorted(pass_dir.glob("app_eval_*.json")):
            for result in json.loads(path.read_text(encoding="utf-8")):
                if "error" in result:
                    continue
                result["_pass"] = pass_dir.name
                by_twin[result["twin"]].append(result)
    return by_twin


def truth(twin: str) -> dict[str, Any]:
    return json.loads((REPO / "demo-lab" / twin / "GROUND_TRUTH.json").read_text("utf-8"))


def written_problems(twin: str) -> list[str]:
    """Problems the file-level audit found, across all passes."""
    out: list[str] = []
    for path in sorted(CAMPAIGN.glob(f"pass-*/written_{twin}.json")):
        for entry in json.loads(path.read_text(encoding="utf-8")):
            for f in entry.get("files", []):
                out.extend(f"{f['file']}: {p}" for p in f.get("problems", []))
    return out


def spread(values: list[float]) -> str:
    if not values:
        return "-"
    if len(values) == 1:
        return f"{values[0]:.0f}"
    return f"{statistics.mean(values):.1f} ({min(values):.0f}-{max(values):.0f})"


def main() -> int:
    by_twin = load()
    if not by_twin:
        print(f"no campaign data under {CAMPAIGN}", file=sys.stderr)
        return 1

    passes = max(len(v) for v in by_twin.values())
    w: list[str] = []
    a = w.append

    a("# QUBIT against four digital twins — campaign results\n")
    a(f"**{passes} independent pass(es)** over four applications, each driven through the shipped")
    a("desktop application (`qubit-desktop.exe`) over the same HTTP routes its own buttons call.")
    a("No in-process orchestrator and no side engine: a route that is broken or silently swallowing")
    a("an error is visible here and is invisible to a library-level harness.\n")
    a("Each twin is **duplicated first** and the copy migrated — a migrated twin is a spent twin.")
    a("Attribution comes from **the bytes on disk**, diffed against the pristine twin, never from")
    a("QUBIT's own record of what it did.\n")

    # ------------------------------------------------------------------ headline
    a("## Headline\n")
    a("| twin | stack | findings | correctly handled | false migrations | controls hit | suite green |")
    a("|---|---|---|---|---|---|---|")
    all_correct: list[float] = []
    total_findings = 0
    total_false: list[float] = []
    for name in sorted(by_twin):
        runs = by_twin[name]
        n = len(truth(name)["findings"])
        correct = [len(r["score"]["correct"]) for r in runs]
        false_m = [len(r["score"]["false_migrations"]) for r in runs]
        controls = [len(r["score"]["controls_wrongly_migrated"]) for r in runs]
        green = sum(1 for r in runs if r["suite_after_migration"]["green"])
        pct = statistics.mean(correct) / n * 100
        all_correct.extend(c / n for c in correct)
        total_false.extend(false_m)
        total_findings += n
        a(f"| {name} | {runs[0]['language']} | {n} | {spread(correct)} = **{pct:.0f}%** | "
          f"{spread(false_m)} | {spread(controls)} | {green}/{len(runs)} |")
    a(f"\n**Overall: {statistics.mean(all_correct) * 100:.0f}% correctly handled** across "
      f"{total_findings} findings in 4 stacks, with a mean of "
      f"{statistics.mean(total_false):.1f} false migration(s) per pass.\n")

    a("> *Correctly handled* means the disposition QUBIT produced is the disposition the manifest")
    a("> names: a finding marked `migrate` was migrated, one marked `refuse` was left byte-identical.")
    a("> It is **not** \"this fraction of vulnerabilities was migrated\" — much of the score is")
    a("> correctly declining to touch code that must not change, which is the harder half of the")
    a("> problem and the reason the twins exist.\n")

    # ------------------------------------------------------------- what was proven
    a("## What the evidence ladder established\n")
    a("A `skipped` gate never counts as a pass, so a patch's level is the level it can defend.\n")
    a("| twin | " + " | ".join(f"`{g}`" for g in GATES) + " |")
    a("|---|" + "---|" * len(GATES))
    for name in sorted(by_twin):
        cells = []
        for gate in GATES:
            tally: dict[str, int] = defaultdict(int)
            for r in by_twin[name]:
                for status, count in (r["stages"].get(gate) or {}).items():
                    tally[status] += count
            cells.append(" ".join(f"{k[:4]}&nbsp;{v}" for k, v in sorted(tally.items())) or "-")
        a(f"| {name} | " + " | ".join(cells) + " |")
    a("")

    # ---------------------------------------------------------- refusal evidence
    a("## The axis that predicts the result\n")
    a("Each manifest records, for every refusal, whether the reason is visible **in the code** the")
    a("scanner can see — a field name, a URL, a wire constant inside the rule's match window — or")
    a("only **in prose**: a docstring, a column comment, the shape of a schema.\n")
    a("| refusal evidence | refusals | correctly refused | false migrations |")
    a("|---|---|---|---|")
    buckets: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for name, runs in by_twin.items():
        for e in truth(name)["findings"]:
            if e["expected_disposition"] != "refuse":
                continue
            row = buckets[e.get("refusal_evidence", "?")]
            for r in runs:
                row[0] += 1
                row[1] += e["id"] in r["score"]["correct"]
                row[2] += e["id"] in r["score"]["false_migrations"]
    for kind, (total, ok, bad) in sorted(buckets.items()):
        pct = f"{100 * ok / total:.0f}%" if total else "-"
        a(f"| {kind} | {total} | {ok} ({pct}) | {bad} |")
    a("")

    # --------------------------------------------------------------- file audit
    a("## Was the migrated code correctly written?\n")
    a("Separate from *was the right finding acted on*. This reads the bytes on disk and checks")
    a("encoding, line endings, truncation, per-language syntax, duplicated imports, and whether each")
    a("changed line actually swapped a weak primitive for an approved one.\n")
    clean = True
    for name in sorted(by_twin):
        problems = written_problems(name)
        if problems:
            clean = False
            a(f"- **{name}**: {len(problems)} problem(s)")
            for p in sorted(set(problems))[:6]:
                a(f"  - {p}")
        else:
            a(f"- **{name}**: clean — no malformed output in any pass")
    if clean:
        a("\nNo pass produced a file that failed any of these checks.")
    a("")

    # --------------------------------------------------------------- per-twin
    a("## Per-twin detail\n")
    for name in sorted(by_twin):
        runs = by_twin[name]
        t = truth(name)
        by_id = {e["id"]: e for e in [*t["findings"], *t["negative_controls"]]}
        a(f"### {name} — {runs[0]['language']}\n")
        a(f"- {runs[0]['assets']} crypto assets inventoried, {runs[0]['tasks']} migration tasks")
        a(f"- migration run: {spread([r['run_seconds'] for r in runs])}s")
        seen_false: dict[str, int] = defaultdict(int)
        seen_missed: dict[str, int] = defaultdict(int)
        for r in runs:
            for fid in r["score"]["false_migrations"]:
                seen_false[fid] += 1
            for fid in r["score"]["expected_migrate_but_not_migrated"]:
                seen_missed[fid] += 1
        if seen_false:
            a("\n**False migrations** (edits to code the manifest marks `refuse`):\n")
            for fid, count in sorted(seen_false.items(), key=lambda kv: -kv[1]):
                e = by_id.get(fid, {})
                a(f"- `{fid}` {e.get('file','?')}::{e.get('symbol','?')} — in {count}/{len(runs)} "
                  f"pass(es); {e.get('constraint_kind','?')}, evidence in "
                  f"**{e.get('refusal_evidence','?')}**")
        if seen_missed:
            a("\n**Migratable findings left alone:**\n")
            for fid, count in sorted(seen_missed.items(), key=lambda kv: -kv[1]):
                e = by_id.get(fid, {})
                a(f"- `{fid}` {e.get('symbol','?')} ({e.get('algorithm','?')}) — "
                  f"in {count}/{len(runs)} pass(es)")
        a("")

    print("\n".join(w))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
