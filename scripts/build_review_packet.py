"""Phase 8.4 — the blind patch-review packet.

Forty accepted patches, arm and engine labels stripped, two raters, rubric
correct / incomplete / wrong / harmful plus "would a maintainer merge this?".

**This is the only part of the evaluation whose dependent variable is not "our own gate said yes".**
Every other number in the study is produced by machinery this project wrote; a human reading a diff
and saying "no" is the one measurement that machinery cannot talk itself into.

## What is stripped, and why

The arm, the generator (`template` or `llm`), the engine and the model name. A reviewer told a diff
came from a language model reads it differently from one told it came from a deterministic codemod,
and the question here is whether the CHANGE is good — not whose it is. The join key is an opaque
token, as in the detection packet.

The rule id and the target algorithm are SHOWN: a reviewer needs to know what the patch was trying
to do in order to judge whether it did it. Withholding that would make `incomplete` unreachable, the
same defect the detection packet had when it withheld the algorithm.

## On n

The pre-registration says 40. It is drawn from whatever accepted patches exist, and if that is fewer
than 40 the packet says so rather than padding it — on the pre-registered corpus the number is
**zero**, because every codemod-reachable finding there is somebody else's contract.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def _collect(workdir: Path, corpus: str, seed: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for arm_dir in sorted(p for p in workdir.iterdir() if p.is_dir()):
        for db in sorted(arm_dir.glob("*.db")):
            try:
                con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
                con.row_factory = sqlite3.Row
            except sqlite3.Error:
                continue
            rows = con.execute(
                "SELECT p.*, t.rule_id FROM migration_patches p "
                "LEFT JOIN migration_tasks t ON t.id = p.task_id"
            ).fetchall()
            for r in rows:
                report = json.loads(r["validation_json"] or "{}")
                if not report.get("passed"):
                    continue
                token = hashlib.sha256(f"{seed}:{r['id']}".encode()).hexdigest()[:12]
                out.append(
                    {
                        "token": token,
                        "corpus": corpus,
                        "file": str(r["file_path"] or ""),
                        "rule_id": str(r["rule_id"] or ""),
                        "diff": str(r["diff_text"] or ""),
                        "evidence_level": r["evidence_level"],
                        # withheld from the packet, kept for the key
                        "_arm": arm_dir.name,
                        "_generator": str(r["generator"] or ""),
                        "_model": str(r["model_name"] or ""),
                    }
                )
            con.close()
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workdir", type=Path, action="append", required=True)
    ap.add_argument("--corpus", action="append", required=True)
    ap.add_argument("--out", type=Path, default=Path("unwanted/paper_evidence"))
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=20260902)
    args = ap.parse_args()

    if len(args.workdir) != len(args.corpus):
        raise SystemExit("--workdir and --corpus must be given the same number of times")

    patches: list[dict[str, Any]] = []
    for wd, corpus in zip(args.workdir, args.corpus, strict=True):
        patches.extend(_collect(wd, corpus, args.seed))

    # Deduplicate on the diff: the same finding patched identically by two arms is one patch to
    # review, not two, and counting it twice would inflate n with no new information.
    seen: dict[str, dict[str, Any]] = {}
    for p in patches:
        digest = hashlib.sha256(p["diff"].encode()).hexdigest()
        seen.setdefault(digest, p)
    unique = sorted(seen.values(), key=lambda p: (p["corpus"], p["file"], p["token"]))[: args.n]

    args.out.mkdir(parents=True, exist_ok=True)
    packet = args.out / "review_packet.csv"
    with packet.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(
            ["item", "token", "corpus", "file", "rule_id", "diff", "verdict", "merge", "note"]
        )
        for i, p in enumerate(unique, start=1):
            w.writerow([i, p["token"], p["corpus"], p["file"], p["rule_id"], p["diff"], "", "", ""])

    key = args.out / "review_key.csv"
    with key.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["token", "arm", "generator", "model", "evidence_level"])
        for p in unique:
            w.writerow([p["token"], p["_arm"], p["_generator"], p["_model"], p["evidence_level"]])

    manifest = {
        "requested": args.n,
        "available": len(seen),
        "in_packet": len(unique),
        "seed": args.seed,
        "corpora": args.corpus,
        "verdicts": ["correct", "incomplete", "wrong", "harmful"],
        "merge_question": "Would a maintainer of this project merge this patch as-is? yes / no",
        "withheld": ["arm", "generator", "model", "evidence_level"],
        "shown": ["corpus", "file", "rule_id", "diff"],
        "why_blind": (
            "A reviewer told a diff came from a language model reads it differently from one told "
            "it came from a codemod. The question is whether the change is good, not whose it is."
        ),
        "short_of_target": len(unique) < args.n,
        "note_if_short": (
            "Fewer than the pre-registered 40 accepted patches exist. On the pre-registered corpus "
            "(pyload) the number is ZERO: every codemod-reachable finding there is protocol-"
            "mandated or an established-KDF parameter change, and the pipeline advises rather than "
            "patches. Reported rather than padded."
        )
        if len(unique) < args.n
        else "",
    }
    (args.out / "review_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"\nwritten: {packet}\n         {key}")


if __name__ == "__main__":
    main()
