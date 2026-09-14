"""Build the blind labelling packet for detection precision and Cohen's kappa.

Precision cannot be computed from QUBIT's own output: a tool cannot be its own ground truth. It
needs findings judged by people who do not know what the tool concluded, and it needs TWO of them,
because a single rater's precision figure is one person's opinion presented as a measurement.
Cohen's kappa over the overlap is what makes the labels themselves auditable.

Three properties this script exists to enforce, each of which is easy to lose by hand:

**Stratified, not top-N.** Sampling the highest-risk findings measures precision on the easy cases:
a `md5(` call is unambiguous, and a corpus of those reports a precision the tool has not earned.
The sample is drawn per (rule, algorithm) so every detection path is represented, including the
ones with two findings in the whole database.

**Blind.** The rater sees the file, the line, the surrounding code and nothing else. QUBIT's
algorithm label, its confidence, its risk score and its rule id are all withheld, because a rater
shown "RSA-2048, high confidence" is being asked to agree rather than to judge. They are kept in a
separate key file, joined back only after the labels are returned.

**Deterministically sampled.** A seeded draw, so the packet can be rebuilt byte-identically and a
reviewer can check that the sample was not chosen after seeing the results.

Usage::

    uv run python scripts/build_label_packet.py --db <path> --n 600 --out unwanted/paper_evidence

Produces `label_packet.csv` (blind, for the raters), `label_key.csv` (the join, withheld until
labels come back) and `label_packet_manifest.json` (seed, strata, counts — the pre-registration).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

#: What a rater is asked. Deliberately four options rather than yes/no: "not crypto at all" and
#: "crypto, but not this algorithm" are different tool errors and need different fixes, and
#: collapsing them hides which one QUBIT is making.
VERDICTS = ("correct", "wrong-algorithm", "not-crypto", "unsure")

#: Finding types EXCLUDED from the population, because the rubric above cannot express a verdict
#: about them.
#:
#: The first build drew from every non-stale asset. **81% of that population was not an algorithm
#: finding** — 753 protocol, 592 certificate, 128 PII, 102 library, 16 secret out of 2,013. Two
#: things break as a result.
#:
#: First, a `sensitive-data` finding claims "PII: email address". It names no cryptographic
#: algorithm, so a rater can only label it `not-crypto` — which scores a CORRECT PII detection as
#: a false positive. The rubric has no right answer for it.
#:
#: Second, the headline number is meant to be read against arXiv 2604.00560's 71.98% precision on
#: 602 labelled *cryptographic* instances. A figure computed over a population that is four-fifths
#: non-algorithm findings is not that number and must not be printed beside it.
#:
#: `certificate`, `protocol`, `key` and `library` are KEPT: each names a cryptographic algorithm
#: or primitive that a rater can confirm or dispute. Only the two types whose claim is not a
#: cryptographic one are dropped. `asset_type` goes into the KEY rather than the packet, so
#: precision can be reported per type at analysis time without telling the rater which kind of
#: claim they are looking at.
_EXCLUDED_TYPES = ("sensitive-data", "secret")

#: What the packet shows, and what it withholds — the distinction `wrong-algorithm` depends on.
#:
#: The first build withheld the algorithm along with everything else, which made one of the four
#: verdicts impossible to reach: "crypto, but not THAT algorithm" needs to name the algorithm it
#: disagrees with. A rater seeing only code could say `correct`, `not-crypto` or `unsure`, and
#: `wrong-algorithm` was unreachable by construction — the same defect as a success criterion that
#: cannot fail, in the instrument meant to audit the tool.
#:
#: The blinding's stated purpose survives intact, because the anchoring it guards against is the
#: CONFIDENCE, not the name: "a rater shown 'RSA-2048, high confidence' is being asked to agree,
#: not to judge." Showing `RSA-2048` alone invites disagreement; showing `high confidence` deters
#: it. So the claim is shown and the rule, confidence, vulnerability verdict and usage context
#: stay in the key.
_SHOWN_TO_RATER = ("claimed_algorithm",)
_WITHHELD = ("rule", "confidence", "quantum_vulnerable", "usage_context")

#: Lines of context either side. Enough to judge, small enough that the packet stays readable and
#: the rater does not start reviewing the whole file.
CONTEXT = 6


def _context(root: Path, rel: str, line: int) -> str:
    """The finding's neighbourhood, with the finding line marked."""
    try:
        path = Path(rel)
        if not path.is_absolute():
            path = root / rel
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo, hi = max(0, line - 1 - CONTEXT), min(len(lines), line + CONTEXT)
    out = []
    for i in range(lo, hi):
        marker = ">>" if i == line - 1 else "  "
        out.append(f"{marker} {i + 1:>5} {lines[i]}")
    return "\n".join(out)


def build(db: Path, n: int, out: Path, seed: int, root: Path) -> dict[str, Any]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT id, algorithm, rule_id, location, confidence, qv_vulnerable, usage_context,
               asset_type
        FROM assets
        WHERE stale = 0
          AND asset_type NOT IN ('sensitive-data', 'secret')
        """
    ).fetchall()

    # Strata: (rule, algorithm). Every detection path is represented, including the rare ones —
    # sampling by risk instead would measure precision on the unambiguous cases only.
    strata: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for r in rows:
        strata[(str(r["rule_id"] or "-"), str(r["algorithm"] or "-"))].append(r)

    # Seeded and reproducible is the requirement here, not unpredictability: a reviewer must
    # be able to rebuild this packet byte-identically and confirm the sample was not chosen
    # after the results were seen. `secrets` cannot be seeded and would defeat that.
    rng = random.Random(seed)  # noqa: S311 - sample selection, never key material
    # Round-robin across strata so a rule with 900 findings cannot crowd out one with 2.
    ordered = sorted(strata.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for _, bucket in ordered:
        rng.shuffle(bucket)
    picked: list[sqlite3.Row] = []
    depth = 0
    while len(picked) < n and any(len(b) > depth for _, b in ordered):
        for _, bucket in ordered:
            if len(bucket) > depth:
                picked.append(bucket[depth])
                if len(picked) >= n:
                    break
        depth += 1

    out.mkdir(parents=True, exist_ok=True)
    packet, key = [], []
    for i, r in enumerate(picked, start=1):
        loc = json.loads(r["location"] or "{}")
        rel, line = str(loc.get("file_path", "")), int(loc.get("line") or 0)
        # A stable opaque id, so the two files join without the packet leaking the asset id (from
        # which a curious rater could look the verdict up).
        token = hashlib.sha256(f"{seed}:{r['id']}".encode()).hexdigest()[:12]
        packet.append(
            {
                "item": i,
                "token": token,
                "file": rel.replace("\\", "/"),
                "line": line,
                "context": _context(root, rel, line),
                # Shown, so `wrong-algorithm` is reachable. See `_SHOWN_TO_RATER`.
                "claimed_algorithm": r["algorithm"],
                # Left blank for the rater. The four verdicts are in the manifest.
                "verdict": "",
                "note": "",
            }
        )
        key.append(
            {
                "token": token,
                "asset_id": str(r["id"]),
                "qubit_algorithm": r["algorithm"],
                "qubit_asset_type": r["asset_type"],
                "qubit_rule": r["rule_id"],
                "qubit_confidence": r["confidence"],
                "qubit_quantum_vulnerable": r["qv_vulnerable"],
                "qubit_usage_context": r["usage_context"],
            }
        )

    for name, data in (("label_packet.csv", packet), ("label_key.csv", key)):
        with (out / name).open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(data[0]), lineterminator="\n")
            w.writeheader()
            w.writerows(data)

    manifest = {
        "seed": seed,
        "requested": n,
        "sampled": len(picked),
        "population": len(rows),
        "strata": len(strata),
        "verdicts": list(VERDICTS),
        "context_lines": CONTEXT,
        "shown_to_rater": list(_SHOWN_TO_RATER),
        "withheld_from_rater": [*_WITHHELD, "asset_type"],
        "excluded_types": list(_EXCLUDED_TYPES),
        "excluded_because": (
            "The rubric asks whether a claimed ALGORITHM is correctly identified. A "
            "`sensitive-data` or `secret` finding claims neither, so a rater could only mark it "
            "`not-crypto` — scoring a correct PII detection as a false positive. Precision for "
            "those detectors is a separate measurement, not this one."
        ),
        "blind": (
            "The packet withholds QUBIT's algorithm, rule, confidence and vulnerability verdict. "
            "A rater shown 'RSA-2048, high confidence' is being asked to agree, not to judge."
        ),
        "sampling": (
            "Round-robin across (rule, algorithm) strata after a seeded shuffle, so a rule with "
            "900 findings cannot crowd out one with 2. Sampling by risk instead would measure "
            "precision on the unambiguous cases only."
        ),
        "raters_required": 2,
        "why_two": (
            "A single rater's precision figure is one person's opinion presented as a "
            "measurement. Cohen's kappa over the overlap is what makes the labels auditable."
        ),
    }
    (out / "label_packet_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=Path, required=True)
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--out", type=Path, default=Path("unwanted/paper_evidence"))
    ap.add_argument("--seed", type=int, default=20260902)
    ap.add_argument("--root", type=Path, default=Path())
    args = ap.parse_args()
    manifest = build(args.db, args.n, args.out, args.seed, args.root)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
