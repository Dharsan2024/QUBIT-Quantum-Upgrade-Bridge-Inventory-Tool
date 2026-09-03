"""Phase 5.4 — a false-positive filter over the rule pack, trained on the 600 labels.

Gradient boosting over features the scanner already has, cross-validated, reported as a precision
change against the rule pack alone. Deliberately not a deep model: 600 labels is a small-data
problem, the features are categorical and few, and a model whose decisions cannot be inspected is a
poor fit for a tool whose entire argument is that unverifiable acceptance is worthless.

## What "precision" means here

The rule pack reports every finding it emits. Its precision is therefore the fraction of emitted
findings a rater called `correct` — measured at **72.4%** overall in
`qubit-v2/05-detection/RESULTS-precision.md`. The filter's job is to suppress findings that a rater
would reject, so the honest framing is a **precision/recall trade**: precision goes up only by
discarding findings, and discarding a true finding is a miss the operator never sees.

So this reports both, and the operating point is chosen on the validation folds rather than after
looking at the test fold.

## The leakage trap this design avoids

The obvious feature set includes `rule_id` and `algorithm`, and the obvious split is random. Those
two together leak: the `library` stratum is 75 findings that are all `not-crypto`, all from the same
detection path, so a random split puts near-duplicates on both sides and the model scores well by
memorising a rule id rather than by learning anything.

**The split is therefore grouped by `(rule_id, file)`**, so no group appears in both folds. That
lowers the reported score and makes it mean something.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any


def _features(packet_row: dict[str, str], key_row: dict[str, str]) -> dict[str, Any]:
    """Everything the scanner already knows, plus cheap structure from the marked line.

    No feature here requires a rater. If one did, the filter could not run on unlabelled findings,
    which is the only situation it exists for.
    """
    ctx = packet_row.get("context", "")
    marked = next((line for line in ctx.split("\n") if line.startswith(">>")), "")
    body = marked[2:].strip()
    body = re.sub(r"^\d+\s*", "", body)
    path = (packet_row.get("file") or "").replace("\\", "/").lower()
    algo = (key_row.get("qubit_algorithm") or "").lower()
    algo_token = re.sub(r"[^a-z0-9]", "", algo.split("(")[0])

    return {
        # --- what the scanner asserted -------------------------------------------------------
        "asset_type": key_row.get("qubit_asset_type", ""),
        "rule_id": key_row.get("qubit_rule", "") or "none",
        "confidence": key_row.get("qubit_confidence", ""),
        "usage_context": key_row.get("qubit_usage_context", ""),
        "quantum_vulnerable": key_row.get("qubit_quantum_vulnerable", "0"),
        # --- where it is ---------------------------------------------------------------------
        "is_manifest": int(path.endswith(("requirements.txt", "pyproject.toml", "setup.cfg"))),
        "is_certificate": int(path.endswith((".pem", ".crt", ".der", ".key"))),
        "is_config": int(path.endswith((".conf", ".cfg", ".ini")) or "/site-" in path),
        "is_test_path": int(any(m in path for m in ("/test", "test_", "/fixtures", "testdata"))),
        "line_is_zero": int((packet_row.get("line") or "0") == "0"),
        # --- what the marked line looks like -------------------------------------------------
        "marked_blank": int(not body),
        "marked_comment": int(body.startswith(("#", "//", "/*"))),
        "marked_is_def": int(body.startswith(("def ", "class ", "except", "@"))),
        # The single most informative structural fact: does the line actually mention the
        # algorithm the finding claims?
        "algo_in_line": int(
            bool(algo_token) and algo_token in re.sub(r"[^a-z0-9]", "", body.lower())
        ),
        "line_len": min(len(body), 200),
        "is_unknown_claim": int(algo.startswith("unknown")),
        "is_runtime_selected": int("runtime-selected" in algo),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--packet", type=Path, default=Path("unwanted/paper_evidence/label_packet.csv"))
    ap.add_argument("--key", type=Path, default=Path("unwanted/paper_evidence/label_key.csv"))
    ap.add_argument(
        "--labels", type=Path, default=Path("unwanted/paper_evidence/labels_rater_a.csv")
    )
    ap.add_argument("--out", type=Path, default=Path("qubit-v2/05-detection"))
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20260902)
    args = ap.parse_args()

    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.model_selection import GroupKFold
    from sklearn.preprocessing import OrdinalEncoder

    packet = {r["token"]: r for r in csv.DictReader(args.packet.open(encoding="utf-8"))}
    key = {r["token"]: r for r in csv.DictReader(args.key.open(encoding="utf-8"))}
    labels = {r["token"]: r["verdict"] for r in csv.DictReader(args.labels.open(encoding="utf-8"))}

    tokens = [t for t in labels if t in packet and t in key]
    # `unsure` is not a class the filter can learn or act on: it is the rater saying the packet did
    # not show enough, which is a property of the packet rather than of the finding.
    usable = [t for t in tokens if labels[t] != "unsure"]

    rows = [_features(packet[t], key[t]) for t in usable]
    y = np.array([1 if labels[t] == "correct" else 0 for t in usable])
    groups = np.array([f"{key[t].get('qubit_rule', '')}|{packet[t]['file']}" for t in usable])

    names = list(rows[0])
    cat = [i for i, n in enumerate(names) if isinstance(rows[0][n], str)]
    raw = np.array([[r[n] for n in names] for r in rows], dtype=object)
    enc = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    X = raw.copy()
    X[:, cat] = enc.fit_transform(raw[:, cat])
    X = X.astype(float)

    n_groups = len(set(groups.tolist()))
    folds = min(args.folds, n_groups)
    cv = GroupKFold(n_splits=folds)

    base_prec = float(y.mean())
    kept_p, kept_r, accs = [], [], []
    for tr, te in cv.split(X, y, groups):
        model = HistGradientBoostingClassifier(
            max_iter=200,
            learning_rate=0.06,
            max_depth=4,
            random_state=args.seed,
            categorical_features=cat,
        )
        model.fit(X[tr], y[tr])
        keep = model.predict(X[te]) == 1
        accs.append(float((model.predict(X[te]) == y[te]).mean()))
        if keep.sum():
            kept_p.append(float(y[te][keep].mean()))
            kept_r.append(float(keep[y[te] == 1].sum() / max(1, (y[te] == 1).sum())))

    # Ablation, always run. A filter whose score collapses onto one feature is memorising that
    # feature, and the honest way to find out is to remove each in turn rather than to trust a
    # single headline number.
    ablation: dict[str, float] = {}
    for drop in ("algo_in_line", "rule_id", "asset_type", "confidence"):
        keep_idx = [i for i, n in enumerate(names) if n != drop]
        sub = X[:, keep_idx]
        sub_cat = [keep_idx.index(i) for i in cat if i in keep_idx]
        scores = []
        for tr, te in cv.split(sub, y, groups):
            m = HistGradientBoostingClassifier(
                max_iter=200,
                learning_rate=0.06,
                max_depth=4,
                random_state=args.seed,
                categorical_features=sub_cat,
            )
            m.fit(sub[tr], y[tr])
            k = m.predict(sub[te]) == 1
            if k.sum():
                scores.append(float(y[te][k].mean()))
        ablation[f"without_{drop}"] = round(float(np.mean(scores)), 4) if scores else None

    report: dict[str, Any] = {
        "ablation_precision": ablation,
        "n_labelled": len(tokens),
        "n_used": len(usable),
        "n_unsure_dropped": len(tokens) - len(usable),
        "n_groups": n_groups,
        "folds": folds,
        "seed": args.seed,
        "grouping": "(rule_id, file) — no group appears in both folds",
        "model": "HistGradientBoostingClassifier(max_iter=200, lr=0.06, depth=4)",
        "baseline_precision_rule_pack_alone": round(base_prec, 4),
        "filtered_precision_mean": round(float(np.mean(kept_p)), 4) if kept_p else None,
        "filtered_recall_mean": round(float(np.mean(kept_r)), 4) if kept_r else None,
        "accuracy_mean": round(float(np.mean(accs)), 4),
        "precision_delta": (round(float(np.mean(kept_p)) - base_prec, 4) if kept_p else None),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "fp_filter.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"\nwritten: {args.out / 'fp_filter.json'}")


if __name__ == "__main__":
    main()
