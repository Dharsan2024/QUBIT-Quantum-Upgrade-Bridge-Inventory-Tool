"""Weak labeling + real-code transfer eval for the sensitivity classifier (doc 02 §6.3.4 step 2-3).

Given harvested real-code context windows, assign two weak labels — the transparent heuristic
(sensitivity_rules regexes applied to the window) and a local-LLM zero-shot pass — then measure:
  - heuristic <-> LLM agreement (weak-labeler consistency),
  - the synthetic-trained DistilBERT's agreement with the weak consensus (real transfer).

Weak labels are a NOISY PROXY, never human ground truth; every number here is reported as such.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import RiskConfig, load_config
from .harvest import _llm_label
from .vocab import CLASSES


def heuristic_label_text(text: str, cfg: RiskConfig) -> str:
    """Apply sensitivity_rules regexes to a context window.

    Mirrors classify_sensitivity scoring, which searches the evidence snippet text.
    """
    rules = cfg.sensitivity_rules
    scores: dict[str, float] = {}
    for rule in rules["rules"]:
        if re.search(rule["regex"], text):
            scores[rule["class"]] = scores.get(rule["class"], 0.0) + float(rule["weight"])
    threshold = float(rules["score_threshold"])
    if not scores:
        return "unknown"
    top = max(scores.values())
    if top < threshold:
        return "unknown"
    winners = [c for c, s in scores.items() if s == top]
    order = rules["tie_break_order"]
    return min(winners, key=lambda c: order.index(c) if c in order else len(order))


def label_windows(
    raw_path: Path, out_path: Path, *, model: str, cfg: RiskConfig | None = None
) -> dict:
    """Weak-label every harvested window; write labeled JSONL; return an agreement report."""
    cfg = cfg or load_config()
    rows = [json.loads(x) for x in raw_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    labeled = []
    agree = 0
    for r in rows:
        text = r["text"]
        heur = heuristic_label_text(text, cfg)
        llm = _llm_label(text, model)
        consensus = heur if (heur == llm and heur != "unknown") else None
        if consensus:
            agree += 1
        labeled.append({**r, "heuristic_label": heur, "llm_label": llm, "consensus": consensus})
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for x in labeled:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")
    n = len(labeled)
    dist: dict[str, int] = {}
    for x in labeled:
        if x["consensus"]:
            dist[x["consensus"]] = dist.get(x["consensus"], 0) + 1
    return {
        "n_windows": n,
        "heuristic_llm_agreement": round(agree / n, 4) if n else 0.0,
        "n_consensus": agree,
        "consensus_class_dist": dist,
    }


def eval_model_on_real(labeled_path: Path, model_dir: Path) -> dict:
    """Agreement of the synthetic-trained DistilBERT with the weak consensus on real code."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    rows = [
        json.loads(x)
        for x in labeled_path.read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]
    consensus_rows = [r for r in rows if r.get("consensus")]
    if not consensus_rows:
        return {"error": "no consensus-labeled windows to evaluate"}

    tok = AutoTokenizer.from_pretrained(str(model_dir))
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
    model.eval()
    id2label = model.config.id2label

    correct = 0
    per_class_tot: dict[str, int] = {}
    per_class_hit: dict[str, int] = {}
    for r in consensus_rows:
        x = tok(r["text"], return_tensors="pt", truncation=True, max_length=256)
        with torch.no_grad():
            pred = id2label[int(model(**x).logits.argmax(-1))]
        gold = r["consensus"]
        per_class_tot[gold] = per_class_tot.get(gold, 0) + 1
        if pred == gold:
            correct += 1
            per_class_hit[gold] = per_class_hit.get(gold, 0) + 1
    n = len(consensus_rows)
    recalls = [per_class_hit.get(c, 0) / per_class_tot[c] for c in CLASSES if per_class_tot.get(c)]
    macro_recall = round(sum(recalls) / len(recalls), 4) if recalls else 0.0
    return {
        "n_consensus_eval": n,
        "model_vs_consensus_accuracy": round(correct / n, 4),
        "macro_recall_over_present_classes": macro_recall,
        "present_classes": sorted(per_class_tot),
    }


__all__ = ["eval_model_on_real", "heuristic_label_text", "label_windows"]
