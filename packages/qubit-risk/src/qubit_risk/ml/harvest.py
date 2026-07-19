"""Tier-2 real-code harvesting + weak labeling (doc 02 §6.3.4 step 2).

Runs the scanner over real permissive repos to collect genuine crypto findings, builds the §6.3.1
context window for each, and weak-labels it two ways: the transparent heuristic classifier and a
local-LLM (Ollama) zero-shot pass. Agreement -> a weak training label; disagreement -> the
adjudication queue (the valuable data, held out from weak-label training per doc 02 §6.3.4 step 3).

Robust by construction: scans file-by-file so one pathological file can't abort a whole repo, and
the LLM labeler degrades to heuristic-only if Ollama is unreachable.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from ..config import RiskConfig, load_config
from ..sensitivity import classify_sensitivity
from .vocab import CLASSES

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_COMMENT_RE = re.compile(r"(?://+|#+)\s*(.+)$")
_SKIP_DIRS = {".git", "node_modules", "vendor", "testdata", "third_party", "dist", "build", ".venv"}
_EXT_LANG = {
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".js": "javascript",
    ".ts": "javascript",
}


@dataclass
class HarvestExample:
    text: str
    heuristic_label: str
    llm_label: str
    agree: bool
    algorithm: str
    repo: str
    file_path: str
    language: str


def _context_window(asset) -> str:
    """Build the §6.3.1 context window from a scanned asset.

    Uses the M2 evidence.context (enclosing function/class + data-flow symbols) in addition to the
    ±5-line snippet — the enclosing scope is where real-world sensitivity signal lives.
    """
    snippet = (asset.evidence.snippet if asset.evidence else "") or ""
    path = asset.location.file_path or "" if asset.location else ""
    ctx = asset.evidence.context if asset.evidence else None
    enclosing = ""
    ctx_ids: list[str] = []
    if ctx is not None:
        fn = ctx.extra.get("enclosing_function")
        cls = ctx.extra.get("enclosing_class")
        enclosing = " ".join(str(x) for x in (cls, fn) if x)
        ctx_ids = list(ctx.symbols.get("defined", [])) + list(ctx.symbols.get("used", []))
    snippet_ids = _IDENT_RE.findall(snippet)
    ids = sorted(set(ctx_ids) | set(snippet_ids))[:24]
    comments = []
    for line in snippet.splitlines():
        m = _COMMENT_RE.search(line.strip())
        if m:
            comments.append(m.group(1).strip())
    comment_txt = "; ".join(comments)[:200]
    code = " ".join(snippet.split())[:400]
    return (
        f"path: {path} | scope: {enclosing} | ids: {', '.join(ids)} "
        f"| comments: {comment_txt} | code: {code}"
    )


def _llm_label(window: str, model: str, base_url: str = "http://127.0.0.1:11434") -> str:
    """Zero-shot classify the window into one of the 7 classes or 'unknown' via local Ollama."""
    import urllib.error
    import urllib.request

    labels = ", ".join([*CLASSES, "unknown"])
    prompt = (
        "Classify the DATA SENSITIVITY of the data handled near this cryptographic code into "
        f"exactly one label from: {labels}.\n"
        "phi=health, financial=money/payments, pii=personal identifiers, "
        "credentials=passwords/keys/tokens, ip=proprietary/trade-secret, "
        "ephemeral=short-lived session/nonce/otp, public=non-sensitive, unknown=cannot tell.\n"
        "Answer with ONLY the label word.\n\n" + window[:1200]
    )
    body = json.dumps(
        {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.0}}
    ).encode()
    if not base_url.startswith(("http://", "https://")):
        return "unknown"
    req = urllib.request.Request(  # noqa: S310 - scheme checked, local server
        f"{base_url}/api/generate", data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            out = json.load(resp).get("response", "").strip().lower()
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return "unknown"
    for c in [*CLASSES, "unknown"]:
        if c in out:
            return c
    return "unknown"


def _iter_source_files(repo: Path):
    for p in repo.rglob("*"):
        if p.is_file() and p.suffix in _EXT_LANG and not (_SKIP_DIRS & set(p.parts)):
            yield p


def harvest_repo(
    repo: Path,
    *,
    model: str,
    cfg: RiskConfig | None = None,
    max_windows: int | None = None,
    use_llm: bool = True,
) -> list[HarvestExample]:
    """Scan one repo file-by-file, weak-label each crypto finding. Never aborts on a bad file."""
    from qubit_scanner import scan_paths

    cfg = cfg or load_config()
    out: list[HarvestExample] = []
    for f in _iter_source_files(repo):
        try:
            res = scan_paths([f], repo=repo.name)
        except Exception:  # noqa: S112 - pathological file, skip and keep harvesting
            continue
        for asset in res.assets:
            window = _context_window(asset)
            heur = classify_sensitivity(asset, cfg).sensitivity
            llm = _llm_label(window, model) if use_llm else "unknown"
            out.append(
                HarvestExample(
                    text=window,
                    heuristic_label=heur,
                    llm_label=llm,
                    agree=(heur == llm and heur != "unknown"),
                    algorithm=asset.algorithm,
                    repo=repo.name,
                    file_path=(asset.location.file_path or "") if asset.location else "",
                    language=_EXT_LANG.get(f.suffix, "python"),
                )
            )
            if max_windows and len(out) >= max_windows:
                return out
    return out


def scan_repo_resilient(repo: Path, work_dir: Path) -> list[dict]:
    """Scan a repo surviving native tree-sitter segfaults via a checkpointing worker subprocess.

    Returns raw finding dicts {text, algorithm, file_path, language}; weak labeling is applied
    afterwards in the stable driver. Files that crash the parser are skipped and counted.
    """
    import subprocess
    import sys

    work_dir.mkdir(parents=True, exist_ok=True)
    files = [str(p) for p in _iter_source_files(repo)]
    list_file = work_dir / f"{repo.name}.files.txt"
    out_jsonl = work_dir / f"{repo.name}.raw.jsonl"
    progress = work_dir / f"{repo.name}.progress.txt"
    list_file.write_text("\n".join(files), encoding="utf-8")
    out_jsonl.write_text("", encoding="utf-8")

    start = 0
    skipped = 0
    while start < len(files):
        r = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-m",
                "qubit_risk.ml._scan_worker",
                repo.name,
                str(list_file),
                str(start),
                str(out_jsonl),
                str(progress),
            ],
            capture_output=True,
        )
        last = progress.read_text(encoding="utf-8").strip()
        if last == "-1":
            break  # clean finish
        idx = int(last)
        if r.returncode != 0:  # worker crashed (likely segfault) on files[idx] -> skip it
            skipped += 1
            start = idx + 1
        else:
            start = idx + 1
    records = [
        json.loads(line)
        for line in out_jsonl.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if skipped:
        records.append({"__skipped__": skipped})
    return records


def write_jsonl(examples: list[HarvestExample], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for ex in examples:
            fh.write(json.dumps(asdict(ex), ensure_ascii=False) + "\n")
    return len(examples)


__all__ = ["HarvestExample", "harvest_repo", "write_jsonl"]
