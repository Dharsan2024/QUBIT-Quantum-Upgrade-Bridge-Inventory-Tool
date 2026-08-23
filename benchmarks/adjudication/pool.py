"""Draw a blind, stratified sample of detector findings for hand adjudication.

The corpus sweep reports that 76-96% of some detectors' exclusive findings are mentions rather than
uses. That number comes from `benchmarks/oracles/adjudicate.py`, which is a heuristic: it looks at
one line, checks whether the algorithm name survives outside quotes, and decides. It has already
been wrong twice in ways that reversed a headline -- once by classifying truncated text, once by
destroying word boundaries -- and both times the error was found by reading output rather than by
the classifier noticing.

So the classifier gets measured instead of believed. This module draws the sample it gets measured
on, and the sample has to be drawn in a way that cannot be steered:

* **Blind.** `worksheet.json` carries the id, repository, file, line, family and +/-3 lines of
  source. It does not carry the detector, the rule id, or the heuristic's opinion. Those go to
  `key.json`, a separate file, unread until scoring. One of the four detectors was written by the
  person running this; a label that can see `detector: qubit` is not evidence about QUBIT.
* **Stratified.** Exclusive findings -- reported by exactly one detector -- are sampled heavily,
  because that is where both precision and recall live. Agreed findings are sampled lightly, to
  check that agreement means truth rather than to estimate anything from it.
* **Seeded and stable.** An item's id is a hash of `(repo, path, line, family)`, so a label survives
  a re-run of the sweep, a re-draw of the sample, and a change to any detector. Labels accumulate
  instead of being invalidated every time the corpus is regenerated.

The exclusive stratum is read straight out of the sweep's saved samples, which cost nothing. The
agreed stratum needs the detectors re-run, so it is drawn from a handful of the corpus's *smallest*
repositories (`--agreed-from`) and reported as the sub-corpus it is, rather than quietly pooled.

**Held-out draws** (`--exclude-labelled labels.jsonl --limit N`). The first 601 labels were used
twice: to measure the screening classifier and the HNDL scanner, and then to repair both. Every
figure that came out afterwards is therefore in-sample, and in-sample numbers answer "were these
specific defects fixed", not "how well does it work". Excluding the already-labelled ids draws from
items nobody has looked at, so the same scoring run answers the second question too.

The reserve exists only because the sweep now saves 60 exclusive findings per detector per
repository instead of 25. At 25 the first pass consumed everything and there was nothing left to
hold back -- which is how the whole evaluation ended up in-sample without anyone deciding it should.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "oracles"))

from adjudicate import is_repository_source  # noqa: E402
from base import Finding, family  # noqa: E402

LOCK_FILE = REPO_ROOT / "benchmarks" / "corpus" / "corpus.lock.json"
SEED = 20260821
CONTEXT_LINES = 3

EXCLUSIVE = "exclusive"
AGREED = "agreed"


def item_id(repository: str, path: str, line: int, fam: str) -> str:
    """A name for a site that does not change when anything about the detectors changes.

    Deliberately not derived from the detector, the rule, or the sample index: a label is a
    statement about a line of somebody else's source code, and it stays true when QUBIT's rules are
    rewritten the next morning.
    """
    key = f"{repository}|{path}|{line}|{fam}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]  # noqa: S324 - a name, not a MAC


def read_context(root: Path, path: str, line: int) -> tuple[str, list[str]]:
    """The line itself, and the lines around it.

    Context is not decoration. A ban list spans several lines and its first entry looks exactly like
    a call argument; `AMBIGUOUS` would swallow most of the interesting cases without it.
    """
    target = root / path
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", []
    index = line - 1
    if not (0 <= index < len(lines)):
        return "", []
    low = max(0, index - CONTEXT_LINES)
    high = min(len(lines), index + CONTEXT_LINES + 1)
    numbered = [f"{n + 1:>6}  {lines[n]}"[:300] for n in range(low, high)]
    return lines[index].strip()[:300], numbered


def _entry(
    *,
    repository: str,
    root: Path,
    path: str,
    line: int,
    fam: str,
    stratum: str,
    detectors: list[str],
    rule_id: str,
    heuristic: str,
) -> tuple[dict, dict] | None:
    source, context = read_context(root, path, line)
    if not source:
        return None
    ident = item_id(repository, path, line, fam)
    visible = {
        "id": ident,
        "repository": repository,
        "path": path,
        "line": line,
        "family": fam,
        "source": source,
        "context": context,
    }
    hidden = {
        "id": ident,
        "stratum": stratum,
        "detectors": sorted(detectors),
        "rule_id": rule_id,
        "heuristic": heuristic,
    }
    return visible, hidden


def exclusive_items(results_dir: Path, lock: dict) -> list[tuple[dict, dict]]:
    """Every exclusive finding the sweep already sampled, with its blinded provenance split off."""
    out: list[tuple[dict, dict]] = []
    seen: set[str] = set()
    for result in sorted(results_dir.glob("*.json")):
        if result.name == "summary.json":
            continue
        record = json.loads(result.read_text(encoding="utf-8"))
        repository = record["repository"]
        meta = lock["repositories"].get(repository)
        if meta is None:
            continue
        root = REPO_ROOT / meta["path"]
        for detector, data in sorted(record.get("adjudication", {}).items()):
            for finding in data.get("sample", []):
                fam = finding["family"]
                if not is_repository_source(finding["path"]):
                    # The saved samples predate the vendored-directory filter; applying it here
                    # keeps the labelled pool over the same files as the comparison.
                    continue
                ident = item_id(repository, finding["path"], finding["line"], fam)
                if ident in seen:
                    # Two detectors can both be "exclusive" at one site when they disagree about
                    # the family; the site is still one line and gets one label.
                    continue
                seen.add(ident)
                entry = _entry(
                    repository=repository,
                    root=root,
                    path=finding["path"],
                    line=finding["line"],
                    fam=fam,
                    stratum=EXCLUSIVE,
                    detectors=[detector],
                    rule_id=finding.get("rule_id", ""),
                    heuristic=finding.get("class", ""),
                )
                if entry:
                    out.append(entry)
    return out


def agreed_items(
    repositories: list[str], lock: dict, *, per_repo: int, rng: random.Random
) -> list[tuple[dict, dict]]:
    """Sites at least two detectors reported, re-derived by running the detectors again.

    The sweep does not persist these -- it only keeps a sample of the exclusive ones -- so this
    costs a full scan per repository. It is therefore pointed at the corpus's cheapest members and
    reported as a sub-corpus rather than pooled into the headline.
    """
    from run_multi import collect

    out: list[tuple[dict, dict]] = []
    for repository in repositories:
        meta = lock["repositories"].get(repository)
        if meta is None:
            print(f"  {repository}: not in the lockfile, skipped", flush=True)
            continue
        root = REPO_ROOT / meta["path"]
        if not root.is_dir():
            print(f"  {repository}: not cloned, skipped", flush=True)
            continue
        print(f"  {repository}: running detectors...", flush=True)
        findings, _ = collect(root)

        by_site: dict[tuple[str, str], dict[str, Finding]] = defaultdict(dict)
        for detector, hits in findings.items():
            for hit in hits:
                if is_repository_source(hit.path):
                    by_site[hit.site].setdefault(detector, hit)

        agreed = [(site, seen) for site, seen in by_site.items() if len(seen) >= 2]
        agreed.sort()
        for site, seen in rng.sample(agreed, min(per_repo, len(agreed))):
            path, fam = site
            any_hit = next(iter(seen.values()))
            entry = _entry(
                repository=repository,
                root=root,
                path=path,
                line=any_hit.line,
                fam=family(fam),
                stratum=AGREED,
                detectors=list(seen),
                rule_id=any_hit.rule_id,
                heuristic="",
            )
            if entry:
                out.append(entry)
        print(f"  {repository}: {len(agreed)} agreed sites", flush=True)
    return out


def already_labelled(path: Path | None) -> set[str]:
    """Ids that have a label, so a held-out draw can avoid them.

    Read from the label file rather than from a worksheet: a worksheet says what was *shown*, and
    the question here is what was *judged*.
    """
    if path is None or not path.exists():
        return set()
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("id"):
            seen.add(str(row["id"]))
    return seen


def build(
    results_dir: Path,
    *,
    agreed_from: list[str] | None = None,
    agreed_per_repo: int = 12,
    limit: int | None = None,
    exclude: set[str] | None = None,
    seed: int = SEED,
) -> tuple[list[dict], list[dict]]:
    lock = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    rng = random.Random(seed)  # noqa: S311 - choosing which findings to read

    entries = exclusive_items(results_dir, lock)
    if agreed_from:
        entries += agreed_items(agreed_from, lock, per_repo=agreed_per_repo, rng=rng)
    if exclude:
        entries = [(visible, hidden) for visible, hidden in entries if visible["id"] not in exclude]

    # Shuffled, so the annotator never works through one repository or one detector in a run and
    # drifts into a house style for it. The seed keeps the order reproducible.
    rng.shuffle(entries)
    if limit is not None:
        entries = entries[:limit]

    worksheet = [visible for visible, _ in entries]
    key = [hidden for _, hidden in entries]
    return worksheet, key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=REPO_ROOT / "benchmarks/corpus/results")
    parser.add_argument("--out", type=Path, default=HERE)
    parser.add_argument(
        "--agreed-from",
        nargs="*",
        default=[],
        help="repositories to re-scan for the agreed stratum; pick small ones",
    )
    parser.add_argument("--agreed-per-repo", type=int, default=12)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--exclude-labelled",
        type=Path,
        default=None,
        help="a labels.jsonl whose ids to skip, for a held-out draw",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=SEED,
        help="a held-out draw should use its own seed, so it is not the same shuffle re-cut",
    )
    args = parser.parse_args()

    excluded = already_labelled(args.exclude_labelled)
    worksheet, key = build(
        args.results,
        agreed_from=args.agreed_from,
        agreed_per_repo=args.agreed_per_repo,
        limit=args.limit,
        exclude=excluded,
        seed=args.seed,
    )
    if excluded:
        print(f"excluding {len(excluded)} already-labelled ids")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "worksheet.json").write_text(json.dumps(worksheet, indent=1), encoding="utf-8")
    (args.out / "key.json").write_text(json.dumps(key, indent=1), encoding="utf-8")

    strata: dict[str, int] = defaultdict(int)
    for hidden in key:
        strata[hidden["stratum"]] += 1
    print(f"\n{len(worksheet)} items: " + ", ".join(f"{k} {v}" for k, v in sorted(strata.items())))
    print(f"wrote {args.out / 'worksheet.json'} (blind) and {args.out / 'key.json'} (provenance)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
