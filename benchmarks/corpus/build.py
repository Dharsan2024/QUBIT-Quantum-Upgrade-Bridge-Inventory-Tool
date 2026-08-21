"""Build a corpus with a sampling frame, instead of picking repositories that looked interesting.

The first version of this benchmark ran on four repositories chosen because they were convenient.
Two of the four turned out to be bad choices for reasons that only became visible afterwards:
`cryptoscan` is a detector's own pattern tables rendered as source (22.3%, measuring agreement with
a word list) and `pqaudit` is the oracle itself. That is what a convenience sample does -- the
selection carries assumptions nobody wrote down, and they surface as results.

So selection happens here, before any detector runs, and it is recorded:

    frame   -- query GitHub's search API for the most-starred repositories in each language
               stratum. This is the population being sampled FROM, written to frame.json.
    sample  -- draw from each stratum with a FIXED SEED. Rerunning gives the same corpus; changing
               the seed to get a better number would be visible in the diff.
    clone   -- shallow-clone each sample at a resolved commit and record it in corpus.lock.json,
               so a rerun a year later either gets identical source or fails loudly.

**What this is and is not.** Sampling from "most-starred repositories in language L" is a
stratified sample of *popular open-source software*, not of all software. Popular projects are
better maintained and more likely to use cryptography correctly and conventionally, which probably
makes every detector look better than it would on average code. That is a threat to external
validity, it is not fixable without a corpus nobody has, and it is stated rather than hidden.

**Inclusion criterion, fixed in advance.** A cloned repository enters the analysis only if at least
TWO detectors report at least one finding in it. A repository no detector fires on carries no
information about relative recall, and one only QUBIT fires on cannot be adjudicated by agreement.
The criterion is applied uniformly and never with reference to which detector did better -- if it
were relaxed after seeing results, the corpus would be selected on the outcome.

Usage:

    uv run python benchmarks/corpus/build.py frame
    uv run python benchmarks/corpus/build.py sample --per-stratum 2
    uv run python benchmarks/corpus/build.py clone
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

FRAME_FILE = HERE / "frame.json"
SAMPLE_FILE = HERE / "sample.json"
LOCK_FILE = HERE / "corpus.lock.json"

#: Where clones land. Outside the repository and git-ignored: corpora are third-party code under
#: their own licences and vendoring them would be both a licence problem and a 10 GB one.
CLONE_ROOT = REPO_ROOT / "git help" / "corpus"

#: Language strata. GitHub's language names, restricted to those QUBIT has a real rule pack for --
#: measuring recall in a language with no rules would report a true zero that says nothing about
#: detection quality and everything about scope.
STRATA: tuple[str, ...] = (
    "Go",
    "Python",
    "Java",
    "JavaScript",
    "TypeScript",
    "C",
    "C++",
    "C#",
    "Rust",
    "Ruby",
    "PHP",
    "Kotlin",
    "Swift",
)

#: Minimum stars for the frame. Not a quality judgement -- a floor that keeps abandoned one-file
#: repositories out of a sample meant to represent software people actually run.
MIN_STARS = 1000

#: Sampling seed. Changing this changes the corpus; that is why it is a constant in a committed
#: file and not a command-line flag.
SEED = 20260821

#: Repositories excluded from the frame by name, each with the reason. Excluding for any reason
#: other than these -- particularly for producing an inconvenient result -- would invalidate the
#: sample.
EXCLUDED: dict[str, str] = {
    "PQCWorld/pqaudit": "is the oracle",
    "csnp/cryptoscan": "is a detector under comparison, and its samples are pattern tables",
    "returntocorp/semgrep": "is a detector under comparison",
    "semgrep/semgrep": "is a detector under comparison",
}


def _get(url: str, *, retries: int = 4) -> dict:
    """GitHub search, unauthenticated, with the rate limit respected rather than hammered."""
    request = urllib.request.Request(  # noqa: S310
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "qubit-benchmark"}
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429) and attempt < retries - 1:
                wait = 20 * (attempt + 1)
                print(f"    rate limited; waiting {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
    raise RuntimeError(f"gave up on {url}")


def build_frame(per_stratum: int = 60) -> dict:
    """Record the population each stratum is sampled from."""
    frame: dict[str, list[dict]] = {}
    for language in STRATA:
        query = f"language:{language}+stars:>{MIN_STARS}"
        url = (
            f"https://api.github.com/search/repositories?q={query}"
            f"&sort=stars&order=desc&per_page={min(per_stratum, 100)}"
        )
        print(f"  {language:12} querying...", file=sys.stderr, flush=True)
        payload = _get(url)
        entries = []
        for item in payload.get("items", []):
            full_name = item["full_name"]
            if full_name in EXCLUDED:
                continue
            entries.append(
                {
                    "full_name": full_name,
                    "clone_url": item["clone_url"],
                    "stars": item["stargazers_count"],
                    "size_kb": item["size"],
                    "license": (item.get("license") or {}).get("spdx_id"),
                    "default_branch": item["default_branch"],
                }
            )
        frame[language] = entries
        print(f"  {language:12} {len(entries)} repositories in frame", file=sys.stderr)
        time.sleep(7)  # unauthenticated search allows ~10/min

    document = {
        "generated_query": f"stars:>{MIN_STARS}, sorted by stars, per stratum",
        "min_stars": MIN_STARS,
        "excluded": EXCLUDED,
        "strata": frame,
    }
    FRAME_FILE.write_text(json.dumps(document, indent=2), encoding="utf-8")
    total = sum(len(v) for v in frame.values())
    print(f"\nwrote {FRAME_FILE} — {total} repositories across {len(frame)} strata")
    return document


def draw_sample(per_stratum: int = 2) -> dict:
    """Draw a fixed-seed random sample from each stratum.

    Random rather than 'the most popular', because the top of a stars ranking is a specific and
    unrepresentative kind of project -- frameworks and language runtimes -- and because a ranked
    pick would let the corpus drift toward whatever scored well.
    """
    if not FRAME_FILE.exists():
        raise SystemExit(f"no frame at {FRAME_FILE}; run `build.py frame` first")
    frame = json.loads(FRAME_FILE.read_text(encoding="utf-8"))

    rng = random.Random(SEED)  # noqa: S311 — corpus selection, not key material
    sample: dict[str, list[dict]] = {}
    #: GitHub assigns one primary language, but a repository can appear in two frames -- the first
    #: draw put `allinurl/goaccess` in both C and C++, which would have scanned it twice and
    #: double-counted every finding in it. Strata are meant to partition the corpus.
    claimed: set[str] = set()
    for language, entries in sorted(frame["strata"].items()):
        available = [e for e in entries if e["full_name"] not in claimed]
        if not available:
            continue
        picked = rng.sample(available, min(per_stratum, len(available)))
        claimed.update(e["full_name"] for e in picked)
        sample[language] = picked
        for entry in picked:
            print(f"  {language:12} {entry['full_name']:45} {entry['stars']:>7} stars")

    document = {"seed": SEED, "per_stratum": per_stratum, "strata": sample}
    SAMPLE_FILE.write_text(json.dumps(document, indent=2), encoding="utf-8")
    total = sum(len(v) for v in sample.values())
    print(f"\nwrote {SAMPLE_FILE} — {total} repositories")
    return document


def clone_sample(*, depth: int = 1) -> dict:
    """Clone every sampled repository and pin the commit each detector will see.

    Shallow by default: the benchmark reads a working tree, not a history, and full clones of 26
    popular repositories is tens of gigabytes for no gain.
    """
    if not SAMPLE_FILE.exists():
        raise SystemExit(f"no sample at {SAMPLE_FILE}; run `build.py sample` first")
    sample = json.loads(SAMPLE_FILE.read_text(encoding="utf-8"))
    CLONE_ROOT.mkdir(parents=True, exist_ok=True)

    lock: dict[str, dict] = {}
    if LOCK_FILE.exists():
        lock = json.loads(LOCK_FILE.read_text(encoding="utf-8")).get("repositories", {})

    for language, entries in sorted(sample["strata"].items()):
        for entry in entries:
            full_name = entry["full_name"]
            target = CLONE_ROOT / full_name.replace("/", "__")
            if target.exists():
                print(f"  {full_name:45} already cloned", file=sys.stderr)
            else:
                print(f"  {full_name:45} cloning...", file=sys.stderr, flush=True)
                result = subprocess.run(  # noqa: S603
                    [  # noqa: S607
                        # Windows MAX_PATH is 260 characters and two of the first 26 repositories
                        # exceeded it -- gatsby nests `node_modules` inside test fixtures, and
                        # compose-multiplatform has deep `expected-*` resource trees. Both failed
                        # with "cannot create directory", which is a filesystem limit and not a
                        # property of the corpus; silently dropping them would have shrunk the
                        # sample for a reason having nothing to do with the sampling frame.
                        "git", "-c", "core.longpaths=true",
                        "clone", "--depth", str(depth), "--quiet",
                        entry["clone_url"], str(target),
                    ],
                    capture_output=True,
                    timeout=1800,
                    check=False,
                )
                if result.returncode != 0:
                    print(
                        f"  {full_name:45} FAILED: "
                        f"{result.stderr.decode('utf-8', 'replace').strip()[:160]}",
                        file=sys.stderr,
                    )
                    continue

            head = subprocess.run(  # noqa: S603
                ["git", "-C", str(target), "rev-parse", "HEAD"],  # noqa: S607
                capture_output=True,
                timeout=60,
                check=False,
            )
            commit = head.stdout.decode("utf-8", "replace").strip()
            pinned = lock.get(full_name, {}).get("commit")
            if pinned and pinned != commit:
                # The lock is the record of what produced the published numbers. A silent update
                # would change the corpus underneath a result nobody re-ran.
                print(
                    f"  {full_name:45} WARNING: on {commit[:12]}, lock says {pinned[:12]}",
                    file=sys.stderr,
                )
            lock[full_name] = {
                "language": language,
                "commit": commit,
                "path": str(target.relative_to(REPO_ROOT)).replace("\\", "/"),
                "stars": entry["stars"],
                "license": entry["license"],
            }

    document = {
        "seed": sample["seed"],
        "clone_root": str(CLONE_ROOT.relative_to(REPO_ROOT)).replace("\\", "/"),
        "repositories": lock,
    }
    LOCK_FILE.write_text(json.dumps(document, indent=2), encoding="utf-8")
    print(f"\nwrote {LOCK_FILE} — {len(lock)} repositories pinned")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    frame_parser = sub.add_parser("frame", help="query GitHub for the sampling frame")
    frame_parser.add_argument("--per-stratum", type=int, default=60)

    sample_parser = sub.add_parser("sample", help="draw a fixed-seed sample from the frame")
    sample_parser.add_argument("--per-stratum", type=int, default=2)

    clone_parser = sub.add_parser("clone", help="clone the sample and pin commits")
    clone_parser.add_argument("--depth", type=int, default=1)

    args = parser.parse_args()
    if args.command == "frame":
        build_frame(args.per_stratum)
    elif args.command == "sample":
        draw_sample(args.per_stratum)
    elif args.command == "clone":
        clone_sample(depth=args.depth)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
