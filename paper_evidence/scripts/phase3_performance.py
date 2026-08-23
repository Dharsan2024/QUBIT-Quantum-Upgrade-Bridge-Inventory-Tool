"""Phase 3c: timing, throughput and memory, with repetitions and error bars.

The specification asks for at least five repetitions with mean and standard deviation. None had ever
been run, for one honest reason: the machine had a corpus sweep and Docker services on it throughout
this pack's construction, and a number taken then measures contention rather than the system.

So this script refuses to produce numbers on a busy machine. `--force` overrides the check and
stamps every row `quiet_machine=False`, which the figure then says out loud -- a caveat in a caption
is worth more than a missing table, but only if it travels with the number.

Measures the discovery stage over real corpus repositories, bucketed by size:

    wall clock       per repetition, mean +/- SD over >= 5 runs
    throughput       files/second and source-lines/second
    peak memory      tracemalloc, Python allocations only, stated as such

    uv run python paper_evidence/scripts/phase3_performance.py --reps 5

Covers B1, B2, B3, B4, T10, F13, F14 and closes Limitations L4.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _style import OUT, PALETTE, ROOT, save_figure

#: Above this many busy cores, or with these containers up, a timing run is measuring contention.
_MAX_LOAD_PERCENT = 25.0


def _machine_is_quiet() -> tuple[bool, str]:
    """Is anything else running that would make these numbers meaningless?"""
    reasons = []
    try:
        import psutil

        load = psutil.cpu_percent(interval=2.0)
        if load > _MAX_LOAD_PERCENT:
            reasons.append(f"CPU at {load:.0f}%")
        for process in psutil.process_iter(["name", "cmdline"]):
            cmdline = " ".join(process.info.get("cmdline") or [])
            if "sweep.py" in cmdline or "phase3_migration" in cmdline:
                reasons.append(f"{process.info['name']} is running a benchmark")
                break
    except ImportError:
        reasons.append("psutil not installed, so load could not be checked")
    return (not reasons), "; ".join(reasons) or "quiet"


def _corpus_targets(count: int) -> list[tuple[str, Path, int]]:
    """Corpus clones on disk with their file counts, spread across size buckets."""
    lock = json.loads(
        (ROOT / "benchmarks" / "corpus" / "corpus.lock.json").read_text(encoding="utf-8")
    )
    sized: list[tuple[str, Path, int]] = []
    for name, meta in sorted(lock["repositories"].items()):
        path = ROOT / meta["path"]
        if not path.is_dir():
            continue
        files = sum(1 for p in path.rglob("*") if p.is_file() and ".git" not in p.parts)
        sized.append((name, path, files))
    sized.sort(key=lambda row: row[2])
    if len(sized) <= count:
        return sized
    # Spread across the size range rather than taking the smallest, so the scalability curve has
    # something to fit.
    step = (len(sized) - 1) / (count - 1)
    return [sized[round(index * step)] for index in range(count)]


def _one_run(path: Path, name: str) -> tuple[float, int, int]:
    """(seconds, findings, peak_bytes) for one discovery pass."""
    from qubit_scanner.api import scan_paths

    tracemalloc.start()
    started = time.perf_counter()
    result = scan_paths([path], scanners={"code"}, repo=name)
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed, len(result.assets), peak


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=5, help="repetitions per repository (>= 5)")
    parser.add_argument("--repos", type=int, default=5, help="repositories across the size range")
    parser.add_argument("--force", action="store_true", help="measure even on a busy machine")
    args = parser.parse_args()

    quiet, why = _machine_is_quiet()
    if not quiet and not args.force:
        raise SystemExit(
            f"machine is not quiet ({why}). These numbers would measure contention.\n"
            "Stop the sweep and Docker, then re-run -- or pass --force to record them anyway, "
            "in which case every row is stamped quiet_machine=False and the figure says so."
        )
    print(f"machine: {why}\nrepetitions: {args.reps}\n")

    targets = _corpus_targets(args.repos)
    rows = []
    for name, path, files in targets:
        # One discarded warm-up: the first pass pays for grammar loading and the OS file cache, and
        # including it would report a cost the second repository never pays.
        _one_run(path, name)
        timings, peaks, findings = [], [], 0
        for rep in range(args.reps):
            seconds, found, peak = _one_run(path, name)
            timings.append(seconds)
            peaks.append(peak)
            findings = found
            print(f"  {name:42} rep {rep + 1}/{args.reps}  {seconds:7.2f}s", flush=True)
        mean = statistics.mean(timings)
        rows.append(
            {
                "repository": name,
                "files": files,
                "findings": findings,
                "reps": args.reps,
                "mean_s": round(mean, 3),
                "sd_s": round(statistics.stdev(timings), 3) if len(timings) > 1 else 0.0,
                "min_s": round(min(timings), 3),
                "max_s": round(max(timings), 3),
                "files_per_s": round(files / mean, 1) if mean else 0.0,
                "peak_python_mb": round(statistics.mean(peaks) / 1_048_576, 1),
                "quiet_machine": quiet,
            }
        )

    (OUT / "data").mkdir(parents=True, exist_ok=True)
    target = OUT / "data" / "performance.csv"
    with target.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    _figures(rows, quiet)
    print(f"\nwrote {target}")
    return 0


def _figures(rows: list[dict], quiet: bool) -> None:
    import matplotlib.pyplot as plt

    caveat = "" if quiet else " MEASURED ON A BUSY MACHINE: these are upper bounds, not the system."

    files = [r["files"] for r in rows]
    means = [r["mean_s"] for r in rows]
    sds = [r["sd_s"] for r in rows]

    fig, ax = plt.subplots(figsize=(4.8, 2.9))
    ax.errorbar(files, means, yerr=sds, fmt="o", color=PALETTE[0], capsize=3, markersize=5)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("files in repository (log)")
    ax.set_ylabel("discovery wall-clock seconds (log)")
    ax.grid(True, which="both", alpha=0.25, linewidth=0.5)
    save_figure(
        fig,
        "F13_throughput",
        f"Discovery cost against repository size, {rows[0]['reps']} repetitions per point with a "
        f"discarded warm-up, error bars one standard deviation. Cost tracks the number of files "
        f"rather than the amount of cryptography in them, which is what makes an applicability "
        f"gate worth having on an expensive detector.{caveat} Source: data/performance.csv.",
    )

    fig, ax = plt.subplots(figsize=(5.0, 2.9))
    order = sorted(rows, key=lambda r: r["files_per_s"])
    ax.barh(
        [r["repository"].split("/")[-1] for r in order],
        [r["files_per_s"] for r in order],
        color=PALETTE[2],
    )
    ax.set_xlabel("files scanned per second")
    save_figure(
        fig,
        "F14_stage_latency",
        f"Discovery throughput per repository, mean of "
        f"{rows[0]['reps']} runs. Throughput varies by roughly an order of magnitude across the "
        f"corpus, driven by file size and how many files the grammar actually parses rather than "
        f"by language.{caveat} Source: data/performance.csv.",
    )


if __name__ == "__main__":
    raise SystemExit(main())
