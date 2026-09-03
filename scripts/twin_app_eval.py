"""Evaluate QUBIT against the digital twins, driving the shipped desktop app.

Every other harness in this repository builds a `MigrationOrchestrator` in-process. This one does
not touch `qubit_migrate` for anything except scoring: it duplicates a twin, then drives the SAME
HTTP endpoints the dashboard's own buttons call, against the engine `qubit-desktop.exe` spawned.
The result is the only kind that supports a claim about the product rather than about the library —
if a route is broken, mis-wired, or silently swallows an error, this harness sees exactly what a
user clicking "Run plan" would see, and the in-process harness never would.

    POST /projects                     — the New Project dialog
    POST /projects/{id}/scans          — Scan
    POST /migrate/plans                — Build plan
    POST /migrate/plans/{id}/run       — Run plan   (generate + apply, the whole migration)
    GET  /migrate/plans/{id}/queue     — the queue table
    GET  /migrate/tasks/{id}/patches   — the per-task evidence drawer

**The twin is duplicated first and the copy is what gets migrated.** A migrated twin is a spent
twin: its vulnerabilities are gone and it can never be used as a scanning target again. The copies
live under `test-output/` and `--cleanup` deletes them.

Usage::

    python scripts/twin_app_eval.py --twin inkwell-esign
    python scripts/twin_app_eval.py --all --cleanup
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from twin_migrate import TWINS, score  # noqa: E402  (needs the path insert above)

API = os.environ.get("QUBIT_API_BASE", "http://127.0.0.1:8787/api/v1")
TOKEN = os.environ.get("QUBIT_API_TOKEN", "dev_token")
OUT = REPO / "test-output"


# --------------------------------------------------------------------------------------- transport


def call(
    method: str, path: str, body: dict[str, Any] | None = None, timeout: int = 1800
) -> Any:
    """One request against the running app. Raises with the server's own detail on an error.

    The long default timeout is deliberate: `/plans/{id}/run` generates and validates every patch
    in the plan synchronously, and on a Java twin that includes a Maven test run per patch inside a
    container. A short timeout here would report a working migration as a client failure.
    """
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{API}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            **({"Content-Type": "application/json"} if data else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:600]
        raise RuntimeError(f"{method} {path} -> {exc.code}: {detail}") from None


def app_is_up() -> bool:
    try:
        return call("GET", "/health", timeout=10).get("status") == "ok"
    except Exception:
        return False


# ----------------------------------------------------------------------------------------- the run


def wait_for_scan(sid: str, timeout: int = 1800) -> dict[str, Any]:
    """Block until the job runner finishes the scan.

    A terminal status is anything that is not `running`/`queued`; `failed` is returned rather than
    raised, so a scan that dies is reported as a result about the app instead of a harness crash.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        scan = call("GET", f"/scans/{sid}", timeout=60)
        scan = scan.get("scan", scan)
        if (scan.get("status") or "").lower() not in {"running", "queued", "pending"}:
            return scan
        time.sleep(2)
    raise RuntimeError(f"scan {sid} still running after {timeout}s")


#: A task is finished when the run will not move it again on its own. Taken from `_TRANSITIONS` in
#: `qubit_migrate.state.machine`: `pending`, `ready`, `generating` and `verifying` are the states
#: the runner is still working through, and everything else is somewhere it stops.
#:
#: `failed`, `rejected` and `apply_failed` belong here even though they read like errors -- they are
#: where a run legitimately ENDS for a finding whose generators were exhausted or whose patch a gate
#: turned down, and omitting them means a plan containing one is polled until the timeout rather
#: than reported. They are outcomes of the run, and the report counts them as such.
TERMINAL_STATES = {
    "applied", "deferred", "verified", "proposed", "approved",
    "failed", "rejected", "apply_failed",
}


def wait_for_plan(plan_id: str, timeout: int = 5400) -> list[dict[str, Any]]:
    """Block until every task in the plan reaches a terminal state."""
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        queue = call("GET", f"/migrate/plans/{plan_id}/queue", timeout=120)
        last = queue if isinstance(queue, list) else queue.get("items", queue.get("tasks", []))
        if last and all((t.get("state") or "") in TERMINAL_STATES for t in last):
            return last
        time.sleep(5)
    pending = [t.get("state") for t in last if t.get("state") not in TERMINAL_STATES]
    raise RuntimeError(f"plan {plan_id} still has {len(pending)} tasks running after {timeout}s")


def changed_lines(original: Path, migrated: Path) -> dict[str, set[int]]:
    r"""`{rel_path: {line numbers touched}}`, comparing the migrated copy to the pristine twin.

    This is the only signal in the harness the tool cannot influence. A task's `state` and
    `resolution` are QUBIT's own account of what it did; the diff is what it actually did to the
    bytes on disk. Scoring a refusal against the tool's claim that it refused would make the whole
    evaluation circular.

    Line numbers are taken from the ORIGINAL side of each hunk, because the manifest's symbol
    ranges are resolved against the original tree.

    This walks the trees and diffs in-process rather than parsing `git diff --no-index`. Git quotes
    any path containing a space in C style -- `"b/X:\final yaer\...\signing.rb"` -- and the
    first version of this function parsed that quoted form into a key no lookup ever matched. Every
    finding then scored as untouched, which reported nine correct refusals on a run that had in
    fact edited all nine sites. A harness whose parse failure looks like a perfect score is worse
    than no harness, so the parsing is gone.
    """
    touched: dict[str, set[int]] = {}
    skip = {".git", "target", "__pycache__", ".pytest_cache", "tmp"}
    for path in sorted(migrated.rglob("*")):
        if not path.is_file() or any(part in skip for part in path.relative_to(migrated).parts):
            continue
        rel = path.relative_to(migrated).as_posix()
        before = original / rel
        try:
            new_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if not before.is_file():
            touched[rel] = set(range(1, len(new_lines) + 1))
            continue
        old_lines = before.read_text(encoding="utf-8", errors="replace").splitlines()
        if old_lines == new_lines:
            continue
        import difflib

        lines: set[int] = set()
        for tag, i1, i2, _j1, _j2 in difflib.SequenceMatcher(
            None, old_lines, new_lines, autojunk=False
        ).get_opcodes():
            if tag == "equal":
                continue
            # `i1`/`i2` index the ORIGINAL side, 0-based half-open; the manifest is 1-based. An
            # insertion has i1 == i2, so record the line it was inserted before.
            lines.update(range(i1 + 1, max(i2, i1 + 1) + 1))
        if lines:
            touched[rel] = lines
    return touched


def _rmtree_force(path: Path) -> None:
    """Delete a tree that contains a `.git` directory, on Windows.

    Git marks everything under `.git/objects` read-only, and `shutil.rmtree` raises `PermissionError`
    on the first one. With `ignore_errors=True` that failure is silent, the directory survives, and
    the `copytree` that follows fails with

        [WinError 183] Cannot create a file when that file already exists

    which reads as a bug in the copy rather than in the delete. Observed on the inkwell run the
    moment copies started keeping their `.git`.
    """
    def clear_readonly(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)

    shutil.rmtree(path, onerror=clear_readonly)
    if path.exists():
        raise RuntimeError(f"could not remove the previous copy at {path}")


def duplicate(twin_name: str) -> Path:
    """Copy the twin to `test-output/`. The copy is the migration target; the original is never
    touched, so the twin stays reusable for the next run."""
    src = REPO / "demo-lab" / twin_name
    dst = OUT / twin_name
    if dst.exists():
        _rmtree_force(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # `.git` is KEPT. The `applies` stage checks the diff against the index with git, and rung 0 of
    # the evidence ladder is `applies` + `parses` -- so a copy without a repository skips `applies`,
    # caps `evidence_level` at NO_EVIDENCE for every patch no matter how many later gates pass, and
    # makes the ladder unreadable. Measured on the first run of this harness: all three applied
    # patches reported `evidence_level: -1` purely because the copy had no `.git`.
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("target", "*.class", "__pycache__"))
    return dst


def run_twin(twin_name: str) -> dict[str, Any]:
    twin = TWINS[twin_name]
    app = duplicate(twin_name)
    scan_root = app / twin.scan_subdir if twin.scan_subdir else app
    started = time.time()

    project = call("POST", "/projects", {"name": f"eval-{twin_name}-{int(started)}",
                                         "root_path": str(app)})
    pid = project["id"]

    scan = call("POST", f"/projects/{pid}/scans",
                {"targets": [str(scan_root)], "scanners": ["code"], "run_risk": True})
    # 202: the route dispatches to the job runner and returns immediately with status "running",
    # nesting the scan under "scan". Reading assets straight off this response yields an empty
    # inventory and a migration plan over nothing -- which is exactly how the first run of this
    # harness reported zero findings on a twin with twenty.
    sid = (scan.get("scan") or scan).get("id") or scan.get("scan_id")
    wait_for_scan(sid)
    assets = call("GET", f"/scans/{sid}/assets")
    asset_rows = assets if isinstance(assets, list) else assets.get("items", assets.get("assets", []))

    plan = call("POST", "/migrate/plans", {"scan_id": sid, "force": True})
    plan_id = plan.get("id") or plan.get("plan_id")

    # The whole migration, in the one call the "Run plan" button makes.
    run_started = time.time()
    call("POST", f"/migrate/plans/{plan_id}/run",
         {"apply": True, "generate": True, "generator": "auto"})
    # This route ALSO dispatches to the job runner, so the POST returns in milliseconds with every
    # task still `ready`. Reading the queue here reports a migration that did nothing -- the first
    # run of this harness recorded exactly that, as `run_seconds: 0.0` over 20 untouched tasks.
    tasks = wait_for_plan(plan_id)
    run_seconds = time.time() - run_started

    # What actually changed on disk. Everything below is attributed against THIS, not against the
    # task states, so a refusal counts as a refusal only when the bytes are genuinely untouched.
    touched = changed_lines(REPO / "demo-lab" / twin_name, app)

    outcomes: list[dict[str, Any]] = []
    stage_tally: dict[str, dict[str, int]] = {}
    # The rung each accepted patch could actually defend. Published beside the stage tally
    # because a gate that was SKIPPED never counts as a pass, so a plan can be all-green on
    # the stages it ran and still establish nothing.
    evidence_levels: dict[int, int] = {}
    resolutions: dict[str, int] = {}
    for task in tasks:
        patches = call("GET", f"/migrate/tasks/{task['id']}/patches") or []
        patches = patches if isinstance(patches, list) else patches.get("items", [])
        for patch in patches:
            # `validation.stages`, and it is a DICT keyed by gate name — not a list of stage
            # objects on the patch itself. Reading `patch["stages"]` silently produced an empty
            # tally for every run, so the evidence-ladder table was blank while the ladder was
            # working perfectly well. A harness that reports nothing looks exactly like a gate that
            # never ran, which is the confusion this whole project exists to remove.
            stages = ((patch.get("validation") or {}).get("stages") or {})
            for name, stage in stages.items():
                status = (stage or {}).get("status") or "?"
                stage_tally.setdefault(name, {}).setdefault(status, 0)
                stage_tally[name][status] += 1
            level = (patch.get("validation") or {}).get("evidence_level")
            if level is not None:
                evidence_levels[level] = evidence_levels.get(level, 0) + 1

        rel = (task.get("file_path") or "").replace("\\", "/")
        app_posix = app.as_posix().rstrip("/") + "/"
        if rel.startswith(app_posix):
            rel = rel[len(app_posix):]
        line = task.get("line")
        # The finding's own line is the honest test of "was this finding acted on". A patch that
        # rewrote a different part of the file has not migrated THIS asset.
        edited = bool(line and line in touched.get(rel, set()))

        resolution = task.get("resolution") or task.get("state") or "?"
        resolutions[resolution] = resolutions.get(resolution, 0) + 1
        outcomes.append(
            {
                "file": task.get("file_path") or "",
                "line": line,
                "algorithm": task.get("algorithm") or "",
                "rule_id": task.get("rule_id") or "",
                "outcome": f"{task.get('state')}/{task.get('resolution')}",
                "applied": edited,
                "claimed_applied": task.get("state") == "applied",
            }
        )

    truth = json.loads((REPO / "demo-lab" / twin_name / "GROUND_TRUTH.json").read_text("utf-8"))
    scored = score(app, outcomes, truth)

    # Did the migrated copy survive? This is the claim the whole exercise exists to test: a patch
    # that passes every gate and still breaks the suite is a false accept, and only running the
    # twin's own tests after the fact can show it.
    suite = run_suite(twin, app)

    return {
        "twin": twin_name,
        "language": twin.language,
        "assets": len(asset_rows),
        "tasks": len(tasks),
        "run_seconds": round(run_seconds, 1),
        "total_seconds": round(time.time() - started, 1),
        "stages": stage_tally,
        "evidence_levels": evidence_levels,
        "resolutions": resolutions,
        "files_touched": {k: sorted(v) for k, v in touched.items()},
        "score": scored,
        "suite_after_migration": suite,
        "outcomes": outcomes,
    }


def run_suite(twin: Any, app: Path) -> dict[str, Any]:
    """Run the migrated copy's own test suite, in its sandbox image."""
    target = app / (twin.scan_subdir or "")
    # Every twin runs in ITS OWN sandbox image, Python included. The Python branch used to shell out
    # to a bare `python -m pytest`, which resolved to whichever interpreter was first on PATH -- a
    # uv-managed one with no pytest installed. The suite then "failed" with
    # `No module named pytest`, and the report recorded a RED suite for medivault-emr against a
    # migration that was in fact clean. A harness that can report a failure the tool did not cause
    # is worse than one that reports nothing.
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network=none", "-v", f"{app}:/work", "-w", "/work",
         twin.sandbox_image, "sh", "-c", twin.test_command_in_sandbox],
        capture_output=True, text=True, timeout=1800,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    return {
        "green": proc.returncode == 0,
        "returncode": proc.returncode,
        "tail": [ln for ln in tail if ln.strip()][-4:],
        "_target": str(target),
    }


# -------------------------------------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--twin", action="append", choices=sorted(TWINS), help="repeatable")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--cleanup", action="store_true", help="delete the copies when done")
    ap.add_argument("--out", type=Path, default=REPO / "qubit-v2" / "data" / "twin_app_eval.json")
    args = ap.parse_args()

    names = sorted(TWINS) if args.all else (args.twin or [])
    if not names:
        ap.error("pass --twin NAME (repeatable) or --all")

    if not app_is_up():
        print("The desktop app is not answering on", API, file=sys.stderr)
        print("Launch qubit-desktop.exe first; this harness deliberately refuses to start its own\n"
              "engine, because a side engine would not be evidence about the shipped app.",
              file=sys.stderr)
        return 2

    results = []
    for name in names:
        print(f"\n=== {name} ===", flush=True)
        try:
            result = run_twin(name)
        except Exception as exc:  # a broken route is a RESULT, not a crash
            print(f"  FAILED: {exc}", flush=True)
            results.append({"twin": name, "error": str(exc)})
            continue
        s = result["score"]
        print(f"  tasks={result['tasks']} in {result['run_seconds']}s  "
              f"correct={len(s['correct'])} "
              f"false_migrations={len(s['false_migrations'])} "
              f"missed={len(s['expected_migrate_but_not_migrated'])} "
              f"controls_hit={len(s['controls_wrongly_migrated'])} "
              f"unmapped={s['unmapped_outcomes']}  "
              f"suite_after={'green' if result['suite_after_migration']['green'] else 'RED'}",
              flush=True)
        results.append(result)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nwrote {args.out}")

    if args.cleanup:
        for name in names:
            shutil.rmtree(OUT / name, ignore_errors=True)
        print(f"deleted the copies under {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
