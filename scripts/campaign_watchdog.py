"""Watch a running evaluation campaign and say something when it stops making progress.

A campaign is hours of container work behind a single background process. The two ways it wastes
that time are silent: the engine dies and every later request fails the same way, or a plan stops
advancing and `wait_for_plan` sits until its 90-minute timeout. Neither prints anything.

This polls the app the campaign is driving and reports one line per check: the newest plan, how many
of its tasks have reached a terminal state, and whether that number moved since last time. It exits
non-zero the moment it can call a stall, so a caller can react instead of waiting out the timeout.

    python scripts/campaign_watchdog.py --minutes 45
"""

from __future__ import annotations

import argparse
import collections
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from twin_app_eval import call  # noqa: E402

#: States the job runner is still working through. Everything else is somewhere a task stops.
IN_FLIGHT = {"pending", "ready", "generating", "verifying"}


def snapshot() -> tuple[str, int, int, dict[str, int]]:
    """`(plan_id, terminal, total, states)` for the newest plan, or a marker that there is none."""
    plans = call("GET", "/migrate/plans", timeout=60)
    plans = plans if isinstance(plans, list) else plans.get("items", [])
    if not plans:
        return ("none", 0, 0, {})
    plan = max(plans, key=lambda p: p["created_at"])
    queue = call("GET", f"/migrate/plans/{plan['id']}/queue", timeout=120)
    tasks = queue if isinstance(queue, list) else queue.get("items", [])
    states = collections.Counter(t.get("state") or "?" for t in tasks)
    terminal = sum(v for k, v in states.items() if k not in IN_FLIGHT)
    return (plan["id"], terminal, len(tasks), dict(states))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--minutes", type=float, default=45.0, help="how long to watch")
    ap.add_argument("--every", type=float, default=90.0, help="seconds between checks")
    ap.add_argument(
        "--stall-after",
        type=int,
        default=8,
        help="consecutive unchanged checks that count as a stall",
    )
    args = ap.parse_args()

    deadline = time.time() + args.minutes * 60
    last: tuple[str, int] | None = None
    unchanged = 0

    while time.time() < deadline:
        try:
            plan_id, terminal, total, states = snapshot()
        except Exception as exc:
            # The engine going away IS the finding: every later request in the campaign fails the
            # same way, and the campaign itself reports it only as a per-twin error at the end.
            print(f"[{time.strftime('%H:%M:%S')}] ENGINE UNREACHABLE: {exc}", flush=True)
            return 2

        here = (plan_id, terminal)
        if here == last:
            unchanged += 1
        else:
            unchanged = 0
        last = here

        moved = "" if unchanged == 0 else f"  (unchanged x{unchanged})"
        print(
            f"[{time.strftime('%H:%M:%S')}] plan {plan_id[:8]}  {terminal}/{total} terminal  "
            f"{states}{moved}",
            flush=True,
        )

        if total and terminal == total:
            print("newest plan is fully settled; the campaign has moved on or finished", flush=True)
            return 0
        if unchanged >= args.stall_after:
            # Deliberately not a timeout: a stall reported at the 8th identical check is actionable,
            # and one discovered when `wait_for_plan` gives up 90 minutes later is not.
            print(
                f"STALLED: {terminal}/{total} for {unchanged} consecutive checks "
                f"({unchanged * args.every / 60:.0f} min). Nothing is advancing.",
                flush=True,
            )
            return 3
        time.sleep(args.every)

    print("watch window ended with the campaign still advancing", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
