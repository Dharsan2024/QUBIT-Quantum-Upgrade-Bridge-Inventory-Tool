"""One row per finding attempt: the dataset that turns `Y` from an estimate into a measurement.

`Y` — time to complete a migration — is an input to every quantum risk model in the literature, and
every one of them ESTIMATES it. Completed migrations do not exist to measure, so the estimates come
from structured expert judgement. The QARS authors (Electronics 2025, 14, 3338) name the collection
of real-world migration times as their own future work.

QUBIT performs migrations, with timestamps, per finding. That is the one number in this field that
requires the artefact already built — and it was being discarded as a log line. `spend_json` came
close but is the wrong shape twice over: it measures MODEL SPEND rather than migration time, and it
accumulates rather than decomposing.

Three rules are baked into the schema rather than left to the reporting code, because each has a
direction of error and all three err the same way — toward making the tool look good.

**A row is written for every terminal path, not only for successes.** A finding that consumed four
repair attempts and was then routed to a human took real time. Dropping it biases `Y` downward.

**The path is recorded, because the pooled mean is not merely imprecise, it is wrong.** Measured on
certbot: 155 codemod, 102 guided, 2 model. A mean over 272 findings averages three unrelated
distributions and describes none of them. The codemod path is milliseconds; one `py-rsa-kex-01`
finding on the model path ran for fifteen minutes. Both are true; neither is the average.

**Time is conditioned on evidence level.** "Median 4.2 s to an L2 patch" and "median 96 s to an L3
patch" are different claims, and reporting the first while implying the second is precisely the
inflation the evidence ladder exists to remove.

Wall clock is separated from work: `started_at - queued_at` is scheduling behind a semaphore and is
not migration time.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from qubit_core import utcnow
from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base

#: How the finding was handled. The decomposition that makes the number meaningful.
#:
#: `satisfied` and `no-rule` are terminal outcomes that cost real time and produce no patch —
#: counting them as anything else, or not counting them, are both ways of shortening `Y`.
PATHS = ("codemod", "model", "guided", "satisfied", "no-rule")

#: Terminal outcomes. `guided` and `satisfied` are outcomes, NOT failures: a finding correctly
#: routed to a written procedure is a successful decision by the tool, and scoring it as a failure
#: understates the tool while scoring it as an acceptance overstates it.
OUTCOMES = ("accepted", "rejected", "guided", "satisfied", "failed")


class MigrationMeasurement(Base):
    """One finding attempt, whatever became of it."""

    __tablename__ = "migration_measurements"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # ----------------------------------------------------------------- identity
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("migration_tasks.id", ondelete="SET NULL"), index=True, nullable=True
    )
    plan_id: Mapped[uuid.UUID | None] = mapped_column(index=True, nullable=True)
    #: `owner/repo@commit`. Denormalised so an exported row identifies its own corpus without a
    #: join into a database the reader does not have.
    corpus: Mapped[str] = mapped_column(String(256), default="")
    rule_id: Mapped[str] = mapped_column(String(128), default="")
    #: Whether the rule was derived at runtime rather than hand-written. A synthesised rule is a
    #: different experimental condition and pooling the two hides which one the tool is good at.
    synthesised: Mapped[bool] = mapped_column(default=False)
    language: Mapped[str] = mapped_column(String(32), default="")
    algorithm: Mapped[str] = mapped_column(String(64), default="")
    usage_context: Mapped[str] = mapped_column(String(32), default="")
    regime: Mapped[str | None] = mapped_column(String(32), nullable=True)
    construction: Mapped[str] = mapped_column(String(16), default="pure")

    # ----------------------------------------------------------------- the path
    path: Mapped[str] = mapped_column(String(16), default="", index=True)
    engine: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Whether the file was excerpted rather than sent whole. Windowing disables self-review, so a
    #: windowed generation is a materially different treatment.
    windowed: Mapped[bool] = mapped_column(default=False)
    #: Answered from the learned-patch store, so no model was called. A cache hit that is counted
    #: as a model success would make the model look faster than it is.
    from_cache: Mapped[bool] = mapped_column(default=False)

    # ----------------------------------------------------------------- time
    queued_at: Mapped[datetime | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    #: To the first candidate patch of ANY quality. Separate from `total_s` because a tool that
    #: produces a wrong answer quickly and a right one slowly has two different latencies, and the
    #: interactive experience is governed by the first.
    first_candidate_s: Mapped[float | None] = mapped_column(nullable=True)
    total_s: Mapped[float] = mapped_column(default=0.0)
    attempts: Mapped[int] = mapped_column(default=0)
    model_seconds: Mapped[float] = mapped_column(default=0.0)
    gate_seconds: Mapped[float] = mapped_column(default=0.0)
    apply_seconds: Mapped[float] = mapped_column(default=0.0)

    # ----------------------------------------------------------------- outcome
    outcome: Mapped[str] = mapped_column(String(16), default="", index=True)
    #: -1 nothing established … 4 the project's own tests. See `transform/validate.py`.
    evidence_level: Mapped[int | None] = mapped_column(nullable=True)
    stage_outcomes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: The rescan expectation could not have failed for this asset. A pass that carries no
    #: information, and countable so the size of the bucket can be reported.
    vacuous: Mapped[bool] = mapped_column(default=False)
    human_needed: Mapped[bool] = mapped_column(default=False)

    # ----------------------------------------------------------------- size
    #: Covariates a reader needs to interpret the time. A 40 kB file and a 400-byte one are not
    #: the same task, and a median over both is a median over the file-size distribution as much
    #: as over the tool's behaviour.
    file_bytes: Mapped[int] = mapped_column(default=0)
    file_lines: Mapped[int] = mapped_column(default=0)
    diff_changed_lines: Mapped[int] = mapped_column(default=0)
    #: Blank-line-only changes. Tracked because it was a real failure mode — 12 of 18 patches in
    #: one run were majority whitespace — and a "changed lines" count that includes them
    #: overstates how much work the tool did.
    diff_noise_lines: Mapped[int] = mapped_column(default=0)

    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    #: Column order for the exported CSV. Explicit, because a byte-reproducible artefact cannot
    #: depend on mapper introspection order — that changes with SQLAlchemy versions and would make
    #: two exports of identical data differ.
    CSV_COLUMNS: tuple[str, ...] = (
        "corpus",
        "plan_id",
        "task_id",
        "rule_id",
        "synthesised",
        "language",
        "algorithm",
        "usage_context",
        "regime",
        "construction",
        "path",
        "engine",
        "windowed",
        "from_cache",
        "queued_at",
        "started_at",
        "first_candidate_s",
        "total_s",
        "attempts",
        "model_seconds",
        "gate_seconds",
        "apply_seconds",
        "outcome",
        "evidence_level",
        "vacuous",
        "human_needed",
        "file_bytes",
        "file_lines",
        "diff_changed_lines",
        "diff_noise_lines",
    )


__all__ = ["OUTCOMES", "PATHS", "MigrationMeasurement"]
