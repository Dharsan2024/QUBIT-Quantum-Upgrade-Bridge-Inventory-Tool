"""An attached engine pool has to be reachable.

`_engines()` returns local Ollama first and externals after it, cheapest-first, and that is the
right default: local costs nothing and has no daily quota, so a finding it can handle should never
spend a metered request.

It was also a ceiling nobody could lift. External was reached only when local FAILED or the file was
too large for its window, so an install with a pool of large hosted engines attached — measured on
this one: eleven, mostly a 120B — sent every generation to a local 7B anyway. The evaluation's own
design notes recorded the consequence as *"B3 (external-only) — not expressible without a code
change"*, and dropped the arm.

`engine_order` is that change.

**These drive the real `_engines()` against a real database.** The first version of this file built
a fake orchestrator, stubbed `_engines` with a reimplementation of the ordering, and asserted on
that — reverting the actual change in `orchestrator.py` left all ten tests green. It was testing a
paraphrase of the code, which is the failure mode this project keeps finding in itself.
"""

from __future__ import annotations

import pytest
from qubit_core.db import secrets_at_rest
from qubit_core.db.models import Base, LlmEngine, LlmProviderConfig
from qubit_migrate.config import MigrateConfig
from qubit_migrate.orchestrator import MigrationOrchestrator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


@pytest.fixture()
def session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _attach_pool(session: Session) -> None:
    """A provider row plus three pooled engines, with distinct budgets so order is observable."""
    session.add(
        LlmProviderConfig(
            id=1,
            provider="openai-compatible",
            base_url="https://primary.example/v1",
            model="primary-model",
            api_key_encrypted=secrets_at_rest.encrypt("primary-key"),
            context_tokens=32000,
        )
    )
    for label, model, budget in (
        ("pool-small", "nemotron-120b", 16384),
        ("pool-large", "gemma-4-31b", 64000),
        ("pool-mid", "codestral", 24000),
    ):
        session.add(
            LlmEngine(
                label=label,
                base_url=f"https://{label}.example/v1",
                model=model,
                api_key_encrypted=secrets_at_rest.encrypt(f"{label}-key"),
                api_key_last4="key1",
                context_tokens=budget,
                enabled=True,
            )
        )
    session.commit()


def _orchestrator(session: Session, order: str) -> MigrationOrchestrator:
    orch = MigrationOrchestrator(session)
    orch.config = MigrateConfig(  # type: ignore[arg-type]
        engine_order=order, allow_external_source_processing=True
    )
    return orch


class TestTheDefaultIsUnchanged:
    """Every number this project has measured was measured cheapest-first, so it must stay the
    default — otherwise those results silently describe a different tool."""

    def test_default_is_cheapest_first(self) -> None:
        assert MigrateConfig().engine_order == "cheapest-first"

    def test_external_source_processing_requires_explicit_opt_in(self, session: Session) -> None:
        _attach_pool(session)
        engines = MigrationOrchestrator(session)._engines()
        assert [engine.name for engine in engines] == [MigrateConfig().model]

    def test_external_source_processing_setting_round_trips_through_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUBIT_MIGRATE_ALLOW_EXTERNAL_SOURCE_PROCESSING", "true")
        assert MigrateConfig().allow_external_source_processing is True

    def test_local_leads(self, session: Session) -> None:
        _attach_pool(session)
        engines = _orchestrator(session, "cheapest-first")._engines()
        assert engines[0].metered is False
        assert engines[0].name == MigrateConfig().model

    def test_externals_follow_in_ascending_budget(self, session: Session) -> None:
        _attach_pool(session)
        engines = _orchestrator(session, "cheapest-first")._engines()
        budgets = [e.budget_tokens for e in engines[1:]]
        assert budgets == sorted(budgets), budgets


class TestExternalFirstActuallyInverts:
    def test_a_metered_engine_leads(self, session: Session) -> None:
        _attach_pool(session)
        assert _orchestrator(session, "external-first")._engines()[0].metered is True

    def test_local_is_still_reachable_as_the_fallback(self, session: Session) -> None:
        """What makes this safe. An inverted order that DROPPED local would turn an exhausted free
        tier into no engine at all — worse than the ceiling it was lifting."""
        _attach_pool(session)
        engines = _orchestrator(session, "external-first")._engines()
        assert engines[-1].metered is False
        assert engines[-1].name == MigrateConfig().model

    def test_no_engine_is_lost_by_inverting(self, session: Session) -> None:
        _attach_pool(session)
        cheap = {e.name for e in _orchestrator(session, "cheapest-first")._engines()}
        ext = {e.name for e in _orchestrator(session, "external-first")._engines()}
        assert cheap == ext

    def test_externals_keep_their_ascending_budget_order(self, session: Session) -> None:
        """Smallest-that-fits is a separately measured decision — it is both the cheapest and the
        fastest choice — and moving local must not disturb it."""
        _attach_pool(session)
        engines = _orchestrator(session, "external-first")._engines()
        budgets = [e.budget_tokens for e in engines if e.metered]
        assert budgets == sorted(budgets), budgets

    def test_with_nothing_attached_it_still_returns_local(self, session: Session) -> None:
        """`external-first` on a bare install must not produce an empty list."""
        engines = _orchestrator(session, "external-first")._engines()
        assert [e.name for e in engines] == [MigrateConfig().model]


@pytest.mark.parametrize("order", ["cheapest-first", "external-first"])
def test_the_setting_round_trips_through_the_environment(
    order: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUBIT_MIGRATE_ENGINE_ORDER", order)
    assert MigrateConfig().engine_order == order


class TestSingleEngineOnly:
    """The fixed-model ablation arm: restrict `_engines()` to the primary local engine alone,
    with no escalation to any attached pool — regardless of `engine_order`."""

    def test_default_is_off(self) -> None:
        assert MigrateConfig().single_engine_only is False

    def test_with_a_pool_attached_only_local_is_returned(self, session: Session) -> None:
        _attach_pool(session)
        orch = MigrationOrchestrator(session)
        orch.config = MigrateConfig(  # type: ignore[arg-type]
            single_engine_only=True, allow_external_source_processing=True
        )
        engines = orch._engines()
        assert [e.name for e in engines] == [MigrateConfig().model]
        assert engines[0].metered is False

    def test_overrides_external_first_too(self, session: Session) -> None:
        """A pool restriction is a hard cap, not a preference `engine_order` can reopen."""
        _attach_pool(session)
        orch = MigrationOrchestrator(session)
        orch.config = MigrateConfig(  # type: ignore[arg-type]
            single_engine_only=True,
            engine_order="external-first",
            allow_external_source_processing=True,
        )
        engines = orch._engines()
        assert len(engines) == 1
        assert engines[0].metered is False

    def test_with_nothing_attached_it_still_returns_local(self, session: Session) -> None:
        orch = MigrationOrchestrator(session)
        orch.config = MigrateConfig(single_engine_only=True)  # type: ignore[arg-type]
        assert [e.name for e in orch._engines()] == [MigrateConfig().model]

    def test_the_setting_round_trips_through_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUBIT_MIGRATE_SINGLE_ENGINE_ONLY", "true")
        assert MigrateConfig().single_engine_only is True
