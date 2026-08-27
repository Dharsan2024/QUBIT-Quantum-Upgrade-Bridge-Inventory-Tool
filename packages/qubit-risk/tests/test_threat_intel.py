"""qubit_risk.threat_intel: the one deliberate exception to QUBIT's offline stance.

Pinned here: a first-ever fetch is never "changed" (there is no baseline yet), a genuinely
different hash IS flagged, a failed fetch is never mistaken for a change, and nothing this module
touches ever writes to the versioned risk-parameter YAML files — it only ever stages a snapshot.
"""

from __future__ import annotations

import urllib.error

import pytest
from qubit_core.db import Base
from qubit_core.db.models import ThreatIntelConfig, ThreatIntelSnapshot
from qubit_risk.threat_intel import (
    SOURCES,
    FetchResult,
    ThreatIntelSource,
    _extract_text,
    check_now,
    fetch_source,
)
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _config(session: Session) -> ThreatIntelConfig:
    config = ThreatIntelConfig(id=1, enabled=True, check_interval_hours=24)
    session.add(config)
    session.commit()
    return config


_SOURCE = ThreatIntelSource(id="test-src", url="https://example.invalid/pqc", label="Test", note="")


class _FakeHeaders:
    def get_content_charset(self) -> None:  # matches http.client.HTTPMessage's signature
        return None


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.headers = _FakeHeaders()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class TestFetchSource:
    def test_a_reachable_page_is_hashed_and_excerpted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        html = b"<html><head><style>.x{}</style></head><body><p>NIST PQC guidance</p></body></html>"
        monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResponse(html))
        result = fetch_source(_SOURCE)
        assert result.error is None
        assert result.content_hash is not None
        assert "NIST PQC guidance" in result.excerpt
        assert ".x{}" not in result.excerpt  # <style> content must not leak into the hash/excerpt

    def test_an_unreachable_source_is_a_recorded_outcome_not_a_crash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise(*a: object, **k: object) -> None:
            raise urllib.error.URLError("name resolution failed")

        monkeypatch.setattr("urllib.request.urlopen", _raise)
        result = fetch_source(_SOURCE)
        assert result.content_hash is None
        assert result.error is not None
        assert result.excerpt == ""

    def test_two_fetches_of_identical_content_hash_the_same(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        html = b"<html><body>stable content</body></html>"
        monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResponse(html))
        first = fetch_source(_SOURCE)
        second = fetch_source(_SOURCE)
        assert first.content_hash == second.content_hash

    def test_the_allowlist_is_a_fixed_curated_set_not_the_open_web(self) -> None:
        # The whole point of the design: adding a source is a code change, not a user setting.
        assert len(SOURCES) >= 1
        assert all(s.url.startswith("https://csrc.nist.gov/") for s in SOURCES)


class TestExtractText:
    def test_script_and_style_content_is_dropped(self) -> None:
        html = "<html><script>evil()</script><style>.a{color:red}</style><p>real text</p></html>"
        text = _extract_text(html)
        assert "real text" in text
        assert "evil()" not in text
        assert "color:red" not in text

    def test_malformed_markup_falls_back_to_raw_text_instead_of_raising(self) -> None:
        assert _extract_text("<div><p>unclosed") is not None


class TestCheckNow:
    def _fake_fetch(self, monkeypatch: pytest.MonkeyPatch, results: list[FetchResult]) -> None:
        it = iter(results)
        monkeypatch.setattr("qubit_risk.threat_intel.fetch_source", lambda *a, **k: next(it))

    def test_a_first_ever_fetch_is_not_flagged_as_changed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from qubit_core.schemas import utcnow

        self._fake_fetch(
            monkeypatch,
            [FetchResult(_SOURCE, utcnow(), "hash-a", "excerpt", None)],
        )
        session = _session()
        config = _config(session)
        created = check_now(session, config, sources=(_SOURCE,))
        session.commit()
        assert len(created) == 1
        assert created[0].changed_from_previous is False

    def test_a_genuinely_different_hash_is_flagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from qubit_core.schemas import utcnow

        session = _session()
        config = _config(session)

        self._fake_fetch(monkeypatch, [FetchResult(_SOURCE, utcnow(), "hash-a", "old text", None)])
        check_now(session, config, sources=(_SOURCE,))
        session.commit()

        self._fake_fetch(monkeypatch, [FetchResult(_SOURCE, utcnow(), "hash-b", "new text", None)])
        second = check_now(session, config, sources=(_SOURCE,))
        session.commit()

        assert second[0].changed_from_previous is True

    def test_unchanged_content_is_never_flagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from qubit_core.schemas import utcnow

        session = _session()
        config = _config(session)
        same = FetchResult(_SOURCE, utcnow(), "hash-a", "same text", None)

        self._fake_fetch(monkeypatch, [same])
        check_now(session, config, sources=(_SOURCE,))
        session.commit()

        self._fake_fetch(monkeypatch, [same])
        second = check_now(session, config, sources=(_SOURCE,))
        session.commit()

        assert second[0].changed_from_previous is False

    def test_a_fetch_failure_after_a_success_is_not_mistaken_for_a_change(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from qubit_core.schemas import utcnow

        session = _session()
        config = _config(session)

        self._fake_fetch(monkeypatch, [FetchResult(_SOURCE, utcnow(), "hash-a", "text", None)])
        check_now(session, config, sources=(_SOURCE,))
        session.commit()

        self._fake_fetch(monkeypatch, [FetchResult(_SOURCE, utcnow(), None, "", "timed out")])
        second = check_now(session, config, sources=(_SOURCE,))
        session.commit()

        assert second[0].changed_from_previous is False
        assert second[0].fetch_error == "timed out"

    def test_check_now_updates_last_checked_at_and_never_commits_itself(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from qubit_core.schemas import utcnow

        self._fake_fetch(monkeypatch, [FetchResult(_SOURCE, utcnow(), "hash-a", "text", None)])
        session = _session()
        config = _config(session)
        assert config.last_checked_at is None

        check_now(session, config, sources=(_SOURCE,))
        assert config.last_checked_at is not None

        # check_now only calls session.add() (see learn.record()'s identical contract); the
        # caller owns commit(). Rolling back before committing must undo everything it staged -
        # if check_now had committed internally, the rollback would have nothing left to undo.
        session.rollback()
        assert session.scalar(select(ThreatIntelSnapshot)) is None
