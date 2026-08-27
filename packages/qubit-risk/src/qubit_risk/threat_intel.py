"""Optional, opt-in checks against a small set of authoritative public PQC reference pages.

QUBIT is offline by design: no telemetry, no crash reporting, source code and scan results never
leave the machine. This module is the one deliberate exception, and it is built to be the
narrowest exception possible:

* **Off by default.** Nothing here runs unless a user flips it on in Settings
  (:class:`qubit_core.db.models.ThreatIntelConfig`).
* **A fixed, curated allowlist** (:data:`SOURCES`), not "the web". Every fetch is a plain HTTPS
  GET of a static NIST reference page — no search, no crawling, no third-party API keys.
* **Nothing about the user's project is ever sent.** These are unauthenticated GETs with no
  query parameters, cookies, or payload derived from scan results.
* **Never auto-applies anything.** A changed source produces a diffable snapshot for a human to
  read (:class:`qubit_core.db.models.ThreatIntelSnapshot`), not an automatic edit to
  ``expert_survey.yaml`` / ``mosca.yaml`` / ``cnsa2_milestones.yaml``. Those files stay
  versioned, cited, and hand-reviewed, the same discipline every other risk parameter already
  follows (see :mod:`qubit_risk.config`). Free text from a web page has no business overwriting
  a number that drives migration prioritization without a person reading it first.
"""

from __future__ import annotations

import hashlib
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from html.parser import HTMLParser

from qubit_core.db.models import ThreatIntelConfig, ThreatIntelSnapshot
from qubit_core.schemas import utcnow
from sqlalchemy import select
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 15
_USER_AGENT = "QUBIT-ThreatIntel/1 (offline PQC migration tool; manual opt-in reference check)"
_EXCERPT_CHARS = 4000


@dataclass(frozen=True)
class ThreatIntelSource:
    id: str
    url: str
    label: str
    note: str


#: The entire allowlist. Adding a source here is a code change (reviewed like any other), not a
#: user-editable setting — that's what keeps "learn from the web" from quietly becoming "learn
#: from wherever the app was pointed at."
SOURCES: tuple[ThreatIntelSource, ...] = (
    ThreatIntelSource(
        id="nist-pqc-project",
        url="https://csrc.nist.gov/projects/post-quantum-cryptography",
        label="NIST PQC Project",
        note="Standardization status, selected algorithms, milestone announcements.",
    ),
    ThreatIntelSource(
        id="nist-pqc-faq",
        url="https://csrc.nist.gov/projects/post-quantum-cryptography/faqs",
        label="NIST PQC FAQs",
        note="NIST's own guidance on migration timelines and deprecation dates.",
    ),
)


class _TextExtractor(HTMLParser):
    """Reduces a page to plain text before hashing, so two fetches of unchanged content hash the
    same regardless of e.g. a rotated tracking script or timestamp embedded in the markup."""

    _SKIP_TAGS = frozenset({"script", "style", "nav", "footer", "header"})

    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            stripped = data.strip()
            if stripped:
                self.chunks.append(stripped)


def _extract_text(html: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(html)
    except Exception:
        logger.warning("threat_intel: HTML parse failed, hashing raw text instead", exc_info=True)
        return html
    return " ".join(parser.chunks)


@dataclass(frozen=True)
class FetchResult:
    source: ThreatIntelSource
    fetched_at: datetime
    content_hash: str | None
    excerpt: str
    error: str | None


def fetch_source(source: ThreatIntelSource, *, timeout: float = _TIMEOUT_SECONDS) -> FetchResult:
    """GET one source, reduce it to text, and hash it.

    Never raises: an unreachable source is a normal, recordable outcome (``error`` set,
    ``content_hash`` ``None``), not a crash in a background check nobody is watching.
    """
    now = utcnow()
    # Fixed HTTPS allowlist, no user-supplied input in the URL - not an SSRF surface.
    request = urllib.request.Request(source.url, headers={"User-Agent": _USER_AGENT})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            charset = response.headers.get_content_charset() or "utf-8"
            raw = response.read().decode(charset, errors="replace")
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return FetchResult(
            source=source, fetched_at=now, content_hash=None, excerpt="", error=str(exc)
        )

    text = _extract_text(raw)
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return FetchResult(
        source=source,
        fetched_at=now,
        content_hash=content_hash,
        excerpt=text[:_EXCERPT_CHARS],
        error=None,
    )


def check_now(
    session: Session, config: ThreatIntelConfig, *, sources: tuple[ThreatIntelSource, ...] = SOURCES
) -> list[ThreatIntelSnapshot]:
    """Fetch every allowlisted source, record a snapshot for each, and flag which ones changed.

    Mirrors :func:`qubit_migrate.transform.learn.record`: rows are staged with ``session.add``
    only. The caller owns the transaction and commits (or not) - this function never commits.
    """
    created: list[ThreatIntelSnapshot] = []
    for source in sources:
        result = fetch_source(source)
        previous = session.scalar(
            select(ThreatIntelSnapshot)
            .where(ThreatIntelSnapshot.source_id == source.id)
            .order_by(ThreatIntelSnapshot.fetched_at.desc())
            .limit(1)
        )
        # A fetch failure is never "changed" - there is nothing new to review, only a source
        # that's temporarily unreachable. And a first-ever fetch has no baseline to differ from.
        changed = (
            result.content_hash is not None
            and previous is not None
            and previous.content_hash is not None
            and previous.content_hash != result.content_hash
        )
        snapshot = ThreatIntelSnapshot(
            source_id=source.id,
            source_url=source.url,
            fetched_at=result.fetched_at,
            content_hash=result.content_hash,
            excerpt=result.excerpt,
            fetch_error=result.error,
            changed_from_previous=changed,
        )
        session.add(snapshot)
        created.append(snapshot)

    config.last_checked_at = utcnow()
    return created
