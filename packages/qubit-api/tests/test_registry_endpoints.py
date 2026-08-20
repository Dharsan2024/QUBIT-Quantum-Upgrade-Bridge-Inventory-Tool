"""The registry endpoints the desktop app reads to show what the engine can actually do.

`/registry/languages` exists because language coverage is otherwise invisible from the app: a
language with no rules behind it parses cleanly, produces no findings, and reports as a scanned
file — byte-identical to a file that genuinely has no cryptography in it. Showing the rule count
next to each language makes an empty pack visible instead of silent, so these tests assert the
count is real rather than merely present.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'registry.db').as_posix()}",
        create_schema_on_startup=True,
    )
    return TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
    )


def test_languages_endpoint_lists_every_grammar_with_a_real_rule_count(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        response = client.get("/api/v1/registry/languages")
        assert response.status_code == 200, response.text
        rows = response.json()

    languages = {row["language"] for row in rows}
    # The languages added for market coverage, each of which was unscannable before.
    for expected in (
        "csharp",
        "cpp",
        "php",
        "rust",
        "kotlin",
        "scala",
        "ruby",
        "swift",
        "dart",
        "sql",
        "bash",
        "powershell",
        "tsx",
    ):
        assert expected in languages, f"{expected} missing from {sorted(languages)}"

    empty = sorted(row["language"] for row in rows if row["rules"] <= 0)
    assert not empty, (
        f"These languages are listed as supported with zero rules: {empty}. A file in one of them "
        "parses, matches nothing, and counts as scanned — indistinguishable from safe code."
    )

    for row in rows:
        assert row["extensions"], f"{row['language']} has no file extension mapped to it"
        assert row["libraries"], f"{row['language']} reports no rule libraries"


def test_languages_endpoint_reports_extensions_that_dispatch_to_that_grammar(
    tmp_path: Path,
) -> None:
    """The extension list is what a user checks their repo against, so it must be truthful."""
    from qubit_scanner.code.languages import language_for

    with _client(tmp_path) as client:
        rows = client.get("/api/v1/registry/languages").json()

    for row in rows:
        for extension in row["extensions"]:
            probe = Path(f"probe{extension}") if extension.startswith(".") else Path(extension)
            assert language_for(probe) == row["language"], (
                f"{extension} is advertised under {row['language']} but dispatches to "
                f"{language_for(probe)}"
            )


def test_algorithms_endpoint_still_serves_the_canonical_registry(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        response = client.get("/api/v1/registry/algorithms")
        assert response.status_code == 200, response.text
        rows = response.json()

    canonical = {row["canonical"] for row in rows}
    # One from each verdict class, so a registry that lost a whole family fails here.
    for expected in ("RSA-2048", "MD5", "AES-256", "ML-KEM-768", "TLSv1.0"):
        assert expected in canonical

    assert any(row["vulnerable"] for row in rows), "no algorithm is marked vulnerable"
    assert any(not row["vulnerable"] for row in rows), "no algorithm is marked safe"
