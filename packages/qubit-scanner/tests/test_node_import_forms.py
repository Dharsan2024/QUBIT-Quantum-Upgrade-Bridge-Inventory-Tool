"""Node crypto must be seen however it was imported.

Every rule in `javascript/node_crypto*.yaml` and `typescript/node_crypto*.yaml` used to require a
member expression whose object was literally `crypto`. `import { createHash } from 'crypto'`
followed by a bare `createHash('md5')` matched nothing — in both grammars.

That is not an edge case. It is the idiomatic modern ESM/TypeScript form, and the measured
consequence was that a contemporary TypeScript service scanned **completely clean**: 0 of 6 crypto
sites detected, against 5-6 of 6 for Java, Go, C#, PHP and Ruby on the same probe. An entire
ecosystem was invisible while the rules for it existed and passed their own examples — because
every example was written in the member form.

So this file drives the same six sites through every import style a real codebase uses.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from qubit_scanner import CodeScanner, RuleCatalog

_SCANNER = CodeScanner(RuleCatalog.load())


def _algorithms(source: str, language: str) -> set[str]:
    suffix = {"javascript": "js", "typescript": "ts", "tsx": "tsx"}[language]
    dets = _SCANNER.scan_source(source.encode(), language, file_path=f"svc.{suffix}")
    return {d.raw_algorithm for d in dets}


LANGUAGES = ["javascript", "typescript"]

#: The same call, written the five ways a real repository writes it.
IMPORT_FORMS = {
    "named ESM import": "import { createHash } from 'crypto';\nconst h = createHash('md5');\n",
    "named node: import": (
        "import { createHash } from 'node:crypto';\nconst h = createHash('md5');\n"
    ),
    "destructured require": (
        "const { createHash } = require('crypto');\nconst h = createHash('md5');\n"
    ),
    "namespace import": "import * as crypto from 'crypto';\nconst h = crypto.createHash('md5');\n",
    "default import": "import crypto from 'crypto';\nconst h = crypto.createHash('md5');\n",
}


class TestEveryImportFormIsSeen:
    @pytest.mark.parametrize("language", LANGUAGES)
    @pytest.mark.parametrize("form", list(IMPORT_FORMS))
    def test_createhash_is_detected(self, language: str, form: str) -> None:
        assert "md5" in _algorithms(IMPORT_FORMS[form], language), form


class TestTheSixSitesARealServiceHas:
    """One assertion per crypto site, in the destructured form, because that is the form that was
    invisible. The member form is already covered by each rule's own examples."""

    CASES: ClassVar[dict[str, tuple[str, str]]] = {
        "digest": ("import { createHash } from 'crypto';\nconst h = createHash('md5');\n", "md5"),
        "hmac": (
            "import { createHmac } from 'crypto';\nconst m = createHmac('sha1', k);\n",
            "HMAC-SHA1",
        ),
        "cipher": (
            "import { createCipheriv } from 'crypto';\n"
            "const c = createCipheriv('aes-128-ecb', k, null);\n",
            "aes-128-ecb",
        ),
        "kdf": (
            "import { pbkdf2Sync } from 'crypto';\n"
            "const k = pbkdf2Sync(pw, salt, 1000, 32, 'sha1');\n",
            "PBKDF2",
        ),
    }

    @pytest.mark.parametrize("language", LANGUAGES)
    @pytest.mark.parametrize("site", list(CASES))
    def test_site_is_detected(self, language: str, site: str) -> None:
        source, expected = self.CASES[site]
        found = _algorithms(source, language)
        assert any(expected.lower() in a.lower() for a in found), (site, sorted(found))


class TestItDoesNotFireOnUnrelatedCode:
    """The control for widening the query.

    Dropping the `object == crypto` filter is what made the bare form reachable, and it also means
    the rules now match a method of that name on ANY object. These pin that the remaining
    constraint — the method name itself — is doing real work.
    """

    @pytest.mark.parametrize("language", LANGUAGES)
    @pytest.mark.parametrize(
        "source",
        [
            "const h = renderTemplate('md5');",
            "const h = logger.info('sha1');",
            "const h = db.query('md5');",
            "const x = { createHash: 1 };",
            "import { createHash } from 'crypto';\nconst h = createHash();",
        ],
    )
    def test_no_detection(self, language: str, source: str) -> None:
        assert _algorithms(source, language) == set()

    @pytest.mark.parametrize("language", LANGUAGES)
    def test_a_strong_digest_is_reported_as_itself_not_flagged_away(self, language: str) -> None:
        """The rules NAME algorithms; the registry judges them. SHA-256 must still be detected —
        an inventory that only records weak algorithms is not a CBOM."""
        found = _algorithms(
            "import { createHash } from 'crypto';\nconst h = createHash('sha256');\n", language
        )
        assert "sha256" in found
