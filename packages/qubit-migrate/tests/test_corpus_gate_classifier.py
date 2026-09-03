"""G3's protocol-mandated detector, which decides a published number.

`scripts/corpus_select.py` is research harness rather than shipped code, and `testpaths` does not
cover `scripts/`. It is tested here anyway because its output *is* a result: `corpus_gates.csv` and
the null result in `RESULTS-corpus-selection.md` are both computed by it, and a silent regression
would corrupt a table a reader cannot recompute without it.

The specific thing pinned is the defect found in it. G3 detected protocol-mandated crypto by file
PATH alone, against a fixed marker list. That catches `psf/requests`, whose HTTP Digest MD5 lives
in `auth.py`. It missed all five of `pyload`'s, which hash a password into an outbound request
under a field name the remote service defines, because the directory is called `accounts/`.
`pyload` therefore scored `incidental_share = 1.00` — not one protocol-mandated finding — and was
briefly recommended as the ideal corpus on that basis.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "corpus_select.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("corpus_select_under_test", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def corpus_select() -> ModuleType:
    if not _SCRIPT.is_file():
        pytest.skip(f"harness not present at {_SCRIPT}")
    return _load()


def _is_protocol(module: ModuleType, path: str, snippet: str) -> bool:
    """The classification as `score_corpus` performs it, against the module's own tables."""
    lowered = path.replace("\\", "/").lower()
    return any(m in lowered for m in module._PROTOCOL_MARKERS) or any(
        m in snippet.lower() for m in module._PROTOCOL_EVIDENCE
    )


class TestTheEvidenceCheckCatchesWhatThePathCheckCannot:
    """Each case is a real line from a real candidate, not an invented one."""

    @pytest.mark.parametrize(
        ("label", "path", "snippet"),
        [
            (
                "pyload Linkifier: the field name is the remote service's contract",
                "src/pyload/plugins/accounts/LinkifierCom.py",
                'post = {"login": user, "md5Pass": hashlib.md5(password.encode()).hexdigest()}',
            ),
            (
                "pyload NoPremium: same shape, different field",
                "src/pyload/plugins/accounts/NoPremiumPl.py",
                'data["hash_password"] = hashlib.sha1(hashlib.md5(password.encode()).hexdigest())',
            ),
            (
                "taiga: GitHub's webhook signature format",
                "taiga/webhooks/tasks.py",
                'mac = hmac.new(key.encode("utf-8"), msg=data, digestmod=hashlib.sha1)',
            ),
            (
                "taiga: Gravatar's API is defined over an MD5 of the email",
                "taiga/users/gravatar.py",
                "return hashlib.md5(email.lower().encode()).hexdigest()",
            ),
        ],
    )
    def test_it_is_classified_protocol_mandated(
        self, corpus_select: ModuleType, label: str, path: str, snippet: str
    ) -> None:
        assert _is_protocol(corpus_select, path, snippet), label

    @pytest.mark.parametrize(
        ("label", "path", "snippet"),
        [
            (
                "a cache key: nothing outside this codebase depends on the algorithm",
                "flexget/utils/tools.py",
                "return hashlib.md5(str(config).encode()).hexdigest()",
            ),
            (
                "a download filename",
                "flexget/plugins/output/download.py",
                "filename = hashlib.md5(url.encode()).hexdigest()",
            ),
            (
                "a content fingerprint for deduplication",
                "scrapy/utils/request.py",
                "fp = hashlib.sha1(to_bytes(canonicalize_url(request.url)))",
            ),
        ],
    )
    def test_genuinely_incidental_hashing_is_left_alone(
        self, corpus_select: ModuleType, label: str, path: str, snippet: str
    ) -> None:
        """The other direction. A detector that called everything protocol-mandated would reject
        every corpus and would be just as broken — G3 would then be unsatisfiable rather than
        merely under-counting."""
        assert not _is_protocol(corpus_select, path, snippet), label

    def test_the_original_path_markers_still_work(self, corpus_select: ModuleType) -> None:
        """`psf/requests` is the negative control the path list was built for, and the evidence
        check is an addition to it rather than a replacement."""
        assert _is_protocol(
            corpus_select, "requests/auth.py", "hashlib.md5(x).hexdigest()  # HTTP Digest"
        )

    def test_both_tables_are_non_empty(self, corpus_select: ModuleType) -> None:
        """Guards the fixture: an emptied marker list would make every assertion above about
        incidental code pass for the wrong reason."""
        assert corpus_select._PROTOCOL_MARKERS
        assert corpus_select._PROTOCOL_EVIDENCE
