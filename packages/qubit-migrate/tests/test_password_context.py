"""Argon2 or SHA-256, and why the difference is not a matter of taste.

The two are not interchangeable in either direction. Argon2id salts every call, so a value hashed
with it changes on every invocation -- fine for a stored password, ruinous for a cache key or a
content fingerprint, which exists precisely to be the same every time. SHA-256 is the opposite
mistake: fast and unsalted, exactly what a password must not be hashed with.

So the heuristic that chooses between them decides whether a migration is correct or silently
destructive, and it has to be answered ABOUT THE FLAGGED LINE. Scanning the whole module was wrong
in a way that shipped: measured on `scrapy/pipelines/files.py`, which computes a media GUID at line
750 with `hashlib.sha1(url)` while carrying `FTP_PASSWORD` at 375, `AWS_SECRET_ACCESS_KEY` at 159
and `ftp.login(...)` at 419 for its unrelated storage backends. The file-wide search hit those,
declared a password context, and rewrote the fingerprint as `_ph.hash(...)` -- after which scrapy's
file cache could never hit again, because the GUID would differ on every call.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.transform.password_context import is_password_context

# A password-ish storage backend and, far below it, an unrelated fingerprint. The filler is
# load-bearing: in the real `files.py` the two are 375 lines apart, and a fixture where they are
# neighbours would pass with the bug still in place.
_FILLER = "\n".join(f"# unrelated line {n}" for n in range(60))

SOURCE = f"""\
import hashlib


class FTPFilesStore:
    FTP_USERNAME = None
    FTP_PASSWORD = None
    AWS_SECRET_ACCESS_KEY = None

    def connect(self, ftp):
        ftp.login(self.username, self.password)
        return ftp


{_FILLER}


def file_path(request):
    media_guid = hashlib.sha1(to_bytes(request.url)).hexdigest()
    return "full/" + media_guid
"""

_LINES = SOURCE.split("\n")
FINGERPRINT_LINE = (
    _LINES.index("    media_guid = hashlib.sha1(to_bytes(request.url)).hexdigest()") + 1
)
LOGIN_LINE = _LINES.index("        ftp.login(self.username, self.password)") + 1


def _asset(line: int | None, usage: UsageContext = UsageContext.hash) -> CryptoAsset:
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm="SHA-1",
        usage_context=usage,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="files.py", line=line),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=datetime.now(UTC),
    )


def test_a_fingerprint_is_not_a_password_because_the_module_mentions_ftp() -> None:
    """The bug, in one assertion. Nothing in `file_path` suggests a password; the tokens that
    triggered Argon2 live in a different class sixty lines away."""
    assert is_password_context(SOURCE, _asset(FINGERPRINT_LINE)) is False


def test_a_hash_inside_a_login_helper_still_reads_as_a_password() -> None:
    """The other half: narrowing the scope must not lose the cases the heuristic exists for."""
    assert is_password_context(SOURCE, _asset(LOGIN_LINE)) is True


def test_the_scanners_own_verdict_outranks_the_neighbourhood() -> None:
    """`usage_context` is evidence about the FINDING, not about the lines near it, so it decides on
    its own -- a password hashed in a module that says nothing about passwords is still a
    password."""
    assert is_password_context(SOURCE, _asset(FINGERPRINT_LINE, UsageContext.password)) is True


def test_with_no_line_to_centre_on_the_whole_file_is_still_read() -> None:
    """Refusing to look at all would lose every genuine case in a file QUBIT could not place a line
    for, which is worse than the over-reach being fixed."""
    # A finding the scanner could not place a line for, and a call with no asset at all.
    assert is_password_context(SOURCE, _asset(None)) is True
    assert is_password_context(SOURCE, None) is True


def test_unparseable_source_falls_back_to_a_window_not_the_file() -> None:
    """A file that does not parse still gets a scoped answer. The window is what stops a syntax
    error anywhere in a module from reinstating the file-wide behaviour."""
    broken = SOURCE.replace("def file_path(request):", "def file_path(request:")

    assert is_password_context(broken, _asset(FINGERPRINT_LINE)) is False
    assert is_password_context(broken, _asset(LOGIN_LINE)) is True


@pytest.mark.parametrize("token", ["password", "passwd", "credential", "login", "auth"])
def test_each_indicator_still_fires_inside_the_finding_s_own_function(token: str) -> None:
    source = f"""\
import hashlib


def store(user, value):
    {token} = value
    return hashlib.md5(value).hexdigest()
"""
    line = source.split("\n").index("    return hashlib.md5(value).hexdigest()") + 1

    assert is_password_context(source, _asset(line)) is True


def test_a_long_function_is_read_whole_even_past_the_window() -> None:
    """Why the enclosing function is the unit rather than a fixed window.

    A password read at the top of a long function is still what the hash at the bottom is
    protecting, however many lines separate them. A window wide enough to cover that would also
    reach into the neighbouring function, which is the over-reach being fixed -- so the boundary
    has to come from the code's own structure, not from a line count.
    """
    body = "\n".join(f"    step_{n} = {n}" for n in range(40))
    source = f"""\
import hashlib


def register(user, password):
{body}
    return hashlib.md5(password).hexdigest()


def fingerprint(url):
    return hashlib.md5(url).hexdigest()
"""
    lines = source.split("\n")
    stored = lines.index("    return hashlib.md5(password).hexdigest()") + 1
    unrelated = lines.index("    return hashlib.md5(url).hexdigest()") + 1

    assert stored - source[: source.index("def register")].count("\n") > 25, (
        "the password must sit further from the hash than the fallback window,"
        " or this proves nothing"
    )
    assert is_password_context(source, _asset(stored)) is True
    assert is_password_context(source, _asset(unrelated)) is False


def test_a_checksum_is_not_a_password_because_the_function_also_logs_in() -> None:
    """Function scope was still too wide, and this is the case that showed it.

    Reduced from `scrapy/pipelines/files.py::_stat_file`, which opens an FTP connection, logs in,
    and then checksums the remote file. The digest is fed by `retrbinary`, never by the password --
    the two merely share a function. Reading only the statements that mention the digest gets this
    right; reading the function does not.
    """
    source = """\
import hashlib


def _stat_file(self, path):
    with FTP() as ftp:
        ftp.connect(self.host, self.port)
        ftp.login(self.username, self.password)
        m = hashlib.md5()
        ftp.retrbinary(f"RETR {path}", m.update)
    return {"checksum": m.hexdigest()}
"""
    line = source.split("\n").index("        m = hashlib.md5()") + 1

    assert is_password_context(source, _asset(line)) is False


def test_a_digest_fed_a_password_is_still_a_password() -> None:
    """The same narrowing must not lose the case it exists for: here the password reaches the
    digest through `update`, several statements after it was created."""
    source = """\
import hashlib


def store(user, password):
    audit(user)
    h = hashlib.md5()
    h.update(password.encode())
    return h.hexdigest()
"""
    line = source.split("\n").index("    h = hashlib.md5()") + 1

    assert is_password_context(source, _asset(line)) is True
