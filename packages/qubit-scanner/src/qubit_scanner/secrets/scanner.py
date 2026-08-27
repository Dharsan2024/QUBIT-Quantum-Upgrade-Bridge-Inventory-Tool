"""HNDL exposure-surface scanner: hardcoded secrets, keys, tokens, and PII in source/config.

QUBIT's thesis is Harvest-Now-Decrypt-Later: an adversary captures encrypted data today and
decrypts it once a quantum computer breaks the crypto. So the risk isn't only *weak algorithms* —
it's everything that weak/eventually-decryptable crypto is protecting. This pass finds the sensitive
material an attacker would harvest: API keys, tokens, private keys, passwords, and PII sitting in
code. Each finding gets an "exploit under HNDL" narrative (see ``hndl_narrative``).

Detection is regex-based over the raw file text (secrets/PII don't live in the AST the way crypto
calls do). Patterns are chosen for high precision — a noisy secret scanner is worse than none.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from qubit_core import Location

from ..models import Detection

# Only scan text-like files; skip binaries/lockfiles/minified assets.
_TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".properties",
    ".txt",
    ".md",
    ".sh",
    ".xml",
    ".gradle",
    ".tf",
}
_SKIP_NAMES = {"package-lock.json", "uv.lock", "yarn.lock", "poetry.lock", "Cargo.lock"}


@dataclass(frozen=True)
class SecretPattern:
    id: str
    label: str  # human name, becomes the asset "algorithm" field
    regex: re.Pattern[str]
    asset_type: str  # "secret" | "sensitive-data"
    sensitivity: str  # maps to CryptoAsset usage/sensitivity narrative
    confidence: str = "high"
    #: A catch-all that must yield to any provider-specific rule on the same line. `GOOGLE_API_KEY
    #: = "AIza..."` is one finding, not two, and the specific rule is the one worth keeping: it
    #: names the provider. Column-level de-duplication cannot see this, because the two patterns
    #: start at different columns of the same line.
    generic: bool = False
    #: Optional second opinion on a match: the matched text, the line it sits on, and the column
    #: it starts at. A regex over source text cannot express "this @ is in a filename, not an
    #: address" or "those sixteen digits are the tail of a float"; a predicate can. False drops it.
    #:
    #: The column is passed explicitly because the match offsets are into the WHOLE FILE while the
    #: line is not -- reusing `re.Match.start()` against the line indexed out of range on the first
    #: file it saw, and `scan_paths` swallowed the exception into an empty inventory.
    validate: Callable[[str, str, int], bool] | None = None


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


#: Final labels that mean the "domain" is really a filename. Measured rather than imagined:
#: hand-adjudicating 152 of this scanner's findings across 26 real repositories found
#: `icon@2x.png`, `sprite@mobile.css`, `backup@2024.sql`, `snapshot@latest.json` and
#: `package@1.0.0.tgz` all reported as email addresses. `PII-EMAIL` alone produced 31 of the 47
#: outright false positives in that sample.
_FILE_EXTENSIONS = frozenset(
    [
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "webp",
        "ico",
        "css",
        "scss",
        "less",
        "js",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "jsx",
        "json",
        "json5",
        "yaml",
        "yml",
        "toml",
        "xml",
        "html",
        "htm",
        "md",
        "txt",
        "sql",
        "sh",
        "bash",
        "zsh",
        "py",
        "rb",
        "go",
        "rs",
        "java",
        "kt",
        "swift",
        "c",
        "h",
        "cpp",
        "hpp",
        "cs",
        "php",
        "lock",
        "tgz",
        "tar",
        "gz",
        "zip",
        "pdf",
        "csv",
        "tsv",
        "log",
        "bak",
        "dat",
        "bin",
        "exe",
        "dll",
        "so",
        "dylib",
        "map",
        "min",
        "woff",
        "woff2",
        "ttf",
        "eot",
        "mp4",
        "mov",
    ]
)

#: What an `@` means when it is not separating a mailbox from a host.
_URL_MARKERS = ("://", "//")

#: Commands whose argument is `user@host`, not an address.
_REMOTE_COMMANDS = ("ssh ", "scp ", "rsync ", "sftp ", "ssh\t", "scp\t")

#: Values that are the NAME of a credential rather than one. `Password = "password"` is an enum
#: member in code-server's `AuthType`; there is nothing there to harvest.
_NON_SECRET_VALUES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "apikey",
        "api_key",
        "api-key",
        "token",
        "accesstoken",
        "access_token",
        "none",
        "null",
        "true",
        "false",
        "unset",
        "redacted",
    }
)

#: Characters that end a token. An address never spans one.
_TOKEN_BREAKS = set(" \t\"'`(),;[]{}<>")


def _enclosing_token(line: str, start: int, end: int) -> str:
    """The whole run of non-separator characters the match sits inside.

    The regex sees `user@host.com`. The token around it is what says whether that is a mailbox or
    the credential half of `ssh://user@host.com`.
    """
    left = start
    while left > 0 and line[left - 1] not in _TOKEN_BREAKS:
        left -= 1
    right = end
    while right < len(line) and line[right] not in _TOKEN_BREAKS:
        right += 1
    return line[left:right]


def _valid_email(text: str, line: str, col: int) -> bool:
    """Reject the two things that parse as an address and are not one.

    **URL userinfo.** `ssh://user@host.com`, `https://$TOKEN@github.com/org/repo`,
    `//root:22@server.com`, and git's scp-style `git@github.com:owner/repo.git`. Each is a
    location, not a mailbox; reporting one as harvested PII is not a marginal call, it is wrong.

    **Filenames.** `icon@2x.png` and `package@1.0.0.tgz` satisfy `local@domain.tld` exactly. The
    tld is a file extension.
    """
    local, _, domain = text.partition("@")
    if not local or not domain:
        return False

    # A domain is a dotted run of labels. Protobuf descriptor bytes produced `2@.memos.store.Xyz`,
    # whose first label is empty -- no real domain has one.
    labels = domain.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    if labels[-1].lower() in _FILE_EXTENSIONS:
        return False

    token = _enclosing_token(line, col, col + len(text))
    offset = token.find(text)
    if offset < 0:
        return True
    before, after = token[:offset], token[offset + len(text) :]
    # `mailto:` is the one scheme whose whole purpose is to introduce an address, so it must not be
    # read as the credential colon below. Two real author contacts in TheAlgorithms/Python are
    # written `Author Anurag Kumar(mailto:anuragkumarak95@gmail.com)`.
    if before.lower().endswith("mailto:"):
        before = before[: -len("mailto:")]

    if any(marker in before for marker in _URL_MARKERS) or "\\" in before:
        # A scheme, a protocol-relative URL, or a UNC path: `\\google.com@evil.com`.
        return False
    if ":" in before:
        # `root:toor@evil.com` -- the colon separates a username from a password, so what follows
        # the `@` is a host.
        return False
    if after.startswith((":", "/")):
        # `git@github.com:owner/repo.git` and `toor@evil.com/payload`. A mailbox is not followed by
        # a port, a path, or an scp-style colon.
        return False
    return not line.lstrip().startswith(_REMOTE_COMMANDS)


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _valid_card(text: str, line: str, col: int) -> bool:
    """A card number is not the tail of a floating-point literal.

    All thirteen `PII-CREDIT-CARD` false positives in the adjudicated sample were values like
    `0.4365079365079365` and `3.130524675073759` printed by doctests: sixteen digits after a
    decimal point, beginning with 4 or 3, matching the Visa and Amex patterns exactly. A word
    boundary does not help, because `.` *is* one. Two independent checks, since either alone still
    lets floats through.
    """
    end = col + len(text)
    before = line[col - 1] if col > 0 else ""
    after = line[end] if end < len(line) else ""
    if before == "." or after == ".":
        return False
    return _luhn(text)


#: A value that names a secret rather than being one. `password="$updatekey"` in a shell script
#: points at a variable; there is nothing on that line to harvest.
_INDIRECTION = re.compile(r"""^["']?(\$\{|\$|%\(|\{\{|<|process\.env|os\.environ)""")


def _valid_secret_value(text: str, line: str, col: int) -> bool:
    separator = "=" if "=" in text else ":"
    _, _, value = text.partition(separator)
    value = value.strip()
    if _INDIRECTION.match(value):
        return False
    return value.strip("\"'").lower() not in _NON_SECRET_VALUES


# High-precision patterns. Ordered most-specific first; a line matched by a provider-specific rule
# is not re-reported by the generic ones.
_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        "SECRET-AWS-AKID",
        "AWS Access Key ID",
        _p(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-GITHUB-PAT",
        "GitHub token",
        _p(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-SLACK",
        "Slack token",
        _p(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-GOOGLE-API",
        "Google API key",
        _p(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-STRIPE",
        "Stripe secret key",
        _p(r"\bsk_(live|test)_[0-9A-Za-z]{16,}\b"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-JWT",
        "JSON Web Token",
        _p(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "secret",
        "token",
    ),
    SecretPattern(
        "SECRET-PRIVATE-KEY",
        "Private key material",
        _p(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "secret",
        "credentials",
    ),
    SecretPattern(
        "SECRET-HARDCODED-PW",
        "Hardcoded password/secret",
        _p(
            # An identifier PREFIX must not hide the keyword. `\b` does not fire between `_` and
            # `P`, so `DB_PASSWORD = "hunter2"` -- one of the commonest shapes there is -- never
            # matched, while the bare `password = "hunter2"` did. Found by scanning a fixture
            # through the running desktop app; no unit test had ever used a prefixed name.
            #
            # A SUFFIX still blocks the match, which is deliberate: `PASSWORD_HASH = "..."` is a
            # digest, not a credential, and the trailing `\b` is what keeps it out.
            # The prefix is BOUNDED. Unbounded, `[A-Za-z0-9]+[_-]` is catastrophic on any file
            # with long alphanumeric runs: at every offset the engine consumes the whole run, then
            # backtracks one character at a time looking for a `_` or `-` that is not there, which
            # is quadratic in the run length.
            #
            # Measured on OpenSSL's own ML-KEM test vectors -- megabytes of unbroken hex -- this
            # single pattern took 22.34s of a 22.50s file scan and matched NOTHING. Twenty such
            # files in `30-test_evp_data` is what made a 6,162-file scan appear to hang at 86%.
            #
            # 32 is far past any real identifier prefix (`DB_`, `AWS_SECRET_`, `MY_APP_`), so the
            # bound costs no recall while capping the work per offset at a constant.
            r"""(?i)(?:[A-Za-z0-9]{1,32}[_-])?(password|passwd|pwd|secret|api[_-]?key"""
            r"""|access[_-]?token)\b\s*[:=]\s*['"][^'"\s]{6,}['"]"""
        ),
        "secret",
        "credentials",
        "medium",
        generic=True,
        validate=_valid_secret_value,
    ),
    # PII / sensitive data
    SecretPattern(
        "PII-EMAIL",
        "PII: email address",
        _p(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "sensitive-data",
        "pii",
        "medium",
        validate=_valid_email,
    ),
    SecretPattern(
        "PII-CREDIT-CARD",
        "PII: credit-card number",
        _p(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        "sensitive-data",
        "financial",
        validate=_valid_card,
    ),
    SecretPattern(
        "PII-SSN",
        "PII: US Social Security Number",
        _p(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
        "sensitive-data",
        "pii",
        "medium",
    ),
]

# Lines containing these are almost always examples/placeholders, not real secrets.
#: RFC 2606 and RFC 6761 reserve `.test`, `.example`, `.invalid` and `.localhost` precisely so
#: that they can never resolve. An address on one of them is a fixture by construction, and the
#: corpus is full of them: `mika-second-member@multica.test`, `ai-e2e@conductor.test`.
_PLACEHOLDER = re.compile(
    r"(?i)(example|placeholder|dummy|your[_-]?key|xxxx|<[^>]+>|changeme|todo|sample|test@|foo@bar"
    r"|\.(?:test|example|invalid|localhost)\b)"
)


def hndl_narrative(asset_type: str, label: str, sensitivity: str) -> str:
    """One-line 'harvest now, decrypt later' exploit explanation for a finding."""
    if asset_type == "secret":
        return (
            f"{label} exposed in source. Under HNDL, an adversary who has harvested traffic or "
            f"backups decrypts them once a CRQC arrives — and any long-lived secret like this "
            f"that is still valid then grants direct access (credential replay), no crypto-break "
            f"needed for the secret itself. Rotate + move to a vault; never commit secrets."
        )
    return (
        f"{label} handled in code. HNDL adversaries harvest this data in transit/at rest today and "
        f"decrypt it after quantum breaks the protecting crypto; {sensitivity} data has a long "
        f"secrecy shelf-life, so it is exactly what HNDL targets. Ensure it is encrypted with "
        f"PQC-ready algorithms and minimized."
    )


class SecretScanner:
    """Regex pass over a text file, emitting secret/PII Detections with HNDL narratives."""

    def scan_file(self, path: Path, *, repo: str | None = None) -> list[Detection]:
        if path.name in _SKIP_NAMES or path.suffix.lower() not in _TEXT_SUFFIXES:
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        out: list[Detection] = []
        claimed: set[tuple[int, int]] = set()  # (line, col) already reported — most-specific wins
        claimed_lines: set[int] = set()  # any line a specific rule took; generic rules yield to it

        # Offset of the first character of every line, computed ONCE, so a match's line number is
        # a binary search rather than a re-scan of everything before it.
        #
        # `text.count("\n", 0, m.start())` is O(n) in the file size, and it ran per MATCH, before
        # any of the filters below could discard that match. On a file whose every line looks
        # secret-ish that is O(matches x n) -- quadratic in practice.
        #
        # Measured on OpenSSL's own ML-KEM test vectors, which are megabytes of hex and match the
        # generic high-entropy patterns on nearly every line: 342 KB took 3.5s and 1,292 KB took
        # 27.9s (3.8x the input for 8x the time), and BOTH produced zero findings. The
        # `30-test_evp_data` directory holds around twenty such files, so a single OpenSSL scan
        # spent roughly ten minutes computing line numbers for matches it then threw away. It is
        # what made a 6,162-file scan appear to hang at 86%.
        line_starts = [0]
        line_starts.extend(i + 1 for i, ch in enumerate(text) if ch == "\n")

        for pat in _PATTERNS:
            for m in pat.regex.finditer(text):
                # `bisect_right - 1` gives the index of the last line start at or before the match,
                # which is its 0-based line; +1 for the 1-based line numbers everything else uses.
                line_index = bisect_right(line_starts, m.start()) - 1
                line_no = line_index + 1
                line_start = line_starts[line_index]
                col = m.start() - line_start
                if (line_no, col) in claimed:
                    continue
                if pat.generic and line_no in claimed_lines:
                    continue
                eol = text.find("\n", m.start())
                line_text = text[line_start : eol if eol != -1 else len(text)]
                if _PLACEHOLDER.search(line_text):
                    continue
                if pat.validate is not None and not pat.validate(m.group(0), line_text, col):
                    continue
                claimed.add((line_no, col))
                if not pat.generic:
                    claimed_lines.add(line_no)
                usage = pat.sensitivity if pat.sensitivity in {"token", "password"} else "unknown"
                out.append(
                    Detection(
                        scanner="code",
                        rule_id=pat.id,
                        raw_algorithm=pat.label,
                        usage_context=usage,
                        asset_type=pat.asset_type,
                        location=Location(repo=repo, file_path=str(path), line=line_no),
                        evidence_snippet=line_text.strip()[:200],
                        evidence_context={
                            "extra": {
                                "hndl_narrative": hndl_narrative(
                                    pat.asset_type, pat.label, pat.sensitivity
                                ),
                                "sensitivity": pat.sensitivity,
                            }
                        },
                        confidence=pat.confidence,
                    )
                )
        return out


__all__ = ["SecretPattern", "SecretScanner", "hndl_narrative"]
