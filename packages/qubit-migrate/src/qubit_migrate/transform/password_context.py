"""Password-context heuristic, kept free of libcst so it can be imported cheaply."""

from __future__ import annotations

import ast
import re

from qubit_core import CryptoAsset

#: Identifiers that suggest the hash being replaced protects a SECRET rather than identifying a
#: byte string. The distinction decides between Argon2id and SHA-256, and the two are not
#: interchangeable in either direction: Argon2 salts every call, so a fingerprint hashed with it
#: changes on every invocation, and SHA-256 over a password is a fast unsalted hash.
_PASSWORD_INDICATORS = re.compile(
    r"\b(password|passwd|pw\b|hash_?password|store_?pass|check_?pass"
    r"|verify_?pass|auth|credential|login)\b",
    re.IGNORECASE,
)

#: Lines either side of the finding to read when the enclosing function cannot be determined --
#: a non-Python file, or source that does not parse. Generous enough to catch a helper's docstring
#: and its caller, tight enough that an unrelated class elsewhere in the module cannot reach it.
_WINDOW_LINES = 25


#: `<name> = hashlib.<something>(...)` -- the flagged line binding a digest object to a name, so
#: the statements that feed it can be found. Only this shape is recognised deliberately: anything
#: cleverer would be guessing, and guessing wrong here silently swaps a deterministic fingerprint
#: for a salted one.
_DIGEST_BINDING = re.compile(r"\s*(?P<name>[A-Za-z_]\w*)\s*=\s*[\w.]*\b(hashlib|hmac)\b")


def _enclosing_span(source: str, line: int) -> tuple[int, int] | None:
    """The function or method containing `line`, as a 1-based inclusive span.

    Returns None when the source does not parse or the line sits at module level, in which case the
    caller falls back to a fixed window. The innermost enclosing function wins, so a nested helper
    is judged on itself rather than on whatever its parent happens to do.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    best: tuple[int, int] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start, end = node.lineno, getattr(node, "end_lineno", None) or node.lineno
        if start <= line <= end and (best is None or start > best[0]):
            best = (start, end)
    return best


def is_password_context(source: str, asset: CryptoAsset | None) -> bool:
    """Is the hash at this finding protecting a password, rather than identifying a byte string?

    Scoped to the finding, not the file. Scanning the whole module was wrong in a way that produced
    a silently broken migration: `scrapy/pipelines/files.py` computes a media GUID at line 750 with
    `hashlib.sha1(url)`, and the same module carries `FTP_PASSWORD` at 375, `AWS_SECRET_ACCESS_KEY`
    at 159 and `ftp.login(...)` at 419 for its unrelated storage backends. The file-wide search hit
    those, declared a password context, and rewrote a **deterministic fingerprint** as an Argon2
    hash -- which salts every call, so scrapy's file cache would never hit again.

    QUBIT's rescan gate caught that one because the expected algorithm was absent, but the gate is
    not what should be catching it: nothing about the flagged line ever suggested a password, and a
    file where Argon2 happened to satisfy the rescan would have shipped the same defect.

    Scope, narrowest first:

    1. **What feeds the hash.** When the flagged line binds the digest to a name
       (`m = hashlib.md5()`), only the statements that mention that name are read. This is the
       semantically right question -- a hash is a password hash because a PASSWORD goes into it,
       not because the function it sits in happens to authenticate somewhere. Measured on the same
       scrapy file: `_stat_file` computes an FTP file checksum with `m = hashlib.md5()` fed by
       `ftp.retrbinary(..., m.update)`, and calls `ftp.login(self.username, self.password)` four
       lines above. Function scope alone still called that a password.
    2. **The enclosing function**, when the digest is not bound to a name -- `hashlib.md5(secret)`
       carries its own evidence on the flagged line, and the function is a safe bound for it.
    3. **A window**, when the source does not parse.
    4. **The whole file**, only when there is no line to centre on at all.

    A usage context recorded by the scanner still counts on its own, ahead of all of these -- that
    is evidence about the finding itself rather than about its neighbourhood.
    """
    if (
        asset is not None
        and asset.usage_context
        and "password" in asset.usage_context.value.lower()
    ):
        return True

    line = asset.location.line if asset is not None and asset.location else None
    if not line:
        # No line to centre on: the whole file is all there is, and refusing to look at it would
        # lose the genuine password cases this heuristic exists for.
        return bool(_PASSWORD_INDICATORS.search(source))

    lines = source.split("\n")
    span = _enclosing_span(source, line)
    if span is None:
        lo = max(0, line - 1 - _WINDOW_LINES)
        hi = min(len(lines), line + _WINDOW_LINES)
    else:
        lo, hi = span[0] - 1, span[1]

    flagged = lines[line - 1] if 0 < line <= len(lines) else ""
    bound = _DIGEST_BINDING.match(flagged)
    if bound:
        # Only what actually reaches the digest: its own statement, and every later statement in
        # the function that names it (`m.update(...)`, `m.hexdigest()`).
        name = re.compile(rf"\b{re.escape(bound.group('name'))}\b")
        feeding = [ln for ln in lines[lo:hi] if name.search(ln)]
        return bool(_PASSWORD_INDICATORS.search("\n".join(feeding)))

    return bool(_PASSWORD_INDICATORS.search("\n".join(lines[lo:hi])))
