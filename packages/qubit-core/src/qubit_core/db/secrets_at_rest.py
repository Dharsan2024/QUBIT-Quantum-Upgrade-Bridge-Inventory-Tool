"""Reversible encryption for the one secret QUBIT has to store and later present outward again.

Every other secret this codebase handles fits one of two existing patterns: never persisted (a
Vault token, single-use and in-memory, gone once the job that used it ends) or one-way hashed
(`ApiToken.token_hash`, verify-only). Neither fits an external LLM provider's API key -- QUBIT has
to send it back out on every generation call after a restart, so it must come back in usable
plaintext, not just verify equality.

`Fernet` (symmetric, authenticated) is keyed by a file next to the database rather than a value
IN the database, so reading the DB file alone is never enough to recover the key -- the same
"one artifact alone doesn't leak it" property the Vault-token pattern already relies on, adapted
for something that has to survive a restart instead of living only in memory.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from platformdirs import user_data_dir

__all__ = ["InvalidToken", "decrypt", "encrypt"]


def _key_path() -> Path:
    data_dir = Path(user_data_dir("qubit", appauthor=False))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "llm_key.bin"


def _load_or_create_key() -> bytes:
    path = _key_path()
    try:
        return path.read_bytes()
    except FileNotFoundError:
        pass
    key = Fernet.generate_key()
    # Written once, on first use, restricted to the owner. `0o600` is a no-op on Windows (no POSIX
    # mode bits), where the file already inherits the user-profile directory's own ACLs -- same
    # reasoning `default_db_url`'s directory already relies on for the database file beside it.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    except FileExistsError:
        # Lost a race with another process creating the same file first -- its key is as valid as
        # the one just generated here, so use what is actually on disk rather than two keys
        # fighting over which one is real.
        return path.read_bytes()
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


def _fernet() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> bytes:
    """Encrypt ``plaintext`` (e.g. an API key) for storage in the database."""
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes) -> str:
    """Reverse `encrypt`. Raises `InvalidToken` if the key file changed or the data is corrupt."""
    return _fernet().decrypt(ciphertext).decode("utf-8")
