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
import tempfile
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
    # Publish only a completely-written key. Creating the final path first and writing into it
    # leaves a window where another process can read an empty or partial Fernet key. A
    # same-directory temporary file is written and fsynced first; `link` atomically publishes it
    # only if no other process has already won. On a loss, the winner's final path is complete.
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temp_name, path)
        except FileExistsError:
            return path.read_bytes()
        return key
    finally:
        Path(temp_name).unlink(missing_ok=True)


def _fernet() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> bytes:
    """Encrypt ``plaintext`` (e.g. an API key) for storage in the database."""
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes) -> str:
    """Reverse `encrypt`. Raises `InvalidToken` if the key file changed or the data is corrupt."""
    return _fernet().decrypt(ciphertext).decode("utf-8")
