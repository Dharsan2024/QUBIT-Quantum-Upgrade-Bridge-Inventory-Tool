"""No contender can observe an incomplete or overwritten encryption key."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from cryptography.fernet import Fernet
from qubit_core.db import secrets_at_rest as secrets


def test_concurrent_first_use_publishes_one_complete_key(tmp_path, monkeypatch):
    path = tmp_path / "key.bin"
    monkeypatch.setattr(secrets, "_key_path", lambda: path)
    link = secrets.os.link
    barrier = Barrier(8)

    def simultaneous_publish(source, target):
        # Every contender has written and flushed its own key before any publishes.
        assert len(Path(source).read_bytes()) == 44
        barrier.wait(timeout=10)
        link(source, target)

    monkeypatch.setattr(secrets.os, "link", simultaneous_publish)
    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _: secrets._load_or_create_key(), range(8)))
    assert len(set(keys)) == 1
    assert keys[0] == path.read_bytes()
    Fernet(keys[0])
    assert list(tmp_path.iterdir()) == [path]
    assert secrets.decrypt(secrets.encrypt("synthetic test value")) == "synthetic test value"


def test_existing_invalid_key_is_not_silently_replaced(tmp_path, monkeypatch):
    path = tmp_path / "key.bin"
    path.write_bytes(b"invalid")
    monkeypatch.setattr(secrets, "_key_path", lambda: path)
    with pytest.raises(ValueError):
        secrets.encrypt("test")
    assert path.read_bytes() == b"invalid"
