import pytest
from qubit_scanner.code.scanner import _cipher_mode


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("aes-256-gcm-siv", "GCM-SIV"),
        ("AES_GCM_SIV", "GCM-SIV"),
        ("AES/GCM-SIV/NoPadding", "GCM-SIV"),
        ("CBC-MAC", None),
        ("CBC_MAC", None),
        ("aes-256-cbc", "CBC"),
        ("AES.MODE_ECB", "ECB"),
        ("recbuf", None),
        (None, None),
        ("AES/GCM/NoPadding", "GCM"),
        ("CBC-MAC; AES/CBC/PKCS5Padding", "CBC"),
    ],
)
def test_compound_modes(text, expected):
    assert _cipher_mode(text) == expected
