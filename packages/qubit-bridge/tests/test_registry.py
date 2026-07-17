from qubit_bridge.registry import codepoint, is_hybrid


def test_registry():
    assert is_hybrid("X25519MLKEM768") is True
    assert is_hybrid("secp256r1") is False
    assert is_hybrid("invalid") is False
    
    assert codepoint("X25519MLKEM768") == 4588
    assert codepoint("MLKEM768") == 513
    assert codepoint("secp256r1") == 23
    assert codepoint("unknown") is None
