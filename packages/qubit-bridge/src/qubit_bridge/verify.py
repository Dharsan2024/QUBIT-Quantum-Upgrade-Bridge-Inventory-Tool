"""Verification module for qubit-bridge."""


from qubit_bridge.models import ProbeResult
from qubit_bridge.probe import probe_host


def verify_group(host: str, port: int, expect: str, **kwargs) -> tuple[bool, ProbeResult]:
    """
    Probe the host and verify that the negotiated group matches the expected one.
    
    Args:
        host: Target hostname.
        port: Target port.
        expect: Expected TLS group (e.g. 'X25519MLKEM768').
        kwargs: Additional arguments to pass to probe_host.
        
    Returns:
        (matched, ProbeResult)
    """
    # If the user expects a specific group, we can pass it as -groups to force it.
    # But usually we just let it negotiate normally and check if the expected group was picked.
    result = probe_host(host, port, **kwargs)
    
    if not result.reachable or result.error:
        return False, result
        
    matched = (result.negotiated_group == expect)
    return matched, result
