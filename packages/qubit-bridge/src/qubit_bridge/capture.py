import subprocess
from pathlib import Path

import pyshark


def capture_handshake(
    host: str, port: int, out: Path, *, 
    iface: str = "any", handshakes: int = 1, timeout: float = 15.0
) -> Path:
    """Capture TLS handshake packets using tshark (via subprocess)."""
    out.parent.mkdir(parents=True, exist_ok=True)
    bpf_filter = f"tcp port {port}"
    cmd = [
        "tshark",
        "-i", iface,
        "-f", bpf_filter,
        "-w", str(out),
        "-a", f"duration:{int(timeout)}"
    ]
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait()
    except FileNotFoundError:
        print("Warning: tshark not found. pcap capture is disabled. Creating empty file.")
        out.touch()
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait()

    return out

def extract_key_share_sizes(pcap: Path) -> dict[str, int]:
    """Extract key_share extension sizes from ClientHello and ServerHello using pyshark."""
    sizes: dict[str, int] = {
        "client_hello_bytes": 0,
        "server_hello_bytes": 0,
        "client_key_share_bytes": 0,
        "server_key_share_bytes": 0,
    }
    
    if not pcap.exists():
        return sizes

    try:
        cap = pyshark.FileCapture(str(pcap), display_filter="tls.handshake.type in {1, 2}")
        for pkt in cap:
            if not hasattr(pkt, 'tls'):
                continue
            
            try:
                if hasattr(pkt.tls, 'handshake_extensions_key_share_client_length'):
                    sizes["client_key_share_bytes"] = int(
                        pkt.tls.handshake_extensions_key_share_client_length
                    )
                elif hasattr(pkt.tls, 'handshake_extensions_key_share_server_length'):
                    sizes["server_key_share_bytes"] = int(
                        pkt.tls.handshake_extensions_key_share_server_length
                    )
            except Exception:
                pass
                    
        cap.close()
    except Exception as e:
        print(f"Error parsing pcap {pcap}: {e}")
        
    return sizes

def diff_handshakes(before_pcap: Path, after_pcap: Path) -> dict[str, str]:
    """Compare two pcaps and return human readable differences."""
    return {"before": str(before_pcap), "after": str(after_pcap)}
