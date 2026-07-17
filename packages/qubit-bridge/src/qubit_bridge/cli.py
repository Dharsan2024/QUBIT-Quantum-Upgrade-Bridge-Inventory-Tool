from typing import Annotated

import typer
from rich.console import Console

from qubit_bridge.probe import probe_host
from qubit_bridge.verify import verify_group

bridge_app = typer.Typer(
    name="bridge",
    help="QUBIT hybrid TLS bridge and probe tooling.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)


@bridge_app.command("probe")
def probe_cmd(
    target: Annotated[str, typer.Argument(help="HOST[:PORT] to probe")],
    groups: Annotated[str | None, typer.Option("--groups", "-g", help="Force specific TLS groups (e.g. X25519MLKEM768)")] = None,
    sni: Annotated[str | None, typer.Option("--sni", help="SNI server name")] = None,
    output_json: Annotated[bool, typer.Option("--json", help="Output JSON")] = False,
    # --push is omitted for M1
):
    """Probe a host to determine its negotiated TLS group."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443
        
    result = probe_host(host, port, groups=groups, sni=sni)
    
    if output_json:
        console.print(result.model_dump_json(exclude={"raw_output"} if result.reachable else None))
        return
        
    if not result.reachable:
        err_console.print(f"[red]Error probing {target}: {result.error}[/red]")
        raise typer.Exit(1)
        
    console.print(f"Host: [bold]{result.host}:{result.port}[/bold]")
    console.print(f"TLS Version: {result.tls_version}")
    
    if result.hybrid_pqc:
        console.print(f"Negotiated Group: [green]{result.negotiated_group} (hybrid PQC)[/green] (codepoint: {result.group_codepoint})")
    else:
        console.print(f"Negotiated Group: [yellow]{result.negotiated_group} (classical)[/yellow] (codepoint: {result.group_codepoint})")
        
    console.print(f"Cipher Suite: {result.cipher_suite}")
    console.print(f"Peer Signature: {result.peer_signature_type}")


@bridge_app.command("verify")
def verify_cmd(
    target: Annotated[str, typer.Argument(help="HOST[:PORT] to verify")],
    expect: Annotated[str, typer.Option("--expect", help="Expected TLS group (e.g. X25519MLKEM768)")],
    exit_code: Annotated[bool, typer.Option("--exit-code/--no-exit-code", help="Exit 1 on mismatch")] = True,
):
    """Verify that a host negotiates a specific TLS group."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443
        
    matched, result = verify_group(host, port, expect)
    
    if not result.reachable:
        err_console.print(f"[red]FAIL  Unreachable: {result.error}[/red]")
        if exit_code:
            raise typer.Exit(1)
        return
        
    if matched:
        hybrid_str = "(hybrid PQC)" if result.hybrid_pqc else "(classical)"
        console.print(f"[green]PASS[/green]  negotiated={result.negotiated_group} {hybrid_str}  expected={expect}")
    else:
        hybrid_str = "(hybrid PQC)" if result.hybrid_pqc else "(classical)"
        console.print(f"[red]FAIL[/red]  negotiated={result.negotiated_group} {hybrid_str}  expected={expect}")
        if exit_code:
            raise typer.Exit(1)
