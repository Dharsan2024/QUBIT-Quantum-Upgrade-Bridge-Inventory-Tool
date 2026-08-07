import csv
from pathlib import Path
from typing import Annotated, cast

import typer
from rich.console import Console

from qubit_bridge.models import BridgeEngine
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
    groups: Annotated[
        str | None,
        typer.Option("--groups", "-g", help="Force specific TLS groups (e.g. X25519MLKEM768)"),
    ] = None,
    sni: Annotated[str | None, typer.Option("--sni", help="SNI server name")] = None,
    output_json: Annotated[bool, typer.Option("--json", help="Output JSON")] = False,
    push: Annotated[bool, typer.Option("--push", help="Push to API")] = False,
):
    """Probe a host to determine its negotiated TLS group."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443

    result = probe_host(host, port, groups=groups, sni=sni)

    if push and result.reachable:
        from qubit_bridge.assets import probe_to_assets, push_assets_to_api

        assets = probe_to_assets(result)
        push_assets_to_api(assets)
        console.print(f"[green]Pushed {len(assets)} assets to API.[/green]")

    if output_json:
        console.print(result.model_dump_json(exclude={"raw_output"} if result.reachable else None))
        return

    if not result.reachable:
        err_console.print(f"[red]Error probing {target}: {result.error}[/red]")
        raise typer.Exit(1)

    console.print(f"Host: [bold]{result.host}:{result.port}[/bold]")
    console.print(f"TLS Version: {result.tls_version}")

    cp = result.group_codepoint
    grp = result.negotiated_group
    if result.hybrid_pqc:
        console.print(f"Negotiated Group: [green]{grp} (hybrid PQC)[/green] (codepoint: {cp})")
    else:
        console.print(f"Negotiated Group: [yellow]{grp} (classical)[/yellow] (codepoint: {cp})")

    console.print(f"Cipher Suite: {result.cipher_suite}")
    console.print(f"Peer Signature: {result.peer_signature_type}")


@bridge_app.command("verify")
def verify_cmd(
    target: Annotated[str, typer.Argument(help="HOST[:PORT] to verify")],
    expect: Annotated[
        str, typer.Option("--expect", help="Expected TLS group (e.g. X25519MLKEM768)")
    ],
    exit_code: Annotated[
        bool, typer.Option("--exit-code/--no-exit-code", help="Exit 1 on mismatch")
    ] = True,
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
        hyb = "(hybrid PQC)" if result.hybrid_pqc else "(classical)"
        console.print(
            f"[green]PASS[/green]  negotiated={result.negotiated_group} {hyb}  expected={expect}"
        )
    else:
        hybrid_str = "(hybrid PQC)" if result.hybrid_pqc else "(classical)"
        console.print(
            f"[red]FAIL[/red]  negotiated={result.negotiated_group} {hybrid_str}  expected={expect}"
        )
        if exit_code:
            raise typer.Exit(1)


@bridge_app.command("capture")
def capture_cmd(
    target: Annotated[str, typer.Argument(help="HOST[:PORT] to capture")],
    out: Annotated[Path, typer.Option("--out", help="Output .pcap file")],
    iface: Annotated[str, typer.Option("--iface", help="Network interface")] = "any",
    handshakes: Annotated[int, typer.Option("--handshakes", help="Number of handshakes")] = 1,
):
    """Capture TLS handshake packets to a pcap file."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443

    from qubit_bridge.capture import capture_handshake

    console.print(f"Capturing handshake on {target}...")
    capture_handshake(host, port, out, iface=iface, handshakes=handshakes)
    console.print(f"[green]Saved capture to {out}[/green]")


@bridge_app.command("diff")
def diff_cmd(
    before_pcap: Annotated[Path, typer.Argument(help="Before pcap")],
    after_pcap: Annotated[Path, typer.Argument(help="After pcap")],
):
    """Compare two pcap files."""
    from qubit_bridge.capture import diff_handshakes

    console.print(f"Diffing {before_pcap} and {after_pcap}...")
    res = diff_handshakes(before_pcap, after_pcap)
    console.print(res)


@bridge_app.command("bench")
def bench_cmd(
    target: Annotated[str, typer.Argument(help="HOST[:PORT] to bench")],
    groups: Annotated[str, typer.Option("--groups", help="Comma-separated groups to benchmark")],
    n: Annotated[int, typer.Option("-n", help="Number of samples per group")] = 100,
    out: Annotated[Path | None, typer.Option("--out", help="Output CSV file")] = None,
    push: Annotated[bool, typer.Option("--push", help="Push to API")] = False,
):
    """Benchmark TLS handshakes for specific groups."""
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 443

    from qubit_bridge.bench import bench_matrix

    group_list = [g.strip() for g in groups.split(",")]
    console.print(f"Benchmarking {group_list} against {target} with N={n}...")
    results = bench_matrix(host, port, group_list, n=n)

    for r in results:
        console.print(
            f"{r.group}: {r.handshake_ms_p50:.2f}ms (median), "
            f"{r.client_key_share_bytes}B client share"
        )

    if out:
        with out.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].model_dump().keys())
            writer.writeheader()
            for r in results:
                writer.writerow(r.model_dump())
        console.print(f"[green]Saved benchmark results to {out}[/green]")


@bridge_app.command("up")
def up_cmd(
    profile_name: Annotated[str, typer.Argument(help="Profile name")],
    engine: Annotated[str, typer.Option("--engine", help="nginx or haproxy")] = "nginx",
    upstream: Annotated[
        str, typer.Option("--upstream", help="Upstream host:port")
    ] = "vulnapp-python:5000",
    port: Annotated[int, typer.Option("--port", help="Listen port")] = 8443,
):
    """Bring up a hybrid terminator container."""
    from qubit_bridge.compose import bring_up
    from qubit_bridge.models import BridgeProfile

    if engine not in ("nginx", "haproxy"):
        raise typer.BadParameter("--engine must be 'nginx' or 'haproxy'")
    profile = BridgeProfile(engine=cast(BridgeEngine, engine), upstream=upstream, listen_port=port)
    console.print(f"Bringing up {profile_name} bridge with {engine}...")
    # hardcode path for compose file since demo-lab is parallel
    compose_file = Path("demo-lab/compose.hybrid.yml")
    if not compose_file.exists():
        console.print(f"[yellow]Warning: {compose_file} not found. Running anyway.[/yellow]")
    bring_up(profile, compose_file)
    console.print(f"[green]Bridge {profile_name} is up on port {port}.[/green]")


@bridge_app.command("down")
def down_cmd(profile_name: Annotated[str, typer.Argument(help="Profile name")]):
    """Tear down a hybrid terminator container."""
    from qubit_bridge.compose import tear_down

    console.print(f"Tearing down {profile_name} bridge...")
    compose_file = Path("demo-lab/compose.hybrid.yml")
    tear_down(compose_file)
    console.print(f"[green]Bridge {profile_name} is down.[/green]")
