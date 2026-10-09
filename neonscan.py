#!/usr/bin/env python3
"""NeonScan — interactive cyberpunk network recon + diagnostics suite.

Self-contained bootstrap:
  * If `vendor/wheels/` exists next to this script, it's added to sys.path
    so all required packages load from the local wheelhouse — no `pip install`
    needed at runtime.  Ideal for Termux / air-gapped boxes.
  * Otherwise we fall back to whatever Python packages are reachable.

Bundling wheels (once, on a build host):
    pip download --dest vendor/wheels rich==13.7.0 markdown_it_py pygments

Usage examples:
    python3 neonscan.py                      # interactive
    python3 neonscan.py full --out r.md      # full diag + report
    python3 neonscan.py wifi                 # Wi-Fi link info
    python3 neonscan.py ping 8.8.4.4 -c 4    # latency
    python3 neonscan.py mtr 1.1.1.1          # MTR with per-hop loss
    python3 neonscan.py net                  # host discovery
    python3 neonscan.py report full -o r.md  # generate a Markdown report
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Vendor / wheel bootstrap (must happen before any third-party imports)
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent
_LIB = _THIS_DIR / "vendor" / "_lib"
_WHEELS = _THIS_DIR / "vendor" / "wheels"


def _bootstrap() -> None:
    """If vendor/_lib exists, install vendored wheels into it. Add to sys.path."""
    # First, if vendor/wheels/*.whl exists but vendor/_lib doesn't, populate
    # vendor/_lib by running `pip install --target vendor/_lib` using the
    # bundled wheelhouse.  This requires pip, which Termux ships with.
    if not _LIB.exists():
        if _WHEELS.exists() and any(_WHEELS.glob("*.whl")):
            try:
                import subprocess
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--quiet",
                     "--target", str(_LIB),
                     "--no-index", "--find-links", str(_WHEELS),
                     "rich"],
                    check=True,
                )
            except Exception as _exc:  # noqa: BLE001
                print(
                    f"[neonscan] bootstrap pip install failed: {_exc}",
                    file=sys.stderr,
                )
    # Always make vendor/_lib available when present.
    if _LIB.exists():
        sys.path.insert(0, str(_LIB))


_bootstrap()

# Sanity: surface a friendly error if the runtime lacks dependencies and there
# is no vendored wheelhouse either.
try:
    import rich  # noqa: F401
except ImportError:
    if _WHEELS.exists() and any(_WHEELS.glob("*.whl")):
        print(
            "[neonscan] vendor/wheels/ is present but 'rich' still fails to import. "
            "Run `make bundle` to re-download wheels, or run `python3 -m pip install rich`.",
            file=sys.stderr,
        )
    else:
        print(
            "[neonscan] Python package 'rich' is required. Run:\n"
            "  pip install rich\n"
            "or copy vendor/wheels/*.whl next to this script and run `make bundle`.",
            file=sys.stderr,
        )
    sys.exit(2)

from rich.console import Console
from rich.prompt import Confirm, Prompt

from neonscan.diagnostics import (
    DiagResult,
    get_connections,
    get_dhcp_lease,
    get_public_ip,
    get_routes,
    get_wifi_info,
    list_nearby_aps,
    measure_dns,
    measure_download,
    measure_upload,
    measure_iperf3,
    measure_ping,
    measure_traceroute,
    measure_mtr,
    monitor_link,
    inspect_tls,
    detect_captive,
    analyze_arp,
    discover_mdns,
    build_baseline,
    save_baseline,
    load_baseline,
    diff_against_baseline,
    export_topology,
    privacy_score_ipv6,
    write_report,
    run_full_diag,
    run_full_diag_summary,
)
from neonscan import network
from neonscan.environment import environment_report, render_environment_report
from neonscan.network import detect_network
from neonscan.theme import NEON_MAGENTA, NEON_PINK, NEON_PURPLE, NEON_YELLOW
from neonscan.ui import (
    console,
    deep_scan_with_progress,
    discover_with_progress,
    export_report as export_host_scan_report,
    prompt_action,
    prompt_host,
    render_empty_state,
    render_host_table,
    render_port_table,
    print_web_links,
    open_web_service_prompt,
    inventory_prompt,
    show_intro,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="neonscan",
        description="Cyberpunk local-network reconnaissance + diagnostics suite.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--offline", action="store_true", help="Do not download the OUI database.")
    p.add_argument("--update-oui", action="store_true", help="Force re-download of the IEEE OUI file.")
    p.add_argument("--no-banner", action="store_true", help="Skip the ASCII banner.")
    p.add_argument("--subnet", help="Override the detected network prefix (IPv4 or IPv6 CIDR).")
    p.add_argument(
        "--cache-dir",
        default=str(Path.home() / ".neonscan" / "cache"),
        help="Directory used to cache the OUI database.",
    )
    p.add_argument("--debug", action="store_true", help="Verbose logging.")
    sub = p.add_subparsers(dest="cmd")

    # Subcommands
    sub.add_parser("wifi", help="Wi-Fi link info (RSSI / channel / BSSID / neighbors)")
    sub.add_parser("routes", help="Default gateway + route summary")
    sub.add_parser("dhcp", help="Active DHCP lease")
    sub.add_parser("public", help="Public IP + ISP + reverse DNS")
    sub.add_parser("connections", help="Active TCP/UDP sockets + listening ports")
    sub.add_parser("monitor", help="Live RSSI + byte-rate monitoring")
    sub.add_parser("aps", help="List nearby Wi-Fi APs")
    sub.add_parser("arp", help="ARP anomaly detection (duplicate IP, multi-IP MAC)")
    sub.add_parser("captive", help="Detect captive portal presence")
    sub.add_parser("mdns", help="Discover local mDNS / Bonjour services")

    ping_p = sub.add_parser("ping", help="Latency / packet-loss / jitter against a target")
    ping_p.add_argument("target", nargs="?", default="8.8.8.8")
    ping_p.add_argument("-c", "--count", type=int, default=10)
    ping_p.add_argument("--interval-ms", type=int, default=200)

    dns_p = sub.add_parser("dns", help="DNS latency across multiple resolvers")
    dns_p.add_argument("name", nargs="?", default="google.com")

    speed_p = sub.add_parser("speed", help="Download bandwidth test (Cloudflare)")
    speed_p.add_argument("--size-mb", type=int, default=10, help="Test blob size (MB)")

    up_p = sub.add_parser("upload", help="Upload bandwidth test (Cloudflare /__up)")
    up_p.add_argument("--size-mb", type=int, default=8, help="Test blob size (MB)")

    iperf_p = sub.add_parser("iperf3", help="LAN bandwidth test (requires iperf3 on PATH)")
    iperf_p.add_argument("--server", help="iperf3 server host")
    iperf_p.add_argument("--duration", type=int, default=6, help="seconds")
    iperf_p.add_argument("--reverse", action="store_true", help="upload instead of download")

    trace_p = sub.add_parser("traceroute", help="Trace the path to a host")
    trace_p.add_argument("target", nargs="?", default="8.8.8.8")
    trace_p.add_argument("--max-hops", type=int, default=20)
    trace_p.add_argument("--wait", type=int, default=1)

    mtr_p = sub.add_parser("mtr", help="MTR-style continuous traceroute (per-hop loss)")
    mtr_p.add_argument("target", nargs="?", default="8.8.8.8")
    mtr_p.add_argument("--cycles", type=int, default=3)
    mtr_p.add_argument("--max-hops", type=int, default=25)
    mtr_p.add_argument("--probes", type=int, default=3)

    tls_p = sub.add_parser("tls", help="Inspect the TLS certificate of host:port")
    tls_p.add_argument("host", help="target host or IP")
    tls_p.add_argument("--port", type=int, default=443)
    tls_p.add_argument("--sni", help="explicit SNI override")

    full_p = sub.add_parser("full", help="Run all diagnostics and dump a report")
    full_p.add_argument("--out", help="Write Markdown/JSON report to this path")
    full_p.add_argument("--format", choices=["md", "json", "mermaid"], help="Force report format")
    full_p.add_argument("--ping-target", default="8.8.8.8")
    full_p.add_argument("--dns-name", default="google.com")
    full_p.add_argument("--speed-mb", type=int, default=8)
    full_p.add_argument("--monitor-s", type=float, default=0.0, help="Sample link for N seconds during full diag")
    full_p.add_argument("--traceroute-target", default="8.8.8.8")
    full_p.add_argument("--mtr-cycles", type=int, default=0, help="include MTR (N cycles)")
    full_p.add_argument("--upload-mb", type=int, default=0, help="include upload test (MB); 0 disables")

    watch_p = sub.add_parser("watch", help="Save baseline or diff current run against saved baseline")
    watch_p.add_argument("--save", action="store_true", help="Save current run as the new baseline")
    watch_p.add_argument("--baseline", default="~/.neonscan/baseline.json", help="Baseline file path")

    top_p = sub.add_parser("topology", help="Export network topology as a Mermaid diagram")
    top_p.add_argument(
        "format_pos", nargs="?", choices=["mermaid", "dot"], default=None,
        help="optional format (default mermaid)",
    )
    top_p.add_argument("--format", choices=["mermaid", "dot"], default="mermaid", dest="format", help="explicit format")
    top_p.add_argument("--out", help="file path; default: stdout")

    report_p = sub.add_parser("report", help="Generate a report file")
    report_p.add_argument("what", choices=[
        "full", "wifi", "ping", "dns", "speed", "traceroute", "routes", "public",
        "connections", "dhcp", "monitor", "aps", "arp", "captive", "mdns",
        "mtr", "tls", "upload", "iperf3", "topology",
    ])
    report_p.add_argument("-o", "--out", required=True)
    report_p.add_argument("--ping-target", default="8.8.8.8")
    report_p.add_argument("--dns-name", default="google.com")
    report_p.add_argument("--size-mb", type=int, default=8)
    report_p.add_argument("--host", help="host for tls/captive/mtr", default="")
    report_p.add_argument("--port", type=int, default=443)

    sub.add_parser("net", aliases=["scan"], help="Host discovery (original feature)")
    udp_p = sub.add_parser("udp", help="Probe common UDP services on one host")
    udp_p.add_argument("host", help="explicit target host or IP")
    udp_p.add_argument(
        "--ports", help="comma-separated subset of supported probes: 53,123,161,1900",
    )

    return p


# ---------------------------------------------------------------------------
# Sub-command runners
# ---------------------------------------------------------------------------

def run_wifi(_args) -> list[DiagResult]:
    r = get_wifi_info()
    _print_diag(r)
    aps = list_nearby_aps(limit=12)
    if aps:
        from rich.table import Table
        t = Table(title="[bold cyan]⟨ Nearby APs ⟩[/]", box=None)
        t.add_column("BSSID"); t.add_column("RSSI", justify="right"); t.add_column("CH", justify="right"); t.add_column("SSID"); t.add_column("Sec")
        for a in aps:
            t.add_row(a["bssid"], str(a["rssi"]), str(a["channel"]), a["ssid"][:24], a["security"])
        console.print(t)
    return [r]


def run_routes(_args) -> list[DiagResult]:
    r = get_routes()
    _print_diag(r)
    return [r]


def run_dhcp(_args) -> list[DiagResult]:
    r = get_dhcp_lease()
    _print_diag(r)
    return [r]


def run_public(_args) -> list[DiagResult]:
    r = get_public_ip()
    _print_diag(r)
    return [r]


def run_connections(_args) -> list[DiagResult]:
    r = get_connections()
    _print_diag(r)
    return [r]


def run_monitor(_args) -> list[DiagResult]:
    r = monitor_link(duration_s=8.0, interval_s=1.0)
    _print_diag(r)
    return [r]


def run_aps(_args) -> list[DiagResult]:
    aps = list_nearby_aps(limit=30)
    from rich.table import Table
    t = Table(title="[bold cyan]⟨ Nearby APs ⟩[/]", box=None)
    t.add_column("BSSID"); t.add_column("RSSI", justify="right"); t.add_column("CH", justify="right"); t.add_column("SSID"); t.add_column("Sec")
    for a in aps:
        t.add_row(a["bssid"], str(a["rssi"]), str(a["channel"]), a["ssid"][:24], a["security"])
    console.print(t)
    return []


def run_arp(_args) -> list[DiagResult]:
    r = analyze_arp()
    _print_diag(r)
    return [r]


def run_captive(_args) -> list[DiagResult]:
    r = detect_captive()
    _print_diag(r)
    return [r]


def run_mdns(_args) -> list[DiagResult]:
    r = discover_mdns()
    _print_diag(r)
    services = (r.raw or {}).get("services", {}) if r.ok else {}
    if services:
        from rich.table import Table
        t = Table(title="[bold cyan]⟨ mDNS services ⟩[/]", box=None)
        t.add_column("Type"); t.add_column("Instance"); t.add_column("Host"); t.add_column("IP"); t.add_column("Port", justify="right"); t.add_column("TXT")
        for label, entries in services.items():
            for e in entries[:30]:
                t.add_row(label, e.get("instance", "")[:40], (e.get("host") or "")[:30],
                          e.get("ip") or "", str(e.get("port", 0)),
                          ",".join(e.get("txt") or [])[:40])
        console.print(t)
    return [r]


def run_ping(args) -> list[DiagResult]:
    r = measure_ping(args.target, count=args.count, interval_ms=args.interval_ms)
    _print_diag(r)
    return [r]


def run_dns(args) -> list[DiagResult]:
    r = measure_dns(args.name)
    _print_diag(r)
    return [r]


def run_speed(args) -> list[DiagResult]:
    r = measure_download(sizes=[args.size_mb * 1_000_000])
    _print_diag(r)
    return [r]


def run_upload(args) -> list[DiagResult]:
    r = measure_upload(sizes=[args.size_mb * 1_000_000])
    _print_diag(r)
    return [r]


def run_iperf3(args) -> list[DiagResult]:
    r = measure_iperf3(server=args.server, duration_s=args.duration, reverse=args.reverse)
    _print_diag(r)
    return [r]


def run_traceroute(args) -> list[DiagResult]:
    r = measure_traceroute(args.target, max_hops=args.max_hops, wait_s=args.wait)
    _print_diag(r)
    return [r]


def run_mtr(args) -> list[DiagResult]:
    r = measure_mtr(target=args.target, cycles=args.cycles, max_hops=args.max_hops, probes=args.probes)
    _print_diag(r)
    return [r]


def run_tls(args) -> list[DiagResult]:
    r = inspect_tls(args.host, port=args.port, sni=args.sni)
    _print_diag(r)
    return [r]


def run_watch(args) -> list[DiagResult]:
    """Save the current run as baseline, or diff against an existing one.

    Without --save, we run all diagnostics and compare to the saved baseline.
    """
    from rich.console import Console
    bs_path = Path(args.baseline).expanduser()
    results = run_full_diag(monitor_s=0.0, speed_size_mb=4)
    if args.save:
        b = build_baseline(results)
        save_baseline(b, bs_path)
        console.print(f"[bold {NEON_PINK}]// baseline saved → {bs_path}[/]")
        return results
    base = load_baseline(bs_path)
    if not base:
        console.print(f"[bold {NEON_MAGENTA}]// no baseline at {bs_path}, saving current run[/]")
        b = build_baseline(results)
        save_baseline(b, bs_path)
        return results
    diff = diff_against_baseline(base, results)
    _print_diag(diff)
    return results + [diff]


def run_topology(args) -> list[DiagResult]:
    from neonscan.diagnostics.topology import topology_to_mermaid
    net = detect_network()
    routes = get_routes()
    r_result = routes
    gw = next((f.value for f in r_result.findings if f.label == "Default gw"), "?")
    # quick scan to assemble host list
    hosts_data = []
    try:
        net_info = detect_network()
        hosts, _ = discover_with_progress(
            subnet=net_info["subnet"], ping_workers=32,
            cache_dir=Path(getattr(args, "cache_dir", Path.home() / ".neonscan" / "cache")),
            offline=getattr(args, "offline", False),
            update_oui=getattr(args, "update_oui", False),
        )
    except Exception:
        hosts = []
    for h in hosts:
        hosts_data.append({"ip": h.ip, "hostname": h.hostname, "manufacturer": h.manufacturer})
    fmt = getattr(args, "format_pos", None) or args.format
    if fmt == "mermaid":
        text = topology_to_mermaid(
            local_ip=net["local_ip"], gateway=gw, hosts=hosts_data
        )
    else:
        from neonscan.diagnostics.topology import topology_to_dot
        text = topology_to_dot(local_ip=net["local_ip"], gateway=gw, hosts=hosts_data)
    if args.out:
        Path(args.out).write_text(text)
        console.print(f"[bold {NEON_PINK}]// saved → {args.out}[/]")
    else:
        console.print(text)
    r = DiagResult(title=f"Topology · {fmt}")
    r.add("Hosts", str(len(hosts_data)))
    r.add("Gateway", gw)
    r.add("Local", net["local_ip"])
    r.add("Scope", "Schematic subnet view; no switch paths are inferred")
    return [r]


def run_full(args) -> list[DiagResult]:
    results = run_full_diag(
        ping_target=args.ping_target,
        ping_count=6,
        speed_size_mb=args.speed_mb,
        dns_name=args.dns_name,
        traceroute_target=args.traceroute_target,
        monitor_s=args.monitor_s,
    )
    # optional: upload, mtr
    upload_mb = getattr(args, "upload_mb", 0) or 0
    if upload_mb > 0:
        results.append(measure_upload(sizes=[upload_mb * 1_000_000]))
    mtr_cycles = getattr(args, "mtr_cycles", 0) or 0
    if mtr_cycles > 0:
        results.append(measure_mtr(target=args.traceroute_target, cycles=mtr_cycles))
    # Always include captive + ARP anomalies in the full report
    try:
        results.append(analyze_arp())
    except Exception:
        pass
    try:
        results.append(detect_captive())
    except Exception:
        pass

    console.rule("[bold]⟨ Full diagnostics ⟩[/]", style=NEON_PINK)
    for r in results:
        _print_diag(r, header=False)
    sm = run_full_diag_summary(results)
    console.print(
        f"[bold]ok={sm['ok']} warn={sm['warn']} fail={sm['fail']} ran={sm['ran']}[/]"
    )
    if args.out:
        fmt = args.format or ("json" if args.out.endswith(".json") else "md")
        if fmt == "mermaid":
            # Build a Mermaid topology using the host list discovered by the
            # network scan inside `run_full_diag`. We pull hosts out of the
            # raw results when available.
            from neonscan.diagnostics.topology import topology_to_mermaid
            net = detect_network()
            gw_f = next((r_ for r_ in results if r_.title == "Routes"), None)
            gw = (
                next((f.value for f in gw_f.findings if f.label == "Default gw"), "?")
                if gw_f
                else "?"
            )
            host_data = []
            for hr in results:
                if hr.title == "Wi-Fi link":
                    continue
            text = topology_to_mermaid(net["local_ip"], gw, host_data)
            Path(args.out).write_text(text)
            console.print(f"[bold {NEON_PINK}]// mermaid → {args.out}[/]")
            return results
        write_report(Path(args.out), results, title="NeonScan full diag", fmt=fmt)
        console.print(f"[bold {NEON_PINK}]// report → {args.out}[/]")
    return results


def run_net(args) -> list[DiagResult]:
    """Original host-discovery mode, kept for back-compat."""
    net_info = detect_network()
    subnet = args.subnet or net_info["subnet"]
    if not args.no_banner:
        show_intro({
            **net_info, "subnet": subnet,
            "subnet_method": "user-supplied CIDR" if args.subnet else net_info["subnet_method"],
        })
    hosts, ports_by_host = discover_with_progress(
        subnet=subnet, ping_workers=32 if network.IS_TERMUX else 64,
        cache_dir=Path(args.cache_dir),
        offline=args.offline, update_oui=args.update_oui,
    )
    if not hosts:
        render_empty_state()
        return []
    console.print(render_host_table(hosts, ports_by_host))
    print_web_links(hosts, ports_by_host)
    console.print()
    action = prompt_action()
    while action != "q":
        if action == "s":
            hosts, ports_by_host = [], {}
            hosts, ports_by_host = discover_with_progress(
                subnet=subnet, ping_workers=32 if network.IS_TERMUX else 64,
                cache_dir=Path(args.cache_dir),
                offline=args.offline, update_oui=args.update_oui,
            )
            if hosts:
                console.print(render_host_table(hosts, ports_by_host))
                print_web_links(hosts, ports_by_host)
        elif action == "d":
            host = prompt_host(hosts)
            if host:
                results = deep_scan_with_progress(host, top=200)
                if results:
                    console.print(render_port_table(host.ip, results))
                    print_web_links([host], {host.ip: results})
                    ports_by_host[host.ip] = results
        elif action == "p":
            host = prompt_host(hosts)
            if host:
                ports = [80, 443, 8080, 8443, 8000, 8888, 3000]
                from neonscan.scanner import scan_host
                results = scan_host(
                    host.ip, ports=ports, workers=20, timeout=1.5,
                    include_states=True,
                )
                host.scanned_ports["tcp"] = list(ports)
                if any(result.open for result in results):
                    console.print(render_port_table(host.ip, results))
                    print_web_links([host], {host.ip: results})
                else:
                    console.print(f"[{NEON_MAGENTA}]// no web ports open[/]")
                    console.print(render_port_table(host.ip, results))
                ports_by_host[host.ip] = results
        elif action == "O":
            host = prompt_host(hosts)
            if host:
                open_web_service_prompt(
                    host.ip, ports_by_host.get(host.ip, [])
                )
        elif action == "U":
            host = prompt_host(hosts)
            if host:
                from neonscan.scanner import scan_udp_host
                results = scan_udp_host(host.ip, timeout=0.8 if network.IS_TERMUX else 1.0)
                host.scanned_ports["udp"] = [result.port for result in results]
                previous = [result for result in ports_by_host.get(host.ip, []) if result.protocol != "udp"]
                ports_by_host[host.ip] = previous + results
                console.print(render_port_table(host.ip, results))
                console.print("[dim]UDP sin respuesta no permite distinguir entre servicio abierto y filtrado.[/]")
        elif action == "i":
            inventory_prompt(subnet, hosts, ports_by_host)
        elif action == "e":
            out = Path.cwd() / "neonscan-net.json"
            tgt = Prompt.ask("[bold]save path[/]", default=str(out))
            export_host_scan_report(Path(tgt), hosts, ports_by_host)
        action = prompt_action()
    return []


def run_udp(args) -> list[DiagResult]:
    """Run a small, read-only UDP service probe against an explicit target."""
    from neonscan.scanner import UDP_COMMON_PORTS, scan_udp_host

    ports = UDP_COMMON_PORTS
    if args.ports:
        try:
            ports = tuple(dict.fromkeys(int(value.strip()) for value in args.ports.split(",")))
        except ValueError as exc:
            raise ValueError("UDP ports must be comma-separated integers") from exc
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise ValueError("UDP ports must be between 1 and 65535")
    results = scan_udp_host(args.host, ports=ports)
    console.print(render_port_table(args.host, results))
    console.print("[dim]UDP sin respuesta no permite distinguir entre servicio abierto y filtrado.[/]")
    return []


def run_report(args) -> list[DiagResult]:
    """Generate a report file using the chosen sub-diagnostic."""
    host = getattr(args, "host", "") or ""
    port = getattr(args, "port", 443)
    fns = {
        "full": lambda: run_full_diag(ping_target=args.ping_target, dns_name=args.dns_name, speed_size_mb=args.size_mb),
        "wifi": lambda: [get_wifi_info()],
        "ping": lambda: [measure_ping(args.ping_target)],
        "dns": lambda: [measure_dns(args.dns_name)],
        "speed": lambda: [measure_download(sizes=[args.size_mb * 1_000_000])],
        "traceroute": lambda: [measure_traceroute(args.ping_target)],
        "routes": lambda: [get_routes()],
        "public": lambda: [get_public_ip()],
        "connections": lambda: [get_connections()],
        "dhcp": lambda: [get_dhcp_lease()],
        "monitor": lambda: [monitor_link(duration_s=6.0)],
        "aps": lambda: [],
        "arp": lambda: [analyze_arp()],
        "captive": lambda: [detect_captive()],
        "mdns": lambda: [discover_mdns()],
        "mtr": lambda: [measure_mtr(args.ping_target)] if host == "" else [measure_mtr(host or args.ping_target)],
        "tls": lambda: [inspect_tls(host or args.ping_target, port=port)],
        "upload": lambda: [measure_upload(sizes=[args.size_mb * 1_000_000])],
        "iperf3": lambda: [measure_iperf3(duration_s=6)],
        "topology": lambda: [],
    }
    results = fns[args.what]()
    out = Path(args.out)
    fmt = "json" if out.suffix.lower() == ".json" else "md"
    write_report(out, results, title=f"NeonScan :: {args.what}", fmt=fmt)
    console.print(f"[bold {NEON_PINK}]// saved → {out}[/]  (format={fmt})")
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_diag(r: DiagResult, header: bool = True) -> None:
    if header:
        console.rule(f"[bold {NEON_PINK}]⟨ {r.title} ⟩[/]", style=NEON_PURPLE)
    if not r.ok:
        console.print(f"[bold {NEON_MAGENTA}]// {r.error}[/]")
        return
    if r.summary:
        console.print(f"  [bold]{r.summary}[/]")
    for f in r.findings:
        console.print("  " + f.format())


SUBCOMMANDS = {
    "wifi": run_wifi,
    "routes": run_routes,
    "dhcp": run_dhcp,
    "public": run_public,
    "connections": run_connections,
    "monitor": run_monitor,
    "aps": run_aps,
    "arp": run_arp,
    "captive": run_captive,
    "mdns": run_mdns,
    "ping": run_ping,
    "dns": run_dns,
    "speed": run_speed,
    "upload": run_upload,
    "iperf3": run_iperf3,
    "traceroute": run_traceroute,
    "mtr": run_mtr,
    "tls": run_tls,
    "watch": run_watch,
    "topology": run_topology,
    "full": run_full,
    "net": run_net,
    "scan": run_net,
    "udp": run_udp,
    "report": run_report,
}


# ---------------------------------------------------------------------------
# Interactive mode (default when no subcommand)
# ---------------------------------------------------------------------------

def interactive_mode(args) -> int:
    """Run the menu-first terminal UI; every network scan is user initiated."""
    net_info = detect_network()
    subnet = args.subnet or net_info["subnet"]
    if not args.no_banner:
        show_intro({
            **net_info, "subnet": subnet,
            "subnet_method": "user-supplied CIDR" if args.subnet else net_info["subnet_method"],
        })
    else:
        console.print(
            f"[bold {NEON_PINK}]neonscan :: subnet={subnet} iface={net_info['interface']}[/]"
        )

    hosts = []
    ports_by_host = {}
    menu_context = "main"
    while True:
        if menu_context == "diagnostics":
            action = interactive_diagnostics_prompt()
            if action is None:
                menu_context = "main"
                continue
        elif menu_context == "hosts":
            action = interactive_hosts_prompt()
            if action is None:
                menu_context = "main"
                continue
        else:
            action = interactive_prompt(
                has_hosts=bool(hosts), ipv6_subnets=net_info.get("ipv6_subnets", [])
            )
        if action == "q":
            console.print(f"[bold {NEON_PINK}]// jack out. 👋[/]")
            return 0
        if action == "v6":
            prefixes = net_info.get("ipv6_subnets", [])
            if not prefixes:
                console.print(f"[{NEON_MAGENTA}]// no se detectaron prefijos IPv6 utilizables[/]")
                continue
            options = [(str(index), prefix) for index, prefix in enumerate(prefixes, start=1)]
            choice = _menu_choice("PREFIJO IPv6", options + [("0", "Cancelar")])
            if choice == "0":
                continue
            selected_prefix = prefixes[int(choice) - 1]
            try:
                from neonscan.network import _network_hosts
                _network_hosts(selected_prefix)
                subnet = selected_prefix
            except ValueError:
                console.print(
                    f"[{NEON_YELLOW}]El prefijo {selected_prefix} es demasiado amplio para enumerarlo. "
                    "Escribe un CIDR más pequeño (máximo 1,024 direcciones).[/]"
                )
                subnet = interactive_subnet_prompt(default_subnet=selected_prefix)
            hosts, ports_by_host = [], {}
            console.print(f"[bold {NEON_PINK}]// escaneando prefijo IPv6 {subnet}[/]")
            action = "s"
        if action == "r":
            subnet = interactive_subnet_prompt(default_subnet=subnet)
            hosts, ports_by_host = [], {}
            console.print(f"[bold {NEON_PINK}]// scan target set to {subnet}[/]")
            continue
        if action == "s":
            try:
                hosts, ports_by_host = discover_with_progress(
                    subnet=subnet,
                    ping_workers=32 if network.IS_TERMUX else 64,
                    cache_dir=Path(args.cache_dir),
                    offline=args.offline,
                    update_oui=args.update_oui,
                )
            except KeyboardInterrupt:
                console.print(f"[bold {NEON_MAGENTA}]// scan cancelled; returning to menu[/]")
                hosts, ports_by_host = [], {}
                continue
            except (ValueError, OSError) as exc:
                console.print(f"[bold {NEON_MAGENTA}]// scan could not start: {exc}[/]")
                continue
            if hosts:
                console.print(render_host_table(hosts, ports_by_host))
                print_web_links(hosts, ports_by_host)
            else:
                hosts, ports_by_host = [], {}
                render_empty_state()
            continue
        if action == "m":
            menu_context = "diagnostics"
            continue
        if action == "h":
            menu_context = "hosts"
            continue
        if action == "E":
            render_environment_report(environment_report())
            continue

        try:
            if action == "d":
                host = prompt_host(hosts)
                if not host:
                    continue
                results = deep_scan_with_progress(host, top=200)
                if not results:
                    console.print(f"[{NEON_MAGENTA}]// no open ports on {host.ip}[/]")
                    continue
                console.print(render_port_table(host.ip, results))
                print_web_links([host], {host.ip: results})
                ports_by_host[host.ip] = results

            elif action == "p":
                host = prompt_host(hosts)
                if not host:
                    continue
                from neonscan.scanner import scan_host
                ports = [80, 443, 8000, 8080, 8081, 8088, 8443, 8888, 3000, 5000, 9000]
                results = scan_host(
                    host.ip,
                    ports=ports,
                    workers=20 if network.IS_TERMUX else 30,
                    timeout=1.5,
                    include_states=True,
                )
                host.scanned_ports["tcp"] = list(ports)
                if not any(result.open for result in results):
                    console.print(f"[{NEON_MAGENTA}]// no web ports open[/]")
                    console.print(render_port_table(host.ip, results))
                else:
                    console.print(render_port_table(host.ip, results))
                    print_web_links([host], {host.ip: results})
                ports_by_host[host.ip] = results

            elif action == "o":
                host = prompt_host(hosts)
                if not host:
                    continue
                open_web_service_prompt(host.ip, ports_by_host.get(host.ip, []))

            elif action == "u":
                host = prompt_host(hosts)
                if not host:
                    continue
                from neonscan.scanner import scan_udp_host
                results = scan_udp_host(host.ip, timeout=0.8 if network.IS_TERMUX else 1.0)
                host.scanned_ports["udp"] = [result.port for result in results]
                previous = [result for result in ports_by_host.get(host.ip, []) if result.protocol != "udp"]
                ports_by_host[host.ip] = previous + results
                console.print(render_port_table(host.ip, results))
                console.print("[dim]UDP sin respuesta no permite distinguir entre servicio abierto y filtrado.[/]")

            elif action == "i":
                inventory_prompt(subnet, hosts, ports_by_host)

            elif action == "e":
                if not hosts:
                    console.print(f"[{NEON_MAGENTA}]// scan the network before exporting hosts[/]")
                    continue
                out = Path.cwd() / "neonscan-host-scan.json"
                target = Prompt.ask("[bold]save path[/]", default=str(out))
                export_host_scan_report(Path(target), hosts, ports_by_host)

            elif action == "D":
                console.rule(f"[bold {NEON_PINK}]⟨ FULL DIAGNOSTICS ⟩[/]", style=NEON_PURPLE)
                results = run_full_diag(ping_target="8.8.8.8", ping_count=6, speed_size_mb=8)
                for result in results:
                    _print_diag(result, header=True)
                if Confirm.ask("[bold]Save report?[/]", default=False):
                    default_path = str(Path.cwd() / "neonscan-report.md")
                    target = Prompt.ask("[bold]path[/]", default=default_path)
                    write_report(Path(target), results, title="NeonScan full diag")
                    console.print(f"[bold {NEON_PINK}]// saved → {target}[/]")

            elif action == "W":
                _print_diag(get_wifi_info())
            elif action == "P":
                _print_diag(measure_ping(Prompt.ask("[bold]target[/]", default="8.8.8.8")))
            elif action == "Z":
                _print_diag(measure_dns(Prompt.ask("[bold]domain[/]", default="google.com")))
            elif action == "N":
                _print_diag(get_public_ip())
            elif action == "T":
                _print_diag(measure_traceroute(Prompt.ask("[bold]target[/]", default="8.8.8.8")))
            elif action == "G":
                _print_diag(get_routes())
                _print_diag(get_dhcp_lease())
            elif action == "C":
                _print_diag(get_connections())
            elif action == "M":
                _print_diag(monitor_link(duration_s=6.0))
            elif action == "U":
                size = Prompt.ask("[bold]size MB[/]", default="5")
                _print_diag(measure_upload(sizes=[int(size) * 1_000_000]))
            elif action == "I":
                _print_diag(measure_iperf3(duration_s=6))
            elif action == "X":
                target = Prompt.ask("[bold]target[/]", default="8.8.8.8")
                _print_diag(measure_mtr(target=target, cycles=3))
            elif action == "K":
                host = Prompt.ask("[bold]host[/]", default="google.com")
                port = int(Prompt.ask("[bold]port[/]", default="443"))
                _print_diag(inspect_tls(host, port=port))
            elif action == "O":
                _print_diag(detect_captive())
            elif action == "A":
                _print_diag(analyze_arp())
            elif action == "B":
                result = discover_mdns()
                _print_diag(result)
                services = (result.raw or {}).get("services", {}) if result.ok else {}
                if services:
                    from rich.table import Table
                    table = Table(title="[bold cyan]⟨ mDNS ⟩[/]", box=None, expand=True)
                    table.add_column("Type")
                    table.add_column("Instance", overflow="ellipsis")
                    table.add_column("Host", overflow="ellipsis")
                    table.add_column("Port", justify="right")
                    for label, entries in services.items():
                        for entry in entries[:30]:
                            table.add_row(label, entry.get("instance", "")[:36],
                                          entry.get("host") or "", str(entry.get("port", 0)))
                    console.print(table)
            elif action == "V":
                baseline_path = Path("~/.neonscan/baseline.json").expanduser()
                save_new = Confirm.ask("[bold]Save this run as the baseline?[/]", default=False)
                if save_new:
                    results = run_full_diag(monitor_s=0.0, speed_size_mb=4)
                    save_baseline(build_baseline(results), baseline_path)
                    console.print(f"[bold {NEON_PINK}]// baseline saved[/]")
                else:
                    baseline = load_baseline(baseline_path)
                    if not baseline:
                        console.print(f"[bold {NEON_MAGENTA}]// no baseline — save one first[/]")
                    else:
                        results = run_full_diag(monitor_s=0.0, speed_size_mb=4)
                        _print_diag(diff_against_baseline(baseline, results))
            elif action == "F":
                run_topology(argparse.Namespace(
                    format="mermaid", format_pos="mermaid", out=None,
                    cache_dir=args.cache_dir, offline=args.offline,
                    update_oui=args.update_oui,
                ))
        except KeyboardInterrupt:
            console.print(f"[bold {NEON_MAGENTA}]// action cancelled; returning to menu[/]")
        except (ValueError, OSError) as exc:
            console.print(f"[bold {NEON_MAGENTA}]// action could not complete: {exc}[/]")


def _menu_choice(title: str, options: list[tuple[str, str]]) -> str:
    from rich.panel import Panel

    body = "\n".join(f"  [{NEON_PINK}][{key}][/] {label}" for key, label in options)
    console.print(Panel(body, title=f"[bold {NEON_PINK}]⟨ {title} ⟩[/]",
                        border_style=NEON_PINK, padding=(0, 1)))
    return Prompt.ask("Elige una opción y pulsa Enter",
                      choices=[key for key, _label in options],
                      show_choices=False, show_default=False)


def interactive_prompt(
    has_hosts: bool = False,
    ipv6_subnets: Optional[list[str]] = None,
) -> str:
    """Compact numbered home menu. A scan is never started implicitly."""
    options = [("1", "Escanear la red local"), ("2", "Diagnósticos"),
               ("3", "Cambiar subred objetivo")]
    if has_hosts:
        options.append(("4", "Herramientas para equipos encontrados"))
    options.append(("5", "Revisar entorno y dependencias"))
    if ipv6_subnets:
        options.append(("6", "Escanear IPv6 detectado"))
    options.append(("0", "Salir"))
    choice = _menu_choice("MENÚ PRINCIPAL", options)
    return {"1": "s", "2": "m", "3": "r", "4": "h", "5": "E",
            "6": "v6", "0": "q"}[choice]


def interactive_diagnostics_prompt() -> Optional[str]:
    """Category-based diagnostic menus sized for a phone terminal."""
    groups = [
        ("1", "Conectividad", [("1", "Diagnóstico completo"), ("2", "Wi-Fi"),
         ("3", "Ping"), ("4", "DNS"), ("5", "IP pública"),
         ("6", "Gateway y DHCP")], {"1": "D", "2": "W", "3": "P", "4": "Z", "5": "N", "6": "G"}),
        ("2", "Red local", [("1", "Conexiones activas"), ("2", "Monitor de tráfico"),
         ("3", "Prueba de subida"), ("4", "Prueba iperf3"), ("5", "Portal cautivo"),
         ("6", "Anomalías ARP"), ("7", "Servicios mDNS / Bonjour")],
         {"1": "C", "2": "M", "3": "U", "4": "I", "5": "O", "6": "A", "7": "B"}),
        ("3", "Avanzado", [("1", "Traceroute"), ("2", "MTR"),
         ("3", "Inspección TLS"), ("4", "Guardar / comparar baseline"),
         ("5", "Exportar topología")], {"1": "T", "2": "X", "3": "K", "4": "V", "5": "F"}),
    ]
    while True:
        choice = _menu_choice("DIAGNÓSTICOS · CATEGORÍA",
                              [(key, label) for key, label, _items, _map in groups]
                              + [("0", "Volver al menú principal")])
        if choice == "0":
            return None
        _key, label, items, mapping = next(group for group in groups if group[0] == choice)
        action = _menu_choice(label, items + [("0", "Volver a categorías")])
        if action != "0":
            return mapping[action]


def interactive_hosts_prompt() -> Optional[str]:
    choice = _menu_choice("EQUIPOS ENCONTRADOS", [
        ("1", "Escaneo profundo de puertos"), ("2", "Buscar servicios web"),
        ("3", "Exportar resultados"), ("4", "Abrir servicio web en navegador"),
        ("5", "Comprobar servicios UDP comunes"),
        ("6", "Historial y cambios del inventario"),
        ("0", "Volver al menú principal"),
    ])
    return {"1": "d", "2": "p", "3": "e", "4": "o", "5": "u", "6": "i", "0": None}[choice]

def interactive_subnet_prompt(default_subnet: str) -> str:
    import ipaddress
    from neonscan.network import _network_hosts

    while True:
        value = Prompt.ask(f"[bold {NEON_PINK}]new subnet (CIDR)[/]", default=default_subnet)
        try:
            subnet = ipaddress.ip_network(value, strict=False)
            _network_hosts(str(subnet))
        except ValueError:
            console.print(f"[{NEON_MAGENTA}]Escribe un CIDR IPv4 o IPv6 con hasta 1,024 direcciones utilizables.[/]")
            continue
        return str(subnet)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = build_parser().parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if args.cmd:
        fn = SUBCOMMANDS.get(args.cmd)
        if not fn:
            console.print(f"[bold {NEON_MAGENTA}]// unknown subcommand: {args.cmd}[/]")
            return 2
        try:
            fn(args)
        except KeyboardInterrupt:
            console.print(f"[bold {NEON_MAGENTA}]// aborted[/]")
            return 130
        except Exception as exc:  # noqa: BLE001
            if args.debug:
                raise
            console.print(f"[bold {NEON_MAGENTA}]// error in '{args.cmd}': {exc}[/]")
            return 1
        return 0

    try:
        return interactive_mode(args)
    except KeyboardInterrupt:
        console.print(f"[bold {NEON_MAGENTA}]// disconnected[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
