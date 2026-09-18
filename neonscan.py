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
from neonscan.network import detect_network
from neonscan.oui import OUICache
from neonscan.theme import NEON_MAGENTA, NEON_PINK, NEON_PURPLE
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
    p.add_argument("--subnet", help="Override the auto-detected /24 (e.g. 10.0.0.0/24).")
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
        hosts, _ = discover_with_progress(subnet=net_info["subnet"], ping_workers=32)
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
        show_intro({**net_info, "subnet": subnet})
    hosts, ports_by_host = discover_with_progress(subnet=subnet, ping_workers=64)
    if not hosts:
        render_empty_state()
        return []
    console.print(render_host_table(hosts, ports_by_host))
    console.print()
    action = prompt_action()
    while action != "q":
        if action == "s":
            hosts, ports_by_host = [], {}
            hosts, ports_by_host = discover_with_progress(subnet=subnet, ping_workers=64)
            if hosts:
                console.print(render_host_table(hosts, ports_by_host))
        elif action == "d":
            host = prompt_host(hosts)
            if host:
                results = deep_scan_with_progress(host, top=200)
                if results:
                    console.print(render_port_table(host.ip, results))
                    ports_by_host[host.ip] = results
        elif action == "p":
            host = prompt_host(hosts)
            if host:
                ports = [80, 443, 8080, 8443, 8000, 8888, 3000]
                from neonscan.scanner import scan_host
                results = scan_host(host.ip, ports=ports, workers=20, timeout=1.5)
                if results:
                    console.print(render_port_table(host.ip, results))
                    ports_by_host[host.ip] = results
                else:
                    console.print(f"[{NEON_MAGENTA}]// no web ports open[/]")
        elif action == "e":
            out = Path.cwd() / "neonscan-net.json"
            tgt = Prompt.ask("[bold]save path[/]", default=str(out))
            export_host_scan_report(Path(tgt), hosts, ports_by_host)
        action = prompt_action()
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
    "report": run_report,
}


# ---------------------------------------------------------------------------
# Interactive mode (default when no subcommand)
# ---------------------------------------------------------------------------

def interactive_mode(args) -> int:
    net_info = detect_network()
    subnet = args.subnet or net_info["subnet"]
    if not args.no_banner:
        show_intro({**net_info, "subnet": subnet})
    else:
        console.print(
            f"[bold {NEON_PINK}]neonscan :: subnet={subnet} iface={net_info['interface']}[/]"
        )

    cache = OUICache(
        cache_dir=Path(args.cache_dir),
        update=args.update_oui,
        offline=args.offline,
    )

    hosts, ports_by_host = [], {}
    diag_results: list[DiagResult] = []

    while True:
        if not hosts:
            try:
                hosts, ports_by_host = discover_with_progress(subnet=subnet, ping_workers=64)
            except KeyboardInterrupt:
                console.print(f"[bold {NEON_MAGENTA}]// aborted[/]")
                return 130
            if not hosts:
                render_empty_state()
                if not Confirm.ask("[bold]retry?[/]", default=True):
                    return 0
                continue
            console.print(render_host_table(hosts, ports_by_host))
            console.print()

        action = interactive_prompt()
        if action == "q":
            console.print(f"[bold {NEON_PINK}]// jack out. 👋[/]")
            return 0

        if action == "s":
            hosts, ports_by_host = [], {}
            continue

        if action == "r":
            subnet = interactive_subnet_prompt(default_subnet=subnet)
            hosts, ports_by_host = [], {}
            continue

        if action == "d":
            host = prompt_host(hosts)
            if not host:
                continue
            try:
                results = deep_scan_with_progress(host, top=200)
            except KeyboardInterrupt:
                console.print(f"[bold {NEON_MAGENTA}]// aborted[/]")
                continue
            if not results:
                console.print(f"[{NEON_MAGENTA}]// no open ports on {host.ip}[/]")
                continue
            console.print(render_port_table(host.ip, results))
            ports_by_host[host.ip] = results
            console.print()

        if action == "p":
            host = prompt_host(hosts)
            if not host:
                continue
            console.rule(
                f"[bold {NEON_PINK}]⟨ WEB QUICK :: {host.ip} ⟩[/]", style=NEON_PURPLE,
            )
            from neonscan.scanner import scan_host
            results = scan_host(
                host.ip,
                ports=[80, 443, 8000, 8080, 8081, 8088, 8443, 8888, 3000, 5000, 9000],
                workers=30, timeout=1.5,
            )
            if not results:
                console.print(f"[{NEON_MAGENTA}]// no web ports open[/]")
            else:
                console.print(render_port_table(host.ip, results))
            ports_by_host[host.ip] = results

        if action == "D":
            # full diagnostics
            console.rule(f"[bold {NEON_PINK}]⟨ FULL DIAGNOSTICS ⟩[/]", style=NEON_PURPLE)
            try:
                diag_results = run_full_diag(
                    ping_target="8.8.8.8", ping_count=6, speed_size_mb=8,
                    monitor_s=0.0,
                )
            except KeyboardInterrupt:
                console.print(f"[bold {NEON_MAGENTA}]// aborted[/]")
                continue
            for r in diag_results:
                _print_diag(r, header=True)
            if Confirm.ask("[bold]Save report?[/]", default=False):
                default_path = str(Path.cwd() / "neonscan-report.md")
                tgt = Prompt.ask("[bold]path[/]", default=default_path)
                write_report(Path(tgt), diag_results, title="NeonScan full diag")
                console.print(f"[bold {NEON_PINK}]// saved → {tgt}[/]")
            continue

        if action == "W":
            _print_diag(get_wifi_info())
        if action == "P":
            target = Prompt.ask("[bold]target[/]", default="8.8.8.8")
            _print_diag(measure_ping(target))
        if action == "N":
            _print_diag(get_public_ip())
        if action == "T":
            target = Prompt.ask("[bold]target[/]", default="8.8.8.8")
            _print_diag(measure_traceroute(target))
        if action == "G":
            _print_diag(get_routes())
            _print_diag(get_dhcp_lease())
        if action == "C":
            _print_diag(get_connections())
        if action == "M":
            _print_diag(monitor_link(duration_s=6.0))
        if action == "U":
            sz = Prompt.ask("[bold]size MB[/]", default="5")
            try:
                _print_diag(measure_upload(sizes=[int(sz) * 1_000_000]))
            except ValueError:
                console.print(f"[{NEON_MAGENTA}]invalid size[/]")
        if action == "I":
            _print_diag(measure_iperf3(duration_s=6))
        if action == "X":
            target = Prompt.ask("[bold]target[/]", default="8.8.8.8")
            _print_diag(measure_mtr(target=target, cycles=3))
        if action == "K":
            host = Prompt.ask("[bold]host[/]", default="google.com")
            port = Prompt.ask("[bold]port[/]", default="443")
            try:
                _print_diag(inspect_tls(host, port=int(port)))
            except ValueError:
                console.print(f"[{NEON_MAGENTA}]invalid port[/]")
        if action == "O":
            _print_diag(detect_captive())
        if action == "A":
            _print_diag(analyze_arp())
        if action == "B":
            r = discover_mdns()
            _print_diag(r)
            services = (r.raw or {}).get("services", {}) if r.ok else {}
            if services:
                from rich.table import Table
                t = Table(title="[bold cyan]⟨ mDNS ⟩[/]", box=None)
                t.add_column("Type"); t.add_column("Instance"); t.add_column("Host"); t.add_column("Port", justify="right")
                for label, entries in services.items():
                    for e in entries[:30]:
                        t.add_row(label, e.get("instance", "")[:36], e.get("host") or "", str(e.get("port", 0)))
                console.print(t)
        if action == "V":
            target = Prompt.ask("[bold]Save current run as baseline? (y/n)[/]", default="n")
            if target.lower().startswith("y"):
                results = run_full_diag(monitor_s=0.0, speed_size_mb=4)
                b = build_baseline(results)
                save_baseline(b, Path("~/.neonscan/baseline.json").expanduser())
                console.print(f"[bold {NEON_PINK}]// baseline saved[/]")
            else:
                base = load_baseline(Path("~/.neonscan/baseline.json").expanduser())
                if not base:
                    console.print(f"[bold {NEON_MAGENTA}]// no baseline — run with 'y' first[/]")
                else:
                    results = run_full_diag(monitor_s=0.0, speed_size_mb=4)
                    diff = diff_against_baseline(base, results)
                    _print_diag(diff)
        if action == "F":
            args_f = argparse.Namespace(format="mermaid", out=None)
            run_topology(args_f)

        if action == "e":
            if not hosts:
                console.print(f"[{NEON_MAGENTA}]// no host scan yet — nothing to export[/]")
                continue
            out = Path.cwd() / "neonscan-host-scan.json"
            tgt = Prompt.ask("[bold]save path[/]", default=str(out))
            export_host_scan_report(Path(tgt), hosts, ports_by_host)


def interactive_prompt() -> str:
    from rich.panel import Panel

    options = [
        ("D", "diag",       "Full diagnostics suite"),
        ("W", "wifi",       "Wi-Fi link info"),
        ("P", "ping",       "Ping a target"),
        ("N", "public",     "Public IP / ISP"),
        ("T", "traceroute", "Traceroute a target"),
        ("G", "gateway",    "Gateway + DHCP lease"),
        ("C", "connections","Active connections"),
        ("M", "monitor",    "Live RSSI + traffic monitor"),
        ("U", "upload",     "Upload bandwidth test"),
        ("I", "iperf3",     "LAN iperf3 test"),
        ("X", "mtr",        "MTR (per-hop loss)"),
        ("K", "tls",        "TLS / cert inspection"),
        ("O", "captive",    "Captive portal check"),
        ("A", "arp",        "ARP anomalies"),
        ("B", "mdns",       "mDNS / Bonjour"),
        ("V", "watch",      "Save/diff against baseline"),
        ("F", "topology",   "Topology export (Mermaid)"),
        ("S", "scan",       "Re-scan local subnet"),
        ("R", "resubnet",   "Re-pick subnet"),
        ("d", "deep",       "Deep-scan a host (top-200 ports)"),
        ("p", "port",       "Web-quick on selected host"),
        ("e", "export",     "Export host scan as JSON"),
        ("q", "quit",       "Disconnect"),
    ]
    body = "\n".join(
        f"  [{NEON_PINK}][{key}][/] {label:<18} [dim]{desc}[/]"
        for key, label, desc in options
    )
    console.print(
        Panel(
            body,
            title=f"[bold {NEON_PINK}]⟨ ACTIONS ⟩[/]",
            border_style=NEON_PINK,
            box=None,
            padding=(0, 2),
        )
    )
    return Prompt.ask(
        f"[bold {NEON_PINK}]action[/]",
        choices=[k for k, *_ in options],
        default="D",
    )


def interactive_subnet_prompt(default_subnet: str) -> str:
    return Prompt.ask(
        f"[bold {NEON_PINK}]new subnet[/]",
        default=default_subnet,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = build_parser().parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    # Cache dir + OUI
    cache_dir = Path(args.cache_dir)
    OUICache(cache_dir=cache_dir, update=args.update_oui, offline=args.offline)

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
