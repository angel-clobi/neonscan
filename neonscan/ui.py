"""Interactive NeonScan UI — banners, tables, prompts, menu loop."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.box import HEAVY, ROUNDED
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .banner import render_banner, render_intro_panel
from .network import Host, detect_network
from .scanner import PortResult, scan_host
from .theme import (
    NEON_CYAN,
    NEON_GREEN,
    NEON_MAGENTA,
    NEON_PINK,
    NEON_PURPLE,
    NEON_YELLOW,
    SCAN_GLYPHS,
)


console = Console()


# ---------------------------------------------------------------------------
# Progress helpers
# ---------------------------------------------------------------------------

def make_progress(label: str) -> Progress:
    return Progress(
        SpinnerColumn("dots", style=f"{NEON_PINK} bold"),
        TextColumn(f"[bold {NEON_CYAN}]{label}[/bold {NEON_CYAN}]"),
        BarColumn(complete_style=f"{NEON_GREEN}", finished_style=f"{NEON_GREEN}"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def render_host_table(hosts: list[Host], ports_by_host: dict[str, list[PortResult]]) -> Table:
    """Render the main ghost-networks table for all discovered hosts."""
    table = Table(
        title=f"[{NEON_PINK} bold]⟨ GHOST NET [{datetime.now().strftime('%H:%M:%S')}] ⟩[/]",
        title_justify="left",
        box=HEAVY,
        border_style=NEON_CYAN,
        header_style=f"bold {NEON_YELLOW}",
        show_lines=True,
        expand=True,
    )
    table.add_column("#", justify="right", style=f"{NEON_PINK}", width=3)
    table.add_column("STATE", justify="center", width=9)
    table.add_column("IP", style=f"bold {NEON_CYAN}", width=16)
    table.add_column("HOSTNAME", style=NEON_GREEN, width=24)
    table.add_column("MAC", style=NEON_YELLOW, width=20)
    table.add_column("MANUFACTURER", style=NEON_PINK, width=24)
    table.add_column("OPEN", justify="center", width=6)
    table.add_column("WEB ⚡", justify="center", width=6)

    for idx, host in enumerate(hosts, start=1):
        prs = ports_by_host.get(host.ip, [])
        open_n = len(prs)
        web_n = sum(1 for p in prs if p.is_web)
        state = f"{SCAN_GLYPHS['online']} [green]ONLINE[/]"
        table.add_row(
            f"{idx:02d}",
            state,
            host.ip,
            host.hostname or "[dim]—[/dim]",
            host.mac or "[dim]—[/dim]",
            host.manufacturer or "[dim]Unknown[/dim]",
            f"[bold {NEON_GREEN}]{open_n}[/]" if open_n else f"[{NEON_PURPLE}]0[/]",
            f"[bold {NEON_YELLOW}]{web_n}[/]" if web_n else f"[{NEON_PURPLE}]0[/]",
        )
    return table


def render_port_table(ip: str, results: list[PortResult]) -> Table:
    table = Table(
        title=f"[{NEON_PINK} bold]⟨ DEEP SCAN :: {ip} ⟩[/]",
        title_justify="left",
        box=ROUNDED,
        border_style=NEON_CYAN,
        header_style=f"bold {NEON_YELLOW}",
        show_lines=False,
        expand=True,
    )
    table.add_column("PORT", justify="right", style=f"bold {NEON_CYAN}", width=6)
    table.add_column("SERVICE", style=NEON_GREEN, width=14)
    table.add_column("HTTP", justify="center", width=6)
    table.add_column("STATUS", justify="center", width=8)
    table.add_column("SERVER", style=NEON_YELLOW, width=22)
    table.add_column("TITLE / BANNER", style=NEON_PINK, width=64)

    for r in results:
        is_web = "YES" if r.is_web else f"[{NEON_PURPLE}]·[/]"
        badge = (
            f"[{NEON_GREEN}]OPEN[/]"
            if r.open
            else f"[{NEON_PURPLE}]CLOSE[/]"
        )
        title = r.web_title or r.banner or ""
        server = r.web_server or ""
        table.add_row(
            str(r.port),
            r.service or "?",
            is_web,
            badge,
            server[:22],
            title[:64],
        )
    return table


# ---------------------------------------------------------------------------
# Menus / prompts
# ---------------------------------------------------------------------------

def show_intro(network_info: dict) -> None:
    """Print banner + network identity panel."""
    render_banner(console, animate=False)
    console.print(render_intro_panel(console, network_info))


def prompt_action() -> str:
    """Display the action menu and return the chosen key."""
    options = [
        ("S", "scan", "Re-scan local subnet"),
        ("D", "deep", "Deep-scan a host (full top-1000 ports + services)"),
        ("P", "port", "Web-quick scan on selected host"),
        ("E", "export", "Export current report as JSON"),
        ("Q", "quit", "Disconnect (exit)"),
    ]
    body = "\n".join(
        f"  [{NEON_PINK}][{key}][/] {label:<22} [dim]{desc}[/]"
        for key, label, desc in options
    )
    console.print(
        Panel(
            body,
            title=f"[bold {NEON_PINK}]⟨ ACTIONS ⟩[/]",
            border_style=NEON_CYAN,
            box=HEAVY,
            padding=(0, 2),
        )
    )
    return Prompt.ask(
        f"[bold {NEON_PINK}]action[/]",
        choices=[k for k, *_ in options],
        default="s",
    )


def prompt_host(hosts: list[Host]) -> Optional[Host]:
    if not hosts:
        console.print(f"[{NEON_MAGENTA}]// no hosts to choose from[/]")
        return None
    console.print("[bold]Choose a target[/]")
    for idx, host in enumerate(hosts, start=1):
        console.print(
            f"  [{NEON_PINK}]{idx:>3}[/] {host.ip:<16} "
            f"[{NEON_CYAN}]{(host.hostname or '—')[:24]:<24}[/] "
            f"[{NEON_YELLOW}]{host.manufacturer or 'Unknown'}[/]"
        )
    raw = Prompt.ask(
        f"[bold {NEON_PINK}]target #[/]",
        default="1",
    )
    try:
        sel = int(raw)
    except ValueError:
        return None
    if not (1 <= sel <= len(hosts)):
        return None
    return hosts[sel - 1]


# ---------------------------------------------------------------------------
# Scan with progress
# ---------------------------------------------------------------------------

def discover_with_progress(
    subnet: str,
    ping_workers: int = 64,
) -> tuple[list[Host], dict[str, list[PortResult]]]:
    """Discover hosts + do a quick web-only port probe per host.

    The ping sweep, host enrichment and port probe all run concurrently, so a
    full /24 completes in seconds instead of minutes.  ``ping_workers`` is the
    fan-out for the sweep (previously ignored).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from .network import _ping_once, _read_arp_table, _normalize_mac, _reverse_dns
    from .oui import OUICache

    cache = OUICache(cache_dir=Path.home() / ".neonscan" / "cache")
    candidates = _list_subnet(subnet)

    def _ip_key(ip: str):
        try:
            return tuple(int(p) for p in ip.split("."))
        except ValueError:
            return (0,)

    # 1. Parallel ping sweep -------------------------------------------------
    console.rule(f"[bold {NEON_PINK}]⟨ PING SWEEP ⟩[/]", style=NEON_PURPLE)
    alive_ips: list[str] = []
    with make_progress("probing") as progress:
        task = progress.add_task("", total=len(candidates) or 1, start=True)
        done = 0
        with ThreadPoolExecutor(max_workers=max(1, ping_workers)) as pool:
            futures = {pool.submit(_ping_once, ip): ip for ip in candidates}
            for fut in as_completed(futures):
                done += 1
                progress.update(task, completed=done)
                try:
                    if fut.result():
                        alive_ips.append(futures[fut])
                except Exception:  # noqa: BLE001 — a single probe failure is not fatal
                    pass
    alive_ips.sort(key=_ip_key)

    # 2. Read the ARP table ONCE and enrich hosts (reverse DNS in parallel) ---
    arp = {ip: mac for ip, mac, _iface in _read_arp_table()}

    def _enrich(ip: str) -> Host:
        mac = _normalize_mac(arp[ip]) if arp.get(ip) else ""
        host = Host(ip=ip, mac=mac)
        host.manufacturer = cache.lookup(mac) if mac else ""
        host.hostname = _reverse_dns(ip)
        return host

    hosts: list[Host] = []
    if alive_ips:
        with ThreadPoolExecutor(max_workers=min(32, len(alive_ips))) as pool:
            hosts = list(pool.map(_enrich, alive_ips))
    hosts.sort(key=lambda h: _ip_key(h.ip))

    console.print(f"[bold {NEON_GREEN}]// {len(hosts)} host(s) alive[/]\n")

    # 3. Quick web probe per host (parallel across hosts) --------------------
    console.rule(f"[bold {NEON_PINK}]⟨ WEB PING (top web ports) ⟩[/]", style=NEON_PURPLE)
    ports_by_host: dict[str, list[PortResult]] = {}
    web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000]
    if hosts:
        with make_progress("scanning") as progress:
            task = progress.add_task("", total=len(hosts), start=True)
            done = 0

            def _probe(host: Host) -> tuple[str, list[PortResult]]:
                return host.ip, scan_host(host.ip, ports=web_ports, workers=20, timeout=1.0)

            with ThreadPoolExecutor(max_workers=min(16, len(hosts))) as pool:
                futures = {pool.submit(_probe, h): h for h in hosts}
                for fut in as_completed(futures):
                    ip, results = fut.result()
                    ports_by_host[ip] = results
                    done += 1
                    progress.update(task, completed=done)

    return hosts, ports_by_host


def deep_scan_with_progress(host: Host, top: int = 200) -> list[PortResult]:
    """Heavy scan on a single host with a fresh progress display."""
    from .scanner import DEFAULT_PORTS

    ports = DEFAULT_PORTS[:top]
    console.rule(
        f"[bold {NEON_PINK}]⟨ DEEP SCAN :: {host.ip} :: {len(ports)} PORTS ⟩[/]",
        style=NEON_PURPLE,
    )
    results: list[PortResult] = []
    with make_progress("deep probing").__enter__() as progress:
        task = progress.add_task("", total=len(ports), start=True)

        def cb(done, total, port):
            progress.update(task, completed=done, visible=True)

        results = scan_host(
            host.ip,
            ports=ports,
            workers=80,
            timeout=1.2,
            progress_cb=cb,
        )
        progress.update(task, completed=len(ports))
    return results


def render_empty_state() -> None:
    console.print(
        Panel(
            f"[{NEON_MAGENTA}]// no neighbors online. check subnet or try again.[/]",
            border_style=NEON_MAGENTA,
            box=HEAVY,
        )
    )


def export_report(
    out_path: Path,
    hosts: list[Host],
    ports_by_host: dict[str, list[PortResult]],
) -> None:
    """Write the current scan results to JSON."""
    payload = {
        "scanner": "neonscan",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hosts": [
            {
                "ip": h.ip,
                "mac": h.mac,
                "manufacturer": h.manufacturer,
                "hostname": h.hostname,
                "ports": [
                    {
                        "port": p.port,
                        "service": p.service,
                        "web_title": p.web_title,
                        "web_status": p.web_status,
                        "web_server": p.web_server,
                        "banner": p.banner,
                    }
                    for p in ports_by_host.get(h.ip, [])
                ],
            }
            for h in hosts
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    console.print(f"[bold {NEON_GREEN}]// saved → {out_path}[/]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _list_subnet(subnet_cidr: str) -> list[str]:
    """Return the host IPs in a /24 (or smaller) subnet."""
    import ipaddress

    net = ipaddress.IPv4Network(subnet_cidr, strict=False)
    return [str(h) for h in net.hosts()]
