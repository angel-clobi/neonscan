"""Interactive NeonScan UI — banners, tables, prompts, menu loop."""

import ipaddress
import json
import shutil
import subprocess
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.box import HEAVY, ROUNDED
from rich.console import Console
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
from rich.style import Style
from rich.text import Text

from .banner import render_banner, render_intro_panel
from .network import (
    IS_TERMUX,
    Host,
    _network_hosts,
    _normalize_mac,
    _read_arp_table,
    _reverse_dns,
    detect_network,
    discover_alive_ips,
)
from .scanner import (
    QUICK_WEB_PORTS,
    PortResult,
    quick_web_check,
    scan_host,
    nmap_service_versions,
    service_name,
)
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

def _port_label(ip: str, result: PortResult) -> Text:
    service = result.service or service_name(result.port)
    prefix = f"{result.protocol}/" if result.protocol != "tcp" else ""
    label = f"{prefix}{result.port}/{service}"
    if result.protocol == "udp" and result.state == "open|filtered":
        label += " [open|filtered]"
    text = Text()
    if result.web_scheme in ("http", "https"):
        url = f"{result.web_scheme}://{_url_host(ip)}:{result.port}/"
        text.append(label, style=Style(color=NEON_CYAN, underline=True, link=url))
    else:
        text.append(label, style=NEON_CYAN)
    return text


def _url_host(ip: str) -> str:
    """Format IPv6 literals for URLs, including a URI-safe interface zone."""
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return ip
    if address.version == 4:
        return ip
    address, separator, zone = ip.partition("%")
    return f"[{address}{'%25' + zone if separator else ''}]"


def _protocol_port_label(ip: str, result: PortResult) -> Text:
    text = Text(f"{result.protocol}/", style=f"bold {NEON_CYAN}")
    text.append_text(_port_label(ip, result))
    return text


def _ports_cell(ip: str, results: list[PortResult]) -> Text:
    text = Text()
    visible_results = [
        result for result in results
        if result.open or result.state == "open|filtered"
    ]
    if not visible_results:
        return Text("—", style="dim")
    for index, result in enumerate(visible_results):
        if index:
            text.append("  ")
        text.append_text(_port_label(ip, result))
    return text


def print_web_links(hosts: list[Host], ports_by_host: dict[str, list[PortResult]]) -> None:
    """Print visible, clickable URLs as a fallback for terminals without OSC 8."""
    endpoints = [
        (host.ip, port)
        for host in hosts
        for port in ports_by_host.get(host.ip, [])
        if port.web_scheme in ("http", "https")
    ]
    if not endpoints:
        return
    table = Table(
        title=f"[bold {NEON_PINK}]⟨ WEB LINKS · click/tap para abrir ⟩[/]",
        box=ROUNDED,
        border_style=NEON_CYAN,
        header_style=f"bold {NEON_YELLOW}",
        expand=True,
    )
    table.add_column("HOST", no_wrap=True)
    table.add_column("URL", overflow="fold")
    for ip, result in endpoints:
        url = f"{result.web_scheme}://{_url_host(ip)}:{result.port}/"
        table.add_row(ip, Text(url, style=Style(color=NEON_CYAN, underline=True, link=url)))
    console.print(table)

def render_host_table(hosts: list[Host], ports_by_host: dict[str, list[PortResult]]) -> Table:
    """Render the main ghost-networks table for all discovered hosts."""
    if console.width < 100:
        table = Table(
            title=f"[{NEON_PINK} bold]⟨ HOSTS [{datetime.now().strftime('%H:%M:%S')}] ⟩[/]",
            box=ROUNDED,
            border_style=NEON_CYAN,
            header_style=f"bold {NEON_YELLOW}",
            expand=True,
        )
        table.add_column("#", justify="right", width=3)
        table.add_column("IP", style=f"bold {NEON_CYAN}", no_wrap=True)
        table.add_column("HOST", style=NEON_GREEN, overflow="ellipsis")
        table.add_column("PORTS / SERVICES", overflow="fold")
        for idx, host in enumerate(hosts, start=1):
            table.add_row(
                str(idx), host.ip, host.hostname or "—",
                _ports_cell(host.ip, ports_by_host.get(host.ip, [])),
            )
        return table

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
    table.add_column("PORTS / SERVICES", overflow="fold")

    for idx, host in enumerate(hosts, start=1):
        prs = ports_by_host.get(host.ip, [])
        state = f"{SCAN_GLYPHS['online']} [green]ONLINE[/]"
        table.add_row(
            f"{idx:02d}",
            state,
            host.ip,
            host.hostname or "[dim]—[/dim]",
            host.mac or "[dim]—[/dim]",
            host.manufacturer or "[dim]Unknown[/dim]",
            _ports_cell(host.ip, prs),
        )
    return table


def render_port_table(ip: str, results: list[PortResult]) -> Table:
    counts = {
        "open": sum(result.state == "open" for result in results),
        "closed": sum(result.state == "closed" for result in results),
        "filtered": sum(result.state in {"filtered", "open|filtered"} for result in results),
        "error": sum(result.state == "error" for result in results),
    }
    count_text = (
        f"{counts['open']} abiertos · {counts['closed']} cerrados · "
        f"{counts['filtered']} filtrados/ambiguos"
        + (f" · {counts['error']} errores" if counts["error"] else "")
    )
    display_results = [
        result for result in results
        if result.open or result.state == "open|filtered"
    ]
    if console.width < 100:
        table = Table(
            title=f"[{NEON_PINK} bold]⟨ PORTS :: {ip} · {count_text} ⟩[/]",
            box=ROUNDED,
            border_style=NEON_CYAN,
            header_style=f"bold {NEON_YELLOW}",
            expand=True,
        )
        table.add_column("PORT", justify="right", width=6)
        table.add_column("SERVICE", width=12, overflow="ellipsis")
        table.add_column("DETAIL", overflow="ellipsis")
        table.caption = "El nombre suele inferirse por puerto; UDP sin respuesta queda como abierto|filtrado."
        for result in display_results:
            fingerprint = " ".join(part for part in (result.product, result.version) if part)
            detail = result.web_title or fingerprint or result.banner or result.web_server or result.state
            if result.web_status:
                detail = f"HTTP {result.web_status} · {detail}"
            table.add_row(
                _protocol_port_label(ip, result),
                Text(result.service or service_name(result.port)), Text(detail),
            )
        return table

    table = Table(
        title=f"[{NEON_PINK} bold]⟨ SCAN :: {ip} · {count_text} ⟩[/]",
        title_justify="left",
        box=ROUNDED,
        border_style=NEON_CYAN,
        header_style=f"bold {NEON_YELLOW}",
        show_lines=False,
        expand=True,
    )
    table.add_column("PORT", justify="right", style=f"bold {NEON_CYAN}", width=12)
    table.add_column("SERVICE", style=NEON_GREEN, width=18)
    table.add_column("HTTP", justify="center", width=6)
    table.add_column("STATUS", justify="center", width=8)
    table.add_column("SERVER", style=NEON_YELLOW, width=22)
    table.add_column("TITLE / BANNER", style=NEON_PINK, width=64)

    table.caption = "Nmap identifica servicios que coinciden con una sonda; los demás nombres se infieren por puerto."
    for r in display_results:
        is_web = "YES" if r.is_web else f"[{NEON_PURPLE}]·[/]"
        state_style = NEON_GREEN if r.state == "open" else NEON_YELLOW
        badge = f"[{state_style}]{r.state.upper()}[/]"
        fingerprint = " ".join(part for part in (r.product, r.version) if part)
        title = r.web_title or fingerprint or r.banner or ""
        server = r.web_server or ""
        table.add_row(
            _protocol_port_label(ip, r),
            Text(
                (r.service or service_name(r.port))
                + (" · Nmap" if r.service_source == "nmap-probe" else " · guess")
            ),
            is_web,
            badge,
            Text(server[:22]),
            Text(title[:64]),
        )
    return table


def open_web_service_prompt(ip: str, results: list[PortResult]) -> bool:
    """Let the user choose a confirmed HTTP(S) endpoint and open its browser."""
    endpoints = [r for r in results if r.web_scheme in ("http", "https")]
    if not endpoints:
        console.print(f"[dim]No hay puertos web guardados para {ip}; comprobando puertos comunes...[/]")
        endpoints = [r for r in quick_web_check(ip) if r.web_scheme in ("http", "https")]
    if not endpoints:
        console.print(f"[bold {NEON_MAGENTA}]// no se detectaron servicios HTTP/HTTPS en {ip}[/]")
        return False

    table = Table(
        title=f"[bold {NEON_PINK}]⟨ ABRIR SERVICIO · {ip} ⟩[/]",
        box=ROUNDED,
        border_style=NEON_CYAN,
        header_style=f"bold {NEON_YELLOW}",
        expand=True,
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("PUERTO / SERVICIO")
    table.add_column("URL", overflow="fold")
    urls = []
    for index, result in enumerate(endpoints, start=1):
        url = f"{result.web_scheme}://{_url_host(ip)}:{result.port}/"
        urls.append(url)
        table.add_row(
            str(index),
            _port_label(ip, result),
            Text(url, style=Style(color=NEON_CYAN, underline=True, link=url)),
        )
    console.print(table)
    choice = Prompt.ask(
        "Número del servicio que quieres abrir (0 para cancelar)",
        choices=[str(i) for i in range(len(urls) + 1)],
        show_choices=False,
        show_default=False,
    )
    if choice == "0":
        return False

    url = urls[int(choice) - 1]
    try:
        termux_open = shutil.which("termux-open-url")
        if IS_TERMUX and termux_open:
            completed = subprocess.run(
                [termux_open, url], capture_output=True, text=True,
                timeout=10, check=False,
            )
            opened = completed.returncode == 0
            error = completed.stderr.strip()
        else:
            opened = webbrowser.open(url, new=2)
            error = ""
    except (OSError, subprocess.SubprocessError, webbrowser.Error) as exc:
        opened, error = False, str(exc)

    if opened:
        console.print(f"[bold {NEON_GREEN}]// navegador abierto: {url}[/]")
    else:
        console.print(f"[bold {NEON_MAGENTA}]// no se pudo abrir el navegador. URL: {url}[/]")
        if error:
            console.print(f"[dim]{error}[/]")
    return opened


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
        ("D", "deep", "Scan common TCP ports and identify available service versions"),
        ("P", "port", "Web-quick scan on selected host"),
        ("O", "open", "Open a detected HTTP/HTTPS service in browser"),
        ("U", "udp", "Probe common UDP services on a selected host"),
        ("I", "inventory", "Save or compare a local scan inventory"),
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
    choice = Prompt.ask(
        f"[bold {NEON_PINK}]action[/]",
        choices=[k for k, *_ in options],
        default="S",
    )
    return {"S": "s", "D": "d", "P": "p", "O": "O", "U": "U",
            "I": "i", "E": "e", "Q": "q"}[choice]


def prompt_host(hosts: list[Host]) -> Optional[Host]:
    if not hosts:
        console.print(f"[{NEON_MAGENTA}]// no hosts to choose from[/]")
        return None
    console.print("[bold]Choose a target[/]")
    for idx, host in enumerate(hosts, start=1):
        if console.width < 100:
            console.print(f"  [{NEON_PINK}]{idx:>2}[/] {host.ip}  [{NEON_CYAN}]{(host.hostname or '—')[:20]}[/]")
        else:
            console.print(
                f"  [{NEON_PINK}]{idx:>3}[/] {host.ip:<16} "
                f"[{NEON_CYAN}]{(host.hostname or '—')[:24]:<24}[/] "
                f"[{NEON_YELLOW}]{host.manufacturer or 'Unknown'}[/]"
            )
    raw = Prompt.ask(
        f"[bold {NEON_PINK}]target #[/]",
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
    cache_dir: Optional[Path] = None,
    offline: bool = False,
    update_oui: bool = False,
) -> tuple[list[Host], dict[str, list[PortResult]]]:
    """Discover hosts + do a quick web-only port probe per host.

    The ping sweep, host enrichment and port probe all run concurrently, so a
    full /24 completes in seconds instead of minutes.  ``ping_workers`` is the
    fan-out for the sweep (previously ignored).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from .oui import OUICache

    _net, candidates = _network_hosts(subnet)
    cache = OUICache(
        cache_dir=cache_dir or Path.home() / ".neonscan" / "cache",
        offline=offline,
        update=update_oui,
    )

    def _ip_key(ip: str):
        try:
            address = ipaddress.ip_address(ip.split("%", 1)[0])
            return address.version, int(address)
        except ValueError:
            return 0, 0

    # 1. Combine ICMP, cached-neighbor, and common TCP evidence ---------------
    console.rule(f"[bold {NEON_PINK}]⟨ HOST DISCOVERY · ICMP / TCP / NEIGHBORS ⟩[/]", style=NEON_PURPLE)
    discovery_methods: dict[str, list[str]] = {}
    arp: dict[str, tuple[str, str]] = {}
    with make_progress("probing") as progress:
        task = progress.add_task("", total=len(candidates) or 1, start=True)
        def _discovery_progress(done: int, total: int, _ip: str) -> None:
            progress.update(task, total=max(1, total), completed=done)

        alive_ips, discovery_methods, arp = discover_alive_ips(
            subnet,
            max_workers=min(ping_workers, 32 if IS_TERMUX else 64),
            progress_cb=_discovery_progress,
        )

    def _enrich(ip: str) -> Host:
        mac, _iface = arp.get(ip, ("", ""))
        mac = _normalize_mac(mac) if mac else ""
        host = Host(ip=ip, mac=mac, discovery_methods=discovery_methods.get(ip, []))
        host.manufacturer = cache.lookup(mac) if mac else ""
        host.hostname = _reverse_dns(ip)
        return host

    hosts: list[Host] = []
    if alive_ips:
        enrich_workers = 4 if IS_TERMUX else 32
        with ThreadPoolExecutor(max_workers=min(enrich_workers, len(alive_ips))) as pool:
            hosts = list(pool.map(_enrich, alive_ips))
    hosts.sort(key=lambda h: _ip_key(h.ip))

    console.print(f"[bold {NEON_GREEN}]// {len(hosts)} host(s) alive[/]\n")
    evidence = {}
    for host in hosts:
        for method in host.discovery_methods:
            evidence[method] = evidence.get(method, 0) + 1
    if evidence:
        detail = " · ".join(f"{method}: {count}" for method, count in sorted(evidence.items()))
        console.print(f"[dim]Detección: {detail}[/]")

    # 3. Quick web probe per host (parallel across hosts) --------------------
    console.rule(f"[bold {NEON_PINK}]⟨ WEB PING (top web ports) ⟩[/]", style=NEON_PURPLE)
    ports_by_host: dict[str, list[PortResult]] = {}
    web_ports = QUICK_WEB_PORTS
    if hosts:
        with make_progress("scanning") as progress:
            task = progress.add_task("", total=len(hosts), start=True)
            done = 0

            def _probe(host: Host) -> tuple[str, list[PortResult]]:
                workers = 4 if IS_TERMUX else 20
                return host.ip, scan_host(
                    host.ip, ports=web_ports, workers=workers, timeout=1.0,
                    include_states=True,
                )

            host_workers = 4 if IS_TERMUX else 16
            with ThreadPoolExecutor(max_workers=min(host_workers, len(hosts))) as pool:
                futures = {pool.submit(_probe, h): h for h in hosts}
                for fut in as_completed(futures):
                    ip, results = fut.result()
                    ports_by_host[ip] = results
                    futures[fut].scanned_ports["tcp"] = list(web_ports)
                    done += 1
                    progress.update(task, completed=done)

    # The web probes above can resolve ARP entries after host discovery. Refresh
    # missing MAC/vendor fields before rendering the table to pick those up.
    if hosts:
        _apply_neighbor_cache(hosts, _read_arp_table(), cache)
    if hosts and (
        any(not host.mac for host in hosts)
        or any(host.manufacturer in ("", "Unknown") for host in hosts)
        or any(not host.hostname for host in hosts)
    ):
        mac_count = sum(bool(host.mac) for host in hosts)
        hostname_count = sum(bool(host.hostname) for host in hosts)
        vendor_count = sum(host.manufacturer not in ("", "Unknown") for host in hosts)
        console.print(
            f"[dim]Identidad recuperada: MAC {mac_count}/{len(hosts)} · "
            f"fabricante {vendor_count}/{len(hosts)} · hostname {hostname_count}/{len(hosts)}. "
            "El hostname requiere DNS inverso o resolución local; el fabricante requiere "
            "una MAC y un prefijo OUI reconocible.[/]"
        )

    return hosts, ports_by_host


def _apply_neighbor_cache(hosts: list[Host], entries, oui_cache) -> None:
    """Fill missing MAC/vendor data from the neighbor cache after active probes."""
    hosts_by_ip = {host.ip: host for host in hosts}
    for ip, mac, _iface in entries:
        host = hosts_by_ip.get(ip)
        if host is None or host.mac or not mac:
            continue
        host.mac = _normalize_mac(mac)
        host.manufacturer = oui_cache.lookup(host.mac)


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
            workers=8 if IS_TERMUX else 64,
            timeout=1.0 if IS_TERMUX else 1.2,
            progress_cb=cb,
            include_states=True,
        )
        progress.update(task, completed=len(ports))
    open_ports = [result.port for result in results if result.open]
    if open_ports and shutil.which("nmap"):
        console.rule(
            f"[bold {NEON_PINK}]⟨ SERVICE / VERSION DETECTION · NMAP ⟩[/]",
            style=NEON_PURPLE,
        )
        with make_progress("identifying services") as progress:
            task = progress.add_task("", total=1, start=True)
            details = nmap_service_versions(
                host.ip, open_ports, timeout=12 if IS_TERMUX else 30,
            )
            progress.update(task, completed=1)
        identified_count = 0
        for result in results:
            detected = details.get(result.port, {})
            # Port-table names remain guesses; only a matched Nmap probe identifies a service.
            if detected.get("method") != "probed":
                continue
            identified_count += 1
            result.service = detected.get("name") or result.service
            result.service_source = "nmap-probe"
            result.product = detected.get("product", "")
            result.version = detected.get("version", "")
            extra = detected.get("extrainfo", "")
            if extra:
                result.banner = extra[:160]
        if not identified_count:
            console.print("[dim]Nmap no pudo identificar un protocolo/versión; conserva las etiquetas orientativas.[/]")
    elif open_ports:
        console.print("[dim]Nmap no está instalado; los nombres de servicio son inferencias por puerto.[/]")
    host.scanned_ports["tcp"] = list(ports)
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hosts": [
            {
                "ip": h.ip,
                "mac": h.mac,
                "manufacturer": h.manufacturer,
                "hostname": h.hostname,
                "discovery_methods": h.discovery_methods,
                "scanned_ports": h.scanned_ports,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "state": p.state,
                        "reason": p.reason,
                        "service": p.service,
                        "service_source": p.service_source,
                        "product": p.product,
                        "version": p.version,
                        "web_title": p.web_title,
                        "web_status": p.web_status,
                        "web_server": p.web_server,
                        "web_scheme": p.web_scheme,
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


def inventory_prompt(
    subnet: str,
    hosts: list[Host],
    ports_by_host: dict[str, list[PortResult]],
) -> None:
    """Explicitly save or compare a local device/port inventory snapshot."""
    if not hosts:
        console.print(f"[{NEON_MAGENTA}]// primero escanea una red para crear el inventario[/]")
        return
    console.print(
        "[dim]El inventario incluye IP, MAC, nombre y puertos observados. "
        "Solo se guarda si eliges la opción 1.[/]"
    )
    choice = Prompt.ask(
        "[bold]1 guardar inventario · 2 comparar con el último · 0 volver[/]",
        choices=["1", "2", "0"], show_choices=False, show_default=False,
    )
    if choice == "0":
        return

    from .inventory import (
        compare_inventories,
        load_latest_inventory,
        make_inventory_snapshot,
        save_inventory_snapshot,
    )

    current = make_inventory_snapshot(subnet, hosts, ports_by_host)
    if choice == "1":
        path = save_inventory_snapshot(current)
        console.print(f"[bold {NEON_GREEN}]// inventario guardado → {path}[/]")
        return

    previous, path = load_latest_inventory()
    if not previous:
        console.print("[dim]// todavía no hay inventarios guardados; usa primero la opción 1[/]")
        return
    console.print(f"[dim]Comparando con {path}[/]")
    diff = compare_inventories(current, previous)
    if diff["scope_changed"]:
        old_scope = diff["scope_changed"]["before"]
        new_scope = diff["scope_changed"]["after"]
        console.print(
            f"[bold {NEON_YELLOW}]// no se compararon los equipos: cambió la subred "
            f"({old_scope or 'desconocida'} → {new_scope or 'desconocida'}). "
            "Guarda primero un inventario para esta subred.[/]"
        )
        return
    console.print(
        f"[dim]Anterior: {diff['previous_timestamp']} · Actual: {diff['current_timestamp']}[/]"
    )

    host_table = Table(title="Cambios en equipos", box=ROUNDED, expand=True)
    host_table.add_column("CAMBIO", no_wrap=True)
    host_table.add_column("IP", no_wrap=True)
    host_table.add_column("HOST", overflow="ellipsis")
    host_table.add_column("MAC", no_wrap=True)
    host_changes = False
    for event, key in (("APARECIÓ", "added_hosts"), ("DESAPARECIÓ", "removed_hosts")):
        for host in diff[key]:
            host_changes = True
            host_table.add_row(event, host.get("ip", ""), Text(host.get("hostname") or "—"), host.get("mac") or "—")
    for host in diff["changed_hosts"]:
        host_changes = True
        changes = ", ".join(
            f"{name}: {values['before'] or '—'} → {values['after'] or '—'}"
            for name, values in host["changes"].items()
        )
        host_table.add_row("CAMBIÓ", host["ip"], Text(changes), "—")
    if host_changes:
        console.print(host_table)

    port_table = Table(title="Cambios en puertos abiertos", box=ROUNDED, expand=True)
    port_table.add_column("CAMBIO", no_wrap=True)
    port_table.add_column("HOST", no_wrap=True)
    port_table.add_column("PROTOCOLO", no_wrap=True)
    port_table.add_column("PUERTO", justify="right")
    port_table.add_column("SERVICIO", overflow="ellipsis")
    port_changes = False
    for event, key in (("ABRIÓ", "added_ports"), ("CERRÓ", "removed_ports")):
        for item in diff[key]:
            port_changes = True
            label = " ".join(part for part in (item.get("service", ""), item.get("product", ""), item.get("version", "")) if part)
            port_table.add_row(event, item["ip"], item["protocol"].upper(), str(item["port"]), Text(label or "—"))
    for item in diff["changed_ports"]:
        port_changes = True
        before = item["before"]
        after = item["after"]
        old_label = " ".join(part for part in (before.get("service", ""), before.get("product", ""), before.get("version", "")) if part)
        new_label = " ".join(part for part in (after.get("service", ""), after.get("product", ""), after.get("version", "")) if part)
        port_table.add_row(
            "CAMBIÓ", item["ip"], after["protocol"].upper(), str(after["port"]),
            Text(f"{old_label or '—'} → {new_label or '—'}"),
        )
    for item in diff["state_changes"]:
        port_changes = True
        before = item["before"]
        after = item["after"]
        port_table.add_row(
            "ESTADO", item["ip"], after["protocol"].upper(), str(after["port"]),
            Text(f"{before['state']} → {after['state']}"),
        )
    if port_changes:
        console.print(port_table)
    if not host_changes and not port_changes:
        console.print(f"[bold {NEON_GREEN}]// sin cambios de equipos ni de puertos abiertos[/]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _list_subnet(subnet_cidr: str) -> list[str]:
    """Return host IPs while refusing accidentally huge interactive sweeps."""
    _net, hosts = _network_hosts(subnet_cidr)
    return hosts
