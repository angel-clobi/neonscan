"""Local network discovery: subnet detection, ping sweep, ARP table parsing."""

import ipaddress
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional


IS_DARWIN = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


def _detect_termux() -> bool:
    """True when running inside Termux (Android)."""
    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    return os.path.isdir("/data/data/com.termux/files")


# Termux is Linux-on-Android; keep IS_LINUX True but flag the Android runtime so
# individual diagnostics can pick Android-friendly tools (termux-api, ss, /proc).
IS_TERMUX = _detect_termux()
IS_ANDROID = IS_TERMUX or "ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ


@dataclass
class Host:
    """A discovered host on the local network."""

    ip: str
    mac: str = ""
    manufacturer: str = ""
    hostname: str = ""
    alive: bool = True
    discovery_methods: list[str] = field(default_factory=list)
    scanned_ports: dict[str, list[int]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Subnet / local IP detection
# ---------------------------------------------------------------------------

def _detect_local_ip() -> str:
    """Return the IP of the interface used for the default route (no DNS)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.connect(("2001:4860:4860::8888", 53, 0, 0))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def _detect_interface() -> str:
    """Return the default-route interface name, including IPv6-only hosts."""
    if IS_DARWIN:
        for command in (
            ["route", "-n", "get", "default"],
            ["route", "-n", "get", "-inet6", "default"],
        ):
            try:
                out = subprocess.check_output(
                    command, stderr=subprocess.DEVNULL, text=True, timeout=3,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            for line in out.splitlines():
                if "interface:" in line:
                    return line.split(":", 1)[1].strip()
    elif IS_LINUX:
        for command in (
            ["ip", "route", "show", "default"],
            ["ip", "-6", "route", "show", "default"],
        ):
            try:
                out = subprocess.check_output(
                    command, stderr=subprocess.DEVNULL, text=True, timeout=3,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            match = re.search(r"\bdev\s+(\S+)", out)
            if match:
                return match.group(1)
    return "unknown"


def detect_network() -> dict:
    """Detect the default-route interface and its real IPv4/IPv6 prefixes."""
    ip = _detect_local_ip()
    interface = _detect_interface()
    subnet, subnet_method = _detect_ipv4_subnet(ip, interface)
    ipv6_subnets = _detect_ipv6_subnets(interface)
    try:
        local_address = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        local_address = None
    if isinstance(local_address, ipaddress.IPv6Address) and not local_address.is_loopback:
        matching_prefix = next(
            (prefix for prefix in ipv6_subnets if local_address in ipaddress.ip_network(prefix)),
            None,
        )
        if matching_prefix and ipaddress.ip_network(matching_prefix).prefixlen >= 118:
            subnet = matching_prefix
            subnet_method = "interface prefix"
        elif matching_prefix:
            subnet = f"{local_address}/128"
            subnet_method = f"host-only /128; detected {matching_prefix} is too large to sweep safely"
        else:
            subnet = f"{local_address}/128"
            subnet_method = "estimated /128 (interface prefix unavailable)"
    return {
        "local_ip": ip,
        "subnet": subnet,
        "subnet_method": subnet_method,
        "ipv6_subnets": ipv6_subnets,
        "interface": interface,
    }


def _detect_ipv4_subnet(ip: str, interface: str) -> tuple[str, str]:
    """Read the interface prefix from the OS instead of assuming /24."""
    try:
        address = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return "127.0.0.1/32", "loopback fallback"
    if address.is_loopback:
        return f"{address}/32", "loopback fallback"

    if interface != "unknown" or platform.system() == "Windows":
        try:
            if IS_LINUX:
                out = subprocess.check_output(
                    ["ip", "-o", "-4", "addr", "show", "dev", interface],
                    stderr=subprocess.DEVNULL, text=True, timeout=3,
                )
                for found, prefix in re.findall(r"\binet\s+(\d+(?:\.\d+){3})/(\d+)", out):
                    if found == str(address):
                        return f"{found}/{prefix}", "interface prefix"
            elif IS_DARWIN:
                out = subprocess.check_output(
                    ["ifconfig", interface], stderr=subprocess.DEVNULL,
                    text=True, timeout=3,
                )
                for found, mask in re.findall(
                    r"\binet\s+(\d+(?:\.\d+){3})\s+netmask\s+(0x[0-9a-fA-F]+|\d+(?:\.\d+){3})",
                    out,
                ):
                    if found != str(address):
                        continue
                    if mask.startswith("0x"):
                        mask = str(ipaddress.IPv4Address(int(mask, 16)))
                    network = ipaddress.IPv4Network((found, mask), strict=False)
                    return str(network), "interface netmask"
            elif platform.system() == "Windows":
                out = subprocess.check_output(
                    ["ipconfig"], stderr=subprocess.DEVNULL, text=True, timeout=5,
                )
                lines = out.splitlines()
                for index, line in enumerate(lines):
                    if str(address) not in line or not re.search(
                        r"(?:IPv4\s+Address|IP\s+Address|Direcci[oó]n\s+IPv4)",
                        line, re.IGNORECASE,
                    ):
                        continue
                    for candidate in lines[index + 1:index + 7]:
                        mask_match = re.search(
                            r"(?:subnet mask|m[aá]scara(?: de subred)?|netmask).*?(\d+\.\d+\.\d+\.\d+)",
                            candidate, re.IGNORECASE,
                        )
                        if mask_match:
                            network = ipaddress.IPv4Network(
                                (str(address), mask_match.group(1)), strict=False,
                            )
                            return str(network), "interface netmask"
        except (OSError, subprocess.SubprocessError, ValueError):
            pass

    # Do not silently claim this heuristic is the real subnet.
    fallback = ipaddress.IPv4Network(f"{address}/24", strict=False)
    return str(fallback), "estimated /24 (interface prefix unavailable)"


def _detect_ipv6_subnets(interface: str) -> list[str]:
    """Return usable IPv6 prefixes on the default interface when available."""
    if interface == "unknown":
        return []
    try:
        if IS_LINUX:
            out = subprocess.check_output(
                ["ip", "-o", "-6", "addr", "show", "dev", interface, "scope", "global"],
                stderr=subprocess.DEVNULL, text=True, timeout=3,
            )
            values = re.findall(r"\binet6\s+([0-9a-fA-F:]+/\d+)", out)
        elif IS_DARWIN:
            out = subprocess.check_output(
                ["ifconfig", interface], stderr=subprocess.DEVNULL,
                text=True, timeout=3,
            )
            values = re.findall(r"\binet6\s+([0-9a-fA-F:]+/\d+)", out)
        else:
            return []
    except (OSError, subprocess.SubprocessError):
        return []

    subnets = set()
    for value in values:
        try:
            net = ipaddress.IPv6Interface(value).network
        except ipaddress.AddressValueError:
            continue
        if not net.network_address.is_link_local:
            subnets.add(str(net))
    return sorted(subnets)


# ---------------------------------------------------------------------------
# Ping sweep
# ---------------------------------------------------------------------------

def _ping_once(ip: str, timeout_ms: int = 600) -> bool:
    """Send a single ping to IP. Return True if reachable.

    Note the ``-W`` unit differs by platform: on macOS/BSD it is **milliseconds**,
    on Linux (iputils, incl. Termux) it is **seconds**.  Passing the macOS
    millisecond value to Linux ping means a 250 ms budget becomes 250 *seconds*,
    so we translate per-platform.
    """
    timeout_s = max(1, round(timeout_ms / 1000))
    try:
        is_ipv6 = ipaddress.ip_address(ip.split("%", 1)[0]).version == 6
    except ValueError:
        is_ipv6 = False
    if IS_DARWIN and is_ipv6:
        cmd = ["ping6", "-c", "1", "-W", str(timeout_ms), ip]
    elif IS_LINUX and is_ipv6:
        cmd = ["ping", "-6", "-c", "1", "-n", "-W", str(timeout_s), ip]
    elif IS_DARWIN:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]          # BSD: ms
    elif IS_LINUX:
        cmd = ["ping", "-c", "1", "-n", "-W", str(timeout_s), ip]      # iputils: seconds
    else:
        family = ["-6"] if is_ipv6 else []
        cmd = ["ping", *family, "-n", "1", "-w", str(timeout_ms), ip]  # Windows: ms

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_sweep(
    subnet_cidr: str,
    max_workers: int = 64,
    progress_cb: Optional[callable] = None,
) -> list[str]:
    """Return IPv4/IPv6 hosts in a CIDR that responded to ICMP echo."""
    _net, candidates = _network_hosts(subnet_cidr)

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {pool.submit(_ping_once, ip): ip for ip in candidates}
        for done, fut in enumerate(as_completed(futures), start=1):
            ip = futures[fut]
            if fut.result():
                alive.append(ip)
            if progress_cb:
                progress_cb(done, len(candidates), ip)
    return sorted(alive, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))


def _network_hosts(subnet_cidr: str, max_hosts: int = 1024) -> tuple[ipaddress._BaseNetwork, list[str]]:
    """Expand a bounded CIDR into probe targets for interactive scans."""
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    if net.version == 4:
        host_count = net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
    else:
        host_count = net.num_addresses if net.prefixlen >= 127 else net.num_addresses - 1
    if host_count > max_hosts:
        raise ValueError(
            f"Subnet {net} contains {host_count:,} usable addresses; "
            f"interactive scans are limited to {max_hosts:,}. Choose a narrower subnet."
        )
    return net, [str(address) for address in net.hosts()]


def _tcp_probe_once(ip: str, port: int, timeout: float = 0.35) -> bool:
    """Lightweight connect probe used only to discover ping-filtered hosts."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_alive_ips(
    subnet_cidr: str,
    max_workers: int = 64,
    tcp_ports: tuple[int, ...] = (22, 80, 443),
    progress_cb: Optional[callable] = None,
) -> tuple[list[str], dict[str, list[str]], dict[str, tuple[str, str]]]:
    """Combine ICMP, cached-neighbor, and common TCP-probe evidence."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    net, candidates = _network_hosts(subnet_cidr)
    candidate_set = set(candidates)
    methods: dict[str, list[str]] = {}
    for ip in ping_sweep(subnet_cidr, max_workers=max_workers, progress_cb=progress_cb):
        methods.setdefault(ip, []).append("icmp")

    arp = {}
    if net.version == 4:
        for ip, mac, iface in _read_arp_table():
            try:
                if ip in candidate_set and ipaddress.ip_address(ip) in net and mac:
                    arp[ip] = (mac, iface)
                    methods.setdefault(ip, []).append("neighbor-cache")
            except ValueError:
                continue

    missed = [ip for ip in candidates if not methods.get(ip)]
    jobs = [(ip, port) for ip in missed for port in tcp_ports]
    if jobs:
        with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
            futures = {
                pool.submit(_tcp_probe_once, ip, port): (ip, port)
                for ip, port in jobs
            }
            for done, future in enumerate(as_completed(futures), start=1):
                ip, port = futures[future]
                try:
                    if future.result():
                        methods.setdefault(ip, []).append(f"tcp/{port}")
                except OSError:
                    pass
                if progress_cb:
                    progress_cb(len(candidates) + done, len(candidates) + len(jobs), ip)

    # TCP probes can populate the neighbor cache after the initial ICMP sweep.
    # Read it again before returning so discovered TCP-only hosts get their MAC.
    if net.version == 4:
        for ip, mac, iface in _read_arp_table():
            try:
                if ip in candidate_set and ipaddress.ip_address(ip) in net and mac:
                    arp.setdefault(ip, (mac, iface))
                    methods.setdefault(ip, [])
                    if "neighbor-cache" not in methods[ip]:
                        methods[ip].append("neighbor-cache")
            except ValueError:
                continue

    alive = sorted(
        methods,
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )
    return alive, methods, arp


# ---------------------------------------------------------------------------
# ARP table → MAC addresses
# ---------------------------------------------------------------------------

_ARP_LINE_DARWIN = re.compile(
    r"\?\s*\((\d+\.\d+\.\d+\.\d+)\)\s*at\s+([0-9a-fA-F:]+)\s+on\s+(\S+).*"
    r"(?:\s\[ethernet\])?",
)
_ARP_LINE_LINUX = re.compile(
    r"\?\s*\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+).*"
    r"\s+(\S+)\s*$"
)
_ARP_LINE_WINDOWS = re.compile(
    r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)"
)
_IP_NEIGH_LINE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+).*?\blladdr\s+"
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b"
)


def _read_arp_table() -> list[tuple[str, str, str]]:
    """Return [(ip, mac, iface), ...] from the system ARP cache.

    Linux/Termux may expose neighbors through `ip neigh` even when `arp` or
    `/proc/net/arp` is unavailable, so merge all supported cache sources.
    """
    if IS_DARWIN or IS_LINUX:
        entries: list[tuple[str, str, str]] = []
        if IS_LINUX:
            try:
                out = subprocess.check_output(
                    ["ip", "-4", "neigh", "show"],
                    stderr=subprocess.DEVNULL, text=True, timeout=4,
                )
                for line in out.splitlines():
                    match = _IP_NEIGH_LINE.search(line)
                    if match:
                        ip, iface, mac = match.groups()
                        entries.append((ip, _normalize_mac(mac), iface))
            except (subprocess.CalledProcessError, OSError, subprocess.SubprocessError):
                pass

        # Also parse the platform's traditional ARP output.
        try:
            out = subprocess.check_output(
                ["arp", "-an"], stderr=subprocess.DEVNULL, text=True, timeout=4
            )
            for line in out.splitlines():
                m = _ARP_LINE_DARWIN.search(line) if IS_DARWIN else _ARP_LINE_LINUX.search(line)
                if m:
                    ip, mac, iface = m.group(1), m.group(2), m.group(3)
                    entries.append((ip, mac, iface))
        except (subprocess.CalledProcessError, OSError, subprocess.SubprocessError):
            pass

        # Last Linux fallback: procfs, when Android/container permissions allow it.
        if IS_LINUX:
            entries.extend(_read_proc_arp())

        # Keep the first usable address; incomplete entries carry no MAC.
        neighbors: dict[str, tuple[str, str]] = {}
        for ip, mac, iface in entries:
            if mac and mac.lower() != "incomplete":
                neighbors.setdefault(ip, (_normalize_mac(mac), iface))
        return [(ip, mac, iface) for ip, (mac, iface) in neighbors.items()]

    # Windows
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, OSError):
        return []
    entries = []
    for line in out.splitlines():
        m = _ARP_LINE_WINDOWS.match(line)
        if m:
            ip, mac, iface = m.group(1), m.group(2), m.group(3)
            mac = mac.replace("-", ":")
            entries.append((ip, mac, iface))
    return entries


_PROC_ARP_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+"
    r"([0-9A-Fa-f:]{17}|\s+)\s+\*\s+(\S+)\s*$"
)


def _read_proc_arp() -> list[tuple[str, str, str]]:
    """Linux /proc/net/arp fallback. Returns (ip, mac, iface)."""
    try:
        text = open("/proc/net/arp").read()
    except OSError:
        return []
    out: list[tuple[str, str, str]] = []
    for line in text.splitlines()[1:]:
        m = _PROC_ARP_RE.match(line)
        if not m:
            continue
        ip, mac, iface = m.group(1), m.group(2).strip(), m.group(3)
        if not mac or mac.lower() == "incomplete":
            continue
        out.append((ip, _normalize_mac(mac), iface))
    return out


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to upper-case AA:BB:CC:DD:EE:FF."""
    return mac.upper().replace("-", ":")


def _reverse_dns(ip: str) -> str:
    """Best-effort reverse lookup using the OS resolver's timeout behavior."""
    try:
        # setdefaulttimeout is process-global and would also alter scanner sockets.
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return ""


def build_host_list(
    subnet: str,
    ping_workers: int = 64,
    reverse_dns: bool = True,
    progress_cb: Optional[callable] = None,
) -> list[Host]:
    """Discover live hosts with ICMP, TCP, and neighbor-cache evidence.

    Args:
        subnet: CIDR like 192.168.0.0/24.
        ping_workers: parallelism for the ping sweep.
        reverse_dns: also resolve hostnames via reverse DNS.
        progress_cb: optional callable(done, total, ip) for live progress.
    """
    candidates, methods, arp_table = discover_alive_ips(
        subnet, max_workers=ping_workers
    )

    hosts: list[Host] = []
    total = len(candidates)
    for idx, ip in enumerate(candidates, start=1):
        mac, iface = arp_table.get(ip, ("", ""))
        if not mac:
            # Some routers update ARP lazily — give it one more chance with a TCP probe.
            mac = _probe_arp_via_tcp(ip) or ""
        mac = _normalize_mac(mac)
        hostname = _reverse_dns(ip) if reverse_dns else ""
        hosts.append(
            Host(
                ip=ip,
                mac=mac,
                hostname=hostname,
                alive=True,
                discovery_methods=methods.get(ip, []),
            )
        )
        if progress_cb:
            progress_cb(idx, total, ip)
    return hosts


def _probe_arp_via_tcp(ip: str) -> str:
    """Last-resort: try to nudge ARP by opening+closing a TCP socket to port 80."""
    try:
        with socket.create_connection((ip, 80), timeout=0.4):
            pass
    except (OSError, socket.timeout):
        pass

    # Re-read the table for this IP only.
    for entry_ip, mac, _ in _read_arp_table():
        if entry_ip == ip and mac:
            return mac
    return ""
