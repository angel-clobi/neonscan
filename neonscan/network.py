"""Local network discovery: subnet detection, ping sweep, ARP table parsing."""

import ipaddress
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, Optional


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
        return "127.0.0.1"


def _detect_interface() -> str:
    """Return the default-route interface name (en0 / eth0 / wlan0)."""
    try:
        if IS_DARWIN:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in out.splitlines():
                if "interface:" in line:
                    return line.split(":", 1)[1].strip()
        elif IS_LINUX:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            m = re.search(r"dev\s+(\S+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "unknown"


def detect_network() -> dict:
    """Detect the local IP, subnet and interface."""
    ip = _detect_local_ip()
    interface = _detect_interface()
    subnet = ".".join(ip.split(".")[:3]) + ".0/24"
    return {"local_ip": ip, "subnet": subnet, "interface": interface}


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
    if IS_DARWIN:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]          # BSD: ms
    elif IS_LINUX:
        cmd = ["ping", "-c", "1", "-n", "-W", str(timeout_s), ip]      # iputils: seconds
    else:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]          # Windows: ms

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


def ping_sweep(subnet_cidr: str, max_workers: int = 64) -> list[str]:
    """Return the list of IPs in the /24 (or smaller) that responded to ping."""
    net = ipaddress.IPv4Network(subnet_cidr, strict=False)
    candidates = [str(h) for h in net.hosts()]

    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping_once, ip): ip for ip in candidates}
        for fut in as_completed(futures):
            if fut.result():
                alive.append(futures[fut])
    return sorted(alive, key=lambda x: tuple(int(p) for p in x.split(".")))


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


def _read_arp_table() -> list[tuple[str, str, str]]:
    """Return [(ip, mac, iface), ...] from the system ARP cache.

    On macOS we shell out to `arp -an`.  On Linux we try `arp -an` first; if
    not available (e.g. Termux) we fall back to /proc/net/arp.
    """
    if IS_DARWIN or IS_LINUX:
        # First: try the standard CLI tool.
        try:
            out = subprocess.check_output(
                ["arp", "-an"], stderr=subprocess.DEVNULL, text=True, timeout=4
            )
            entries: list[tuple[str, str, str]] = []
            for line in out.splitlines():
                m = _ARP_LINE_DARWIN.search(line) if IS_DARWIN else _ARP_LINE_LINUX.search(line)
                if m:
                    ip, mac, iface = m.group(1), m.group(2), m.group(3)
                    entries.append((ip, mac, iface))
            if entries:
                return entries
        except (subprocess.CalledProcessError, OSError):
            pass

        # Fallback: /proc/net/arp (Android/Termux, some Linux containers).
        entries = _read_proc_arp()
        if entries:
            return entries
        return []

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


def _reverse_dns(ip: str, timeout: float = 0.5) -> str:
    """Best-effort reverse DNS lookup."""
    try:
        socket.setdefaulttimeout(timeout)
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
    """Discover live hosts: ping sweep + ARP enrichment.

    Args:
        subnet: CIDR like 192.168.0.0/24.
        ping_workers: parallelism for the ping sweep.
        reverse_dns: also resolve hostnames via reverse DNS.
        progress_cb: optional callable(done, total, ip) for live progress.
    """
    candidates = ping_sweep(subnet, max_workers=ping_workers)
    arp_table = {ip: (mac, iface) for ip, mac, iface in _read_arp_table()}

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
