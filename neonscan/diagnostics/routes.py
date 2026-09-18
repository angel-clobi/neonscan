"""Routing + DHCP diagnostics: route table, default gateway, DHCP lease."""

from __future__ import annotations

import json
import platform
import re
import socket
import struct
import subprocess
from typing import Optional

from .result import DiagResult, Severity


IS_DARWIN = platform.system() == "Darwin"


def _parse_proc_route(text: str) -> tuple[str, str, int]:
    """Parse /proc/net/route → (default_gw, iface, route_count).

    The Gateway/Destination columns are little-endian hex.  This needs no
    external binary, so it works on bare Termux without `iproute2`.
    """
    gw = "?"
    iface = "?"
    count = 0
    for line in text.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 8:
            continue
        count += 1
        dest, gw_hex = parts[1], parts[2]
        if dest == "00000000":  # default route
            iface = parts[0]
            try:
                gw = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
            except (ValueError, struct.error, OSError):
                gw = "?"
    return gw, iface, count


def _routes_from_proc() -> Optional[DiagResult]:
    """Build a Routes DiagResult from /proc/net/route (no `ip`/`route` needed)."""
    try:
        with open("/proc/net/route") as f:
            text = f.read()
    except OSError:
        return None
    gw, iface, count = _parse_proc_route(text)
    if gw == "?" and iface == "?":
        return None
    from ..network import _detect_local_ip

    res = DiagResult(title="Routes")
    res.add("Default gw", gw)
    res.add("Interface", iface)
    local_ip = _detect_local_ip()
    if local_ip and local_ip != "127.0.0.1":
        res.add("Interface IP", local_ip)
    res.add("Custom routes", str(max(count - 1, 0)))
    res.raw = {"gateway": gw, "interface": iface, "local_ip": local_ip, "tool": "/proc/net/route"}
    return res


def get_routes() -> DiagResult:
    """Return the local interface, default gateway, and a tiny route summary."""
    res = DiagResult(title="Routes")
    if IS_DARWIN:
        try:
            cp = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=4, check=False,
            )
            out = cp.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            res.error = str(exc)
            return res

        gw_m = re.search(r"gateway:\s*(\S+)", out)
        if_m = re.search(r"interface:\s*(\S+)", out)
        gw = gw_m.group(1) if gw_m else "?"
        iface = if_m.group(1) if if_m else "?"
        # Local IP — prefer ifconfig which is reliable, fall back to parsed values.
        local_ip = "?"
        if iface != "?":
            try:
                ifcp = subprocess.run(
                    ["ifconfig", iface],
                    capture_output=True, text=True, timeout=3, check=False,
                )
                inet4 = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ifcp.stdout)
                if inet4:
                    local_ip = inet4.group(1)
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass
        res.add("Default gw", gw)
        res.add("Interface", iface)
        res.add("Interface IP", local_ip)

        # Try to get the routing table for richer info
        try:
            rt = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True, text=True, timeout=4, check=False,
            )
            table = rt.stdout
            routes_count = sum(
                1 for l in table.splitlines()
                if re.match(r"^\d+\.\d+", l) and "default" not in l
            )
            res.add("Custom routes", str(routes_count))
        except Exception:
            pass
        res.raw = {"gateway": gw, "interface": iface, "local_ip": local_ip}
        return res

    # Linux / Termux
    try:
        cp = subprocess.run(
            ["ip", "route"],
            capture_output=True, text=True, timeout=4, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # No `iproute2` (common on bare Termux) — read the kernel table directly.
        proc_res = _routes_from_proc()
        if proc_res is not None:
            return proc_res
        res.error = "no 'ip'/'route' tool and /proc/net/route unavailable"
        return res
    out = cp.stdout
    gw = "?"
    iface = "?"
    src_ip = "?"
    for line in out.splitlines():
        if line.startswith("default"):
            parts = line.split()
            try:
                gw = parts[parts.index("via") + 1]
            except (ValueError, IndexError):
                pass
            try:
                iface = parts[parts.index("dev") + 1]
            except (ValueError, IndexError):
                pass
            m_src = re.search(r"src\s+(\S+)", line)
            if m_src:
                src_ip = m_src.group(1)
            break
    if gw == "?" and iface == "?":
        proc_res = _routes_from_proc()
        if proc_res is not None:
            return proc_res
    res.add("Default gw", gw)
    res.add("Interface", iface)
    if src_ip != "?":
        res.add("Interface IP", src_ip)
    routes_count = sum(1 for l in out.splitlines() if l and not l.startswith("default"))
    res.add("Custom routes", str(routes_count))
    res.raw = {"gateway": gw, "interface": iface, "local_ip": src_ip}
    return res


def get_dhcp_lease(interface: Optional[str] = None, timeout_s: float = 4.0) -> DiagResult:
    """Dump the active DHCP lease for a given interface (macOS-focused)."""
    res = DiagResult(title="DHCP lease")
    if interface is None:
        # Try to infer default interface
        r = get_routes()
        iface_match = next((f for f in r.findings if f.label == "Interface"), None)
        interface = iface_match.value if iface_match else "en0"

    if not IS_DARWIN:
        res.error = "DHCP lease parsing for Linux not implemented in this build"
        return res

    try:
        cp = subprocess.run(
            ["ipconfig", "getpacket", interface],
            capture_output=True, text=True, timeout=timeout_s, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        res.error = str(exc)
        return res

    if cp.returncode != 0:
        res.error = cp.stderr.strip() or f"no lease on {interface}"
        return res

    raw = cp.stdout

    def pick(label):
        """Pick a value from formats 'label (type): value' or 'label = value'."""
        for sep in (r":\s+", r"\s+\(.*?\):\s+", r"=\s*"):
            m = re.search(rf"^{label}{sep}(.+)$", raw, re.MULTILINE)
            if m:
                return m.group(1).strip()
        return ""

    server = pick("server_identifier")
    lease = pick("lease_time")
    subnet = pick("subnet_mask")
    router = pick("router")
    dns_servers = re.findall(r"domain_name_server[^\d]*\{([^}]+)\}", raw)
    # also try the alternate "domain_name_server (ip_mult): {10.10.10.1}" form
    if not dns_servers:
        for m in re.finditer(r"domain_name_server[^:\n]*:\s*(.+)", raw):
            for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(1)):
                dns_servers.append(ip)
    search = re.findall(r"search_domain\[\d+\][^\n]*:\s*(\S+)", raw)
    yiaddr = pick("yiaddr")

    if not server and not router and not yiaddr:
        res.error = f"no DHCP info for {interface}"
        return res
    res.add("Server", server or "?")
    if lease:
        try:
            seconds = int(lease, 16) if lease.startswith("0x") else int(lease)
            res.add("Lease time", f"{seconds}s ({seconds // 3600}h)")
        except ValueError:
            res.add("Lease time", lease)
    if subnet and router:
        try:
            octets = router.split(".")
            mask_oct = subnet.split(".")
            net = ".".join(
                str(int(a) & int(b)) for a, b in zip(octets, mask_oct)
            )
            prefix = sum(bin(int(x)).count('1') for x in mask_oct)
            res.add("Subnet", f"{net}/{prefix}")
        except (ValueError, IndexError):
            res.add("Subnet mask", subnet)
    if router:
        res.add("Router", router)
    if dns_servers:
        res.add("DNS", ", ".join(dns_servers))
    if search:
        res.add("Search domain", ", ".join(search))
    res.raw = {
        "interface": interface,
        "server": server,
        "lease_time": lease,
        "subnet_mask": subnet,
        "router": router,
        "dns": dns_servers,
        "search": search,
        "yiaddr": yiaddr,
        "raw": raw,
    }
    return res
