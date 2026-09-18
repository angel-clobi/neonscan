"""Active connections + listening sockets (via lsof / netstat fallback)."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from typing import Optional

from .result import DiagResult, Severity


IS_DARWIN = platform.system() == "Darwin"


_IPv4_PORT = re.compile(r"(\d+\.\d+\.\d+\.\d+)(?::(\d+)|(?:->)(\d+\.\d+\.\d+\.\d+)(?::(\d+))?)?")
_LSOF_LINE = re.compile(
    r"^(\S+)\s+(\d+)\s+\S+\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+\s+\S+|\S+)\s+(\S+)"
)


def get_connections(limit: int = 60) -> DiagResult:
    """Return currently-open TCP + UDP connections and listening sockets."""
    res = DiagResult(title="Active connections")
    # On Linux/Termux `ss` (iproute2) is the modern tool and is usually present
    # even where net-tools (`lsof`/`netstat`) are not.
    if not IS_DARWIN and shutil.which("ss"):
        out = _ss_connections(limit=limit, res=res)
        if out.ok and out.findings:
            return out
        res = DiagResult(title="Active connections")
    if shutil.which("lsof"):
        return _lsof_connections(limit=limit, res=res)
    return _netstat_connections(limit=limit, res=res)


def _ss_connections(limit: int, res: DiagResult) -> DiagResult:
    """Enumerate sockets with `ss -tuna` (Linux/Termux, no root needed)."""
    try:
        cp = subprocess.run(
            ["ss", "-tuna"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        res.error = f"ss failed: {exc}"
        return res
    rows = _parse_ss_output(cp.stdout)
    if not rows:
        res.error = "ss returned no sockets"
        return res
    listening = [r for r in rows if r["state"] in ("LISTEN", "UNCONN")]
    established = [r for r in rows if r["state"] == "ESTABLISHED"]
    res.add(
        "Summary",
        f"{len(rows)} total · {len(established)} established · {len(listening)} listening",
    )
    if listening[:limit]:
        res.add("Listening ports", ", ".join(_short_addr(r["local"]) for r in listening[:limit]))
    if established[:limit]:
        res.add(
            "Active peers",
            ", ".join(_short_addr(r["remote"], include_port=True) for r in established[:limit]),
        )
    res.raw = {
        "rows": rows[:limit],
        "total": len(rows),
        "listening": len(listening),
        "established": len(established),
        "tool": "ss",
    }
    return res


def _parse_ss_output(stdout: str) -> list[dict]:
    """Parse `ss -tuna` rows into dicts. Header line is skipped.

    Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]
    """
    rows: list[dict] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        if parts[0].lower() in ("netid", "state"):  # header (with/without -H)
            continue
        if parts[0].lower() not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        proto = parts[0].upper()
        state = parts[1].upper()
        if state == "ESTAB":
            state = "ESTABLISHED"
        local, remote = parts[4], parts[5]
        rows.append({
            "proto": proto, "local": local, "remote": remote, "state": state,
        })
    return rows


def _lsof_connections(limit: int, res: DiagResult) -> DiagResult:
    """Use lsof -nP to enumerate sockets. Falls back to netstat if empty."""
    try:
        cp = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-sTCP:established,listen"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        res.error = f"lsof failed: {exc}"
        return _netstat_connections(limit=limit, res=res)

    lines = cp.stdout.splitlines()
    rows: list[dict] = []
    state_re = re.compile(r"\(([A-Z]+)\)\s*$")
    for line in lines[1:]:
        cols = re.split(r"\s+", line, maxsplit=8)
        if len(cols) < 9:
            continue
        comm, pid, _user, _fd, _type, _node, _size, _name, addr_field = cols
        m_state = state_re.search(addr_field)
        state = m_state.group(1) if m_state else "?"
        # remove the trailing "(STATE)"
        addr_part = state_re.sub("", addr_field).strip()
        local = remote = ""
        if "->" in addr_part:
            # TCP 192.168.0.10:53011->93.184.216.34:443
            arrow = addr_part.split("->", 1)
            local = arrow[0].split(None, 1)[1] if len(arrow[0].split(None, 1)) > 1 else arrow[0]
            remote = arrow[1].strip()
        else:
            # TCP *:80   or  TCP [fe80::...]:80
            parts = addr_part.split(None, 1)
            if len(parts) > 1:
                local = parts[1]
            else:
                local = parts[0]
        try:
            pid_int = int(pid)
        except ValueError:
            pid_int = 0
        rows.append({
            "proto": "TCP", "pid": pid_int, "comm": comm,
            "local": local, "remote": remote, "state": state,
        })

    if not rows:
        return _netstat_connections(limit=limit, res=res)

    listening = [r for r in rows if r["state"] == "LISTEN"]
    established = [r for r in rows if r["state"] == "ESTABLISHED"]
    res.add(
        "Summary",
        f"{len(rows)} total · {len(established)} established · {len(listening)} listening",
    )

    if listening[:limit]:
        res.add(
            "Listening ports",
            ", ".join(_short_addr(r["local"]) for r in listening[:limit]),
        )
    if established[:limit]:
        res.add(
            "Active peers",
            ", ".join(_short_addr(r["remote"], include_port=True) for r in established[:limit]),
        )

    res.raw = {
        "rows": rows[:limit],
        "total": len(rows),
        "listening": len(listening),
        "established": len(established),
        "tool": "lsof",
    }
    if not established and not listening:
        res.error = "no connections reported"
    return res


def _netstat_connections(limit: int, res: DiagResult) -> DiagResult:
    """Fallback: parse netstat -an output (BSD and Linux syntaxes differ)."""
    # BSD: `netstat -an -p tcp` selects the protocol. Linux: `-p` means
    # show-PID and takes no argument, so use `-tuan` to get TCP+UDP numeric.
    cmd = ["netstat", "-an", "-p", "tcp"] if IS_DARWIN else ["netstat", "-tuan"]
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        res.error = f"netstat failed: {exc}"
        return res

    rows: list[dict] = []
    for line in cp.stdout.splitlines():
        if "tcp" not in line and "udp" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        if proto in ("tcp4", "tcp6", "tcp"):
            proto = "TCP"
        elif proto in ("udp4", "udp6", "udp"):
            proto = "UDP"
        # BSD netstat separates host/port with '.', Linux uses ':' already.
        norm = _netstat_norm if IS_DARWIN else (lambda a: a)
        local = norm(parts[3]) if len(parts) > 3 else ""
        remote = norm(parts[4]) if len(parts) > 4 else ""
        state = parts[5] if len(parts) > 5 else ""
        rows.append({
            "proto": proto, "local": local, "remote": remote, "state": state,
        })

    listening = [r for r in rows if r["state"] == "LISTEN"]
    established = [r for r in rows if r["state"] == "ESTABLISHED"]
    res.add(
        "Summary",
        f"{len(rows)} total · {len(established)} established · {len(listening)} listening",
    )
    if listening[:limit]:
        res.add("Listening ports", ", ".join(_short_addr(r["local"]) for r in listening[:limit]))
    if established[:limit]:
        res.add(
            "Active peers",
            ", ".join(_short_addr(r["remote"], include_port=True) for r in established[:limit]),
        )
    res.raw = {
        "rows": rows[:limit],
        "total": len(rows),
        "listening": len(listening),
        "established": len(established),
        "tool": "netstat",
    }
    return res


def _netstat_norm(addr: str) -> str:
    """macOS netstat uses '.' to separate host and port; convert to ':'."""
    if not addr:
        return ""
    # IPv4 dotted form: a.b.c.d.XYZ  → a.b.c.d:XYZ
    # IPv6 form:  fe80::1.61000      → [fe80::1]:61000
    # Bracketed IPv6 with .port:  [::1].1234 → [::1]:1234
    if addr.startswith("[") and "]" in addr:
        host, _, rest = addr.partition("]")
        tail = rest.lstrip(".")
        return f"{host}]:{tail}" if tail else host + "]"
    # Plain IPv6 (contains ':'), find rightmost dot → bracket + dot → colon
    if ":" in addr:
        host, _, port = addr.rpartition(".")
        return f"[{host}]:{port}" if port else addr
    parts = addr.rsplit(".", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return f"{parts[0]}:{parts[1]}"
    return addr


_ADDR_TAIL = re.compile(r"(\]:|:)(\d+)$")


def _short_addr(addr: str, include_port: bool = False) -> str:
    """Turn '192.168.0.10:53011' into a tight 'host:port' string. IPv6-safe."""
    if not addr:
        return "?"
    if "*" in addr:
        return addr
    # bracketed IPv6: [fe80::1]:443
    if addr.startswith("["):
        if "]:" in addr:
            host, rest = addr.split("]:", 1)
            port = rest.split()[0]
            return f"{host}]:{port}" if include_port and port else host + "]"
        return addr
    # bare IPv6 (no brackets) — take last colon-separated token as port
    if addr.count(":") >= 2:
        m = _ADDR_TAIL.search(addr)
        if m:
            host_part = addr[: m.start()]
            port = m.group(2)
            host_part = host_part.lstrip("[").rstrip("]")
            return f"[{host_part}]:{port}" if include_port else f"[{host_part}]"
        return addr
    if ":" in addr:
        host, _, port = addr.rpartition(":")
    else:
        host, _, port = addr, "", ""
    if include_port and port:
        return f"{host}:{port}"
    return host
