"""Traceroute diagnostic — single probe per hop with summary stats."""

from __future__ import annotations

import platform
import re
import socket
import subprocess
from typing import Optional

from .result import DiagResult, Severity


IS_DARWIN = platform.system() == "Darwin"


_HOP_RE_DARWIN = re.compile(
    r"^\s*(\d+)\s+(?:(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))"
)
_HOP_RE_LINUX = re.compile(r"^\s*(\d+)\s+(.*)$")
_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _parse(stdout: str) -> list[dict]:
    hops: list[dict] = []
    for line in stdout.splitlines():
        m = _HOP_RE_DARWIN.match(line) if IS_DARWIN else _HOP_RE_LINUX.match(line)
        if not m:
            continue
        if IS_DARWIN:
            num = int(m.group(1))
            host = m.group(2) or m.group(4) or "?"
            ip = m.group(3) or m.group(4) or "?"
        else:
            num = int(m.group(1))
            rest = m.group(2)
            ip_m = _IPV4.search(rest)
            ip = ip_m.group(1) if ip_m else "?"
            host = ip if ip != "?" else "?"
        times = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)]
        hops.append({"hop": num, "host": host, "ip": ip, "times_ms": times})
    return hops


def measure_traceroute(target: str = "8.8.8.8", max_hops: int = 20, wait_s: int = 1) -> DiagResult:
    """Run traceroute to a target (defaults to 8.8.8.8)."""
    res = DiagResult(title=f"Traceroute :: {target}")
    cmd = ["traceroute", "-m", str(max_hops), "-w", str(wait_s), target]
    try:
        cp = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max_hops * wait_s + 10, check=False
        )
    except FileNotFoundError:
        res.error = "traceroute not found (install the 'traceroute' package)"
        return res
    except subprocess.TimeoutExpired:
        res.error = "traceroute timed out"
        return res

    if cp.returncode != 0 and not cp.stdout.strip():
        res.error = cp.stderr.strip() or "traceroute exited non-zero"
        return res

    hops = _parse(cp.stdout)
    if not hops:
        res.add("Hops", "0", severity=Severity.WARN, note="no traceroute output")
        return res

    last_reached = next((h for h in reversed(hops) if h["ip"] not in ("?", "*")), None)

    # Resolve the target so a hostname compares against the final hop's IP.
    try:
        target_ip = socket.gethostbyname(target)
    except OSError:
        target_ip = target
    reached = bool(last_reached and last_reached["ip"] == target_ip)

    res.add("Hops", str(len(hops)))
    res.add("Reaches target", "yes" if reached else "no",
            severity=Severity.OK if reached else Severity.WARN)
    res.add("Path summary", _summarize_path(hops))
    res.raw = {"target": target, "hops": hops, "raw": cp.stdout}

    # Spread findings
    for h in hops[:10]:
        if h["times_ms"]:
            avg = sum(h["times_ms"]) / len(h["times_ms"])
            sev = Severity.OK if avg < 50 else (Severity.WARN if avg < 150 else Severity.FAIL)
            res.add(
                f"Hop {h['hop']:>2}",
                f"{h['host']} ({h['ip']}) — {avg:.0f} ms",
                severity=sev,
            )
        else:
            res.add(f"Hop {h['hop']:>2}", f"{h['host']} ({h['ip']}) — *", severity=Severity.WARN)
    return res


def _summarize_path(hops: list[dict]) -> str:
    private = [h for h in hops if h["ip"].startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))]
    public = [h for h in hops if h["ip"] != "?" and not h["ip"].startswith(("10.", "192.168.", "172."))]
    return f"{len(private)} private, {len(public)} public hops"
