"""DNS diagnostic: latency + correctness across multiple resolvers.

Two strategies:
  * Fast path: shell out to `dig` per resolver if available (per-resolver timing).
  * Fallback: hand-rolled DNS UDP query (QNAME + A record parse) using only stdlib.
"""

from __future__ import annotations

import random
import re
import socket
import statistics
import struct
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from .result import DiagResult, Severity


# Curated list of public resolvers to test against the SAME domain.
# The machine's own resolver(s) are added separately from /etc/resolv.conf
# (see `_find_resolvers`) — we don't hardcode 127.0.0.1, which is usually not
# listening and would drag the "N/M OK" tally down for no reason.
DEFAULT_RESOLVERS: list[tuple[str, str]] = [
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rcode_text(code: int) -> str:
    return {
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
        4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 8: "NXRRSET",
    }.get(code, f"RCODE{code}")


def _find_resolvers() -> list[tuple[str, str]]:
    """Discover configured resolvers from /etc/resolv.conf when present."""
    out = []
    try:
        text = open("/etc/resolv.conf").read()
    except OSError:
        return out
    seen = set()
    for line in text.splitlines():
        if line.startswith(("nameserver", "nameserver ")):
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1].strip()
                if ip not in seen:
                    seen.add(ip)
                    out.append((ip, "Local-config"))
    return out


# ---------------------------------------------------------------------------
# DNS via dig (preferred — full-feature)
# ---------------------------------------------------------------------------

_DIG_STATS = re.compile(r";;\s*Query time:\s*(\d+)\s*msec")
_DIG_SERVER = re.compile(r";;\s*server\s*\((\d+\.\d+\.\d+\.\d+)\)")
_DIG_STATUS = re.compile(r"status:\s*(\w+)", re.IGNORECASE)
_DIG_ANSWER_LINE = re.compile(
    r"^\s*(\S+)\s+\d+\s+IN\s+A\s+(\S+)"
)


def _dig_resolver(server: str, name: str, timeout: float = 3.0) -> dict:
    """Run dig for `name` against `server` and return stats."""
    cmd = [
        "dig", "+time=1", "+tries=1",
        "@" + server, name, "A",
        "+noall", "+answer", "+comments", "+stats",
    ]
    try:
        cp = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return {"ok": False, "skip": True, "reason": "dig not installed"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "skip": False, "reason": "timeout"}

    out = cp.stdout
    m_status = _DIG_STATUS.search(out)
    m_time = _DIG_STATS.search(out)
    rcode_name = m_status.group(1).upper() if m_status else "NOERROR"
    ms = float(m_time.group(1)) if m_time else None

    # Extract A answers.  dig emits FQDNs with trailing dots; matches tabular A lines.
    answers: list[str] = []
    base = name.rstrip(".")
    for line in out.splitlines():
        m = _DIG_ANSWER_LINE.match(line)
        if m:
            rname, rdata = m.group(1), m.group(2)
            if rname.rstrip(".") == base:
                answers.append(rdata)

    if cp.returncode != 0 and not answers:
        return {"ok": False, "skip": False, "reason": cp.stderr.strip() or "no answer", "ms": ms}

    return {
        "ok": rcode_name == "NOERROR" and bool(answers),
        "rcode": rcode_name,
        "ms": ms,
        "answers": answers,
        "server": server,
    }


# ---------------------------------------------------------------------------
# DNS via raw UDP (fallback)
# ---------------------------------------------------------------------------

def _encode_dns_query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    """Encode a simple DNS A query packet (one question)."""
    qid = random.randint(0, 65535)
    flags = 0x0100  # RD = recursion desired
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    parts: list[bytes] = []
    for label in name.strip(".").split("."):
        if not label:
            continue
        try:
            lab = label.encode("ascii")
        except UnicodeEncodeError:
            lab = label.encode("idna")  # IDN / punycode
        parts.append(bytes([len(lab)]) + lab)
    question = b"".join(parts) + b"\x00" + struct.pack(">HH", qtype, qclass)
    return header + question


def _decode_dns_response(buf: bytes) -> dict:
    """Parse a DNS response and return rcode + A record answers."""
    if len(buf) < 12:
        return {"ok": False, "reason": "short response"}
    _qid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0xF
    answers: list[str] = []
    pos = 12

    # skip the question
    for _ in range(qd):
        pos = _skip_name(buf, pos)
        pos += 4  # type + class

    # parse answers
    for _ in range(an):
        pos = _skip_name(buf, pos)
        if pos + 10 > len(buf):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", buf[pos:pos + 10])
        pos += 10
        rdata = buf[pos:pos + rdlen]
        pos += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in rdata))
        elif rtype == 5:  # CNAME
            try:
                cname = _read_name(buf, pos - rdlen)[0]
            except Exception:
                cname = ""
            if cname:
                answers.append(f"CNAME→{cname.rstrip('.')}")

    return {"ok": rcode == 0 and bool(answers), "rcode": _rcode_text(rcode), "answers": answers}


def _skip_name(buf: bytes, pos: int) -> int:
    """Advance past a DNS name (handling compression)."""
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length
    return pos


def _read_name(buf: bytes, pos: int) -> tuple[str, int]:
    """Read a DNS name at pos into a string. Returns (name, end_pos)."""
    out: list[str] = []
    jumps = 0
    cur = pos
    while True:
        if cur >= len(buf):
            break
        length = buf[cur]
        if length == 0:
            cur += 1
            break
        if length & 0xC0 == 0xC0:
            if cur + 1 >= len(buf):
                break
            offset = struct.unpack(">H", buf[cur:cur + 2])[0] & 0x3FFF
            jumps += 1
            if jumps > 10:
                break
            cur = offset
            continue
        cur += 1
        out.append(buf[cur:cur + length].decode("ascii", errors="ignore"))
        cur += length
    return ".".join(out) + ".", cur


def _udp_resolver(server: str, name: str, timeout: float = 3.0) -> dict:
    """Send a UDP DNS query to `server` and time the response."""
    pkt = _encode_dns_query(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (server, 53))
        buf, _ = s.recvfrom(4096)
    except (socket.timeout, OSError) as exc:
        return {"ok": False, "skip": False, "reason": f"udp: {exc}", "ms": None, "server": server}
    finally:
        s.close()
    dt = (time.perf_counter() - t0) * 1000.0
    parsed = _decode_dns_response(buf)
    parsed["ms"] = dt
    parsed["server"] = server
    return parsed


def _query_one(server: str, name: str) -> dict:
    """Try dig first, fall back to UDP on missing dig."""
    d = _dig_resolver(server, name)
    if d.get("skip"):
        return _udp_resolver(server, name)
    return d


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class DNSResultRow:
    server: str
    label: str
    ok: bool
    ms: Optional[float]
    answers: list[str]
    rcode: str = ""
    note: str = ""


def measure_dns(name: str = "google.com", extra_resolvers: Optional[list[tuple[str, str]]] = None) -> DiagResult:
    """Run a DNS query for `name` against many resolvers and aggregate."""
    res = DiagResult(title=f"DNS :: {name}")

    resolvers: list[tuple[str, str]] = list(DEFAULT_RESOLVERS)
    resolvers.extend(_find_resolvers())
    if extra_resolvers:
        resolvers.extend(extra_resolvers)
    # de-duplicate while keeping order
    seen = set()
    deduped: list[tuple[str, str]] = []
    for s, l in resolvers:
        if s in seen:
            continue
        seen.add(s)
        deduped.append((s, l))
    resolvers = deduped

    rows: list[DNSResultRow] = []
    for server, label in resolvers:
        d = _query_one(server, name)
        rows.append(
            DNSResultRow(
                server=server,
                label=label,
                ok=bool(d.get("ok")),
                ms=d.get("ms"),
                answers=list(d.get("answers") or []),
                rcode=d.get("rcode", ""),
                note=d.get("reason", "") or "",
            )
        )

    # severity stats
    ok_count = sum(1 for r in rows if r.ok)
    timings = [r.ms for r in rows if r.ok and r.ms is not None]
    fastest = min(timings) if timings else None
    slowest = max(timings) if timings else None
    avg_ms = statistics.mean(timings) if timings else None

    sev_summary = Severity.OK if ok_count == len(rows) else (
        Severity.WARN if ok_count > 0 else Severity.FAIL
    )
    res.add(
        "Resolvers",
        f"{ok_count}/{len(rows)} OK",
        severity=sev_summary,
        note=f"resolving {name}",
    )
    if avg_ms is not None:
        sev_lat = Severity.OK if avg_ms < 50 else (Severity.WARN if avg_ms < 150 else Severity.FAIL)
        res.add(
            "Avg latency",
            f"{avg_ms:.1f} ms",
            severity=sev_lat,
        )
    if fastest is not None and slowest is not None:
        spread = slowest - fastest
        sev_spread = Severity.OK if spread < 80 else (Severity.WARN if spread < 200 else Severity.FAIL)
        res.add(
            "Spread",
            f"{spread:.1f} ms ({fastest:.0f}→{slowest:.0f})",
            severity=sev_spread,
            note="diff between fastest and slowest resolver",
        )

    # add each resolver as a finding for visibility
    for r in rows:
        ms_text = f"{r.ms:.1f} ms" if r.ms is not None else "—"
        sev = (
            Severity.OK if r.ok
            else Severity.WARN if r.note == "timeout"
            else Severity.FAIL
        )
        note = r.note or r.rcode or "ok"
        res.add(f"{r.label} ({r.server})", f"{ms_text} · {','.join(r.answers)[:40] or 'no answer'}",
                severity=sev, note=note)

    res.raw = {
        "domain": name,
        "rows": [
            {
                "server": r.server,
                "label": r.label,
                "ok": r.ok,
                "ms": r.ms,
                "answers": r.answers,
                "rcode": r.rcode,
                "note": r.note,
            }
            for r in rows
        ],
        "avg_ms": avg_ms,
        "fastest_ms": fastest,
        "slowest_ms": slowest,
    }
    if ok_count == 0:
        res.error = "No resolver returned a usable answer"
    return res
