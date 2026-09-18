"""mDNS / Bonjour discovery: ask the local network what's broadcasting.

We send a multicast query to 224.0.0.251:5353 for common service types
(_http._tcp, _ssh._tcp, _smb._tcp, _ipp._tcp, _airplay._tcp, etc.) and
parse the responses.

Implementation notes
--------------------
* No external deps.  We construct a small DNS-SD query packet directly.
* Multicast TTL=255 (required by mDNS).
* Wait up to `wait_ms` after sending for responses to come back.
"""

from __future__ import annotations

import random
import socket
import struct
import time
from typing import Iterable, Optional

from .result import DiagResult, Severity


# (service type, friendly label) — list can be extended by callers.
DEFAULT_SERVICES: list[tuple[str, str]] = [
    ("_http._tcp.local.",       "http"),
    ("_https._tcp.local.",      "https"),
    ("_ssh._tcp.local.",        "ssh"),
    ("_smb._tcp.local.",        "smb"),
    ("_ipp._tcp.local.",        "ipp"),
    ("_airplay._tcp.local.",    "airplay"),
    ("_googlecast._tcp.local.", "googlecast"),
    ("_homekit._tcp.local.",    "homekit"),
    ("_workstation._tcp.local.","workstation"),
]


def _encode_mdns_query(name: str) -> bytes:
    """Build a single-question DNS-SD PTR query in a multicast format."""
    qid = random.randint(0, 65535)
    flags = 0x0000
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    qbytes = b""
    for label in name.strip(".").split("."):
        if not label:
            continue
        qbytes += bytes([len(label)]) + label.encode("ascii")
    qbytes += b"\x00" + struct.pack(">HH", 12, 1)  # PTR, IN
    return header + qbytes


def _decode_mdns_name(buf: bytes, pos: int) -> tuple[str, int, list[tuple[str, str]]]:
    """Walk a DNS name starting at pos, returning (name, end_pos, [(type, value)]).

    Bonus: collect interesting typed records encountered.
    """
    out = []
    labels = []
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
            cur = offset
            continue
        cur += 1
        labels.append(buf[cur:cur + length].decode("ascii", errors="ignore"))
        cur += length
    out.append(("name", ".".join(labels) + "."))
    return ".".join(labels) + ".", cur, out


def _parse_response(buf: bytes, target_base: str) -> list[dict]:
    """Extract PTR + SRV + TXT records belonging to `target_base`."""
    if len(buf) < 12:
        return []
    _qid, flags, _qd, _an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    pos = 12

    # skip question section
    for _ in range(_qd):
        # skip name
        while pos < len(buf):
            l = buf[pos]
            if l == 0:
                pos += 1
                break
            if l & 0xC0 == 0xC0:
                pos += 2
                break
            pos += l + 1
        pos += 4  # type+class

    entries: dict[str, dict] = {}

    def walk_name(p: int, store_ptr_name: bool = False) -> tuple[str, int]:
        labels = []
        jumps = 0
        cur = p
        while True:
            if cur >= len(buf):
                break
            l = buf[cur]
            if l == 0:
                cur += 1
                break
            if l & 0xC0 == 0xC0:
                if cur + 1 >= len(buf):
                    break
                offset = struct.unpack(">H", buf[cur:cur + 2])[0] & 0x3FFF
                jumps += 1
                cur = offset
                continue
            cur += 1
            labels.append(buf[cur:cur + l].decode("ascii", errors="ignore"))
            cur += l
        return (".".join(labels) + "."), cur

    def read_record() -> Optional[tuple[str, int, int, int, int]]:
        """Skip a name; return (rdname, type, class, ttl, rdlen, end_pos)."""
        nonlocal pos
        rdname, npos = walk_name(pos)
        if npos + 10 > len(buf):
            return None
        pos = npos
        rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", buf[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(buf):
            return None
        return rdname, rtype, rclass, rdlen, pos

    for _ in range(_an + _ns + _ar):
        rec = read_record()
        if rec is None:
            break
        rdname, rtype, _rclass, rdlen, rdata_pos = rec
        rdata = buf[rdata_pos:rdata_pos + rdlen]
        # group by service instance (e.g. "My Printer._http._tcp.local.")
        if rtype in (12, 33):  # PTR
            target, _ = walk_name(rdata_pos)
            key = rdname
            slot = entries.setdefault(key, {"ptr": [], "srv": None, "txt": [], "a_records": []})
            slot["ptr"].append(target)
        elif rtype == 33:  # SRV
            _pri, _weight, _port = struct.unpack(">HHH", rdata[:6])
            target, _ = walk_name(rdata_pos + 6)
            target_base_name = target.replace("._tcp.local.", "._tcp.local.")
            slot = entries.setdefault(rdname, {"ptr": [], "srv": None, "txt": [], "a_records": []})
            if slot["srv"] is None:
                slot["srv"] = {"target": target, "port": _port}
        elif rtype == 16:  # TXT
            # txt chunks are length-prefixed strings
            chunks = []
            i = 0
            while i < len(rdata) and rdata[i] <= len(rdata) - i - 1:
                ln = rdata[i]
                i += 1
                chunks.append(rdata[i:i + ln].decode("ascii", errors="ignore"))
                i += ln
            slot = entries.setdefault(rdname, {"ptr": [], "srv": None, "txt": [], "a_records": []})
            slot["txt"].extend(chunks)
        elif rtype == 1 and rdlen == 4:  # A
            ip = ".".join(str(b) for b in rdata)
            # find slot by parent name
            slot = entries.setdefault(rdname, {"ptr": [], "srv": None, "txt": [], "a_records": []})
            slot["a_records"].append(ip)
        pos = rdata_pos + rdlen

    # Compact for output
    out = []
    for name, slot in entries.items():
        for tgt in slot["ptr"]:
            srv = slot["srv"] or {}
            out.append({
                "service": name,
                "instance": tgt,
                "port": srv.get("port", 0),
                "host": srv.get("target", ""),
                "txt": slot["txt"],
                "ip": slot["a_records"][0] if slot["a_records"] else "",
            })
    return out


def discover_mdns(
    services: Optional[Iterable[tuple[str, str]]] = None,
    wait_ms: int = 1500,
) -> DiagResult:
    """Issue mDNS PTR queries for the supplied services and aggregate responses."""
    res = DiagResult(title="mDNS · Bonjour")
    if services is None:
        services = DEFAULT_SERVICES

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.settimeout(wait_ms / 1000)
    try:
        s.bind(("", 5353))
    except OSError:
        try:
            s.bind(("", 0))
        except OSError as exc:
            res.error = f"could not bind for mDNS: {exc}"
            return res
    try:
        all_results: dict[str, list[dict]] = {}
        for query_name, label in services:
            pkt = _encode_mdns_query(query_name)
            sent_at = time.time()
            try:
                s.sendto(pkt, ("224.0.0.251", 5353))
            except OSError as exc:
                res.add(label, f"send failed: {exc}", severity=Severity.WARN)
                continue
            collected = []
            while time.time() - sent_at < wait_ms / 1000.0 / max(len(list(services)), 1):
                try:
                    _data, _addr = s.recvfrom(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                # we ignore _data here; we'll let the global parser decode it
                collected.append(_data)
            all_results[label] = [len(collected)] + collected  # store count + raw

        # parse globally
        per_service: dict[str, list[dict]] = {}
        for label, lst in all_results.items():
            count = lst[0]
            entries = []
            for buf in lst[1:]:
                if isinstance(buf, bytes):
                    entries.extend(_parse_response(buf, ""))
            per_service[label] = entries

        total = 0
        per_service_counts = []
        for label, entries in per_service.items():
            if not entries:
                continue
            total += len(entries)
            per_service_counts.append((label, entries))
            res.add(
                label,
                f"{len(entries)} service(s)",
                severity=Severity.OK,
            )

        res.raw = {
            "services": {
                label: entries
                for label, entries in per_service_counts
            },
            "count": total,
        }
        res.summary = f"{total} service announcements"
        if total == 0:
            res.error = "no mDNS responses received (is multicast enabled on the interface?)"
    finally:
        s.close()
    return res
