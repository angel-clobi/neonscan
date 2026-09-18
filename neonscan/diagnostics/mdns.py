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


def _parse_response(buf: bytes, target_base: str = "") -> list[dict]:
    """Extract service instances (PTR + SRV + TXT + A) from an mDNS response.

    Record types: PTR = 12 (service-type -> instance), SRV = 33 (instance ->
    host + port), TXT = 16 (instance metadata), A = 1 (host -> IPv4).  We key
    the SRV/TXT slots by *instance* name so the port/host attach to the PTR's
    instance, and resolve the IP through the SRV target.
    """
    if len(buf) < 12:
        return []
    _qid, _flags, _qd, _an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    pos = 12

    def walk_name(p: int) -> tuple[str, int]:
        labels: list[str] = []
        jumps = 0
        cur = p
        while cur < len(buf):
            l = buf[cur]
            if l == 0:
                cur += 1
                break
            if l & 0xC0 == 0xC0:
                if cur + 1 >= len(buf) or jumps > 20:
                    break
                cur = struct.unpack(">H", buf[cur:cur + 2])[0] & 0x3FFF
                jumps += 1
                continue
            cur += 1
            labels.append(buf[cur:cur + l].decode("ascii", errors="ignore"))
            cur += l
        return (".".join(labels) + "."), cur

    # skip question section
    for _ in range(_qd):
        _qname, pos = walk_name(pos)
        pos += 4  # type + class

    instances: dict[str, dict] = {}
    a_by_host: dict[str, str] = {}

    def slot_for(name: str) -> dict:
        return instances.setdefault(name, {"service": "", "host": "", "port": 0, "txt": []})

    for _ in range(_an + _ns + _ar):
        rdname, npos = walk_name(pos)
        if npos + 10 > len(buf):
            break
        pos = npos
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", buf[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(buf):
            break
        rdata_pos = pos
        rdata = buf[rdata_pos:rdata_pos + rdlen]

        if rtype == 12:  # PTR: rdname = service type, rdata = instance name
            instance, _ = walk_name(rdata_pos)
            slot = slot_for(instance)
            if not slot["service"]:
                slot["service"] = rdname
        elif rtype == 33 and rdlen >= 6:  # SRV: rdname = instance
            _pri, _weight, port = struct.unpack(">HHH", rdata[:6])
            target, _ = walk_name(rdata_pos + 6)
            slot = slot_for(rdname)
            slot["port"] = port
            slot["host"] = target
        elif rtype == 16:  # TXT: rdname = instance
            chunks: list[str] = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                if ln == 0 or i + ln > len(rdata):
                    break
                chunks.append(rdata[i:i + ln].decode("ascii", errors="ignore"))
                i += ln
            if chunks:
                slot_for(rdname)["txt"].extend(chunks)
        elif rtype == 1 and rdlen == 4:  # A: rdname = hostname
            a_by_host[rdname] = ".".join(str(b) for b in rdata)

        pos = rdata_pos + rdlen

    out = []
    for instance, slot in instances.items():
        if not slot["service"] and not slot["host"] and slot["port"] == 0 and not slot["txt"]:
            continue  # bare A-record host, not a service instance
        out.append({
            "service": slot["service"],
            "instance": instance,
            "port": slot["port"],
            "host": slot["host"],
            "txt": slot["txt"],
            "ip": a_by_host.get(slot["host"], ""),
        })
    return out


def discover_mdns(
    services: Optional[Iterable[tuple[str, str]]] = None,
    wait_ms: int = 1500,
) -> DiagResult:
    """Issue mDNS PTR queries for the supplied services and aggregate responses."""
    res = DiagResult(title="mDNS · Bonjour")
    services = list(services) if services is not None else DEFAULT_SERVICES
    type_to_label = {stype: label for stype, label in services}

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:  # SO_REUSEPORT lets us bind 5353 alongside mDNSResponder/avahi
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

    bound_5353 = True
    try:
        s.bind(("", 5353))
    except OSError:
        bound_5353 = False
        try:
            s.bind(("", 0))
        except OSError as exc:
            s.close()
            res.error = f"could not bind for mDNS: {exc}"
            return res

    # Join the mDNS multicast group so responses to 224.0.0.251 reach us.
    try:
        mreq = struct.pack("=4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    s.settimeout(0.4)

    packets: list[bytes] = []
    try:
        # Fire all queries first, then listen once for the whole window.
        for query_name, _label in services:
            try:
                s.sendto(_encode_mdns_query(query_name), ("224.0.0.251", 5353))
            except OSError:
                pass
        deadline = time.time() + wait_ms / 1000.0
        while time.time() < deadline:
            try:
                data, _addr = s.recvfrom(9000)
                packets.append(data)
            except socket.timeout:
                continue
            except OSError:
                break
    finally:
        s.close()

    # Parse everything, de-duplicate by (instance, port).
    entries: list[dict] = []
    seen: set = set()
    for buf in packets:
        for e in _parse_response(buf):
            key = (e["instance"], e["port"])
            if key in seen:
                continue
            seen.add(key)
            entries.append(e)

    # Group by the requested service labels (fall back to "other").
    by_label: dict[str, list[dict]] = {}
    for e in entries:
        label = "other"
        for stype, lab in type_to_label.items():
            if stype in e["service"] or stype in e["instance"]:
                label = lab
                break
        by_label.setdefault(label, []).append(e)

    total = len(entries)
    for label, ents in sorted(by_label.items()):
        res.add(label, f"{len(ents)} service(s)", severity=Severity.OK)

    res.raw = {"services": by_label, "count": total, "bound_5353": bound_5353}
    res.summary = f"{total} service instance(s)"
    if total == 0:
        res.error = "no mDNS responses received (multicast may be filtered on this interface)"
    return res
