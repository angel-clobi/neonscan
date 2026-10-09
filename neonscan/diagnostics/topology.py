"""Schematic host/gateway export (Mermaid / Graphviz) + IPv6 privacy heuristic."""

from __future__ import annotations

import re
from typing import Iterable

from .result import DiagResult, Severity


# ---------------------------------------------------------------------------
# Mermaid export
# ---------------------------------------------------------------------------

def topology_to_mermaid(
    local_ip: str,
    gateway: str,
    hosts: list[dict],
    dns_servers: list[str] = (),
) -> str:
    """Return a schematic subnet view, not an inferred physical topology.

    Hosts are shown as discovered in the subnet. Physical switches and paths
    cannot be inferred without protocols such as LLDP or managed-switch data.
    """
    lines = [
        "graph LR",
        "  %% Schematic only: physical links and switch paths are not inferred.",
    ]
    gw = _safe_id(gateway or "gw")
    me = _safe_id(local_ip or "me")
    lines.append(f"  {gw}[('{_mermaid_label(gateway or 'gateway')}')]")
    lines.append(f"  {me}[('{_mermaid_label(local_ip or 'this host')}')]")
    lines.append(f"  {gw} -. default route .- {me}")

    for host in hosts:
        ip = host.get("ip", "")
        label = _mermaid_label(host.get("hostname") or host.get("manufacturer") or ip)
        nid = _safe_id(ip)
        lines.append(f"  {me} -. discovered in subnet .- {nid}[('{label}')]")

    for d in dns_servers:
        if not d:
            continue
        did = _safe_id(d)
        lines.append(f"  {gw} -.- {did}[('DNS · {_mermaid_label(d)}')]")

    return "\n".join(lines)


def _safe_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", (s or "").strip() or "node")


def _mermaid_label(value: str) -> str:
    """Keep discovered host labels from changing Mermaid diagram structure."""
    return re.sub(r"[\r\n\[\]{}()|<>`'\"]", " ", str(value)).strip()[:80] or "host"


def _dot_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def export_topology(
    local_ip: str,
    gateway: str,
    hosts: list[dict],
    dns_servers: Iterable[str] = (),
    fmt: str = "mermaid",
) -> DiagResult:
    """Wrap topology export as a DiagResult; write nothing here."""
    res = DiagResult(title=f"Topology · {fmt}")
    res.add("Scope", "Schematic subnet view; switch paths and physical links are not inferred")
    if fmt == "mermaid":
        text = topology_to_mermaid(local_ip, gateway, hosts, list(dns_servers))
        res.add("Format", "mermaid `graph LR`")
        res.add("Hosts", str(len(hosts)))
        res.raw = {"text": text}
    elif fmt == "dot":
        text = topology_to_dot(local_ip, gateway, hosts, list(dns_servers))
        res.add("Format", "graphviz DOT")
        res.add("Hosts", str(len(hosts)))
        res.raw = {"text": text}
    else:
        res.error = f"unknown format {fmt}"
        return res
    return res


def topology_to_dot(local_ip: str, gateway: str, hosts: list[dict], dns_servers: list[str] = ()) -> str:
    lines = [
        "digraph G {",
        "  rankdir=LR;",
        '  label="Schematic only: physical links and switch paths are not inferred";',
        "  labelloc=t;",
    ]
    if gateway:
        safe_gateway = _dot_escape(gateway)
        lines.append(f'  "{safe_gateway}" [label="{safe_gateway}\\ngateway", shape=triangle];')
    if local_ip:
        safe_local = _dot_escape(local_ip)
        lines.append(f'  "{safe_local}" [label="this host", shape=doublecircle];')
        if gateway:
            lines.append(f'  "{_dot_escape(gateway)}" -> "{safe_local}" [style=dashed, label="default route"];')
    for host in hosts:
        ip = host.get("ip", "")
        label = host.get("hostname") or host.get("manufacturer") or ip
        lines.append(f'  "{_dot_escape(ip)}" [label="{_dot_escape(label)}"];')
        if local_ip:
            lines.append(f'  "{_dot_escape(local_ip)}" -> "{_dot_escape(ip)}" [style=dashed, label="discovered in subnet"];')
    for d in dns_servers:
        if not d:
            continue
        lines.append(f'  "{_dot_escape(d)}" [label="DNS {_dot_escape(d)}", shape=box];')
        if gateway:
            lines.append(f'  "{_dot_escape(d)}" -> "{_dot_escape(gateway)}" [style=dashed, dir=back];')
    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# IPv6 privacy address heuristic
# ---------------------------------------------------------------------------

def privacy_score_ipv6(addr: str) -> float:
    """Heuristic: returns 1.0 if the address looks randomly generated
    (RFC 4941 privacy extension), 0.0 if clearly a stable interface
    identifier (EUI-64 from MAC), 0.5 otherwise.

    The actual RFC 4941 check requires remembering whether the bit at
    position 6 of byte 8 is set (the "u" bit) AND historical state. We
    can't satisfy that without data across runs, so we approximate by
    looking at the structure: a random IID will be all-zeros in the
    embedded-IPv4 case + varied last 64 bits, while EUI-64 produces a
    recognizable pattern (FF:FE in the middle, inverted MAC bit).
    """
    if not addr or ":" not in addr:
        return 0.0
    addr = addr.strip()
    # extract last 64 bits (interface ID)
    parts = addr.split(":")
    # Pad with leading zeros to 8 parts
    padded: list[str] = []
    if ":" in addr and "::" in addr:
        full = ("0:" * 8 + addr.replace("::", ":")).strip(":")
        parts = full.split(":")
    while len(parts) < 8:
        parts.insert(0, "0000")
    if len(parts) > 8:
        # take the right-most 8 — IPv4-mapped etc.
        parts = parts[-8:]
    iid = parts[-4:]
    low = iid[2] if len(iid) >= 4 else ""
    high = iid[3] if len(iid) >= 4 else ""
    mid = iid[1] if len(iid) >= 3 else ""

    s = "".join(iid).lower()
    hexes = re.findall(r"[0-9a-f]+", s)
    bits = "".join(b for b in hexes)

    if not bits or len(bits) < 16:
        return 0.5

    # EUI-64 marker: fffe at positions 6..10 of 16 hex chars
    if mid.lower() in ("fffe",):
        return 0.0  # clearly EUI-64
    # Link-local patterns: fe80::
    if addr.lower().startswith("fe80"):
        return 0.1
    # All-zero IID (::): stable but rare, treat as random
    if all(b == "0" for b in hexes):
        return 0.7
    # Count distinct nibbles — random IIDs typically have varied bits
    distinct = len(set(bits))
    if distinct <= 4:
        return 0.0  # very patterned → stable
    if distinct >= 12:
        return 0.85  # looks random
    return 0.55


def classify_ipv6_for_hosts(hosts: list[dict]) -> DiagResult:
    """Annotate hosts with a 'random IPv6 heuristic' rating."""
    res = DiagResult(title="IPv6 · privacy")
    if not hosts:
        res.error = "no hosts provided"
        return res
    random_count = 0
    stable_count = 0
    for h in hosts:
        ip = h.get("ip", "")
        if ":" not in ip:
            continue
        s = privacy_score_ipv6(ip)
        verdict = "random IID (privacy)" if s >= 0.6 else (
            "stable IID (EUI-64)" if s <= 0.3 else "neutral"
        )
        if s >= 0.6:
            random_count += 1
        elif s <= 0.3:
            stable_count += 1
        res.add(ip, verdict, severity=Severity.INFO)
    res.add("Random IIDs", str(random_count))
    res.add("Stable IIDs", str(stable_count))
    return res
