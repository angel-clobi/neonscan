"""ARP anomaly detection: duplicate IP+MAC mappings, suspicious flips.

The goal is *defensive* sanity checking — not IDS. We surface things that
look wrong: the same IP held by two MACs (potential spoofing), or an
unexpected vendor on the gateway's IP.
"""

from __future__ import annotations

import re
import subprocess
from collections import defaultdict
from typing import Optional

from .result import DiagResult, Severity
from ..oui import OUICache  # noqa: F401 — re-export from package
from pathlib import Path


# Reuse the platform-specific ARP reader from neonscan.network.
from ..network import _read_arp_table, _normalize_mac  # type: ignore


def analyze_arp(
    expected_gateway_oui: Optional[str] = None,
    cache_dir: Optional[Path] = None,
    offline: bool = False,
) -> DiagResult:
    """Read the system ARP table and report anomalies."""
    res = DiagResult(title="ARP · anomalies")
    entries = _read_arp_table()  # list of (ip, mac, iface)
    if not entries:
        res.error = "ARP table is empty"
        return res

    by_ip: dict[str, list[tuple[str, str]]] = defaultdict(list)
    by_mac: dict[str, list[str]] = defaultdict(list)
    for ip, mac, _iface in entries:
        by_ip[ip].append((mac, _iface))
        by_mac[_normalize_mac(mac)].append(ip)

    # 1) IP → multiple MACs
    dup_ips = {ip: mac_ifaces for ip, mac_ifaces in by_ip.items() if len(set(m for m, _ in mac_ifaces)) > 1}
    # 2) MAC → multiple IPs
    dup_macs = {m: ips for m, ips in by_mac.items() if len(ips) > 1}

    # 3) Multicast / broadcast entries
    weird = []
    for ip, mac, _ in entries:
        if mac.startswith("ff:ff:ff") or ip.endswith(".255") or ip.startswith("224."):
            weird.append((ip, mac))

    if not any([dup_ips, dup_macs, weird]):
        res.add("Clean", "yes", severity=Severity.OK,
                note=f"{len(entries)} ARP entries, no duplicates")
        res.raw = {"entries": entries, "dup_ips": {}, "dup_macs": {}, "weird": []}
        return res

    if dup_ips:
        for ip, mac_ifaces in dup_ips.items():
            res.add(
                f"Conflict: {ip}",
                " ← ".join(m for m, _ in mac_ifaces),
                severity=Severity.FAIL,
                note="two MACs claim this IP (possible ARP spoofing)",
            )
    if dup_macs:
        for m, ips in dup_macs.items():
            res.add(
                f"Multi-IP: {m}",
                ", ".join(ips),
                severity=Severity.WARN,
                note="one MAC for multiple IPs — fine if multi-homed",
            )
    if weird:
        res.add("Multicast/broadcast", str(len(weird)), severity=Severity.INFO)

    res.raw = {
        "entries": entries,
        "dup_ips": dup_ips,
        "dup_macs": dup_macs,
        "weird": weird,
    }
    return res
