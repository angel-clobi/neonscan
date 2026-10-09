"""Opt-in local snapshots and change detection for discovered network assets."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .network import Host
from .scanner import PortResult


DEFAULT_INVENTORY_DIR = Path.home() / ".neonscan" / "scans"


def make_inventory_snapshot(
    subnet: str,
    hosts: list[Host],
    ports_by_host: dict[str, list[PortResult]],
) -> dict:
    """Create a JSON-safe point-in-time view of the current discovery result."""
    return {
        "schema_version": 1,
        "scanner": "neonscan",
        "scanner_version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subnet": subnet,
        "hosts": [
            {
                "ip": host.ip,
                "mac": host.mac,
                "manufacturer": host.manufacturer,
                "hostname": host.hostname,
                "discovery_methods": list(host.discovery_methods),
                "scanned_ports": {
                    protocol: sorted(set(ports))
                    for protocol, ports in host.scanned_ports.items()
                },
                "ports": [
                    {
                        "port": result.port,
                        "protocol": result.protocol,
                        "state": result.state,
                        "service": result.service,
                        "service_source": result.service_source,
                        "product": result.product,
                        "version": result.version,
                    }
                    for result in ports_by_host.get(host.ip, [])
                ],
            }
            for host in hosts
        ],
    }


def save_inventory_snapshot(
    snapshot: dict,
    directory: Optional[Path] = None,
) -> Path:
    """Save a snapshot chosen by the user under ~/.neonscan/scans by default."""
    target_dir = Path(directory or DEFAULT_INVENTORY_DIR).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    target = target_dir / f"scan-{stamp}.json"
    target.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def load_latest_inventory(directory: Optional[Path] = None) -> tuple[Optional[dict], Optional[Path]]:
    """Return the most recently modified valid local scan snapshot."""
    target_dir = Path(directory or DEFAULT_INVENTORY_DIR).expanduser()
    if not target_dir.is_dir():
        return None, None
    for path in sorted(target_dir.glob("scan-*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("schema_version") == 1 and isinstance(data.get("hosts"), list):
            return data, path
    return None, None


def compare_inventories(current: dict, previous: dict) -> dict:
    """Compare host presence, identity metadata, and open TCP/UDP ports."""
    previous_scope = _normalize_scope(previous.get("subnet"))
    current_scope = _normalize_scope(current.get("subnet"))
    if previous_scope and current_scope and previous_scope != current_scope:
        return {
            "previous_timestamp": previous.get("timestamp", "unknown"),
            "current_timestamp": current.get("timestamp", "unknown"),
            "scope_changed": {"before": previous.get("subnet"), "after": current.get("subnet")},
            "added_hosts": [],
            "removed_hosts": [],
            "changed_hosts": [],
            "added_ports": [],
            "removed_ports": [],
            "changed_ports": [],
            "state_changes": [],
        }
    old_hosts = {host.get("ip", ""): host for host in previous.get("hosts", []) if host.get("ip")}
    new_hosts = {host.get("ip", ""): host for host in current.get("hosts", []) if host.get("ip")}
    old_ips, new_ips = set(old_hosts), set(new_hosts)

    changed_hosts = []
    added_ports = []
    removed_ports = []
    changed_ports = []
    state_changes = []
    for ip in sorted(new_ips - old_ips):
        for details in _open_port_map(new_hosts[ip]).values():
            added_ports.append({"ip": ip, **details})
    for ip in sorted(old_ips - new_ips):
        for details in _open_port_map(old_hosts[ip]).values():
            removed_ports.append({"ip": ip, **details})
    for ip in sorted(old_ips & new_ips):
        before, after = old_hosts[ip], new_hosts[ip]
        identity = {
            key: {"before": before.get(key, ""), "after": after.get(key, "")}
            for key in ("mac", "manufacturer", "hostname")
            if before.get(key, "") != after.get(key, "")
        }
        if identity:
            changed_hosts.append({"ip": ip, "changes": identity})

        shared_scope = _scanned_port_set(before) & _scanned_port_set(after)
        old_results = _port_result_map(before)
        new_results = _port_result_map(after)
        for key in sorted(shared_scope):
            old_result = old_results.get(key)
            new_result = new_results.get(key)
            if old_result is None or new_result is None:
                continue
            old_state = old_result.get("state", "unknown")
            new_state = new_result.get("state", "unknown")
            if old_state != "open" and new_state == "open":
                added_ports.append({"ip": ip, **new_result})
            elif old_state == "open" and new_state == "closed":
                removed_ports.append({"ip": ip, **old_result})
            elif old_state != new_state:
                state_changes.append({"ip": ip, "before": old_result, "after": new_result})
            elif old_state == "open" and old_result != new_result:
                changed_ports.append({
                    "ip": ip,
                    "before": old_result,
                    "after": new_result,
                })

    return {
        "previous_timestamp": previous.get("timestamp", "unknown"),
        "current_timestamp": current.get("timestamp", "unknown"),
        "scope_changed": None,
        "added_hosts": [new_hosts[ip] for ip in sorted(new_ips - old_ips)],
        "removed_hosts": [old_hosts[ip] for ip in sorted(old_ips - new_ips)],
        "changed_hosts": changed_hosts,
        "added_ports": added_ports,
        "removed_ports": removed_ports,
        "changed_ports": changed_ports,
        "state_changes": state_changes,
    }


def _normalize_scope(value: object) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value.strip()


def _open_port_map(host: dict) -> dict[tuple[str, int], dict]:
    return {
        key: value for key, value in _port_result_map(host).items()
        if value.get("state") == "open"
    }


def _port_result_map(host: dict) -> dict[tuple[str, int], dict]:
    result = {}
    for item in host.get("ports", []):
        try:
            port = int(item["port"])
        except (KeyError, TypeError, ValueError):
            continue
        protocol = item.get("protocol", "tcp")
        key = (protocol, port)
        result[key] = {
            "protocol": protocol,
            "port": port,
            "state": item.get("state", "unknown"),
            "service": item.get("service", ""),
            "service_source": item.get("service_source", ""),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
        }
    return result


def _scanned_port_set(host: dict) -> set[tuple[str, int]]:
    scanned = host.get("scanned_ports", {})
    result = set()
    if not isinstance(scanned, dict):
        return result
    for protocol, ports in scanned.items():
        if not isinstance(ports, list):
            continue
        for value in ports:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                result.add((protocol, port))
    return result
