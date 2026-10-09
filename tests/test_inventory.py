"""Tests for opt-in local scan snapshots and conservative change detection."""

from neonscan.inventory import compare_inventories, make_inventory_snapshot
from neonscan.network import Host
from neonscan.scanner import PortResult


def test_inventory_snapshot_keeps_probe_coverage_and_port_evidence():
    host = Host(
        ip="192.0.2.10",
        mac="AA:BB:CC:DD:EE:FF",
        discovery_methods=["icmp", "tcp/443"],
        scanned_ports={"tcp": [80, 443]},
    )
    ports = [
        PortResult(
            443, True, service="https", protocol="tcp", state="open",
            reason="tcp-connect", service_source="nmap-probe",
            product="Example TLS service", version="2.1",
        ),
    ]

    snapshot = make_inventory_snapshot("192.0.2.0/24", [host], {host.ip: ports})

    assert snapshot["hosts"][0]["discovery_methods"] == ["icmp", "tcp/443"]
    assert snapshot["hosts"][0]["scanned_ports"] == {"tcp": [80, 443]}
    assert snapshot["hosts"][0]["ports"][0]["version"] == "2.1"


def test_inventory_compares_only_ports_scanned_in_both_snapshots():
    previous = {
        "subnet": "192.0.2.0/24",
        "hosts": [{
            "ip": "192.0.2.10",
            "scanned_ports": {"tcp": [22, 80]},
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
                {"port": 80, "protocol": "tcp", "state": "closed", "service": "http"},
            ],
        }],
    }
    current = {
        "subnet": "192.0.2.8/24",  # same network after CIDR normalization
        "hosts": [{
            "ip": "192.0.2.10",
            "scanned_ports": {"tcp": [22, 443]},
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "closed", "service": "ssh"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ],
        }],
    }

    diff = compare_inventories(current, previous)

    assert diff["scope_changed"] is None
    assert [(item["port"], item["ip"]) for item in diff["removed_ports"]] == [
        (22, "192.0.2.10")
    ]
    assert diff["added_ports"] == []  # port 443 was not probed in the previous run
    assert not diff["state_changes"]


def test_inventory_refuses_to_compare_different_subnets():
    current = {"subnet": "192.0.2.0/24", "hosts": [{"ip": "192.0.2.3"}]}
    previous = {"subnet": "198.51.100.0/24", "hosts": [{"ip": "198.51.100.4"}]}

    diff = compare_inventories(current, previous)

    assert diff["scope_changed"] == {
        "before": "198.51.100.0/24",
        "after": "192.0.2.0/24",
    }
    assert not diff["added_hosts"]
    assert not diff["removed_hosts"]
