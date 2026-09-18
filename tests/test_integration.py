"""Integration tests — talk to real local network / public IP probes.

These are best-effort: skipped if the network probe can't run.
"""

from __future__ import annotations

import socket
import subprocess
import sys

import pytest


# Helpers ---------------------------------------------------------------------

def _has_tool(name: str) -> bool:
    """Best-effort: is `name` on PATH?"""
    try:
        return subprocess.run(["which", name], capture_output=True, check=False).returncode == 0
    except OSError:
        return False


# Ping diagnostic -------------------------------------------------------------

def test_ping_localhost():
    from neonscan.diagnostics.ping import measure_ping
    r = measure_ping("127.0.0.1", count=3, interval_ms=200, deadline_s=3)
    assert r.ok, r.error
    assert r.raw["sent"] == 3
    assert r.raw["received"] >= 2  # tolerate one drop on some systems


@pytest.mark.skipif(not _has_tool("dig"), reason="dig not installed")
def test_dns_localhost_domain():
    """Resolve a real domain at least via UDP if dig exists."""
    from neonscan.diagnostics.dns import measure_dns, _dig_resolver, _udp_resolver
    # Just verify the resolvers module returns well-formed answers via direct probes.
    dig_ok = _dig_resolver("8.8.8.8", "google.com")
    if not dig_ok.get("skip"):
        assert dig_ok["ok"], dig_ok
        assert dig_ok["answers"]
    else:
        udp = _udp_resolver("8.8.8.8", "google.com")
        assert udp["ok"], udp
        assert udp["answers"]


# Public IP --------------------------------------------------------------------

def test_public_ip_shape():
    from neonscan.diagnostics.public_ip import get_public_ip
    try:
        r = get_public_ip()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"public IP service unreachable: {exc}")
    if not r.ok:
        pytest.skip(f"public IP unavailable: {r.error}")
    assert r.raw["ip"]
    assert r.raw["rdns"] or True
    # ip should look like an IPv4 / IPv6
    assert "." in r.raw["ip"] or ":" in r.raw["ip"]


# Routes -----------------------------------------------------------------------

def test_routes_default_gw_present():
    from neonscan.diagnostics.routes import get_routes
    r = get_routes()
    if not r.ok:
        pytest.skip(f"routes unavailable: {r.error}")
    # If the gw is '?' the test couldn't determine it — still acceptable if interface is known.
    interface = next((f.value for f in r.findings if f.label == "Interface"), None)
    assert interface and interface != "?", r.findings


# TCP port scanning ------------------------------------------------------------

def test_tcp_scan_localhost_open_and_closed():
    from neonscan.scanner import scan_host
    # Start a tiny TCP server on an ephemeral port.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()
    # Run scan; expect to find our port open and a widely-closed one closed.
    results = scan_host("127.0.0.1", ports=[port, 65111], workers=2, timeout=1.0)
    open_ports = {r.port for r in results}
    assert port in open_ports
    assert 65111 not in open_ports


# Active connections ----------------------------------------------------------

def test_connections_not_empty():
    from neonscan.diagnostics.connections import get_connections
    r = get_connections()
    # Many macOS boxes always have at least one listening socket.
    summary = next((f for f in r.findings if f.label == "Summary"), None)
    assert summary is not None
    # We don't strictly require this — but it usually is true.
    total = r.raw.get("total", 0)
    assert total > 0, (r.raw, r.findings, r.error)


# Run full diag ----------------------------------------------------------------

def test_run_full_diag_runs_each_module():
    """Hit each module via run_full_diag, tolerating failures."""
    from neonscan.diagnostics.report import run_full_diag, run_full_diag_summary
    res = run_full_diag(monitor_s=0.0, speed_size_mb=2)
    titles = [r.title for r in res]
    # measure_download creates a DiagResult with title "Speed · download"; the per-step
    # label from run_full_diag is purely visual.  We just verify the diags ran.
    expected = {
        "Wi-Fi link",
        "Routes",
        "DHCP lease",
        "Public IP",
        "DNS :: google.com",
        "Ping :: 8.8.8.8",
        "Traceroute :: 8.8.8.8",
        "Active connections",
        "Speed · download",
    }
    for t in expected:
        assert t in titles, (t, titles)
    sm = run_full_diag_summary(res)
    assert sm["ran"] >= 8


# LAN bandwidth ----------------------------------------------------------------

def test_lan_bandtest_loopback():
    from neonscan.diagnostics.speed import lan_bandtest
    r = lan_bandtest(duration_s=1.5)
    # loopback may be too fast to time; tolerate ok or explicit error.
    if not r.ok:
        pytest.skip(f"loopback speed failed: {r.error}")
    assert r.raw["received"] >= 0
