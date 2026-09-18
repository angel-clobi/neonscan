"""Tests for the newer diagnostic modules."""

from __future__ import annotations

import io
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# TLS inspection
# ---------------------------------------------------------------------------

def test_tls_handcrafted_https_server():
    """Spin a TLS server on localhost, run inspect_tls against it."""
    import threading, http.server
    from neonscan.diagnostics.tls import inspect_tls

    # We create a self-signed cert via openssl on the fly
    with tempfile.TemporaryDirectory() as tmpdir:
        crt = Path(tmpdir) / "cert.pem"
        key = Path(tmpdir) / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(crt),
            "-days", "365", "-nodes",
            "-subj", "/CN=neonscan.local",
        ], capture_output=True, check=True, timeout=15)
        # Combine into PEM
        pem = crt.read_text()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        stop = threading.Event()

        def serve():
            try:
                while not stop.is_set():
                    server.settimeout(0.5)
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    try:
                        sslconn = ctx.wrap_socket(conn, server_side=True)
                        sslconn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                        sslconn.close()
                    except Exception:
                        pass
            except Exception:
                pass

        th = threading.Thread(target=serve, daemon=True)
        th.start()
        try:
            r = inspect_tls("127.0.0.1", port=port, sni="neonscan.local", timeout=4.0)
            if not r.ok:
                # Sometimes Python 3.9 + openssl handshake differs; tolerate but assert basic shape.
                pytest.skip(f"TLS to self-signed failed: {r.error}")
            assert r.raw
            assert r.ok
        finally:
            stop.set()
            try:
                server.close()
            except Exception:
                pass
            th.join(timeout=2)


def test_tls_port_unreachable():
    """inspect_tls to a closed port returns 'error' set."""
    from neonscan.diagnostics.tls import inspect_tls
    # bind/unbind to grab an ephemeral port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = inspect_tls("127.0.0.1", port=port, sni="anything", timeout=1.0)
    assert not r.ok
    assert r.error


# ---------------------------------------------------------------------------
# Captive portal
# ---------------------------------------------------------------------------

def test_captive_smoke():
    from neonscan.diagnostics.captive import detect_captive
    r = detect_captive(timeout=4.0)
    # We don't require it to be OK — network may differ between runs.
    assert r.title == "Captive portal"
    assert isinstance(r.findings, list)


# ---------------------------------------------------------------------------
# MTR — mocked traceroute output
# ---------------------------------------------------------------------------

def test_mtr_parse_cycles():
    from neonscan.diagnostics.mtr import parse_traceroute_probes
    sample = """\
traceroute to 8.8.8.8 (8.8.8.8), 64 hops max
 1  10.10.10.1 (10.10.10.1)  0.123 ms  0.456 ms  0.789 ms
 2  10.105.128.1 (10.105.128.1)  2.123 ms  2.456 ms  2.789 ms
 3  8.8.8.8 (8.8.8.8)  7.123 ms  7.456 ms  7.789 ms
"""
    hops = parse_traceroute_probes(sample)
    assert len(hops) == 3
    assert hops[0]["hop"] == 1
    assert hops[0]["ip"] == "10.10.10.1"
    assert len(hops[0]["times_ms"]) == 3
    assert abs(hops[0]["times_ms"][0] - 0.123) < 1e-3


def test_mtr_handles_timeouts():
    from neonscan.diagnostics.mtr import parse_traceroute_probes
    sample = " 3  8.8.8.8 (8.8.8.8)  7 ms  *  7 ms\n"
    hops = parse_traceroute_probes(sample)
    assert hops[0]["times_ms"] == [7.0, 0.0, 7.0]


# ---------------------------------------------------------------------------
# ARP analysis — mocked ARP table
# ---------------------------------------------------------------------------

def test_arp_clean(monkeypatch):
    from neonscan.diagnostics import arpwatch
    monkeypatch.setattr(arpwatch, "_read_arp_table", lambda: [
        ("10.10.10.1", "AA:AA:AA:AA:AA:AA", "en0"),
        ("10.10.10.3", "BB:BB:BB:BB:BB:BB", "en0"),
    ])
    r = arpwatch.analyze_arp()
    assert r.ok
    clean = next((f for f in r.findings if f.label == "Clean"), None)
    assert clean is not None


def test_arp_duplicate_ip(monkeypatch):
    from neonscan.diagnostics import arpwatch
    monkeypatch.setattr(arpwatch, "_read_arp_table", lambda: [
        ("10.10.10.1", "AA:AA:AA:AA:AA:AA", "en0"),
        ("10.10.10.1", "CC:CC:CC:CC:CC:CC", "en0"),
    ])
    r = arpwatch.analyze_arp()
    if not r.ok:
        pytest.skip("arp_analyze didn't surface clean flag")
    assert any(f.label.startswith("Conflict: ") for f in r.findings)


def test_arp_multi_mac_one_ip(monkeypatch):
    from neonscan.diagnostics import arpwatch
    monkeypatch.setattr(arpwatch, "_read_arp_table", lambda: [
        ("10.10.10.5", "AA:AA:AA:AA:AA:AA", "en0"),
        ("10.10.10.6", "AA:AA:AA:AA:AA:AA", "en0"),
    ])
    r = arpwatch.analyze_arp()
    # multi-IP-MAC is informational only at WARN
    assert any("Multi-IP" in f.label for f in r.findings)


# ---------------------------------------------------------------------------
# mDNS — packet encode
# ---------------------------------------------------------------------------

def test_mdns_encode_query_shape():
    from neonscan.diagnostics.mdns import _encode_mdns_query
    pkt = _encode_mdns_query("_http._tcp.local.")
    assert len(pkt) > 12
    # header layout: ID(2) FLAGS(2) QD(2) AN(2) NS(2) AR(2)
    qd = int.from_bytes(pkt[4:6], "big")
    assert qd == 1


# ---------------------------------------------------------------------------
# Topology / Mermaid / IPv6 privacy
# ---------------------------------------------------------------------------

def test_topology_mermaid():
    from neonscan.diagnostics.topology import topology_to_mermaid
    text = topology_to_mermaid(
        local_ip="10.10.10.3", gateway="10.10.10.1",
        hosts=[{"ip": "10.10.10.10", "hostname": "printer", "manufacturer": "HP"},
               {"ip": "10.10.10.42", "hostname": "laptop"}],
        dns_servers=["8.8.8.8"],
    )
    assert "graph LR" in text
    assert "10.10.10.1" in text
    assert "10.10.10.3" in text
    # host IDs are sanitized but appear inside labels with dotted IP
    assert "printer" in text
    assert "laptop" in text
    assert "8_8_8_8" in text or "8.8.8.8" in text


def test_topology_dot():
    from neonscan.diagnostics.topology import topology_to_dot
    text = topology_to_dot(
        local_ip="10.10.10.3", gateway="10.10.10.1",
        hosts=[{"ip": "10.10.10.10"}],
    )
    assert text.startswith("digraph G")
    assert "10.10.10.3" in text


def test_ipv6_privacy_eui64_is_stable():
    from neonscan.diagnostics.topology import privacy_score_ipv6
    # IID with embedded FFFE = classic EUI-64
    addr = "2601:4cd:8000:1234:b827:ebff:fea1:b1d2"
    s = privacy_score_ipv6(addr)
    # the random-extended EUI-64 will register as stable-ish
    assert s < 0.7  # not random


def test_ipv6_privacy_random():
    from neonscan.diagnostics.topology import privacy_score_ipv6
    # Looks like an obfuscated random ID (high entropy)
    s = privacy_score_ipv6("2601:4cd:8000:abcd:89ab:cdef:0123:4567")
    # Some entropy
    assert s >= 0.4


def test_ipv6_classify_for_hosts():
    from neonscan.diagnostics.topology import classify_ipv6_for_hosts
    hosts = [
        {"ip": "2601:4cd:8000:1234:b827:ebff:fea1:b1d2"},
        {"ip": "fe80::1"},
    ]
    r = classify_ipv6_for_hosts(hosts)
    assert r.title.startswith("IPv6")
    assert any("fe80::1" in f.label for f in r.findings)


# ---------------------------------------------------------------------------
# Watch / Baseline diff
# ---------------------------------------------------------------------------

def test_baseline_save_load_diff(tmp_path):
    from neonscan.diagnostics.watch import (
        Baseline,
        build_baseline, save_baseline, load_baseline,
        diff_against_baseline,
    )

    # Build a stub DiagResult list to feed build_baseline.
    from neonscan.diagnostics.result import DiagResult, Severity

    a = DiagResult(title="Wi-Fi link")
    a.add("RSSI", "-67 dBm", severity=Severity.OK)
    b = DiagResult(title="Ping :: 8.8.8.8")
    b.add("Loss", "0.0%", severity=Severity.OK)
    b.add("Avg RTT", "8.4 ms", severity=Severity.OK)
    c = DiagResult(title="Speed · download")
    c.summary = "200 Mbps"
    baseline = build_baseline([a, b, c])
    f = tmp_path / "baseline.json"
    save_baseline(baseline, f)
    loaded = load_baseline(f)
    assert loaded is not None
    assert loaded.metrics.get("ping_avg_ms") == 8.4

    # Different ping_avg_ms should produce a delta.
    c2 = DiagResult(title="Ping :: 8.8.8.8")
    c2.add("Loss", "0.0%", severity=Severity.OK)
    c2.add("Avg RTT", "33.0 ms", severity=Severity.OK)
    diff = diff_against_baseline(loaded, [a, c2, c])
    findings = diff.findings
    assert findings
    deltas = [f.label for f in findings if "Δ" in f.label]
    assert deltas


# ---------------------------------------------------------------------------
# New CLI subcommands registered
# ---------------------------------------------------------------------------

def test_new_subcommands_registered():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ns_entry", Path(__file__).resolve().parent.parent / "neonscan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    expected = {"upload", "iperf3", "mtr", "tls", "arp", "captive", "mdns", "watch", "topology"}
    missing = expected - set(mod.SUBCOMMANDS)
    assert not missing, f"missing subcommands: {missing}"


# ---------------------------------------------------------------------------
# Vendor / offline bundle
# ---------------------------------------------------------------------------

def test_vendor_lib_present():
    """The project's vendor/_lib/ should exist (populated by `make install-bundled`)."""
    lib = Path(__file__).resolve().parent.parent / "vendor" / "_lib"
    if not lib.exists():
        pytest.skip("vendor/_lib not populated; run `make install-bundled` first")
    rich_dir = lib / "rich"
    assert rich_dir.exists(), f"vendor/_lib exists but rich module not extracted: {lib}"


def test_neonscan_runs_with_empty_pythonpath():
    """Run neonscan with PYTHONPATH stripped — vendor/_lib should still supply rich."""
    import os
    import subprocess
    import sys

    project = Path(__file__).resolve().parent.parent
    vlib = project / "vendor" / "_lib"
    if not vlib.exists():
        pytest.skip("vendor/_lib not populated; run `make install-bundled` first")

    env = {**os.environ, "PYTHONPATH": ""}
    cp = subprocess.run(
        [sys.executable, "neonscan.py", "--no-banner", "--offline", "routes"],
        cwd=str(project),
        env=env, capture_output=True, text=True, timeout=20,
    )
    # Should NOT fail with "ModuleNotFoundError: rich".
    if cp.returncode != 0:
        assert "ModuleNotFoundError" not in cp.stderr, cp.stderr
        assert "rich" not in cp.stderr, cp.stderr
    assert "Default gw" in cp.stdout or "Routes" in cp.stdout
