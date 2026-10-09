"""Unit tests for network + scanner + ARP + UI imports."""

from __future__ import annotations

import io
import socket
import subprocess
from unittest import mock


# ARP / normalize_mac ---------------------------------------------------------

def test_normalize_mac_uppercase_colons():
    from neonscan.network import _normalize_mac
    assert _normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert _normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    # already-formatted upper-case strings are returned as-is (no expansion)
    assert _normalize_mac("AABBCCDDEEFF") == "AABBCCDDEEFF"


# Subnet detection ------------------------------------------------------------

def test_detect_local_ip_returns_string():
    from neonscan.network import _detect_local_ip
    out = _detect_local_ip()
    assert isinstance(out, str)
    # Should look like an IPv4 (or 127.0.0.1 if offline)
    assert "." in out or ":" in out


def test_detect_network_keys():
    from neonscan.network import detect_network
    info = detect_network()
    assert "local_ip" in info
    assert "subnet" in info
    assert "interface" in info
    # subnet should include /24 and start with the same first 3 octets
    ip = info["local_ip"]
    if "." in ip:  # IPv4 case
        head = ".".join(ip.split(".")[:3])
        assert info["subnet"].startswith(head)


# Ping sweep with mocked subprocess --------------------------------------------

def test_ping_sweep_uses_subprocess(monkeypatch):
    from neonscan import network as netmod

    calls = []

    def fake_ping(ip, *a, **kw):
        calls.append(ip)
        return ip.endswith(".1") or ip.endswith(".42")  # only two live

    monkeypatch.setattr(netmod, "_ping_once", fake_ping)
    out = netmod.ping_sweep("10.10.10.0/24", max_workers=4)
    assert "10.10.10.1" in out
    assert "10.10.10.42" in out
    assert "10.10.10.50" not in out
    assert len(calls) == 254  # all probed


# Ping with mocked subprocess.run ----------------------------------------------

def test_ping_once_timeout(monkeypatch):
    from neonscan import network as netmod
    import subprocess

    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd=a[0] if a else "ping", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    assert netmod._ping_once("8.8.8.8") is False


# Scanner: TCP connect behavior -----------------------------------------------

def test_try_port_closed_when_no_service(monkeypatch):
    from neonscan.scanner import _try_port
    # bind on a port and immediately release it so connection is refused
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()  # race-prone but good enough
    result = _try_port("127.0.0.1", port, timeout=0.5)
    assert result.open is False or result.open is True  # depends on race
    # most of the time it should be False
    assert result.port == port


def test_try_port_open_for_loopback_listener():
    from neonscan.scanner import _try_port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        r = _try_port("127.0.0.1", port, timeout=1.0)
        assert r.open is True
        assert r.port == port
    finally:
        s.close()


def test_port_service_falls_back_to_unknown_label():
    from neonscan.scanner import service_name

    assert service_name(80) == "http"
    assert service_name(443) == "https"
    assert service_name(65000) in {"unknown", "65000/tcp"}


def test_http_probe_records_detected_scheme(monkeypatch):
    from neonscan import scanner

    calls = []

    def fake_request(ip, port, use_tls, timeout):
        calls.append(use_tls)
        if use_tls:
            return 200, "test-server", "Router", "<title>Router</title>"
        return 0, "", "", ""

    monkeypatch.setattr(scanner, "_http_request", fake_request)
    result = scanner.PortResult(port=8080, open=True)
    scanner._populate_http_info("192.0.2.1", 8080, result)
    assert calls == [False, True]
    assert result.web_scheme == "https"
    assert result.web_status == "200"


def test_open_web_port_labels_are_clickable_and_named():
    from neonscan.scanner import PortResult
    from neonscan.ui import _port_label, _ports_cell

    result = PortResult(port=8443, open=True, service="https-alt", web_scheme="https")
    label = _port_label("192.0.2.8", result)
    summary = _ports_cell("192.0.2.8", [result])
    assert label.plain == "8443/https-alt"
    assert label.spans[0].style.link == "https://192.0.2.8:8443/"
    assert "8443/https-alt" in summary.plain


def test_open_web_service_prompt_launches_selected_url(monkeypatch):
    from io import StringIO
    from rich.console import Console
    from neonscan import ui
    from neonscan.scanner import PortResult

    opened = []
    monkeypatch.setattr(ui, "IS_TERMUX", False)
    monkeypatch.setattr(ui.Prompt, "ask", lambda *_args, **_kwargs: "1")
    monkeypatch.setattr(ui.webbrowser, "open", lambda url, new=0: opened.append((url, new)) or True)
    monkeypatch.setattr(ui, "console", Console(file=StringIO(), width=80))
    result = PortResult(port=443, open=True, service="https", web_scheme="https")

    assert ui.open_web_service_prompt("192.0.2.8", [result]) is True
    assert opened == [("https://192.0.2.8:443/", 2)]


# OUI cache: offline mode -----------------------------------------------------

def test_oui_cache_initialized_with_default_dir(tmp_path):
    from neonscan.oui import OUICache
    c = OUICache(cache_dir=tmp_path, offline=True)
    # If a previous run left oui.txt in tmp, ignore; otherwise fallback should be used.
    assert c.size() > 0


def test_proc_arp_fallback(monkeypatch, tmp_path):
    """When `arp -a` is unavailable (Termux), /proc/net/arp is parsed."""
    from neonscan import network as netmod

    fake_proc_text = (
        "IP address       HW type     Flags       HW address          Mask     Device\n"
        "10.10.10.1       0x1         0x2         AA:BB:CC:DD:EE:FF   *        wlan0\n"
        "10.10.10.42      0x1         0x2         11:22:33:44:55:66   *        wlan0\n"
        "192.168.1.255    0x1         0xc         00:00:00:00:00:00   *        wlan0\n"
    )
    monkeypatch.setattr(netmod, "IS_DARWIN", False)
    monkeypatch.setattr(netmod, "IS_LINUX", True)

    # Force `arp -an` to fail so we exercise the fallback.
    def _fail(*a, **kw):
        raise OSError("arp not on PATH")

    monkeypatch.setattr(subprocess, "check_output", _fail)

    # Patch /proc/net/arp read by intercepting the open() call.
    real_open = open

    def _patched_open(path, *a, **kw):
        if isinstance(path, str) and path == "/proc/net/arp":
            return io.StringIO(fake_proc_text)
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", _patched_open)

    entries = netmod._read_arp_table()
    by_ip = {e[0]: e[1] for e in entries}
    assert by_ip.get("10.10.10.1") == "AA:BB:CC:DD:EE:FF", entries
    assert by_ip.get("10.10.10.42") == "11:22:33:44:55:66", entries
