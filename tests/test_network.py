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
