"""Regression tests for the v1.3.1 correctness fixes."""

import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from neonscan.diagnostics import mdns, public_ip, speed
from neonscan.diagnostics.dns import _encode_dns_query
from neonscan.diagnostics.result import DiagResult, Severity
from neonscan.diagnostics.watch import build_baseline, diff_against_baseline


# ---------------------------------------------------------------------------
# mDNS: PTR(12) vs SRV(33) — SRV must be parsed so port/host/ip are populated
# ---------------------------------------------------------------------------

def _enc_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _build_mdns_response() -> bytes:
    instance = "Apple TV._airplay._tcp.local."
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 4, 0, 0)  # 4 answers

    # PTR: service type -> instance
    ptr_rd = _enc_name(instance)
    ptr = _enc_name("_airplay._tcp.local.") + struct.pack(">HHIH", 12, 1, 120, len(ptr_rd)) + ptr_rd

    # SRV: instance -> priority/weight/port + target
    srv_rd = struct.pack(">HHH", 0, 0, 7000) + _enc_name("appletv.local.")
    srv = _enc_name(instance) + struct.pack(">HHIH", 33, 1, 120, len(srv_rd)) + srv_rd

    # TXT: instance metadata
    txt_val = b"model=AppleTV"
    txt_rd = bytes([len(txt_val)]) + txt_val
    txt = _enc_name(instance) + struct.pack(">HHIH", 16, 1, 120, len(txt_rd)) + txt_rd

    # A: hostname -> IPv4
    a_rd = bytes([10, 0, 0, 50])
    a = _enc_name("appletv.local.") + struct.pack(">HHIH", 1, 1, 120, 4) + a_rd

    return header + ptr + srv + txt + a


def test_mdns_parses_srv_port_and_a_record():
    entries = mdns._parse_response(_build_mdns_response())
    inst = [e for e in entries if "Apple TV" in e["instance"]]
    assert inst, "instance not parsed"
    e = inst[0]
    assert e["port"] == 7000            # was always 0 before the PTR/SRV fix
    assert e["host"].startswith("appletv")
    assert e["ip"] == "10.0.0.50"       # resolved via the SRV target's A record
    assert "_airplay._tcp.local." in e["service"]
    assert any("model=AppleTV" in t for t in e["txt"])


# ---------------------------------------------------------------------------
# iperf3: passing an explicit server must not raise UnboundLocalError
# ---------------------------------------------------------------------------

def test_iperf3_with_server_does_not_crash():
    # Whether or not iperf3 is installed, this must return a DiagResult and
    # never raise (previously: UnboundLocalError on server_proc).
    r = speed.measure_iperf3(server="127.0.0.1", duration_s=1)
    assert isinstance(r, DiagResult)


# ---------------------------------------------------------------------------
# public_ip: _reverse_dns must restore the process-wide default socket timeout
# ---------------------------------------------------------------------------

def test_reverse_dns_restores_default_timeout():
    prev = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(12.34)
        public_ip._reverse_dns("192.0.2.1")  # TEST-NET-1, no PTR
        assert socket.getdefaulttimeout() == 12.34
    finally:
        socket.setdefaulttimeout(prev)


# ---------------------------------------------------------------------------
# DNS: an IDN name must not raise on encode (punycode fallback)
# ---------------------------------------------------------------------------

def test_dns_encode_idn_name():
    pkt = _encode_dns_query("münchen.example")
    assert b"xn--" in pkt  # punycode label present


# ---------------------------------------------------------------------------
# watch: RSSI delta severity must not be inverted for small drops
# ---------------------------------------------------------------------------

def _wifi_results(rssi: int):
    r = DiagResult(title="Wi-Fi link")
    r.add("RSSI", f"{rssi} dBm", severity=Severity.OK)
    return [r]


def _rssi_delta_severity(base_rssi: int, now_rssi: int):
    base = build_baseline(_wifi_results(base_rssi))
    diff = diff_against_baseline(base, _wifi_results(now_rssi))
    f = next((x for x in diff.findings if x.label == "Δ RSSI"), None)
    assert f is not None, "no RSSI delta produced"
    return f.severity


def test_watch_rssi_small_drop_is_ok():
    # 2 dBm dip = within noise → OK (was FAIL before the fix)
    assert _rssi_delta_severity(-60, -62) == Severity.OK


def test_watch_rssi_medium_drop_is_warn():
    assert _rssi_delta_severity(-60, -70) == Severity.WARN


def test_watch_rssi_large_drop_is_fail():
    assert _rssi_delta_severity(-60, -80) == Severity.FAIL


def test_watch_rssi_improvement_is_ok():
    assert _rssi_delta_severity(-70, -60) == Severity.OK
