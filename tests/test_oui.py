"""Pure unit tests — no network or subprocess."""

from __future__ import annotations

import pytest


# ------------------------- OUI lookup -------------------------

def test_oui_apple_known():
    from neonscan.oui import OUICache
    from pathlib import Path
    c = OUICache(cache_dir=Path("/tmp/_neonscan_test_oui"), offline=True)
    assert c.lookup("3C:22:FB:11:22:33") == "Apple, Inc."
    assert c.lookup("AC:84:C9:AA:BB:CC") == "TP-Link Technologies"
    assert "Unknown" in c.lookup("FF:FF:FF:11:22:33") or c.lookup("FF:FF:FF:11:22:33") == "Unknown"


def test_oui_normalize_dashed_and_dot():
    from neonscan.oui import OUICache
    from pathlib import Path
    c = OUICache(cache_dir=Path("/tmp/_neonscan_test_oui"), offline=True)
    assert c.lookup("3c-22-fb-11-22-33") == "Apple, Inc."  # mixed case + dash
    assert c.lookup("3c22fb112233") == "Apple, Inc."  # no separator


def test_oui_unknown_returns_unknown():
    from neonscan.oui import OUICache
    from pathlib import Path
    c = OUICache(cache_dir=Path("/tmp/_neonscan_test_oui"), offline=True)
    assert c.lookup("xx:xx:xx:11:22:33") == "Unknown"


# ------------------------- Ping output parser -------------------------

def test_ping_parse_clean():
    from neonscan.diagnostics.ping import parse_ping_output
    sample = """\
    PING 8.8.8.8 (8.8.8.8): 56 data bytes
    64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=23.4 ms
    64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=24.0 ms
    64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=23.9 ms

    --- 8.8.8.8 ping statistics ---
    4 packets transmitted, 4 packets received, 0.0% packet loss
    round-trip min/avg/max/stddev = 23.4/23.766/24.0/0.249 ms
    """
    s = parse_ping_output(sample)
    assert s["sent"] == 4
    assert s["received"] == 4
    assert s["loss_pct"] == 0.0
    assert 23 < s["avg_ms"] < 24
    assert s["jitter_ms"] >= 0


def test_ping_parse_loss_50():
    from neonscan.diagnostics.ping import parse_ping_output
    sample = """\
    64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=24.0 ms
    64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=24.0 ms

    --- 8.8.8.8 ping statistics ---
    4 packets transmitted, 2 packets received, 50.0% packet loss
    round-trip min/avg/max/stddev = 24.0/24.0/24.0/0.0 ms
    """
    s = parse_ping_output(sample)
    assert s["sent"] == 4
    assert s["received"] == 2
    assert abs(s["loss_pct"] - 50.0) < 0.1


# ------------------------- DNS encode / decode -------------------------

def test_dns_encode_decode_round_trip():
    from neonscan.diagnostics.dns import _encode_dns_query, _decode_dns_response
    q = _encode_dns_query("example.com")
    assert len(q) > 12
    # We don't have a real response here — verify encoder is plausible: header bytes 0..1 = ID, RD flag set.
    import struct
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", q[:12])
    assert qd == 1
    assert flags & 0x0100 == 0x0100


def test_dns_decode_handcrafted_response():
    """Build a hand-rolled DNS response for google.com with a single A answer.

    The response packets we use are byte-level correct (header + question + answer).
    """
    import socket, struct
    from neonscan.diagnostics.dns import _encode_dns_query, _decode_dns_response

    # ask resolver normally to build a query, then we'll pretend the response is something fake
    # — but easier: send a real query to a public resolver and decode the actual response.
    # We'll skip it if there's no live network and just verify parse on a tiny synthesized packet.
    qid = 0xDEAD
    flags = 0x8180  # QR=1, RD=1, RA=1, RCODE=NOERROR
    header = struct.pack(">HHHHHH", qid, flags, 1, 1, 0, 0)
    # question: google.com
    qb = b"\x06google\x03com\x00" + struct.pack(">HH", 1, 1)
    # answer: google.com.  60 IN A 142.251.41.110
    ab = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x8e\xfb\x29\x6e"
    buf = header + qb + ab
    parsed = _decode_dns_response(buf)
    assert parsed["ok"], parsed
    assert parsed["rcode"] == "NOERROR"
    assert "142.251.41.110" in parsed["answers"]


# ------------------------- DiagResult dataclass -------------------------

def test_diagresult_format():
    from neonscan.diagnostics.result import DiagResult, Severity
    r = DiagResult(title="t", summary="sum")
    r.add("ok", "yes", Severity.OK)
    r.add("warn", "uhh", Severity.WARN, note="see")
    assert len(r.findings) == 2
    assert r.ok
    d = r.to_dict()
    assert d["ok"] is True
    assert d["findings"][1]["severity"] == "warn"


def test_diagresult_error_short_circuits():
    from neonscan.diagnostics.result import DiagResult
    r = DiagResult(title="t")
    r.error = "boom"
    assert not r.ok
    assert r.to_dict()["error"] == "boom"


def test_diagresult_add_returns_self():
    from neonscan.diagnostics.result import DiagResult, Severity
    r = DiagResult(title="t")
    assert r.add("k", "v") is r


# ------------------------- Report writer -------------------------

def test_report_markdown_contains_sections():
    from neonscan.diagnostics.result import DiagResult, Severity
    r1 = DiagResult(title="x", summary="ok")
    r1.add("a", 1, Severity.OK)
    r2 = DiagResult(title="y")
    r2.error = "fail"
    md = __import__("neonscan.diagnostics.report", fromlist=["to_markdown"]).to_markdown([r1, r2])
    assert "# NeonScan report" in md
    assert "## x" in md
    assert "## y" in md
    assert "ERROR" in md


def test_report_json_valid():
    import json
    from neonscan.diagnostics.result import DiagResult
    r = DiagResult(title="x")
    r.add("k", "v")
    txt = __import__("neonscan.diagnostics.report", fromlist=["to_json"]).to_json([r])
    data = json.loads(txt)
    assert data["scanner"] == "neonscan"
    assert data["results"][0]["title"] == "x"


def test_report_write(tmp_path):
    from neonscan.diagnostics.result import DiagResult
    from neonscan.diagnostics.report import write_report
    r = DiagResult(title="a")
    md = tmp_path / "out.md"
    js = tmp_path / "out.json"
    write_report(md, [r])
    write_report(js, [r])
    assert md.read_text().startswith("# ")
    assert js.read_text().startswith('{')


# ------------------------- OUI prefix extractor -------------------------

def test_oui_prefix_extractor():
    from neonscan.oui import OUICache
    from pathlib import Path
    c = OUICache(cache_dir=Path("/tmp/_neonscan_test_oui2"), offline=True)
    assert c._oui_prefix("AA:BB:CC:DD:EE:FF") == "AABBCC"
    assert c._oui_prefix("aa-bb-cc-dd-ee-ff") == "AABBCC"
    assert c._oui_prefix("AABBCCDDEEFF") == "AABBCC"
    assert c._oui_prefix("") == ""
    assert c._oui_prefix("AA") == ""
