"""Deterministic tests for multi-type DNS record queries."""

import base64
import struct
import subprocess

import pytest

from neonscan.diagnostics import dns_records


def test_dns_records_parses_dig_answers_and_status(monkeypatch):
    monkeypatch.setattr(dns_records.shutil, "which", lambda _name: "/usr/bin/dig")
    calls = []

    def fake_run(command, **_kwargs):
        record_type = command[-1]
        calls.append((record_type, "@1.1.1.1" in command))
        output = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
        if record_type == "A":
            output += "example.com. 300 IN A 203.0.113.7\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(dns_records.subprocess, "run", fake_run)

    result = dns_records.query_dns_records(
        "example.com", ["A", "MX"], server="1.1.1.1", timeout=1.0
    )

    assert result.raw["records"] == [{
        "owner": "example.com", "ttl": 300, "type": "A", "data": "203.0.113.7",
    }]
    assert result.raw["queries"]["MX"]["rcode"] == "NOERROR"
    assert calls == [("A", True), ("MX", True)] or calls == [("MX", True), ("A", True)]


def test_wire_dns_decoder_reads_compressed_mx_target():
    query = dns_records._encode_dns_query("example.com", qtype=15)
    query_id = struct.unpack(">H", query[:2])[0]
    rdata = b"\x00\x0a\x04mail\xc0\x0c"
    answer = (
        b"\xc0\x0c"
        + struct.pack(">HHIH", 15, 1, 600, len(rdata))
        + rdata
    )
    response = struct.pack(">HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + query[12:] + answer

    parsed = dns_records._parse_wire_response(response, query_id)

    assert parsed["rcode"] == "NOERROR"
    assert parsed["records"] == [{
        "owner": "example.com",
        "ttl": 600,
        "type": "MX",
        "data": "10 mail.example.com",
    }]


def test_wire_dns_decoder_displays_null_mx_target():
    assert dns_records._decode_rdata(b"\x00\x00\x00\x00", 15, 0, 4) == "0 ."


def test_wire_dns_decoder_formats_rrsig_fields():
    raw = (
        struct.pack(">HBBIIIH", 1, 8, 2, 300, 1_800_000_000, 1_700_000_000, 1234)
        + b"\x07example\x03com\x00"
        + b"signature"
    )
    decoded = dns_records._decode_rdata(raw, 46, 0, len(raw))

    assert decoded.startswith("A 8 2 300 ")
    assert "1234 example.com " in decoded
    assert decoded.endswith(base64.b64encode(b"signature").decode("ascii"))


def test_dns_records_falls_back_to_stdlib_wire_query(monkeypatch):
    monkeypatch.setattr(dns_records.shutil, "which", lambda _name: None)
    calls = []

    def fake_wire(owner, record_type, code, server, timeout):
        calls.append((owner, record_type, code, server, timeout))
        return {
            "rcode": "NOERROR",
            "records": [{"owner": owner.rstrip("."), "ttl": 60,
                         "type": record_type, "data": "2001:db8::1"}],
            "error": "",
        }

    monkeypatch.setattr(dns_records, "_query_wire", fake_wire)

    result = dns_records.query_dns_records(
        "münich.example", ["AAAA"], server="192.0.2.53", timeout=0.5
    )

    assert calls == [("xn--mnich-kva.example.", "AAAA", 28, "192.0.2.53", 0.5)]
    assert result.raw["records"][0]["data"] == "2001:db8::1"


def test_dns_records_distinguishes_nxdomain_from_resolver_errors(monkeypatch):
    monkeypatch.setattr(dns_records.shutil, "which", lambda _name: "/usr/bin/dig")

    def fake_run(command, **_kwargs):
        status = "NXDOMAIN" if command[-1] == "A" else "REFUSED"
        output = f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    monkeypatch.setattr(dns_records.subprocess, "run", fake_run)
    result = dns_records.query_dns_records("missing.example", ["A", "AAAA"])

    assert "NXDOMAIN" in result.summary
    assert "AAAA: respuesta REFUSED" in result.summary
    assert not result.error
    assert result.raw["queries"]["AAAA"]["rcode"] == "REFUSED"


def test_dns_records_rejects_invalid_types_and_resolver_addresses():
    with pytest.raises(ValueError, match="Tipo DNS no reconocido"):
        dns_records.query_dns_records("example.com", ["NOT-A-RECORD"])
    with pytest.raises(ValueError, match="dirección IPv4 o IPv6"):
        dns_records.query_dns_records("example.com", ["A"], server="resolver.example")


def test_scoped_ipv6_resolver_preserves_interface():
    assert dns_records._normalize_server("fe80::1%en0") == "fe80::1%en0"
    with pytest.raises(ValueError, match="solo se admite en IPv6"):
        dns_records._normalize_server("192.0.2.53%en0")
