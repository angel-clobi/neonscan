"""Query common DNS RR types for one owner name, with dig and stdlib paths."""

from __future__ import annotations

import base64
import ipaddress
import math
import re
import shutil
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional, Sequence

from .dns import DEFAULT_RESOLVERS, _encode_dns_query, _find_resolvers
from .result import DiagResult, Severity


RECORD_TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "NAPTR": 35,
    "DS": 43,
    "SSHFP": 44,
    "RRSIG": 46,
    "DNSKEY": 48,
    "TLSA": 52,
    "SVCB": 64,
    "HTTPS": 65,
    "CAA": 257,
    "ANY": 255,
}
DEFAULT_RECORD_TYPES = (
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV",
    "PTR", "NAPTR", "DS", "DNSKEY", "RRSIG", "SSHFP", "TLSA", "HTTPS", "SVCB",
)
_RECORD_TYPE_NAMES = {code: name for name, code in RECORD_TYPE_CODES.items()}
_RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}
_DIG_STATUS = re.compile(r"status:\s*([A-Z0-9]+)", re.IGNORECASE)


def _normalize_owner_name(name: str) -> str:
    value = str(name).strip().rstrip(".")
    if not value:
        raise ValueError("Escribe un dominio DNS")
    try:
        labels = [label.encode("idna").decode("ascii") for label in value.split(".")]
    except UnicodeError as exc:
        raise ValueError(f"Dominio inválido: {name}") from exc
    if (
        len(".".join(labels)) > 253
        or any(not label or len(label) > 63 or not re.fullmatch(r"[A-Za-z0-9_-]+", label)
               for label in labels)
    ):
        raise ValueError(f"Dominio DNS inválido: {name}")
    return ".".join(labels) + "."


def _normalize_server(server: str) -> str:
    """Validate a resolver IP while preserving an IPv6 interface scope ID."""
    value = str(server).strip()
    address, separator, scope = value.partition("%")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("El servidor DNS debe ser una dirección IPv4 o IPv6") from exc
    if separator and (parsed.version != 6 or not scope or "%" in scope):
        raise ValueError("El ámbito de una dirección DNS solo se admite en IPv6")
    return str(parsed) + (f"%{scope}" if separator else "")


def _normalize_record_types(record_types: Optional[Sequence[str]]) -> list[tuple[str, int]]:
    if isinstance(record_types, str):
        values = record_types.split(",")
    else:
        values = list(record_types or DEFAULT_RECORD_TYPES)
    if not values:
        raise ValueError("Selecciona al menos un tipo de registro DNS")
    normalized: list[tuple[str, int]] = []
    seen: set[str] = set()
    for raw in values:
        name = str(raw).strip().upper()
        if name in RECORD_TYPE_CODES:
            code = RECORD_TYPE_CODES[name]
        elif re.fullmatch(r"TYPE\d{1,5}", name):
            code = int(name[4:])
            if not 1 <= code <= 65535:
                raise ValueError(f"Tipo DNS fuera de rango: {name}")
        else:
            raise ValueError(f"Tipo DNS no reconocido: {raw}")
        if name not in seen:
            seen.add(name)
            normalized.append((name, code))
    return normalized


def _parse_dig_output(output: str) -> tuple[str, list[dict]]:
    match = _DIG_STATUS.search(output)
    rcode = match.group(1).upper() if match else "UNKNOWN"
    records = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) != 5 or not parts[1].isdigit() or parts[2].upper() != "IN":
            continue
        owner, ttl, _class, record_type, data = parts
        records.append({
            "owner": owner.rstrip("."),
            "ttl": int(ttl),
            "type": record_type.upper(),
            "data": data.strip(),
        })
    return rcode, records


def _query_with_dig(
    owner: str, record_type: str, server: Optional[str], timeout: float
) -> dict:
    command = [
        "dig", "+time=" + str(max(1, math.ceil(timeout))), "+tries=1",
        "+noall", "+comments", "+answer", owner, record_type,
    ]
    if server:
        command.insert(1, "@" + server)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout + 1, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"rcode": "TIMEOUT", "records": [], "error": "timeout"}
    except OSError as exc:
        return {"rcode": "ERROR", "records": [], "error": str(exc)}
    rcode, records = _parse_dig_output(completed.stdout)
    if rcode == "UNKNOWN" and completed.returncode:
        return {
            "rcode": "ERROR", "records": [],
            "error": completed.stderr.strip() or "dig failed",
        }
    return {"rcode": rcode, "records": records, "error": ""}


def _read_wire_name(packet: bytes, position: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = position
    consumed = None
    pointers: set[int] = set()
    for _ in range(128):
        if cursor >= len(packet):
            raise ValueError("DNS name exceeds packet")
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet) or pointer in pointers:
                raise ValueError("Invalid DNS compression pointer")
            pointers.add(pointer)
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise ValueError("Invalid DNS label type")
        cursor += 1
        if length == 0:
            if consumed is None:
                consumed = cursor
            return (".".join(labels) + "." if labels else "."), consumed
        if cursor + length > len(packet):
            raise ValueError("Truncated DNS label")
        labels.append(packet[cursor:cursor + length].decode("ascii", errors="replace"))
        cursor += length
    raise ValueError("DNS compression pointer loop")


def _quoted_txt(raw: bytes) -> str:
    value = raw.decode("utf-8", errors="replace")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _display_dns_name(name: str) -> str:
    return name.rstrip(".") or "."


def _decode_rdata(packet: bytes, record_type: int, start: int, end: int) -> str:
    raw = packet[start:end]
    try:
        if record_type == 1 and len(raw) == 4:
            return str(ipaddress.IPv4Address(raw))
        if record_type == 28 and len(raw) == 16:
            return str(ipaddress.IPv6Address(raw))
        if record_type in (2, 5, 12, 39):
            return _display_dns_name(_read_wire_name(packet, start)[0])
        if record_type == 15 and len(raw) >= 3:
            exchange, _ = _read_wire_name(packet, start + 2)
            return f"{int.from_bytes(raw[:2], 'big')} {_display_dns_name(exchange)}"
        if record_type in (16, 99):
            strings = []
            cursor = start
            while cursor < end:
                length = packet[cursor]
                cursor += 1
                if cursor + length > end:
                    raise ValueError("Truncated TXT string")
                strings.append(_quoted_txt(packet[cursor:cursor + length]))
                cursor += length
            return " ".join(strings)
        if record_type == 6:
            mname, cursor = _read_wire_name(packet, start)
            rname, cursor = _read_wire_name(packet, cursor)
            if cursor + 20 > end:
                raise ValueError("Truncated SOA record")
            values = struct.unpack(">IIIII", packet[cursor:cursor + 20])
            return f"{_display_dns_name(mname)} {_display_dns_name(rname)} " + " ".join(map(str, values))
        if record_type == 33 and len(raw) >= 7:
            priority, weight, port = struct.unpack(">HHH", raw[:6])
            target, _ = _read_wire_name(packet, start + 6)
            return f"{priority} {weight} {port} {_display_dns_name(target)}"
        if record_type == 257 and len(raw) >= 2:
            flags, tag_length = raw[0], raw[1]
            if 2 + tag_length > len(raw):
                raise ValueError("Truncated CAA record")
            tag = raw[2:2 + tag_length].decode("ascii", errors="replace")
            value = _quoted_txt(raw[2 + tag_length:])
            return f"{flags} {tag} {value}"
        if record_type == 43 and len(raw) >= 4:
            return f"{int.from_bytes(raw[:2], 'big')} {raw[2]} {raw[3]} {raw[4:].hex().upper()}"
        if record_type == 44 and len(raw) >= 2:
            return f"{raw[0]} {raw[1]} {raw[2:].hex().upper()}"
        if record_type == 48 and len(raw) >= 4:
            key = base64.b64encode(raw[4:]).decode("ascii")
            flags, protocol, algorithm = struct.unpack(">HBB", raw[:4])
            return f"{flags} {protocol} {algorithm} {key}"
        if record_type == 46 and len(raw) >= 19:
            covered = int.from_bytes(raw[:2], "big")
            algorithm, labels = raw[2], raw[3]
            original_ttl = int.from_bytes(raw[4:8], "big")
            expiration = datetime.fromtimestamp(
                int.from_bytes(raw[8:12], "big"), timezone.utc
            ).strftime("%Y%m%d%H%M%S")
            inception = datetime.fromtimestamp(
                int.from_bytes(raw[12:16], "big"), timezone.utc
            ).strftime("%Y%m%d%H%M%S")
            key_tag = int.from_bytes(raw[16:18], "big")
            signer, cursor = _read_wire_name(packet, start + 18)
            signature = base64.b64encode(packet[cursor:end]).decode("ascii")
            covered_name = _RECORD_TYPE_NAMES.get(covered, f"TYPE{covered}")
            return (
                f"{covered_name} {algorithm} {labels} {original_ttl} {expiration} "
                f"{inception} {key_tag} {_display_dns_name(signer)} {signature}"
            )
        if record_type == 52 and len(raw) >= 3:
            return f"{raw[0]} {raw[1]} {raw[2]} {raw[3:].hex().upper()}"
        if record_type == 35 and len(raw) >= 7:
            order, preference = struct.unpack(">HH", raw[:4])
            cursor = start + 4
            fields = []
            for _ in range(3):
                length = packet[cursor]
                cursor += 1
                if cursor + length > end:
                    raise ValueError("Truncated NAPTR character string")
                fields.append(_quoted_txt(packet[cursor:cursor + length]))
                cursor += length
            replacement, _ = _read_wire_name(packet, cursor)
            return f"{order} {preference} " + " ".join(fields) + f" {_display_dns_name(replacement)}"
        if record_type in (64, 65) and len(raw) >= 3:
            priority = int.from_bytes(raw[:2], "big")
            target, cursor = _read_wire_name(packet, start + 2)
            params = []
            while cursor + 4 <= end:
                key, length = struct.unpack(">HH", packet[cursor:cursor + 4])
                cursor += 4
                if cursor + length > end:
                    raise ValueError("Truncated SVCB parameter")
                params.append(f"key{key}={packet[cursor:cursor + length].hex().upper()}")
                cursor += length
            return f"{priority} {_display_dns_name(target)}" + (" " + " ".join(params) if params else "")
    except (IndexError, OverflowError, struct.error, ValueError):
        pass
    return f"\\# {len(raw)} {raw.hex().upper()}"


def _parse_wire_response(packet: bytes, expected_id: int) -> dict:
    if len(packet) < 12:
        raise ValueError("Respuesta DNS demasiado corta")
    transaction_id, flags, question_count, answer_count, authority_count, additional_count = struct.unpack(
        ">HHHHHH", packet[:12]
    )
    if transaction_id != expected_id:
        raise ValueError("El ID de respuesta DNS no coincide")
    position = 12
    for _ in range(question_count):
        _question, position = _read_wire_name(packet, position)
        position += 4
        if position > len(packet):
            raise ValueError("Pregunta DNS truncada")
    records = []
    counts = (answer_count, authority_count, additional_count)
    for section, count in zip(("answer", "authority", "additional"), counts):
        for _ in range(count):
            owner, position = _read_wire_name(packet, position)
            if position + 10 > len(packet):
                raise ValueError("Registro DNS truncado")
            record_type, record_class, ttl, length = struct.unpack(
                ">HHIH", packet[position:position + 10]
            )
            position += 10
            end = position + length
            if end > len(packet):
                raise ValueError("Datos DNS truncados")
            if section == "answer" and record_class == 1:
                records.append({
                    "owner": owner.rstrip("."),
                    "ttl": ttl,
                    "type": _RECORD_TYPE_NAMES.get(record_type, f"TYPE{record_type}"),
                    "data": _decode_rdata(packet, record_type, position, end),
                })
            position = end
    return {
        "rcode": _RCODE_NAMES.get(flags & 0xF, f"RCODE{flags & 0xF}"),
        "truncated": bool(flags & 0x0200),
        "records": records,
    }


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise OSError("DNS/TCP peer closed the connection")
        data.extend(chunk)
    return bytes(data)


def _query_wire(owner: str, record_type: str, code: int, server: str, timeout: float) -> dict:
    packet = _encode_dns_query(owner, qtype=code)
    query_id = struct.unpack(">H", packet[:2])[0]
    address, separator, scope = server.partition("%")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        if family == socket.AF_INET6:
            scope_id = (int(scope) if scope.isdigit() else socket.if_nametoindex(scope)) if separator else 0
            destination = (address, 53, 0, scope_id)
        else:
            destination = (address, 53)
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, destination)
            response, _ = sock.recvfrom(65535)
        parsed = _parse_wire_response(response, query_id)
        if parsed["truncated"]:
            with socket.create_connection(destination, timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(struct.pack(">H", len(packet)) + packet)
                response_length = struct.unpack(">H", _recv_exact(sock, 2))[0]
                parsed = _parse_wire_response(_recv_exact(sock, response_length), query_id)
        return {**parsed, "error": ""}
    except (OSError, socket.timeout, ValueError) as exc:
        return {"rcode": "ERROR", "records": [], "error": str(exc)}


def query_dns_records(
    name: str,
    record_types: Optional[Sequence[str]] = None,
    server: Optional[str] = None,
    timeout: float = 2.0,
) -> DiagResult:
    """Query a curated set of RR types for one DNS name, without zone walking.

    `dig` is used when available; otherwise DNS queries are sent using the
    standard library to the selected or configured recursive resolver.
    """
    owner = _normalize_owner_name(name)
    query_types = _normalize_record_types(record_types)
    if timeout <= 0 or timeout > 30:
        raise ValueError("El timeout debe estar entre 0 y 30 segundos")
    if server:
        server = _normalize_server(server)

    use_dig = bool(shutil.which("dig"))
    if not use_dig and not server:
        resolvers = _find_resolvers()
        server = resolvers[0][0] if resolvers else DEFAULT_RESOLVERS[0][0]
        try:
            server = _normalize_server(server)
        except ValueError:
            server = DEFAULT_RESOLVERS[0][0]

    results: dict[str, dict] = {}
    max_workers = min(6, len(query_types))
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {}
        for record_type, code in query_types:
            if use_dig:
                future = pool.submit(_query_with_dig, owner, record_type, server, timeout)
            else:
                future = pool.submit(_query_wire, owner, record_type, code, server, timeout)
            futures[future] = record_type
        for future in as_completed(futures):
            results[futures[future]] = future.result()

    records = []
    seen_records = set()
    for record_type, _code in query_types:
        for record in results.get(record_type, {}).get("records", []):
            key = (record["owner"].lower(), record["type"], record["data"], record["ttl"])
            if key not in seen_records:
                seen_records.add(key)
                records.append(record)

    failed = []
    for record_type, data in results.items():
        rcode = data.get("rcode", "UNKNOWN")
        if data.get("error"):
            failed.append(f"{record_type}: {data['error']}")
        elif rcode not in ("NOERROR", "NXDOMAIN"):
            failed.append(f"{record_type}: respuesta {rcode}")
    no_answer = [
        record_type for record_type, _code in query_types
        if not results.get(record_type, {}).get("records")
        and not results.get(record_type, {}).get("error")
        and results.get(record_type, {}).get("rcode") == "NOERROR"
    ]
    nonexistent = [
        record_type for record_type, _code in query_types
        if not results.get(record_type, {}).get("records")
        and results.get(record_type, {}).get("rcode") == "NXDOMAIN"
    ]
    display_owner = owner.rstrip(".")
    summary = f"{len(records)} registros encontrados en {display_owner} consultando {len(query_types)} tipos"
    if no_answer:
        summary += "; sin respuesta: " + ", ".join(no_answer)
    if nonexistent:
        if len(nonexistent) == len(query_types):
            summary += "; el nombre no existe (NXDOMAIN)"
        else:
            summary += "; NXDOMAIN para: " + ", ".join(nonexistent)
    if failed:
        summary += "; errores: " + "; ".join(failed)
    result = DiagResult(title=f"DNS records :: {display_owner}", summary=summary)
    for record in records:
        result.add(
            f"{record['type']} · {record['owner']} · TTL {record['ttl']}",
            record["data"],
            Severity.OK,
        )
    for record_type, data in results.items():
        rcode = data.get("rcode", "UNKNOWN")
        if data.get("error") or rcode not in ("NOERROR", "NXDOMAIN"):
            result.add(record_type, data.get("error") or f"Respuesta DNS: {rcode}", Severity.WARN)
    if not records and not failed:
        result.add("Resultado", "El resolvedor no devolvió registros para los tipos consultados", Severity.INFO)
    if failed and len(failed) == len(query_types):
        result.error = "No se pudo consultar el DNS: " + "; ".join(failed)
    if any(record_type == "ANY" for record_type, _code in query_types):
        result.add(
            "Nota",
            "ANY puede devolver una respuesta parcial; se consultan tipos individuales para mayor cobertura",
            Severity.INFO,
        )
    result.raw = {
        "name": owner,
        "server": server or "system resolver",
        "queries": results,
        "records": records,
    }
    return result
