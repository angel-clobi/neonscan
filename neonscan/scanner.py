"""TCP/UDP service probes, port states, and best-effort identification."""

import contextlib
import errno
import http.client
import re
import shutil
import socket
import subprocess
import ssl
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, Optional


# Curated common TCP ports. UDP probes are deliberately separate and selective.
DEFAULT_PORTS: list[int] = [
    7, 21, 22, 23, 25, 26, 37, 53, 67, 68,
    69, 79, 80, 81, 88, 110, 111, 113, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 201,
    264, 389, 443, 444, 445, 450, 458, 464, 497, 500,
    502, 512, 513, 514, 515, 520, 521, 540, 548, 554,
    587, 631, 636, 873, 902, 989, 990, 993, 995,
    1080, 1194, 1433, 1521, 1701, 1723, 1741, 1812, 1883, 1900,
    2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375,
    2376, 3000, 3001, 3306, 3389, 3690, 4000, 4040, 4500, 4567,
    4848, 5000, 5001, 5060, 5222, 5432, 5601, 5672, 5900, 5984,
    5985, 5986, 6379, 6443, 6666, 7001, 7077, 7474, 8000, 8008,
    8009, 8080, 8081, 8083, 8086, 8088, 8089, 8090, 8181, 8443,
    8500, 8883, 8888, 9000, 9001, 9042, 9090, 9091, 9092, 9100,
    9200, 9300, 9418, 9443, 11211, 15672, 27017, 27018, 27019, 50000,
]


# Port → service-name guess. A matching protocol probe is stronger evidence.
PORT_HINTS = {
    7: "echo", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp-client", 69: "tftp", 79: "finger", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmp-trap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 515: "lpd", 587: "smtp-submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "mssql", 1521: "oracle", 1701: "l2tp", 1723: "pptp", 1812: "radius",
    1883: "mqtt", 1900: "ssdp/upnp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4000: "http-alt", 5000: "upnp/http-alt",
    5001: "http-alt", 5060: "sip", 5222: "xmpp", 5432: "postgres",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    5985: "winrm-http", 5986: "winrm-https", 6379: "redis", 6443: "k8s-api",
    7001: "weblogic", 7474: "neo4j-http", 8000: "http-alt", 8008: "http-alt",
    8009: "ajp", 8080: "http-alt", 8081: "http-alt", 8083: "http-alt",
    8086: "influxdb", 8088: "http-alt", 8089: "http-alt", 8090: "http-alt",
    8181: "http-alt", 8443: "https-alt", 8500: "consul", 8883: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9001: "http-alt", 9042: "cassandra",
    9090: "prometheus/webmin", 9091: "transmission", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
}

# Subset of ports we treat as "web service" candidates for HTTP detection.
WEB_PORTS = {
    80, 81, 443, 444, 3000, 3001, 4000, 5000, 5001, 5601, 5984, 5985,
    5986, 6443, 7474, 8000, 8008, 8080, 8081, 8083, 8086, 8088, 8089,
    8090, 8181, 8443, 8500, 8888, 9000, 9001, 9090, 9200, 9443,
}
QUICK_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
TLS_PORTS = {443, 444, 5986, 6443, 8443, 9443}
UDP_COMMON_PORTS = (53, 123, 161, 1900)
UDP_PORT_HINTS = {53: "dns", 123: "ntp", 161: "snmp", 1900: "ssdp/upnp"}


def service_name(port: int) -> str:
    """Return a port-based service hint, falling back to the OS TCP database."""
    known = PORT_HINTS.get(port)
    if known:
        return known
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    banner: str = ""
    web_title: str = ""
    web_status: str = ""
    web_server: str = ""
    web_scheme: str = ""
    protocol: str = "tcp"
    state: str = ""
    reason: str = ""
    service_source: str = "port-hint"
    product: str = ""
    version: str = ""

    def __post_init__(self) -> None:
        # Keep older callers that construct PortResult(open=...) compatible.
        if not self.state:
            self.state = "open" if self.open else "closed"

    @property
    def is_web(self) -> bool:
        return bool(self.web_title or self.web_server) or self.port in WEB_PORTS


# ---------------------------------------------------------------------------
# TCP connect + banner grabbing
# ---------------------------------------------------------------------------

def _grab_banner(sock: socket.socket, proto: str) -> str:
    """Best-effort banner read given a freshly-opened socket."""
    try:
        sock.settimeout(2.0)
        if proto == "http":
            sock.sendall(b"HEAD / HTTP/1.0\r\nUser-Agent: neonscan/1.0\r\n\r\n")
        elif proto == "ssh":
            # SSH servers usually banner first
            pass
        else:
            sock.sendall(b"\r\n")
        data = sock.recv(512)
        return data.decode(errors="ignore").strip()[:160]
    except Exception:
        return ""


@contextlib.contextmanager
def _tcp_connection(ip: str, port: int, timeout: float = 1.0):
    """Yield an open socket or None."""
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        yield s
    except (OSError, socket.timeout):
        yield None
    finally:
        if s is not None:
            with contextlib.suppress(OSError):
                s.close()


def _try_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    """Probe a single port and capture as much info as possible."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except (socket.timeout, TimeoutError):
        return PortResult(
            port=port, open=False, service=service_name(port),
            state="filtered", reason="timeout",
        )
    except OSError as exc:
        if isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED:
            state, reason = "closed", "connection-refused"
        elif exc.errno in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            state, reason = "filtered", "unreachable-or-timeout"
        else:
            state, reason = "error", exc.strerror or exc.__class__.__name__
        return PortResult(
            port=port, open=False, service=service_name(port),
            state=state, reason=reason,
        )

    with s:
        result = PortResult(
            port=port, open=True, service=service_name(port),
            state="open", reason="tcp-connect",
        )

        if port in WEB_PORTS:
            _populate_http_info(ip, port, result)
        elif port == 22:
            banner = _grab_banner(s, "ssh")
            result.banner = banner
        elif port in (21,):
            banner = _grab_banner(s, "ftp")
            result.banner = banner
        elif port == 25:
            banner = _grab_banner(s, "smtp")
            result.banner = banner
        return result


# ---------------------------------------------------------------------------
# HTTP(S) title / server probing
# ---------------------------------------------------------------------------

def _http_request(
    ip: str, port: int, use_tls: bool, timeout: float = 2.5
) -> tuple[int, str, str, str]:
    """Issue a quick GET via http.client. Return (status, server, title, body)."""
    conn = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(
                ip, port=port, timeout=timeout, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
        conn.request(
            "GET",
            "/",
            headers={
                "User-Agent": "neonscan/1.0 (+cyberpunk-recon)",
                "Accept": "*/*",
            },
        )
        resp = conn.getresponse()
        raw_status = resp.status
        headers = {k.lower(): v for k, v in resp.getheaders()}
        body = b""
        if resp.status >= 200:
            body = resp.read(2048)

        server = headers.get("server", "")
        title = _extract_title(body.decode(errors="ignore")) if body else ""
        return raw_status, server, title, body.decode(errors="ignore")[:512]
    except Exception:
        return 0, "", "", ""
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


_TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> str:
    m = _TITLE_RE.search(html)
    if not m:
        return ""
    return m.group(1).strip()[:140]


def _populate_http_info(ip: str, port: int, result: PortResult) -> None:
    use_tls = port in TLS_PORTS
    scheme = "https" if use_tls else "http"
    status, server, title, body = _http_request(
        ip, port, use_tls=use_tls, timeout=1.5
    )
    if not status:
        # Non-standard ports may serve HTTPS (or HTTP on a conventional TLS port).
        status, server, title, body = _http_request(
            ip, port, use_tls=not use_tls, timeout=1.5
        )
        scheme = "http" if use_tls else "https"
    if status:
        result.web_scheme = scheme
        result.web_status = str(status)
    if server:
        result.web_server = server
    if title:
        result.web_title = title
    elif body:
        # Try harder inside the body once (some HTML splits tags across lines).
        m = _TITLE_RE.search(body)
        if m:
            result.web_title = m.group(1).strip()[:140]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_host(
    ip: str,
    ports: Optional[Iterable[int]] = None,
    workers: int = 80,
    timeout: float = 1.0,
    progress_cb: Optional[callable] = None,
    include_states: bool = False,
) -> list[PortResult]:
    """Scan IP across the given ports (default top list) and return results.

    By default only open ports are returned. Set ``include_states`` to also
    return closed, filtered, and error results from each TCP connection probe.
    """
    if ports is None:
        ports = DEFAULT_PORTS
    ports = list(ports)

    results: list[PortResult] = []
    total = len(ports)
    done = 0

    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=min(max(1, workers), len(ports))) as pool:
        futures = {pool.submit(_try_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            done += 1
            res = fut.result()
            if res.open or include_states:
                results.append(res)
            if progress_cb:
                progress_cb(done, total, res.port)

    results.sort(key=lambda r: r.port)
    return results


def quick_web_check(ip: str, progress_cb: Optional[callable] = None) -> list[PortResult]:
    """Light web-service-only scan on ports we know are HTTP-shaped."""
    return scan_host(
        ip, ports=QUICK_WEB_PORTS, workers=20, timeout=1.5,
        progress_cb=progress_cb,
    )


def _udp_probe_payload(port: int) -> bytes:
    """Return a small, read-only protocol request for UDP identification."""
    if port == 53:
        # DNS A query for example.com; no recursive behavior beyond a normal query.
        return (
            b"\x4e\x53\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x01\x00\x01"
        )
    if port == 123:
        # NTP client request (client mode, version 4).
        return b"\x23" + bytes(47)
    if port == 161:
        # SNMPv1 GET sysDescr.0 using the conventional read-only community.
        return bytes.fromhex(
            "302902010104067075626C6963A01C020470757262020100020100"
            "300E300C06082B060102010101000500"
        )
    if port == 1900:
        return (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        )
    raise ValueError(f"No safe built-in UDP probe exists for port {port}")


def _try_udp_port(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    """Probe one common UDP service; silence is reported as open|filtered."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.send(_udp_probe_payload(port))
        try:
            response = sock.recv(2048)
        except socket.timeout:
            return PortResult(
                port=port, open=False, protocol="udp", state="open|filtered",
                service=UDP_PORT_HINTS.get(port, "unknown"), reason="no-response",
            )
        if response:
            return PortResult(
                port=port, open=True, protocol="udp", state="open",
                service=UDP_PORT_HINTS.get(port, "unknown"), reason="udp-response",
                banner=response.decode(errors="replace").strip()[:160],
            )
        return PortResult(
            port=port, open=False, protocol="udp", state="open|filtered",
            service=UDP_PORT_HINTS.get(port, "unknown"), reason="empty-response",
        )
    except (ConnectionRefusedError, OSError) as exc:
        if isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED:
            state, reason = "closed", "icmp-port-unreachable"
        else:
            state, reason = "open|filtered", exc.strerror or "no-response"
        return PortResult(
            port=port, open=False, protocol="udp", state=state,
            service=UDP_PORT_HINTS.get(port, "unknown"), reason=reason,
        )
    finally:
        sock.close()


def scan_udp_host(
    ip: str,
    ports: Iterable[int] = UDP_COMMON_PORTS,
    timeout: float = 1.0,
    progress_cb: Optional[callable] = None,
) -> list[PortResult]:
    """Probe selected common UDP services on one explicitly selected host.

    UDP silence is inherently ambiguous; results use ``open|filtered`` unless
    the service replies or reports that the port is closed.
    """
    selected = list(dict.fromkeys(int(port) for port in ports))
    unsupported = [port for port in selected if port not in UDP_PORT_HINTS]
    if unsupported:
        raise ValueError(
            "Safe protocol probes are available only for UDP ports "
            + ", ".join(map(str, UDP_COMMON_PORTS))
        )
    if timeout <= 0:
        raise ValueError("UDP timeout must be greater than zero")
    results = []
    for done, port in enumerate(selected, start=1):
        result = _try_udp_port(ip, port, timeout=timeout)
        results.append(result)
        if progress_cb:
            progress_cb(done, len(selected), port)
    return results


def nmap_service_versions(
    ip: str,
    ports: Iterable[int],
    timeout: float = 45.0,
) -> dict[int, dict[str, str]]:
    """Use Nmap's lightweight service probes to identify open TCP services.

    Nmap is optional. Callers should keep the native scan results when it is
    unavailable or fails; this function never runs NSE scripts or OS detection.
    """
    nmap = shutil.which("nmap")
    selected = sorted(set(int(port) for port in ports))
    if not nmap or not selected:
        return {}
    if any(port < 1 or port > 65535 for port in selected):
        raise ValueError("TCP ports must be between 1 and 65535")

    command = [nmap, "-n", "-Pn", "-sT", "-sV", "--version-light", "-T3", "-p",
               ",".join(map(str, selected)), "-oX", "-"]
    if ":" in ip:
        command.insert(1, "-6")
    command.append(ip)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode != 0 or not completed.stdout.strip():
        return {}
    try:
        root = ET.fromstring(completed.stdout)
    except ET.ParseError:
        return {}

    identified: dict[int, dict[str, str]] = {}
    for port_node in root.findall(".//port[@protocol='tcp']"):
        port_id = port_node.get("portid")
        service_node = port_node.find("service")
        state_node = port_node.find("state")
        if not port_id or service_node is None or (state_node is not None and state_node.get("state") != "open"):
            continue
        try:
            port = int(port_id)
        except ValueError:
            continue
        fields = {
            key: service_node.get(key, "")
            for key in ("name", "product", "version", "extrainfo", "tunnel", "method", "conf")
        }
        identified[port] = fields
    return identified
