"""TCP port scanning + service banner grabbing."""

import contextlib
import http.client
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable, Optional


# Default top-100 ports to scan. Combined TCP/UDP-but-we-do-TCP-only.
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


# Port → service hint. Used in the UI when no banner is captured.
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
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8083, 8088, 8181, 8443, 8888, 9000, 3000}


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    banner: str = ""
    web_title: str = ""
    web_status: str = ""
    web_server: str = ""

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
    with _tcp_connection(ip, port, timeout=timeout) as s:
        if s is None:
            return PortResult(port=port, open=False, service=PORT_HINTS.get(port, ""))

        result = PortResult(port=port, open=True, service=PORT_HINTS.get(port, ""))

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

def _http_request(ip: str, port: int, use_tls: bool) -> tuple[int, str, str, str]:
    """Issue a quick GET via http.client. Return (status, server, title, body)."""
    conn = None
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(
                ip, port=port, timeout=2.5, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(ip, port=port, timeout=2.5)
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
    use_tls = port in (443, 8443, 9443, 5986, 8002, 8883)
    status, server, title, body = _http_request(ip, port, use_tls=use_tls)
    if status:
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
) -> list[PortResult]:
    """Scan IP across the given ports (default top list) and return results.

    Only the open ports are returned.
    """
    if ports is None:
        ports = DEFAULT_PORTS
    ports = list(ports)

    results: list[PortResult] = []
    total = len(ports)
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_try_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            done += 1
            res = fut.result()
            if res.open:
                results.append(res)
            if progress_cb:
                progress_cb(done, total, res.port)

    results.sort(key=lambda r: r.port)
    return results


def quick_web_check(ip: str, progress_cb: Optional[callable] = None) -> list[PortResult]:
    """Light web-service-only scan on ports we know are HTTP-shaped."""
    ports = sorted(WEB_PORTS)
    return scan_host(ip, ports=ports, workers=20, timeout=1.5, progress_cb=progress_cb)
