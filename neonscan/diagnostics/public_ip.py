"""Public-IP + ISP / geo lookup with multiple endpoints."""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Optional

from .result import DiagResult, Severity


# Free, no-auth public IP services.
_ENDPOINTS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    "https://ipinfo.io/json",
]


def _fetch_json(url: str, timeout: float = 4.0) -> tuple[bool, Optional[dict], str]:
    try:
        ctx_factory = _ssl_ctx()
        req = urllib.request.Request(url, headers={"User-Agent": "neonscan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx_factory) as resp:
            data = resp.read()
            return True, json.loads(data), ""
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return False, None, str(exc)


def _ssl_ctx():
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return ""


def get_public_ip() -> DiagResult:
    """Resolve the public IP, ISP, ASN, reverse DNS, and detect possible proxy."""
    res = DiagResult(title="Public IP")

    ip = None
    info: dict = {}
    source = ""
    last_err = ""
    for url in _ENDPOINTS:
        ok, data, err = _fetch_json(url, timeout=3.5)
        if not ok:
            last_err = err
            continue
        if "ip" in data:
            ip = data["ip"]
            info = data
            source = url.split("//", 1)[-1].split("/", 1)[0]
            break
        if "ip_addr" in data:
            ip = data["ip_addr"]
            info = data
            source = url.split("//", 1)[-1].split("/", 1)[0]
            break

    if not ip:
        res.error = f"all endpoints failed: {last_err}"
        return res

    rdns = _reverse_dns(ip)

    # ISP / ASN
    isp = (
        info.get("org")
        or info.get("asn")
        or info.get("isp")
        or "unknown"
    )
    country = info.get("country") or ""
    region = info.get("region") or info.get("region_name") or ""
    city = info.get("city") or ""
    tz = info.get("timezone") or ""

    # Naive proxy/VPN hint: latency to ipify vs latency to a known-leaking endpoint
    # is unreliable. Best simple heuristic: real-RFC1918 shows up as "private".
    proxy_hint = "no"
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.")):
        proxy_hint = "private (NAT)"
    elif rdns and any(t in rdns.lower() for t in ("tor", "exit", "vpn", "proxy", "host")):
        proxy_hint = "possible proxy/exit (hostname)"

    res.add("IP", ip, severity=Severity.OK)
    if rdns:
        res.add("Reverse DNS", rdns)
    res.add("ISP/ASN", str(isp))
    if country:
        res.add("Geo", ", ".join(x for x in (city, region, country) if x))
    if tz:
        res.add("Timezone", tz)
    res.add("Source", source)
    res.add("Proxy hint", proxy_hint,
            severity=Severity.INFO if proxy_hint == "no" else Severity.WARN)

    res.raw = {
        "ip": ip, "rdns": rdns, "isp": isp, "country": country,
        "region": region, "city": city, "timezone": tz,
        "source": source, "proxy_hint": proxy_hint,
    }
    res.summary = f"{ip} ({isp})"
    return res
