"""TLS / certificate inspection: server cert details + chain + expiry."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Optional

from .result import DiagResult, Severity


def _parse_cert_date(value: str) -> Optional[datetime.datetime]:
    """Parse an ASN.1 time string (YYYYMMDDhhmmssZ) into a UTC datetime."""
    if not value:
        return None
    try:
        return datetime.datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None


def inspect_tls(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    timeout: float = 5.0,
) -> DiagResult:
    """Connect to `host:port`, retrieve TLS certificate, return findings.

    Args:
        host: target IP or hostname (used as SNI fallback).
        port: TCP port (default 443).
        sni: explicit SNI override; defaults to `host` if it looks like a hostname.
        timeout: total timeout.
    """
    res = DiagResult(title=f"TLS :: {host}:{port}")
    sni_target = sni or host

    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # we'll match SNI manually below
    ctx.verify_mode = ssl.CERT_NONE  # we want cert data even if chain is broken

    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        ssock = ctx.wrap_socket(s, server_hostname=sni_target)
        cert_der = ssock.getpeercert(binary_form=True)
        cert = ssock.getpeercert() or {}
        cipher = ssock.cipher()
        # Collect the chain (peer + intermediates). The API only exists on
        # Python 3.13+ (`get_unverified_chain` / `get_verified_chain`); older
        # names never existed. On 3.9 we simply won't have the intermediates.
        chain = []
        for _meth in ("get_unverified_chain", "get_verified_chain"):
            _fn = getattr(ssock, _meth, None)
            if _fn is None:
                continue
            try:
                _c = _fn()
            except (ValueError, ssl.SSLError, OSError):
                _c = None
            if _c:
                chain = list(_c)
                break
        ssock.close()
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        if s is not None:
            with_ssl_close(s)
        res.error = f"TLS failed: {exc}"
        return res
    finally:
        if s is not None:
            with_ssl_close(s)

    if not cert and not cert_der:
        res.error = "no certificate returned"
        return res

    # When `cert` is empty (Python 3.9 + CERT_NONE), fall back to openssl parsing.
    if not cert and cert_der:
        openssl_info = _openssl_parse(cert_der)
        subject = {"commonName": openssl_info.get("cn")}
        issuer = {"commonName": openssl_info.get("issuer_cn"), "organizationName": openssl_info.get("issuer_o")}
        sans = openssl_info.get("sans", [])
        nb = openssl_info.get("notbefore")
        na = openssl_info.get("notafter")
        notbefore = openssl_info.get("notbefore_raw", "")
        notafter = openssl_info.get("notafter_raw", "")
    else:
        subject = dict(item[0] for item in cert.get("subject", []))
        issuer = dict(item[0] for item in cert.get("issuer", []))
        sans = [v for tup in cert.get("subjectAltName", ()) for v in tup[1:]] if cert.get("subjectAltName") else []
        notbefore = cert.get("notBefore", "")
        notafter = cert.get("notAfter", "")
        nb = _parse_cert_date(notbefore)
        na = _parse_cert_date(notafter)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if na is not None:
        secs_left = (na - now).total_seconds()
        days_left = secs_left / 86400.0
    else:
        days_left = None

    cn = subject.get("commonName", "?")
    res.add("Subject CN", cn)
    res.add("Issuer", issuer.get("commonName", "?") or issuer.get("organizationName", "?"))
    if sans:
        # only first 10 SANS for brevity
        res.add("SANs", ", ".join(sans[:10]) + ("…" if len(sans) > 10 else ""))
    if nb is not None and na is not None:
        res.add("Validity", f"{nb.date()} → {na.date()}")
    if days_left is not None:
        sev = Severity.OK if days_left > 30 else (Severity.WARN if days_left > 7 else Severity.FAIL)
        res.add(
            "Days left",
            f"{days_left:.0f}",
            severity=sev,
            note="expiry proximity" if days_left < 30 else "",
        )

    if cipher:
        name, version, secret_bits = cipher
        weak = secret_bits < 128 or "RC4" in name or "MD5" in name or "NULL" in name or version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
        sev = Severity.FAIL if weak else Severity.OK
        res.add("Cipher", f"{name} ({version}, {secret_bits} bits)", severity=sev)

    # host match: does SNI match any SAN? if user provided hostname, evaluate.
    if sni and sans:
        matched = any(sni.lower() == san.lower() or san.startswith("*.") and _wildcard_match(sni, san) for san in sans)
        if matched:
            res.add("SNI match", "OK")
        else:
            res.add("SNI match", "no match", severity=Severity.WARN,
                    note=f"SNI={sni!r} not in SAN list")

    # chain info
    if chain:
        chain_count = len(chain)
        res.add("Chain length", str(chain_count))
    elif cert_der:
        chain_count = 1
        res.add("Chain length", "1", note="peer only (full chain needs Python 3.13+)")
    else:
        chain_count = 0

    # quick fingerprint
    if cert_der:
        import hashlib
        fingerprint = hashlib.sha256(cert_der).hexdigest()
        res.add("SHA-256 fingerprint", ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)).upper()[:32] + "…")

    res.raw = {
        "subject": subject, "issuer": issuer, "sans": sans,
        "notBefore": notbefore, "notAfter": notafter,
        "cipher": cipher, "chain_length": chain_count,
        "days_left": days_left, "sni": sni,
    }
    return res


def _wildcard_match(sni: str, pattern: str) -> bool:
    """Minimal *.example.com matching."""
    if not pattern.startswith("*."):
        return False
    rest = pattern[2:]
    return sni.endswith("." + rest) or sni == rest


def with_ssl_close(s: socket.socket) -> None:
    try:
        s.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# OpenSSL-based parsing fallback (when getpeercert() returns empty).
# ---------------------------------------------------------------------------

import re
import subprocess
import tempfile
from pathlib import Path as _Path

_SAN_RE = re.compile(r"DNS:([^,\s]+)")
_CN_RE = re.compile(r"Subject:.*?CN\s*=\s*([^/\n]+)", re.DOTALL)
_ISSUER_RE = re.compile(r"Issuer:.*?CN\s*=\s*([^/\n]+)", re.DOTALL)
_NOTBEFORE_RE = re.compile(r"Not Before\s*:\s*(.+)")
_NOTAFTER_RE = re.compile(r"Not After\s*:\s*(.+)")


def _openssl_parse(der: bytes) -> dict:
    """Pipe a DER blob through `openssl x509 -text -noout` and pull key fields."""
    if not der:
        return {}
    fd, path = tempfile.mkstemp(suffix=".der")
    try:
        with __import__("os").fdopen(fd, "wb") as f:
            f.write(der)
    except Exception:
        try:
            __import__("os").unlink(path)
        except OSError:
            pass
        return {}
    try:
        cp = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", path, "-text", "-noout"],
            capture_output=True, text=True, timeout=8, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {}
    finally:
        try:
            __import__("os").unlink(path)
        except OSError:
            pass
    text = cp.stdout
    if not text:
        return {}

    san_block = re.search(r"X509v3 Subject Alternative Name:\s*\n?\s*([^\n]+)", text)
    sans = _SAN_RE.findall(san_block.group(1)) if san_block else []

    cn = ""
    m = _CN_RE.search(text)
    if m:
        cn = m.group(1).strip().rstrip(",")

    issuer_cn = ""
    m = _ISSUER_RE.search(text)
    if m:
        issuer_cn = m.group(1).strip().rstrip(",")
    issuer_o = ""
    m = re.search(r"Issuer:[^\n]*O\s*=\s*([^/\n]+)", text)
    if m:
        issuer_o = m.group(1).strip().rstrip(",")

    nb_raw = ""
    na_raw = ""
    m = _NOTBEFORE_RE.search(text)
    if m:
        nb_raw = m.group(1).strip()
    m = _NOTAFTER_RE.search(text)
    if m:
        na_raw = m.group(1).strip()

    nb = None
    na = None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            nb = datetime.datetime.strptime(nb_raw, fmt).replace(tzinfo=datetime.timezone.utc)
            break
        except (ValueError, TypeError):
            continue
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            na = datetime.datetime.strptime(na_raw, fmt).replace(tzinfo=datetime.timezone.utc)
            break
        except (ValueError, TypeError):
            continue

    return {
        "cn": cn,
        "sans": sans,
        "issuer_cn": issuer_cn,
        "issuer_o": issuer_o,
        "notbefore": nb,
        "notafter": na,
        "notbefore_raw": nb_raw,
        "notafter_raw": na_raw,
    }
