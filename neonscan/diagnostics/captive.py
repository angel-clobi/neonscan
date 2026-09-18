"""Captive portal detection: probe well-known connectivity-check URLs.

Different OSes use different probe URLs to check for captive-portal
interception. We replicate the check in Python and look for redirects
or unexpected content.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import Optional

from .result import DiagResult, Severity


# Each probe (URL, expected behavior) — the "expected" is what we'd see
# on a connection that's NOT behind a captive portal.
PROBES = [
    (
        "http://captive.apple.com/hotspot-detect.html",
        {"expected_substr": "Success", "max_status": 200, "description": "Apple hotspot detect"},
    ),
    (
        "http://nmcheck.gnome.org/check_network_status.txt",
        {"expected_substr": "NetworkManager is online", "max_status": 200, "description": "GNOME NM check"},
    ),
    (
        "http://connectivitycheck.gstatic.com/generate_204",
        {"expected_status": 204, "description": "Google connectivity check"},
    ),
    (
        "http://www.msftncsi.com/ncsi.txt",
        {"expected_substr": "Microsoft NCSI", "description": "Microsoft NCSI"},
    ),
]


def _probe(url: str, expected: dict, timeout: float = 4.0) -> dict:
    """Issue a GET against `url` and return what we got + the verdict."""
    # Avoid environment trust of system proxies.
    proxy_hander = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_hander)
    try:
        ctx_factory = _ssl_ctx()
    except Exception:
        ctx_factory = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "neonscan/1.0 (+captive-check)"})
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            final_url = resp.geturl()
            content = resp.read(2048).decode(errors="ignore")
        return {
            "ok": True,
            "status": status,
            "url": final_url,
            "content_preview": content[:160],
        }
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "status": exc.code,
            "url": exc.url or url,
            "content_preview": (exc.read() or b"").decode(errors="ignore")[:160],
            "error": str(exc),
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc), "url": url, "status": None}


def _ssl_ctx():
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def detect_captive(timeout: float = 4.0) -> DiagResult:
    """Run several well-known captive-portal checks; report whether the
    network seems to be behind a captive portal.
    """
    res = DiagResult(title="Captive portal")

    redirects = []
    unexpected = []
    errors = []
    response_time_ms = []
    reachable = 0

    import time
    for url, expected in PROBES:
        t0 = time.perf_counter()
        r = _probe(url, expected, timeout=timeout)
        if r.get("error") and not r.get("status"):
            errors.append(url)
            res.add(f"[{expected['description']}]", "unreachable", severity=Severity.WARN, note=str(r.get("error")))
            continue
        reachable += 1
        dt = (time.perf_counter() - t0) * 1000
        response_time_ms.append(dt)
        final_url = r.get("url", url)
        status = r.get("status")
        if final_url and final_url != url:
            redirects.append((url, final_url, status))
        # Expected-status check (for the 204 probe)
        exp_status = expected.get("expected_status")
        if exp_status is not None and status != exp_status:
            unexpected.append((url, status))
        # Expected-content check
        exp_substr = expected.get("expected_substr")
        if exp_substr and exp_substr not in r.get("content_preview", ""):
            unexpected.append((url, f"no '{exp_substr}'"))
        res.add(
            expected["description"],
            f"{status} · {dt:.0f}ms" + (" · REDIRECT" if final_url != url else ""),
        )

    captured = bool(redirects) or len(unexpected) >= 2
    if errors and reachable == 0:
        res.error = "all probes failed (no network?)"
        return res

    sev = Severity.FAIL if captured else (Severity.WARN if (errors or unexpected) else Severity.OK)
    res.add(
        "Verdict",
        "portal present" if captured else "no portal",
        severity=sev,
    )
    if redirects:
        res.add("Redirects", f"{len(redirects)}", note="strong portal signal")
    if unexpected:
        res.add("Unexpected responses", str(len(unexpected)))
    if errors:
        res.add("Unreachable", str(len(errors)), severity=Severity.WARN)

    res.raw = {
        "redirects": redirects,
        "unexpected": unexpected,
        "errors": errors,
        "response_times_ms": response_time_ms,
        "reachable": reachable,
    }
    return res
