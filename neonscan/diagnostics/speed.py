"""Speed / bandwidth diagnostic: HTTP download (Cloudflare speed endpoint)."""

from __future__ import annotations

import contextlib
import http.server
import json
import random
import socket
import socketserver
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Iterable, Optional

from .result import DiagResult, Severity


# ---------------------------------------------------------------------------
# Internet download (Cloudflare's public endpoint)
# ---------------------------------------------------------------------------

CF_DOWN = "https://speed.cloudflare.com/__down?bytes={bytes}"


def measure_download(
    sizes: Iterable[int] = (1_000_000, 25_000_000),
    timeout: float = 12.0,
) -> DiagResult:
    """Download fixed-size blobs from Cloudflare's speed endpoint and report Mbps.

    Args:
        sizes: list of byte counts to fetch (1 MB default warm-up, 25 MB test).
        timeout: per-request timeout in seconds.
    """
    res = DiagResult(title="Speed · download")

    sizes = list(sizes)
    if not sizes:
        sizes = [1_000_000, 25_000_000]

    samples = []
    for size in sizes:
        try:
            r = _download_benchmark(size, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            res.add(f"{size} B download", f"failed ({exc})", severity=Severity.FAIL)
            res.error = str(exc)
            return res
        if r.get("error"):
            res.add(f"{size // 1_000_000} MB", f"failed ({r['error']})", severity=Severity.FAIL)
            res.error = r["error"]
            return res
        mb = size / 8 / 1024 / 1024
        samples.append({"size": size, "elapsed": r["elapsed"], "mbps": r["mbps"]})
        res.add(
            f"{size // 1_000_000} MB download",
            f"{r['mbps']:.1f} Mbps (in {r['elapsed']:.2f}s)",
        )

    usable = [s["mbps"] for s in samples[1:]] if len(samples) > 1 else [s["mbps"] for s in samples]
    avg = statistics.mean(usable) if usable else 0
    sev = Severity.OK if avg > 50 else (Severity.WARN if avg > 10 else Severity.FAIL)
    res.add("Average", f"{avg:.1f} Mbps", severity=sev)
    res.raw = {"samples": samples, "avg_mbps": avg}
    res.summary = f"{avg:.0f} Mbps"
    return res


def _download_benchmark(size: int, timeout: float) -> dict:
    """Stream a fixed-size blob and return elapsed + Mbps."""
    ctx_factory = _make_ssl_ctx()
    t0 = time.perf_counter()
    received = 0
    err: Optional[str] = None
    try:
        req = urllib.request.Request(
            CF_DOWN.format(bytes=size),
            headers={"User-Agent": "neonscan/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx_factory) as resp:
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                received += len(chunk)
        elapsed = time.perf_counter() - t0
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"elapsed": 0.0, "mbps": 0.0, "received": 0, "error": str(exc)}
    mbps = (received * 8 / 1_000_000) / elapsed if elapsed > 0 else 0.0
    return {"elapsed": elapsed, "mbps": mbps, "received": received, "error": err}


def _make_ssl_ctx():
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


# ---------------------------------------------------------------------------
# LAN bandwidth via ephemeral http.server (machine↔self or machine↔peer)
# ---------------------------------------------------------------------------

def lan_bandtest(
    duration_s: float = 6.0,
    port: int = 0,
    payload_kb: int = 1024,
    peer: Optional[str] = None,
) -> DiagResult:
    """Measure LAN bandwidth by serving+downloading from a local http.server.

    If `peer` is None: run server + client locally (loopback).
    If `peer` is a URL (e.g. http://192.168.0.5:8123/data): probe that endpoint.

    Note: this works without root and uses an ephemeral port.
    """
    res = DiagResult(title="Speed · LAN")

    if peer:
        try:
            req = urllib.request.Request(peer, headers={"User-Agent": "neonscan/1.0"})
            t0 = time.perf_counter()
            received = 0
            with urllib.request.urlopen(req, timeout=duration_s + 4) as resp:
                while True:
                    if time.perf_counter() - t0 >= duration_s:
                        break
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
            elapsed = max(time.perf_counter() - t0, 1e-6)
            mbps = (received * 8 / 1_000_000) / elapsed
            res.add("Host", peer)
            res.add("Bytes", f"{received:,}")
            res.add("Elapsed", f"{elapsed:.2f} s")
            res.add("Throughput", f"{mbps:.1f} Mbps")
            res.summary = f"{mbps:.0f} Mbps"
            res.raw = {"peer": peer, "received": received, "elapsed": elapsed, "mbps": mbps}
            return res
        except Exception as exc:  # noqa: BLE001
            res.error = f"peer probe failed: {exc}"
            return res

    server, host, bound_port = _start_lan_server(payload_kb, port)
    if server is None:
        res.error = "could not start local http.server (port in use?)"
        return res
    try:
        url = f"http://{host}:{bound_port}/data"
        t0 = time.perf_counter()
        received = 0
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "neonscan/1.0"})
            with urllib.request.urlopen(req, timeout=duration_s + 4) as resp:
                while time.perf_counter() - t0 < duration_s:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
            elapsed = max(time.perf_counter() - t0, 1e-6)
            mbps = (received * 8 / 1_000_000) / elapsed
            res.add("Mode", "loopback (single-host)")
            res.add("URL", url)
            res.add("Bytes", f"{received:,}")
            res.add("Elapsed", f"{elapsed:.2f} s")
            res.add("Throughput", f"{mbps:.1f} Mbps")
            res.summary = f"{mbps:.0f} Mbps (loopback)"
            res.raw = {"received": received, "elapsed": elapsed, "mbps": mbps}
        except Exception as exc:  # noqa: BLE001
            res.error = f"loopback probe failed: {exc}"
    finally:
        with contextlib.suppress(Exception):
            server.shutdown()
            server.server_close()
    return res


class _LANHandler(http.server.BaseHTTPRequestHandler):
    payload_kb = 256

    def log_message(self, *a, **kw):  # silence stderr noise
        return

    def do_GET(self):
        body = b"\x00" * (self.payload_kb * 1024)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start_lan_server(payload_kb: int, port: int = 0):
    try:
        host = _detect_local_ip()
    except Exception:
        host = "127.0.0.1"
    _LANHandler.payload_kb = payload_kb
    try:
        server = _ThreadingHTTPServer((host, port or 0), _LANHandler)
    except OSError:
        return None, host, 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, host, server.server_address[1]


def _detect_local_ip() -> str:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


# ---------------------------------------------------------------------------
# Upload (Cloudflare /__up) — same shape as download.
# ---------------------------------------------------------------------------

CF_UP = "https://speed.cloudflare.com/__up"


def measure_upload(
    sizes: Iterable[int] = (1_000_000, 10_000_000),
    timeout: float = 18.0,
) -> DiagResult:
    """POST random bytes to Cloudflare's /__up and report upload Mbps."""
    res = DiagResult(title="Speed · upload")
    sizes = list(sizes)
    if not sizes:
        sizes = [1_000_000, 10_000_000]
    samples = []
    for size in sizes:
        try:
            r = _upload_benchmark(size, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            res.add(f"{size} B upload", f"failed ({exc})", severity=Severity.FAIL)
            res.error = str(exc)
            return res
        if r.get("error"):
            res.add(f"{size // 1_000_000} MB", f"failed ({r['error']})", severity=Severity.FAIL)
            res.error = r["error"]
            return res
        mb = size / 8 / 1024 / 1024
        samples.append({"size": size, "elapsed": r["elapsed"], "mbps": r["mbps"]})
        res.add(
            f"{size // 1_000_000} MB upload",
            f"{r['mbps']:.1f} Mbps (in {r['elapsed']:.2f}s)",
        )
    usable = [s["mbps"] for s in samples[1:]] if len(samples) > 1 else [s["mbps"] for s in samples]
    avg = statistics.mean(usable) if usable else 0
    sev = Severity.OK if avg > 25 else (Severity.WARN if avg > 5 else Severity.FAIL)
    res.add("Average", f"{avg:.1f} Mbps", severity=sev)
    res.raw = {"samples": samples, "avg_mbps": avg}
    res.summary = f"{avg:.0f} Mbps"
    return res


def _upload_benchmark(size: int, timeout: float) -> dict:
    """POST `size` random bytes to Cloudflare /__up and time it."""
    ctx_factory = _make_ssl_ctx()
    body = random.randbytes(size)
    req = urllib.request.Request(
        CF_UP,
        data=body,
        method="POST",
        headers={
            "User-Agent": "neonscan/1.0",
            "Content-Type": "application/octet-stream",
        },
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx_factory) as resp:
            resp.read()
        elapsed = time.perf_counter() - t0
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"elapsed": 0.0, "mbps": 0.0, "sent": 0, "error": str(exc)}
    mbps = (size * 8 / 1_000_000) / elapsed if elapsed > 0 else 0.0
    return {"elapsed": elapsed, "mbps": mbps, "sent": size, "error": None}


# ---------------------------------------------------------------------------
# iperf3 (LAN)
# ---------------------------------------------------------------------------

def measure_iperf3(
    server: Optional[str] = None,
    duration_s: int = 6,
    parallel: int = 1,
    reverse: bool = False,
) -> DiagResult:
    """Run an iperf3 test against `server`. Returns Mbps + jitter/loss stats.

    Requires iperf3 on PATH; if missing, the result has `error` set gracefully.
    """
    res = DiagResult(title=f"iperf3 :: {server or 'localhost'}")

    try:
        iperf = subprocess.run(["which", "iperf3"], capture_output=True, text=True, timeout=3)
        if iperf.returncode != 0:
            raise FileNotFoundError("iperf3 not on PATH")
        iperf_path = iperf.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fall back: spawn a local server and client as a self-contained test.
        return _iperf3_self(duration_s=duration_s)

    if server is None:
        # No remote server specified: try to start a local iperf3 server, then
        # connect our client to ourselves.
        server_proc = None
        try:
            server_proc = subprocess.Popen(
                [iperf_path, "-s", "-1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)
            server = "127.0.0.1"
        except OSError as exc:
            res.error = f"could not start iperf3 server: {exc}"
            return res

    cmd = [
        iperf_path, "-c", server,
        "-t", str(duration_s),
        "-P", str(parallel),
    ]
    if reverse:
        # upload test instead of download
        cmd.insert(1, "-R")

    t0 = time.perf_counter()
    try:
        cp = subprocess.run(
            cmd, capture_output=True, text=True, timeout=duration_s + 6, check=False
        )
        raw = cp.stdout + cp.stderr
    except subprocess.TimeoutExpired:
        res.error = "iperf3 timed out"
        return res
    elapsed = time.perf_counter() - t0

    if server_proc is not None:
        with contextlib.suppress(Exception):
            server_proc.terminate()
            server_proc.wait(timeout=3)

    return _parse_iperf3_output(raw, res, elapsed)


def _iperf3_self(duration_s: int) -> DiagResult:
    """No iperf3 binary on PATH: return a placeholder with helpful guidance."""
    res = DiagResult(title="iperf3")
    res.error = "iperf3 not installed; run `brew install iperf3` for LAN bandwidth tests"
    return res


def _parse_iperf3_output(raw: str, res: DiagResult, elapsed: float) -> DiagResult:
    """Parse iperf3's standard summary blocks."""
    if not raw:
        res.error = "empty iperf3 output"
        return res
    # Lines like:
    # [  5]   0.00-1.00   sec  12.5 MBytes   105 Mbits/sec
    mbps_vals = []
    loss_vals = []
    jitter_vals = []
    for line in raw.splitlines():
        m = re.search(r"([\d\.]+)\s*Mbits/sec", line)
        if m:
            try:
                mbps_vals.append(float(m.group(1)))
            except ValueError:
                pass
        m = re.search(r"\((\d+(?:\.\d+)?)\s*%\s*\)", line)
        if m:
            try:
                loss_vals.append(float(m.group(1)))
            except ValueError:
                pass
        m = re.search(r"([\d\.]+)\s*ms\s+jitter", line)
        if m:
            try:
                jitter_vals.append(float(m.group(1)))
            except ValueError:
                pass
    if not mbps_vals:
        res.error = "iperf3 produced no throughput samples"
        return res
    avg = statistics.mean(mbps_vals)
    peak = max(mbps_vals)
    res.add("Throughput", f"{avg:.1f} Mbps (peak {peak:.0f})")
    if loss_vals:
        avg_loss = statistics.mean(loss_vals)
        sev = Severity.OK if avg_loss < 0.5 else (Severity.WARN if avg_loss < 5 else Severity.FAIL)
        res.add("Loss", f"{avg_loss:.2f}%", severity=sev)
    if jitter_vals:
        avg_jit = statistics.mean(jitter_vals)
        sev = Severity.OK if avg_jit < 5 else (Severity.WARN if avg_jit < 20 else Severity.FAIL)
        res.add("Jitter", f"{avg_jit:.2f} ms", severity=sev)
    res.add("Duration", f"{elapsed:.2f} s")
    res.raw = {"samples": mbps_vals, "loss": loss_vals, "jitter": jitter_vals, "avg_mbps": avg}
    res.summary = f"{avg:.0f} Mbps"
    return res


import re
