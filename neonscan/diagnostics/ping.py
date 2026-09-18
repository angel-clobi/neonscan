"""Ping diagnostic: latency, packet loss, jitter."""

from __future__ import annotations

import platform
import re
import statistics
import subprocess
from typing import Optional

from .result import DiagResult, Severity


IS_DARWIN = platform.system() == "Darwin"


def _run_ping(target: str, count: int, interval_ms: int, deadline_s: int) -> tuple[int, str, str]:
    """Invoke ping with platform-correct flags."""
    if IS_DARWIN:
        cmd = ["ping", "-c", str(count), "-i", str(max(interval_ms, 100) / 1000.0), "-W", "2000", target]
    else:
        cmd = ["ping", "-c", str(count), "-i", str(max(interval_ms, 100) / 1000.0), "-W", "2", target]
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=deadline_s + 5,
            check=False,
        )
        return out.returncode, out.stdout, out.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, "", str(exc)


# Match: 64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=23.4 ms
_TIME_LINE = re.compile(r"time[=<]([\d\.]+)\s*ms")
_LOSS_LINE = re.compile(r"([\d.]+)%\s+packet\s+loss", re.IGNORECASE)
_STATS_LINE = re.compile(r"min/avg/max/(?:stddev|mdev)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")


def parse_ping_output(stdout: str) -> dict:
    """Parse ping statistics out of the standard ping output."""
    times = [float(m.group(1)) for m in _TIME_LINE.finditer(stdout)]
    sent = 0
    received = 0
    loss_pct: Optional[float] = None
    # macOS: "N packets transmitted, M packets received"
    # Linux/iputils (incl. Termux): "N packets transmitted, M received"
    m_total = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received", stdout)
    if m_total:
        sent, received = int(m_total.group(1)), int(m_total.group(2))
    m_loss = _LOSS_LINE.search(stdout)
    if m_loss:
        loss_pct = float(m_loss.group(1))
    elif sent:
        loss_pct = (sent - received) / sent * 100

    min_t = avg_t = max_t = mdev_t = None
    m_stats = _STATS_LINE.search(stdout)
    if m_stats:
        min_t, avg_t, max_t, mdev_t = (float(m_stats.group(i)) for i in (1, 2, 3, 4))

    jitter = statistics.pstdev(times) if len(times) > 1 else 0.0
    return {
        "sent": sent,
        "received": received,
        "loss_pct": loss_pct if loss_pct is not None else (100.0 if sent and not received else 0.0),
        "min_ms": min_t if min_t is not None else (min(times) if times else None),
        "avg_ms": avg_t if avg_t is not None else (statistics.mean(times) if times else None),
        "max_ms": max_t if max_t is not None else (max(times) if times else None),
        "mdev_ms": mdev_t if mdev_t is not None else jitter,
        "jitter_ms": jitter,
        "times_ms": times,
    }


def measure_ping(
    target: str = "8.8.8.8",
    count: int = 10,
    interval_ms: int = 200,
    deadline_s: int = 5,
) -> DiagResult:
    """Run a ping of N probes against the target and report stats."""
    res = DiagResult(title=f"Ping :: {target}")
    rc, stdout, stderr = _run_ping(target, count, interval_ms, deadline_s)
    if rc != 0 and not stdout:
        res.error = stderr.strip() or f"ping failed (rc={rc})"
        return res
    stats = parse_ping_output(stdout)

    sev_loss = Severity.OK if (stats["loss_pct"] or 0) < 1 else (
        Severity.WARN if (stats["loss_pct"] or 0) < 5 else Severity.FAIL
    )
    sev_lat = Severity.OK if (stats["avg_ms"] or 0) < 80 else (
        Severity.WARN if (stats["avg_ms"] or 0) < 200 else Severity.FAIL
    )
    sev_jit = Severity.OK if (stats["jitter_ms"] or 0) < 10 else (
        Severity.WARN if (stats["jitter_ms"] or 0) < 30 else Severity.FAIL
    )

    res.add(
        "Sent/Recv",
        f"{stats['sent']}/{stats['received']}",
    )
    res.add(
        "Loss",
        f"{stats['loss_pct']:.1f}%",
        severity=sev_loss,
    )
    res.add(
        "Avg RTT",
        f"{stats['avg_ms']:.1f} ms" if stats["avg_ms"] is not None else "—",
        severity=sev_lat,
    )
    if stats["min_ms"] is not None and stats["max_ms"] is not None:
        res.add("Min/Max", f"{stats['min_ms']:.1f}/{stats['max_ms']:.1f} ms")
    res.add(
        "Jitter",
        f"{stats['jitter_ms']:.1f} ms" if stats["jitter_ms"] is not None else "—",
        severity=sev_jit,
    )
    res.raw = stats

    summary_bits = []
    if stats["loss_pct"] is not None:
        summary_bits.append(f"loss={stats['loss_pct']:.0f}%")
    if stats["avg_ms"] is not None:
        summary_bits.append(f"avg={stats['avg_ms']:.0f}ms")
    if stats["jitter_ms"] is not None:
        summary_bits.append(f"jit={stats['jitter_ms']:.0f}ms")
    res.summary = " · ".join(summary_bits)
    return res
