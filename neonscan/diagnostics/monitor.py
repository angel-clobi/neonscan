"""Live monitor — poll RSSI + per-interface byte counters for N seconds.

Outputs a small time-series + summary statistics.
"""

from __future__ import annotations

import platform
import re
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .result import DiagResult, Severity


IS_DARWIN = platform.system() == "Darwin"


def _is_termux() -> bool:
    import os

    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    return os.path.isdir("/data/data/com.termux/files")


_AIRPORT = Path(
    "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
)


@dataclass
class Sample:
    t: float
    rssi: Optional[int]
    noise: Optional[int]
    bytes_in: int
    bytes_out: int


def _read_airport_rssi() -> tuple[Optional[int], Optional[int]]:
    """Read current RSSI/Noise (airport on macOS, termux-api on Android)."""
    if _is_termux():
        try:
            from .wifi import termux_wifi_connectioninfo

            data = termux_wifi_connectioninfo()
            if data and isinstance(data.get("rssi"), int):
                return data["rssi"], None
        except Exception:  # noqa: BLE001
            pass
        return None, None
    if not IS_DARWIN or not _AIRPORT.exists():
        return None, None
    try:
        cp = subprocess.run(
            [str(_AIRPORT), "-I"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None, None
    if cp.returncode != 0:
        return None, None
    rssi = noise = None
    for line in cp.stdout.splitlines():
        m = re.search(r"agrctlRSSI:\s*(-?\d+)", line)
        if m:
            rssi = int(m.group(1))
        m = re.search(r"agrctlNoise:\s*(-?\d+)", line)
        if m:
            noise = int(m.group(1))
    return rssi, noise


def _read_iface_bytes(iface: str) -> tuple[int, int]:
    """Read (rx_bytes, tx_bytes) for an interface."""
    if IS_DARWIN:
        try:
            cp = subprocess.run(
                ["netstat", "-I", iface, "-b"],
                capture_output=True, text=True, timeout=2, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return 0, 0
        if cp.returncode != 0:
            return 0, 0
        lines = [l for l in cp.stdout.splitlines() if l]
        # `netstat -I <if> -b` columns:
        #   0 Name 1 Mtu 2 Network 3 Address 4 Ipkts 5 Ierrs 6 Ibytes
        #   7 Opkts 8 Oerrs 9 Obytes 10 Coll
        for line in lines:
            cols = re.split(r"\s+", line.strip())
            if len(cols) >= 10 and cols[0] == iface:
                try:
                    return int(cols[6]), int(cols[9])  # Ibytes, Obytes
                except (ValueError, IndexError):
                    continue
        return 0, 0
    # Linux / Termux: /proc/net/dev
    try:
        with open("/proc/net/dev") as f:
            text = f.read()
    except OSError:
        return 0, 0
    return _parse_proc_net_dev(text, iface)


def _parse_proc_net_dev(text: str, iface: str) -> tuple[int, int]:
    """Return (rx_bytes, tx_bytes) for `iface` from /proc/net/dev contents.

    The interface name is right-justified and followed by ':', e.g.
    ``"  wlan0: 12345 67 ..."``.  Receive bytes is the 1st field after the
    colon, transmit bytes the 9th.
    """
    for line in text.splitlines():
        name, sep, rest = line.partition(":")
        if not sep or name.strip() != iface:
            continue
        fields = rest.split()
        if len(fields) < 9:
            return 0, 0
        try:
            return int(fields[0]), int(fields[8])
        except (ValueError, IndexError):
            return 0, 0
    return 0, 0


def monitor_link(
    duration_s: float = 8.0,
    interval_s: float = 1.0,
    iface: Optional[str] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> DiagResult:
    """Sample RSSI and per-interface bytes for `duration_s` seconds."""
    res = DiagResult(title=f"Monitor ({duration_s:.0f}s)")

    if iface is None:
        from .routes import get_routes
        r = get_routes()
        iface_match = next((f for f in r.findings if f.label == "Interface"), None)
        iface = iface_match.value if iface_match and iface_match.value != "?" else "en0"

    samples: list[Sample] = []
    t0 = time.time()
    next_tick = t0
    elapsed = 0.0
    prev_rx, prev_tx = _read_iface_bytes(iface)
    first_capture = True
    while elapsed <= duration_s:
        now = time.time()
        if now < next_tick:
            time.sleep(min(next_tick - now, 0.05))
            continue
        next_tick += interval_s
        rssi, noise = _read_airport_rssi()
        rx, tx = _read_iface_bytes(iface)
        if not first_capture:
            samples.append(
                Sample(
                    t=now,
                    rssi=rssi,
                    noise=noise,
                    bytes_in=max(rx - prev_rx, 0),
                    bytes_out=max(tx - prev_tx, 0),
                )
            )
        else:
            first_capture = False
        prev_rx, prev_tx = rx, tx
        elapsed = now - t0
        if progress_cb is not None:
            progress_cb(int(elapsed), int(duration_s))

    if not samples:
        res.error = "no samples collected"
        return res

    rx = [s.bytes_in for s in samples]
    tx = [s.bytes_out for s in samples]
    rssi_vals = [s.rssi for s in samples if s.rssi is not None]
    res.add("Interface", iface)
    res.add("Samples", str(len(samples)))
    if rssi_vals:
        avg = sum(rssi_vals) / len(rssi_vals)
        mn = min(rssi_vals)
        mx = max(rssi_vals)
        sev = Severity.OK if avg >= -65 else (Severity.WARN if avg >= -75 else Severity.FAIL)
        res.add("RSSI", f"avg={avg:.0f} dBm (range {mn}/{mx})", severity=sev)
    if rx:
        sum_rx = sum(rx)
        sum_tx = sum(tx)
        period = sum(1 for _ in samples) * interval_s
        bps_rx = sum_rx * 8 / max(period, 1e-6)
        bps_tx = sum_tx * 8 / max(period, 1e-6)
        res.add("Total bytes", f"in {sum_rx:,} / out {sum_tx:,}")
        res.add("Throughput", f"rx {bps_rx / 1e6:.2f} Mbps / tx {bps_tx / 1e6:.2f} Mbps")

    # ASCII bar (rx rate) over time
    if rx:
        maxv = max(rx + [1])
        bars = []
        for s in samples[::max(1, len(samples) // 24)]:
            width = int((s.bytes_in / maxv) * 24)
            bars.append("█" * width + "·" * (24 - width))
        res.add("Rx pattern (downsampled)", " ".join(bars))

    res.raw = {
        "interface": iface,
        "duration_s": duration_s,
        "interval_s": interval_s,
        "samples": [s.__dict__ for s in samples],
    }
    return res
