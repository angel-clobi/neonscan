"""Wi-Fi link diagnostics: SSID, BSSID, RSSI, channel, link rate, country."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .result import DiagResult, Severity


IS_DARWIN = platform.system() == "Darwin"


def _is_termux() -> bool:
    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    return os.path.isdir("/data/data/com.termux/files")


# macOS stores the private 'airport' utility inside the Apple80211 framework bundle.
# NOTE: 'airport' is deprecated since macOS 14 (Sonoma) and returns no data on
# 14.4+, so we fall back to `system_profiler SPAirPortDataType` there.
_AIRPORT = (
    Path("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
)


# ---------------------------------------------------------------------------
# Termux (Android) path — needs the Termux:API app + `pkg install termux-api`
# ---------------------------------------------------------------------------

def termux_wifi_connectioninfo() -> Optional[dict]:
    """Return the parsed `termux-wifi-connectioninfo` JSON, or None."""
    if not shutil.which("termux-wifi-connectioninfo"):
        return None
    rc, stdout, _ = _run(["termux-wifi-connectioninfo"], timeout=6.0)
    if rc != 0 or not stdout.strip():
        return None
    return _parse_termux_conninfo(stdout)


def _parse_termux_conninfo(stdout: str) -> Optional[dict]:
    try:
        data = json.loads(stdout)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _wifi_termux(res: DiagResult) -> Optional[DiagResult]:
    data = termux_wifi_connectioninfo()
    if not data:
        return None
    ssid = (data.get("ssid") or "").strip('"') or "—"
    if ssid in ("<unknown ssid>", "0x", ""):
        ssid = "—"
    bssid = data.get("bssid") or "—"
    rssi = data.get("rssi")
    freq = data.get("frequency_mhz")
    rate = data.get("link_speed_mbps")
    res.add("SSID", ssid)
    res.add("BSSID", bssid)
    if isinstance(rssi, int):
        sev = Severity.OK if rssi >= -65 else (Severity.WARN if rssi >= -75 else Severity.FAIL)
        res.add("RSSI", f"{rssi} dBm", severity=sev)
    if isinstance(freq, int) and freq > 0:
        ghz = freq / 1000.0
        band = "2.4 GHz" if freq < 2500 else ("5 GHz" if freq < 5925 else "6 GHz")
        ch = _mhz_to_channel(freq)
        res.add("Channel", f"{ch} ({band})" if ch else band)
    if isinstance(rate, int) and rate > 0:
        res.add("TX rate", f"{rate} Mbps")
    if data.get("ip"):
        res.add("IP", data["ip"])
    state = data.get("supplicant_state")
    if state:
        res.add("State", str(state))
    res.raw = {**data, "tool": "termux-wifi-connectioninfo"}
    return res


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: float = 6.0) -> tuple[int, str, str]:
    """Run a subprocess and capture (rc, stdout, stderr)."""
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return out.returncode, out.stdout, out.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 1, "", str(exc)


def _channel_band(channel: Optional[int]) -> str:
    """Classify a Wi-Fi channel into 2.4/5/6 GHz band."""
    if channel is None:
        return "?"
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    if channel >= 1 and channel <= 233:
        # ambiguous 5 GHz with newer 6E numbers that overlap the same range mapping
        # We'll refine once channel width is known via system_profiler.
        if channel >= 1:
            return "5 GHz"  # default guess
        return "6 GHz"
    return "?"


# ---------------------------------------------------------------------------
# macOS path
# ---------------------------------------------------------------------------

_AIRPORT_INFO_LINE = re.compile(r"^\s*([A-Za-z ][A-Za-z0-9 ]*?):\s*(.*)$")


def _parse_airport_info(stdout: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in stdout.splitlines():
        # macOS 14+ emits only a deprecation notice here — ignore it so the
        # caller sees an empty dict and falls back to system_profiler.
        if "deprecated" in line.lower() or line.lstrip().startswith("WARNING:"):
            continue
        if "Wireless Diagnostics" in line or "wdutil" in line:
            continue
        m = _AIRPORT_INFO_LINE.match(line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            # 'AgrCtlRSSI:' etc.
            out[key] = val
            # Stable lookup form for code below
            canonical = re.sub(r"[^A-Za-z0-9]+", "", key).lower()
            out[canonical] = val
    return out


_AIRPORT_SCAN_LINE = re.compile(
    r"^\s*([0-9A-Fa-f:]{17})\s+(-?\d+)\s+(\S+)\s+([A-Z0-9-]+)\s+.*?\b(\d+)\b,\s*(-?\d+)"
)


def get_wifi_info() -> DiagResult:
    """Return current Wi-Fi link info. Cross-platform (macOS / Linux / Termux)."""
    res = DiagResult(title="Wi-Fi link")

    # Termux (Android): use the termux-api bridge before anything else.
    if _is_termux():
        termux_res = _wifi_termux(res)
        if termux_res is not None:
            return termux_res

    if IS_DARWIN and _AIRPORT.exists():
        rc, info_stdout, _ = _run([str(_AIRPORT), "-I"])
        info = _parse_airport_info(info_stdout) if rc == 0 else {}

        rc2, scan_stdout, _ = _run([str(_AIRPORT), "-s"])
        # gather neighbor count from scan
        neighbor_count = 0
        if rc2 == 0:
            for _ in _AIRPORT_SCAN_LINE.finditer(scan_stdout):
                neighbor_count += 1

        ssid = info.get("SSID") or info.get("ssid") or info.get("networkname") or "—"
        bssid = info.get("BSSID") or info.get("bssid") or "—"
        rssi_raw = info.get("agrctlRSSI") or info.get("RSSI") or "—"
        try:
            rssi = int(re.findall(r"-?\d+", rssi_raw)[0])
        except (ValueError, IndexError):
            rssi = None
        noise_raw = info.get("agrctlNoise") or info.get("Noise") or "—"
        try:
            noise = int(re.findall(r"-?\d+", noise_raw)[0])
        except (ValueError, IndexError):
            noise = None
        channel = info.get("channel") or info.get("Channel") or info.get("channelinuse")
        try:
            ch_int: Optional[int] = int(re.findall(r"\d+", channel)[0]) if channel else None
        except (ValueError, IndexError):
            ch_int = None
        rate_raw = info.get("lastTxRate") or info.get("TxRate") or info.get("Maximumtransmissionrate") or "—"
        try:
            rate_mbps = int(re.findall(r"\d+", rate_raw)[0])
        except (ValueError, IndexError):
            rate_mbps = None
        auth = info.get("Authentication") or info.get("auth") or "—"
        mode = info.get("Mode") or info.get("mode") or "—"
        country = info.get("CountryCode") or info.get("country") or info.get("countryCode") or "—"

        snr: Optional[int] = None
        if rssi is not None and noise is not None:
            snr = rssi - noise

        sev = Severity.OK if (rssi is None or rssi >= -65) else (
            Severity.WARN if (rssi >= -75) else Severity.FAIL
        )
        res.add("SSID", ssid)
        res.add("BSSID", bssid)
        res.add("RSSI", f"{rssi} dBm" if rssi is not None else "?", severity=sev)
        if noise is not None:
            noise_sev = Severity.OK if (noise >= -90) else Severity.WARN
            res.add("Noise", f"{noise} dBm", severity=noise_sev)
        if snr is not None:
            snr_sev = Severity.OK if (snr >= 30) else (Severity.WARN if (snr >= 15) else Severity.FAIL)
            res.add("SNR", f"{snr} dB", severity=snr_sev, note="signal-to-noise ratio")
        if ch_int is not None:
            res.add("Channel", f"{ch_int} ({_channel_band(ch_int)})")
        if rate_mbps is not None:
            res.add("TX rate", f"{rate_mbps} Mbps")
        res.add("Authentication", auth)
        res.add("Mode", mode)
        res.add("Country", country)
        if neighbor_count:
            note = "nearby APs in scan" if rssi is not None and rssi >= -65 else (
                "neighbors visible" if rssi is not None and rssi >= -75 else "congested airspace"
            )
            sev2 = Severity.OK if neighbor_count < 8 else (
                Severity.WARN if neighbor_count < 20 else Severity.FAIL
            )
            res.add("Neighbors", neighbor_count, severity=sev2, note=note)

        res.raw = {
            "ssid": ssid, "bssid": bssid, "rssi": rssi, "noise": noise,
            "snr": snr, "channel": ch_int, "rate_mbps": rate_mbps,
            "auth": auth, "mode": mode, "country": country,
            "neighbors": neighbor_count, "tool": "airport",
        }
        if not info:
            # macOS 14+ neutered `airport`; fall back to system_profiler.
            sp = _wifi_macos_system_profiler(DiagResult(title="Wi-Fi link"))
            if sp is not None:
                return sp
            res.error = (
                "No Wi-Fi info without elevated rights on macOS 14+ "
                "(airport is deprecated; try `sudo wdutil info`, or enable Location "
                "Services so `system_profiler SPAirPortDataType` exposes the SSID)."
            )
        return res

    if IS_DARWIN:
        sp = _wifi_macos_system_profiler(res)
        if sp is not None:
            return sp

    # Linux fallback via iwconfig / iw dev
    rc, stdout, _ = _run(["iwconfig"])
    if rc == 0 and stdout.strip():
        ssid = ""
        bssid = ""
        freq = ""
        rssi = None
        for line in stdout.splitlines():
            if "ESSID:" in line:
                ssid = line.split("ESSID:", 1)[1].strip().strip('"') or "<hidden>"
            if "Access Point:" in line or "Cell:" in line:
                m = re.search(r"([0-9A-Fa-f:]{17})", line)
                if m:
                    bssid = m.group(1)
            if "Frequency:" in line:
                freq = line.split("Frequency:", 1)[1].split()[0]
            if "Signal level" in line:
                m = re.search(r"Signal level=(-?\d+)\s*dBm", line)
                if m:
                    rssi = int(m.group(1))
        res.add("SSID", ssid or "—")
        res.add("BSSID", bssid or "—")
        if freq:
            try:
                ghz = float(freq)
                if 2.4 <= ghz <= 2.5:
                    band = "2.4 GHz"
                elif 5 <= ghz <= 6:
                    band = "5 GHz"
                elif 6 <= ghz <= 7:
                    band = "6 GHz"
                else:
                    band = "?"
                ch = _freq_to_channel(ghz) if band != "?" else None
                res.add("Channel", f"{ch} ({band})" if ch else band)
            except ValueError:
                res.add("Channel", freq)
        if rssi is not None:
            sev = Severity.OK if rssi >= -65 else (Severity.WARN if rssi >= -75 else Severity.FAIL)
            res.add("RSSI", f"{rssi} dBm", severity=sev)
        res.raw = {"ssid": ssid, "bssid": bssid, "freq": freq, "rssi": rssi, "tool": "iwconfig"}
        return res

    if _is_termux():
        res.error = (
            "No Wi-Fi info — install Termux:API (app + `pkg install termux-api`) "
            "for `termux-wifi-connectioninfo`."
        )
    else:
        res.error = "No Wi-Fi tool available (need 'airport'/system_profiler on macOS or 'iwconfig' on Linux)."
    return res


# ---------------------------------------------------------------------------
# macOS 14+ fallback: system_profiler SPAirPortDataType (no airport needed)
# ---------------------------------------------------------------------------

def _wifi_macos_system_profiler(res: DiagResult) -> Optional[DiagResult]:
    """Parse current Wi-Fi link from `system_profiler SPAirPortDataType`.

    Works on modern macOS where the private `airport` tool no longer returns
    data.  Returns None if the block can't be found.
    """
    rc, stdout, _ = _run(["system_profiler", "SPAirPortDataType"], timeout=12.0)
    if rc != 0 or "Current Network Information" not in stdout:
        return None
    info = _parse_system_profiler(stdout)
    if not info.get("ssid"):
        return None
    res.add("SSID", info["ssid"])
    if info.get("bssid"):
        res.add("BSSID", info["bssid"])
    rssi = info.get("rssi")
    if rssi is not None:
        sev = Severity.OK if rssi >= -65 else (Severity.WARN if rssi >= -75 else Severity.FAIL)
        res.add("RSSI", f"{rssi} dBm", severity=sev)
        noise = info.get("noise")
        if noise is not None:
            res.add("SNR", f"{rssi - noise} dB", note="signal-to-noise ratio")
    if info.get("channel_label"):
        res.add("Channel", info["channel_label"])
    if info.get("phy"):
        res.add("Mode", info["phy"])
    if info.get("rate_mbps"):
        res.add("TX rate", f"{info['rate_mbps']} Mbps")
    res.raw = {**info, "tool": "system_profiler"}
    return res


def _parse_system_profiler(stdout: str) -> dict:
    """Pull the fields under 'Current Network Information:' into a dict."""
    out: dict = {}
    lines = stdout.splitlines()
    # The SSID is the indented line right under "Current Network Information:".
    for i, line in enumerate(lines):
        if "Current Network Information:" in line:
            for j in range(i + 1, min(i + 2, len(lines))):
                ssid = lines[j].strip().rstrip(":")
                if ssid:
                    out["ssid"] = ssid
            break

    def grab(label: str) -> str:
        m = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", stdout, re.MULTILINE)
        return m.group(1).strip() if m else ""

    phy = grab("PHY Mode")
    if phy:
        out["phy"] = phy
    ch = grab("Channel")
    if ch:
        out["channel_label"] = ch
    sig = grab("Signal / Noise")
    if sig:
        nums = re.findall(r"-?\d+", sig)
        if len(nums) >= 1:
            out["rssi"] = int(nums[0])
        if len(nums) >= 2:
            out["noise"] = int(nums[1])
    rate = grab("Transmit Rate")
    if rate:
        m = re.search(r"\d+", rate)
        if m:
            out["rate_mbps"] = int(m.group(0))
    return out


def _mhz_to_channel(mhz: int) -> Optional[int]:
    """Convert a Wi-Fi centre frequency in MHz to a channel number."""
    if 2412 <= mhz <= 2484:
        if mhz == 2484:
            return 14
        return (mhz - 2407) // 5
    if 5000 <= mhz < 5900:
        return (mhz - 5000) // 5
    if 5925 <= mhz <= 7125:  # 6 GHz (Wi-Fi 6E)
        return (mhz - 5950) // 5 + 1
    return None


def _freq_to_channel(ghz: float) -> Optional[int]:
    """Approximate channel from frequency (works for 2.4/5/6 GHz)."""
    if 2.4 <= ghz <= 2.5:
        return int(round((ghz - 2.412) / 0.005)) + 1
    if 5.0 <= ghz <= 5.9:
        # crude mapping for 5 GHz
        return int(ghz * 1000 - 5000)
    if 6.0 <= ghz <= 7.0:
        # 6E: ch = (freq_mhz - 5950) / 5 + 1
        return int((ghz * 1000 - 5950) / 5) + 1
    return None


# ---------------------------------------------------------------------------
# Convenience: list nearby APs (used by tests / future live UI)
# ---------------------------------------------------------------------------

def list_nearby_aps(limit: int = 25) -> list[dict]:
    """Return a list of nearby APs (BSSID, RSSI, channel, ssid).

    macOS uses the (deprecated) airport scan; Termux uses `termux-wifi-scaninfo`
    from Termux:API.  Everything else returns an empty list.
    """
    out: list[dict] = []
    if _is_termux():
        return _aps_termux(limit)
    if not (IS_DARWIN and _AIRPORT.exists()):
        return out
    rc, stdout, _ = _run([str(_AIRPORT), "-s"])
    if rc != 0:
        return out
    for line in stdout.splitlines():
        m = _AIRPORT_SCAN_LINE.match(line)
        if m:
            bssid, rssi, _ssid, sec, channel, _extra = m.groups()
            out.append(
                {
                    "bssid": bssid.upper(),
                    "rssi": int(rssi),
                    "ssid": _ssid,
                    "security": sec,
                    "channel": int(channel),
                }
            )
    out.sort(key=lambda a: a["rssi"], reverse=True)
    return out[:limit]


def _aps_termux(limit: int = 25) -> list[dict]:
    """Nearby APs via `termux-wifi-scaninfo` (Termux:API)."""
    if not shutil.which("termux-wifi-scaninfo"):
        return []
    rc, stdout, _ = _run(["termux-wifi-scaninfo"], timeout=8.0)
    if rc != 0 or not stdout.strip():
        return []
    out = _parse_termux_scaninfo(stdout)
    out.sort(key=lambda a: a["rssi"], reverse=True)
    return out[:limit]


def _parse_termux_scaninfo(stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    out: list[dict] = []
    for ap in data:
        if not isinstance(ap, dict):
            continue
        mhz = ap.get("frequency_mhz") or 0
        ch = _mhz_to_channel(int(mhz)) if mhz else None
        out.append({
            "bssid": (ap.get("bssid") or "").upper(),
            "rssi": int(ap.get("rssi", 0)),
            "ssid": ap.get("ssid") or "—",
            "security": "?",
            "channel": ch or 0,
        })
    return out
