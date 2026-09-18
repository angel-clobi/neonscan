"""Watch mode: take a baseline, run diagnostics, report deltas.

Stores a snapshot of selected metrics (signal/ping/dns/public-ip) and
can compare a second run against it to highlight changes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .result import DiagResult, Severity


@dataclass
class Baseline:
    """Snapshot of key diagnostics — used as reference for `--watch`."""

    saved_at: str = ""
    metrics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"saved_at": self.saved_at, "metrics": self.metrics}

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        b = cls()
        b.saved_at = data.get("saved_at", "")
        b.metrics = data.get("metrics", {})
        return b


def build_baseline(results: list[DiagResult]) -> Baseline:
    """Pull representative numbers out of a run and save them as a Baseline."""
    b = Baseline()
    b.saved_at = datetime.now(tz=__import__("datetime").timezone.utc).isoformat()
    for r in results:
        title = r.title
        if title.startswith("Wi-Fi link"):
            rssi_f = next((f for f in r.findings if f.label == "RSSI" and f.severity != Severity.INFO), None)
            if rssi_f:
                b.metrics["wifi_rssi"] = str(rssi_f.value)
            snr_f = next((f for f in r.findings if f.label == "SNR"), None)
            if snr_f:
                b.metrics["wifi_snr"] = str(snr_f.value)
        elif title.startswith("Ping ::"):
            loss_f = next((f for f in r.findings if f.label == "Loss"), None)
            avg_f = next((f for f in r.findings if f.label == "Avg RTT"), None)
            if loss_f:
                m = __import__("re").search(r"([\d.]+)\s*%", str(loss_f.value))
                if m:
                    b.metrics["ping_loss_pct"] = float(m.group(1))
            if avg_f:
                m = __import__("re").search(r"([\d.]+)", str(avg_f.value))
                if m:
                    b.metrics["ping_avg_ms"] = float(m.group(1))
        elif title.startswith("Speed ·"):
            b.metrics["speed_mbps"] = r.summary  # e.g. "227 Mbps"
        elif title.startswith("DNS ::"):
            res_f = next((f for f in r.findings if f.label == "Resolvers"), None)
            if res_f:
                m = __import__("re").search(r"(\d+)/(\d+)", str(res_f.value))
                if m:
                    b.metrics["dns_ok"] = int(m.group(1))
                    b.metrics["dns_total"] = int(m.group(2))
        elif title.startswith("Public IP"):
            ip_f = next((f for f in r.findings if f.label == "IP"), None)
            if ip_f:
                b.metrics["public_ip"] = str(ip_f.value)
    return b


def save_baseline(b: Baseline, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(b.to_dict(), indent=2))


def load_baseline(path: Path) -> Optional[Baseline]:
    if not path.exists():
        return None
    try:
        return Baseline.from_dict(json.loads(path.read_text()))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def diff_against_baseline(b: Baseline, results: list[DiagResult]) -> DiagResult:
    """Return a DiagResult describing how the current run differs from `b`."""
    res = DiagResult(title="Diff vs baseline")
    cur = build_baseline(results)

    # numeric deltas
    numeric_targets = {
        "ping_avg_ms": ("Δ ping avg RTT", "%+.1f ms", Severity.WARN, 25, Severity.FAIL, 75),
        "ping_loss_pct": ("Δ ping loss", "%+.1f%%", Severity.WARN, 1.0, Severity.FAIL, 5.0),
        "wifi_rssi": ("Δ RSSI", "%+s dBm", Severity.WARN, 5, Severity.FAIL, 15),
    }
    if cur.metrics.get("speed_mbps") != b.metrics.get("speed_mbps"):
        res.add("Speed", f"{b.metrics.get('speed_mbps','—')} → {cur.metrics.get('speed_mbps','—')}")
    if cur.metrics.get("public_ip") and cur.metrics["public_ip"] != b.metrics.get("public_ip"):
        res.add("Public IP", f"{b.metrics.get('public_ip','—')} → {cur.metrics['public_ip']}",
                severity=Severity.WARN, note="IP changed")
    if cur.metrics.get("dns_ok") is not None and cur.metrics.get("dns_total") is not None:
        ok = cur.metrics["dns_ok"]
        total = cur.metrics["dns_total"]
        b_ok = b.metrics.get("dns_ok")
        if b_ok is not None:
            res.add(
                "DNS resolvers OK",
                f"{b_ok}/{cur.metrics.get('dns_total', total)} → {ok}/{total}",
            )

    for k, (lbl, fmt, warn_sev, warn_thr, fail_sev, fail_thr) in numeric_targets.items():
        old = b.metrics.get(k)
        new = cur.metrics.get(k)
        if old is None or new is None:
            continue
        try:
            old_f, new_f = float(old), float(new)
        except (TypeError, ValueError):
            continue
        delta = new_f - old_f
        # Strip a "wifi_rssi": string such as "-67 dBm"
        def numval(v):
            m = __import__("re").search(r"-?\d+", str(v))
            return float(m.group()) if m else None

        old_n = numval(old)
        new_n = numval(new)
        if old_n is None or new_n is None:
            continue
        delta = new_n - old_n
        sign = "%+.1f"
        # Wi-Fi RSSI got worse if it's more negative
        if k == "wifi_rssi":
            severity = (
                Severity.OK if delta >= 0 else
                (warn_sev if -delta >= warn_thr and -delta < fail_thr else fail_sev)
            )
        else:
            severity = (
                Severity.OK if abs(delta) < warn_thr else (
                    warn_sev if abs(delta) < fail_thr else fail_sev
                )
            )
        res.add(lbl, sign % delta, severity=severity,
                note=f"baseline {old_n}, now {new_n}")
    # if no deltas at all:
    if not res.findings:
        res.add("Verdict", "no measurable change", severity=Severity.OK,
                note="snapshot within noise")
    res.raw = {"baseline": b.to_dict(), "current": cur.to_dict()}
    return res


def watch_loop(
    out: Path,
    interval_s: float = 30.0,
    cycles: int = 3,
):
    """Run diagnostics `cycles` times with `interval_s` between, comparing cycles.

    Imports inside to avoid cycles between `watch` and `report`.
    """
    import time
    from .report import run_full_diag

    last: Optional[Baseline] = None
    snapshots: list[Baseline] = []
    for i in range(cycles):
        results = run_full_diag(monitor_s=0.0, speed_size_mb=2)
        b = build_baseline(results)
        snapshots.append(b)
        if last is not None:
            diff_against_baseline(last, results)
        last = b
        time.sleep(interval_s)
    return snapshots
