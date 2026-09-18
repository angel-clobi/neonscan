"""MTR-style continuous traceroute.

Shells out to system `traceroute -q N -w T` to get multiple probes per hop,
which reveals per-hop packet loss. Falls back to sequential traceroute +
ping-by-ping if multiple probes aren't available.
"""

from __future__ import annotations

import platform
import re
import socket
import statistics
import subprocess
from typing import Optional

from .result import DiagResult, Severity


IS_DARWIN = platform.system() == "Darwin"


def _traceroute_with_probes(target: str, max_hops: int, probes: int, wait_s: int) -> str:
    """Run system traceroute requesting `probes` probes per hop."""
    cmd = [
        "traceroute", "-m", str(max_hops),
        "-q", str(probes),
        "-w", str(wait_s),
        target,
    ]
    try:
        cp = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max_hops * wait_s * probes + 30,
            check=False,
        )
        return cp.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return f"# ERROR: traceroute unavailable: {exc}"


_HOP_LINE = re.compile(r"^\s*(\d+)\s+(\S+)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?\s*(.*)$")


def parse_traceroute_probes(stdout: str) -> list[dict]:
    """Parse traceroute -q N output rows into {hop, host, ip, times_ms: []}."""
    out: list[dict] = []
    for line in stdout.splitlines():
        if not line.strip() or line.strip().startswith(("traceroute to", "darwin", "linux")):
            continue
        m = _HOP_LINE.match(line)
        if not m:
            continue
        hop = int(m.group(1))
        host = m.group(2)
        ip = m.group(3) or "?"
        rest = m.group(4) or ""
        # Walk left-to-right collecting either <num>ms (positive) or bare '*' (timeout).
        times: list[float] = []
        tokens = re.split(r"\s+", rest.strip())
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "*":
                times.append(0.0)
                i += 1
                continue
            # numeric ms (or ms suffix)
            mm = re.match(r"^(\d+(?:\.\d+)?)(ms)?$", tok)
            if mm:
                times.append(float(mm.group(1)))
                # consume optional unit token
                if mm.group(2) is None and i + 1 < len(tokens) and tokens[i + 1] == "ms":
                    i += 2
                    continue
                i += 1
                continue
            i += 1
        out.append({"hop": hop, "host": host, "ip": ip, "times_ms": times})
    return out


def measure_mtr(
    target: str = "8.8.8.8",
    cycles: int = 3,
    max_hops: int = 25,
    probes: int = 3,
) -> DiagResult:
    """Run `cycles` traceroute passes (each with `probes` per hop).

    Aggregates per-hop: avg / min / max / loss% across cycles.
    """
    res = DiagResult(title=f"MTR :: {target}")

    # First pass to learn the actual hop count.
    base = parse_traceroute_probes(
        _traceroute_with_probes(target, max_hops, probes, 1)
    )
    if not base:
        res.error = "traceroute returned no usable output"
        return res
    last_reached = next((h for h in reversed(base) if h["ip"] not in ("?", "*")), None)
    try:
        target_ip = socket.gethostbyname(target)
    except OSError:
        target_ip = target
    reached = bool(last_reached and last_reached["ip"] == target_ip)

    # Aggregate per-hop timing across cycles
    hop_stats: dict[int, dict] = {}
    for h in base:
        hop_stats[h["hop"]] = {
            "host": h["host"], "ip": h["ip"],
            "samples": list(h["times_ms"]),
        }
    for _ in range(max(cycles - 1, 0)):
        nxt = parse_traceroute_probes(
            _traceroute_with_probes(target, max_hops, probes, 1)
        )
        for h in nxt:
            bucket = hop_stats.setdefault(h["hop"], {"host": h["host"], "ip": h["ip"], "samples": []})
            bucket["samples"].extend(h["times_ms"])

    if not hop_stats:
        res.error = "no hops captured across cycles"
        return res

    # Compute statistics
    rows = []
    for hop, info in hop_stats.items():
        samples = info["samples"]
        n = len(samples)
        if n == 0:
            continue
        timeout_count = sum(1 for s in samples if s == 0.0)
        loss_pct = (timeout_count / n) * 100 if n > 0 else 0.0
        good = [s for s in samples if s > 0]
        avg = statistics.mean(good) if good else None
        rows.append({
            "hop": hop, "host": info["host"], "ip": info["ip"],
            "n": n, "loss_pct": loss_pct,
            "avg_ms": avg,
            "min_ms": min(good) if good else None,
            "max_ms": max(good) if good else None,
        })

    rows.sort(key=lambda r: r["hop"])
    res.add("Reaches target", "yes" if reached else "no",
            severity=Severity.OK if reached else Severity.WARN)
    res.add("Total hops", str(len(rows)))
    res.add("Cycles", str(cycles))
    res.add("Probes per hop", str(probes))

    # Surface the worst hops (high loss or rising latency)
    rendered = []
    loss_hops = []
    for r in rows:
        sev = Severity.OK
        if r["loss_pct"] >= 30:
            sev = Severity.FAIL
            loss_hops.append(r["hop"])
        elif r["loss_pct"] >= 5:
            sev = Severity.WARN
        if r["avg_ms"] is not None:
            if r["avg_ms"] >= 200:
                sev = Severity.FAIL
            elif r["avg_ms"] >= 100:
                sev = max([Severity.WARN, sev], key=lambda s: list(Severity).index(s))
        avg_label = f"{r['avg_ms']:.0f}" if r["avg_ms"] is not None else "—"
        res.add(
            f"Hop {r['hop']:>2}",
            f"{r['host']} ({r['ip']}) · {avg_label} ms avg · {r['loss_pct']:.0f}% loss",
            severity=sev,
        )
        rendered.append(r)
    if loss_hops:
        sev = Severity.FAIL if reached else Severity.WARN
        res.add("Lossy hops", ", ".join(str(h) for h in loss_hops),
                severity=sev,
                note="any hop with >5% loss")

    sev_overall = Severity.OK if (reached and not loss_hops) else (
        Severity.WARN if reached and loss_hops else Severity.FAIL
    )
    res.add("Verdict",
            "healthy" if sev_overall == Severity.OK else ("loss upstream" if reached else "did not reach target"),
            severity=sev_overall)
    res.raw = {"rows": rendered, "reached": reached, "cycles": cycles, "probes": probes}
    return res
