"""Combine multiple DiagResults into a single Markdown + JSON report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from rich.console import Console
from rich.table import Table

from .result import DiagResult, Severity
from .wifi import get_wifi_info
from .ping import measure_ping
from .dns import measure_dns
from .speed import measure_download
from .public_ip import get_public_ip
from .traceroute import measure_traceroute
from .connections import get_connections
from .routes import get_routes, get_dhcp_lease
from .monitor import monitor_link


SEV_BADGES = {
    Severity.OK: "✅",
    Severity.INFO: "•",
    Severity.WARN: "⚠️",
    Severity.FAIL: "❌",
}


def to_markdown(results: list[DiagResult], title: str = "NeonScan report") -> str:
    """Render a Markdown report suitable for sharing / pasting."""
    lines: list[str] = [f"# {title}", ""]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"_generated {ts}_  ")
    lines.append("")
    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Diagnostic | Status | Summary |")
    lines.append("|---|---|---|")
    for r in results:
        badge = (
            "❌"
            if not r.ok
            else (
                "⚠️"
                if any(f.severity == Severity.WARN for f in r.findings)
                else (
                    "✅"
                    if r.findings and all(f.severity == Severity.OK for f in r.findings)
                    else "•"
                )
            )
        )
        lines.append(f"| {r.title} | {badge} | {r.summary or (r.error or '—')} |")
    lines.append("")

    # Detail sections
    for r in results:
        lines.append(f"## {r.title}")
        lines.append("")
        if not r.ok:
            lines.append(f"**ERROR**: {r.error or 'unknown'}")
            lines.append("")
        if r.summary:
            lines.append(f"> {r.summary}")
            lines.append("")
        if r.findings:
            lines.append("| Field | Value | Note |")
            lines.append("|---|---|---|")
            for f in r.findings:
                lines.append(f"| {f.label} | {f.value} | {f.note or ''} |")
            lines.append("")
    return "\n".join(lines)


def to_json(results: list[DiagResult]) -> str:
    """Serialize all diagnostic results to JSON."""
    out = {
        "scanner": "neonscan",
        "generated": datetime.now(timezone.utc).isoformat(),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(out, indent=2, default=str)


def write_report(
    path: Path,
    results: list[DiagResult],
    title: str = "NeonScan report",
    fmt: Optional[str] = None,
) -> None:
    """Write results to disk. If fmt is None, infer from extension."""
    fmt = fmt or path.suffix.lstrip(".").lower() or "md"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = to_json(results) if fmt == "json" else to_markdown(results, title=title)
    path.write_text(text)


def render_table(console: Console, results: list[DiagResult]) -> Table:
    """Pretty summary table (rich)."""
    table = Table(title="[bold]Full diagnostics", box=None)
    table.add_column("Module", style="cyan bold")
    table.add_column("Status", justify="center")
    table.add_column("Summary", style="magenta")
    for r in results:
        worst = _worst(r)
        badge = SEV_BADGES.get(worst, "•")
        table.add_row(r.title, badge, r.summary or (r.error or "—"))
    return table


def run_full_diag(
    *,
    ping_target: str = "8.8.8.8",
    ping_count: int = 6,
    speed_size_mb: int = 8,
    dns_name: str = "google.com",
    traceroute_target: str = "8.8.8.8",
    traceroute_hops: int = 16,
    monitor_s: float = 0.0,
    step_cb: Optional[Callable[[int, str], None]] = None,
) -> list[DiagResult]:
    """Run the full diagnostics suite in sequence. Returns the ordered results."""
    results: list[DiagResult] = []

    def step(idx: int, label: str):
        if step_cb is not None:
            step_cb(idx, label)

    step(1, "Wi-Fi link");         results.append(get_wifi_info())
    step(2, "Routes / gateway");    results.append(get_routes())
    step(3, "DHCP lease");          results.append(get_dhcp_lease())
    step(4, "Public IP");           results.append(get_public_ip())
    step(5, "DNS resolvers");       results.append(measure_dns(name=dns_name))
    step(6, f"Ping {ping_target}"); results.append(measure_ping(target=ping_target, count=ping_count))
    step(7, f"Traceroute {traceroute_target}"); results.append(measure_traceroute(target=traceroute_target, max_hops=traceroute_hops))
    step(8, "Active connections");  results.append(get_connections())
    step(9, f"Download {speed_size_mb} MB"); results.append(measure_download(sizes=[speed_size_mb * 1_000_000]))
    if monitor_s > 0:
        step(10, f"Link monitor ({monitor_s:.0f}s)"); results.append(monitor_link(duration_s=monitor_s))
    return results


def run_full_diag_summary(results: list[DiagResult]) -> dict:
    """Cheap aggregator useful for the dashboard."""
    out = {
        "ran": len(results),
        "ok": sum(1 for r in results if r.ok and not any(f.severity == Severity.FAIL for f in r.findings)),
        "warn": sum(1 for r in results if any(f.severity == Severity.WARN for f in r.findings) and not any(f.severity == Severity.FAIL for f in r.findings)),
        "fail": sum(1 for r in results if (not r.ok) or any(f.severity == Severity.FAIL for f in r.findings)),
        "errors": [r.title for r in results if not r.ok],
        "warnings": [r.title for r in results if any(f.severity == Severity.WARN for f in r.findings)],
    }
    return out


def _worst(r: DiagResult) -> Severity:
    if not r.ok:
        return Severity.FAIL
    seen = {f.severity for f in r.findings}
    if Severity.FAIL in seen:
        return Severity.FAIL
    if Severity.WARN in seen:
        return Severity.WARN
    if r.findings:
        return Severity.OK
    return Severity.INFO
