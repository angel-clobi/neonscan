"""Diagnostics suite for NeonScan.

Each module is self-contained, returns a structured dataclass, and degrades
gracefully when optional tools (iperf3, dig, lsof) are missing.
"""

from .result import DiagResult, Finding, Severity
from .wifi import get_wifi_info, list_nearby_aps
from .ping import measure_ping
from .dns import measure_dns
from .speed import (
    measure_download,
    measure_upload,
    measure_iperf3,
    lan_bandtest,
)
from .public_ip import get_public_ip
from .traceroute import measure_traceroute
from .connections import get_connections
from .routes import get_routes, get_dhcp_lease
from .monitor import monitor_link
from .report import (
    to_markdown,
    to_json,
    write_report,
    render_table as render_diag_table,
    run_full_diag,
    run_full_diag_summary,
)
from .tls import inspect_tls
from .captive import detect_captive
from .mtr import measure_mtr
from .arpwatch import analyze_arp
from .mdns import discover_mdns
from .watch import (
    Baseline,
    build_baseline,
    save_baseline,
    load_baseline,
    diff_against_baseline,
)
from .topology import (
    topology_to_mermaid,
    topology_to_dot,
    export_topology,
    privacy_score_ipv6,
    classify_ipv6_for_hosts,
)

__all__ = [
    "DiagResult",
    "Finding",
    "Severity",
    "get_wifi_info",
    "list_nearby_aps",
    "measure_ping",
    "measure_dns",
    "measure_download",
    "measure_upload",
    "measure_iperf3",
    "lan_bandtest",
    "get_public_ip",
    "measure_traceroute",
    "get_connections",
    "get_routes",
    "get_dhcp_lease",
    "monitor_link",
    "inspect_tls",
    "detect_captive",
    "measure_mtr",
    "analyze_arp",
    "discover_mdns",
    "Baseline",
    "build_baseline",
    "save_baseline",
    "load_baseline",
    "diff_against_baseline",
    "topology_to_mermaid",
    "topology_to_dot",
    "export_topology",
    "privacy_score_ipv6",
    "classify_ipv6_for_hosts",
    "to_markdown",
    "to_json",
    "write_report",
    "render_diag_table",
    "run_full_diag",
    "run_full_diag_summary",
]
