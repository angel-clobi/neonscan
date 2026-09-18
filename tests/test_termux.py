"""Tests for the Termux / Linux portability adapters (pure parsers).

These exercise the parsing helpers directly with captured command output, so
they run and pass on any platform (no Android or extra binaries required).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from neonscan.diagnostics import connections, monitor, ping, routes, wifi
from neonscan import network


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def test_platform_flags_exist():
    assert isinstance(network.IS_TERMUX, bool)
    assert isinstance(network.IS_ANDROID, bool)
    # On a normal dev box these must be False.
    assert network.IS_TERMUX is False


# ---------------------------------------------------------------------------
# ping — Linux/iputils "N received" (no "packets") must be parsed
# ---------------------------------------------------------------------------

_LINUX_PING = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=11.2 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=10.9 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=118 time=12.1 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 10.9/11.4/12.1/0.51 ms
"""

_MAC_PING = """PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=118 time=11.2 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 10.9/11.4/12.1/0.51 ms
"""


def test_ping_parse_linux_sent_recv():
    stats = ping.parse_ping_output(_LINUX_PING)
    assert stats["sent"] == 3
    assert stats["received"] == 3
    assert stats["loss_pct"] == 0.0
    assert abs(stats["avg_ms"] - 11.4) < 0.01


def test_ping_parse_macos_sent_recv():
    stats = ping.parse_ping_output(_MAC_PING)
    assert stats["sent"] == 3 and stats["received"] == 3


# ---------------------------------------------------------------------------
# connections — `ss -tuna`
# ---------------------------------------------------------------------------

_SS_OUT = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22        0.0.0.0:*
tcp   ESTAB  0      0      10.0.0.2:54000    140.82.112.25:443
tcp6  LISTEN 0      128    [::]:22           [::]:*
udp   UNCONN 0      0      0.0.0.0:68        0.0.0.0:*
"""


def test_parse_ss_output():
    rows = connections._parse_ss_output(_SS_OUT)
    assert len(rows) == 4
    states = {r["state"] for r in rows}
    assert "ESTABLISHED" in states  # ESTAB normalized
    assert "LISTEN" in states
    est = [r for r in rows if r["state"] == "ESTABLISHED"][0]
    assert est["remote"] == "140.82.112.25:443"


def test_parse_ss_ignores_header_and_junk():
    assert connections._parse_ss_output("") == []
    assert connections._parse_ss_output("garbage line without columns") == []


# ---------------------------------------------------------------------------
# routes — /proc/net/route (hex, little-endian gateway)
# ---------------------------------------------------------------------------

# Default route via 10.0.0.1 on wlan0. Gateway 0x0100000A = 10.0.0.1 (LE).
_PROC_ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "wlan0\t00000000\t0100000A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
    "wlan0\t0000000A\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
)


def test_parse_proc_route():
    gw, iface, count = routes._parse_proc_route(_PROC_ROUTE)
    assert gw == "10.0.0.1"
    assert iface == "wlan0"
    assert count == 2


# ---------------------------------------------------------------------------
# monitor — /proc/net/dev (right-justified iface name)
# ---------------------------------------------------------------------------

_PROC_NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo:  123456     789    0    0    0     0          0         0   123456     789
  wlan0: 9988776   54321    0    0    0     0          0         0  1122334   11111
"""


def test_parse_proc_net_dev():
    rx, tx = monitor._parse_proc_net_dev(_PROC_NET_DEV, "wlan0")
    assert rx == 9988776
    assert tx == 1122334


def test_parse_proc_net_dev_missing_iface():
    assert monitor._parse_proc_net_dev(_PROC_NET_DEV, "eth7") == (0, 0)


# ---------------------------------------------------------------------------
# wifi — Termux JSON parsers + channel math + system_profiler
# ---------------------------------------------------------------------------

_TERMUX_CONNINFO = (
    '{"bssid":"aa:bb:cc:dd:ee:ff","frequency_mhz":5180,"ip":"10.0.0.42",'
    '"link_speed_mbps":866,"rssi":-52,"ssid":"MyNet","supplicant_state":"COMPLETED"}'
)


def test_parse_termux_conninfo():
    data = wifi._parse_termux_conninfo(_TERMUX_CONNINFO)
    assert data["ssid"] == "MyNet"
    assert data["rssi"] == -52
    assert data["frequency_mhz"] == 5180


def test_parse_termux_conninfo_bad_json():
    assert wifi._parse_termux_conninfo("not json") is None


def test_parse_termux_scaninfo():
    js = (
        '[{"bssid":"aa:bb:cc:dd:ee:ff","frequency_mhz":2437,"rssi":-40,"ssid":"A"},'
        '{"bssid":"11:22:33:44:55:66","frequency_mhz":5745,"rssi":-70,"ssid":"B"}]'
    )
    aps = wifi._parse_termux_scaninfo(js)
    assert len(aps) == 2
    assert aps[0]["channel"] == 6      # 2437 MHz -> ch 6
    assert aps[1]["channel"] == 149    # 5745 MHz -> ch 149


def test_mhz_to_channel():
    assert wifi._mhz_to_channel(2412) == 1
    assert wifi._mhz_to_channel(2437) == 6
    assert wifi._mhz_to_channel(2484) == 14
    assert wifi._mhz_to_channel(5180) == 36
    assert wifi._mhz_to_channel(5745) == 149


_SP_OUT = """    Wi-Fi:

      Interfaces:
        en0:
          Card Type: Wi-Fi
          Status: Connected
          Current Network Information:
            HomeNet:
              PHY Mode: 802.11ax
              Channel: 44 (5GHz, 80MHz)
              Signal / Noise: -55 dBm / -92 dBm
              Transmit Rate: 866
"""


def test_parse_system_profiler():
    info = wifi._parse_system_profiler(_SP_OUT)
    assert info["ssid"] == "HomeNet"
    assert info["rssi"] == -55
    assert info["noise"] == -92
    assert info["rate_mbps"] == 866
    assert "802.11ax" in info["phy"]
