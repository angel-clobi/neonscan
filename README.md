# ⚡ NeonScan v1.3.1

> Cyberpunk-styled, interactive **local-network reconnaissance + diagnostics** terminal for macOS / Linux.
> Discovers live hosts, MAC addresses, vendor (OUI), open ports and active web services — **plus** runs Wi-Fi, DNS, latency, bandwidth, traceroute, gateway/DHCP, public IP, active connections, **live monitor, MTR with per-hop loss, TLS inspection, captive portal detection, ARP anomaly detection, mDNS/Bonjour discovery, watch/baseline diff, topology export** and **upload/iperf3**.

```
    _   ______ ____                  __
   / | / / __ )/ __ \____ __________/ /
  /  |/ / __  / / / / __ `/ ___/ __  /
 / /|  / /_/ / /_/ / /_/ / /  / /_/ /
/_/ |_/_____/_____/\__,_/_/   \__,_/
           |___/   v1.3.1
```

## ✦ Modules (20+)

| Command | What it does |
|---|---|
| `wifi` | SSID, BSSID, RSSI, channel, link rate, neighbors |
| `routes` | Default gateway + custom route count |
| `dhcp` | Active DHCP lease (server, lease time, DNS) |
| `public` | Public IP via 3 endpoints, reverse DNS, ISP, proxy hint |
| `dns [name]` | Multi-resolver latency + correctness |
| `ping [target]` | Loss / RTT / jitter over N pings |
| `traceroute <host>` | One-shot path latency |
| `mtr <host>` | **MTR** — cycles of traceroute with per-hop loss% |
| `speed [--size-mb]` | Cloudflare download test |
| `upload [--size-mb]` | **Cloudflare upload test** |
| `iperf3 [--server] [--duration] [--reverse]` | **LAN bandwidth** (graceful fallback if iperf3 missing) |
| `connections` | Active TCP/UDP sockets + listening ports |
| `monitor` | Per-interface byte counters + RSSI |
| `aps` | Nearby Wi-Fi APs sorted by signal |
| `arp` | **ARP anomalies** (duplicate IP, multi-IP MAC) |
| `captive` | **Captive portal detection** (4 URL probes) |
| `mdns` | **mDNS/Bonjour** service discovery |
| `tls <host>` | **TLS cert inspection** (subject, issuer, expiry, cipher, fingerprint) |
| `topology [--format]` | **Export topology** as Mermaid or Graphviz DOT |
| `watch [--save]` | **Save / diff against baseline** |
| `full` | Run all of the above and dump a report |
| `net / scan` | Original host discovery |
| `report <module>` | Save any single module to Markdown/JSON |

## ✦ Install

### Standard (macOS / Linux)

```bash
cd neonscan
python3 -m pip install -r requirements.txt   # only 'rich' is required

# Optional for richer diagnostics:
brew install iperf3 dig                      # macOS
sudo apt install iperf3 traceroute lsof      # Debian/Ubuntu
```

### Self-contained (works offline, on Termux, no internet at runtime)

The repo already ships the dependency wheels in `vendor/wheels/` (rich +
transitive deps, ~1.5 MB). On first run, NeonScan extracts them into
`vendor/_lib/` from the bundled wheelhouse — **no internet needed** — and adds
that to `sys.path`:

```bash
git clone https://github.com/angel-clobi/neonscan
cd neonscan
python3 neonscan.py            # first run extracts vendor/wheels → vendor/_lib (offline)
```

The only runtime requirement is a working `python3 ≥ 3.9` (with its bundled
`pip`, used once for the local, offline extract). If you'd rather pre-extract,
or refresh the wheelhouse:

```bash
make bundle          # (re)download wheels into vendor/wheels/  (needs internet once)
make install-bundled # extract them into vendor/_lib/           (offline)
```

### Termux (Android) — first-class target

```bash
# 1. Install Termux from F-Droid (the Google Play build is outdated).

# 2. Base packages (Python + the tools the recon half relies on):
pkg install python iproute2 iputils traceroute openssl-tool

#    iproute2 gives `ip` and `ss`; iputils gives `ping`; openssl-tool
#    lets the TLS module verify certs. All optional-but-recommended:
pkg install lsof nmap netcat-openbsd dnsutils

# 3. Wi-Fi info needs the Termux:API bridge (install the Termux:API *app*
#    from F-Droid too, then):
pkg install termux-api

# 4. Copy the project (git clone, scp, Termux storage, …):
git clone https://github.com/angel-clobi/neonscan
cd neonscan

# 5. Run — no pip install, no internet needed (rich is vendored):
python3 neonscan.py --offline
```

**What works where on Termux**

| Works out of the box (pure stdlib) | Needs a package | Needs Termux:API |
|---|---|---|
| `dns` `tls` `speed` `upload` `public` `captive` `mdns` `ping <host>` `scan`/`net` `topology` | `routes`/`ss` connections (`iproute2`), `traceroute`, `iperf3` | `wifi` / `aps` (`termux-api` + app) |

`neonscan` is Android-aware and degrades gracefully:
- **Discovery is parallel** — a full /24 sweep finishes in seconds, and the
  `ping -W` timeout is translated to Linux seconds (it means milliseconds on
  macOS), so it never stalls for minutes on Android.
- **Wi-Fi** uses `termux-wifi-connectioninfo` / `termux-wifi-scaninfo` from
  Termux:API; without it, `wifi` prints how to enable it.
- **Routes** fall back to reading `/proc/net/route` directly when `ip` is absent.
- **Connections** prefer `ss` (from `iproute2`), then `lsof`, then `netstat`.
- **ARP** falls back to `/proc/net/arp` (may be empty on Android 10+ without root).

> Tested on macOS 15 (Python 3.9) and against Termux command output. On macOS
> 14+ the private `airport` tool is deprecated, so `wifi` needs
> `sudo wdutil info` or Location Services (the tool tells you which).

## ✦ Run

```bash
python3 neonscan.py                       # interactive mode

# One-shot subcommands:
python3 neonscan.py wifi
python3 neonscan.py dns
python3 neonscan.py ping 8.8.4.4 -c 6
python3 neonscan.py speed --size-mb 12
python3 neonscan.py upload --size-mb 12
python3 neonscan.py iperf3                 # local self-loop; needs iperf3 binary
python3 neonscan.py traceroute 1.1.1.1
python3 neonscan.py mtr 8.8.8.8 --cycles 3
python3 neonscan.py tls google.com
python3 neonscan.py captive
python3 neonscan.py arp
python3 neonscan.py mdns
python3 neonscan.py topology mermaid > net.mmd

# Save baseline + diff:
python3 neonscan.py watch --save
python3 neonscan.py watch                  # diff against baseline

# Generate any report:
python3 neonscan.py report full -o f.md
python3 neonscan.py report wifi -o w.json
```

Flags:

```
--offline              # don't download OUI; use bundled list only
--update-oui           # force re-download of the IEEE OUI file
--no-banner            # skip ASCII splash
--subnet CIDR          # override the auto-detected /24
--cache-dir DIR        # where to cache oui.txt (default ~/.neonscan/cache)
--debug                # verbose logging
```

## ✦ Interactive mode

```
  [D] diag        Full diagnostics suite
  [U] upload      Upload bandwidth test
  [I] iperf3      LAN iperf3 test
  [X] mtr         MTR (per-hop loss)
  [K] tls         TLS / cert inspection
  [O] captive     Captive portal check
  [A] arp         ARP anomalies
  [B] mdns        mDNS / Bonjour
  [V] watch       Save/diff against baseline
  [F] topology    Topology export (Mermaid)
  [W] wifi        Wi-Fi link info
  [P] ping        Ping a target
  [N] public      Public IP / ISP
  [T] traceroute  Traceroute a target
  [G] gateway     Gateway + DHCP lease
  [C] connections Active connections
  [M] monitor     Live RSSI + traffic monitor
  [S] scan        Re-scan local subnet
  [R] re-pick subnet
  [d] deep        Deep-scan a host (top-200 ports)
  [p] port        Web-quick on selected host
  [e] export      Export host scan as JSON
  [q] quit        Disconnect
```

## ✦ Sample output

### Captive portal
```
────────────────────────────── ⟨ Captive portal ⟩ ──────────────────────────────
  ·  Apple hotspot detect: 200 · 85ms
  ·  GNOME NM check: 200 · 38ms
  ·  Google connectivity check: 204 · 29ms
  ·  Microsoft NCSI: 200 · 33ms
  OK  Verdict: no portal
```

### TLS
```
────────────────────────── ⟨ TLS :: google.com:443 ⟩ ───────────────────────────
  ·  Subject CN: *.google.com
  ·  Issuer: WE2
  ·  SANs: *.google.com, *.appengine.google.com, *.bdn.dev, …
  ·  Validity: 2026-09-04 → 2026-11-27
  OK  Days left: 70
  OK  Cipher: ECDHE-ECDSA-CHACHA20-POLY1305 (TLSv1/SSLv3, 256 bits)
  ·  SHA-256 fingerprint: 0E:75:68:E9:92:5A:62:3C:49:65:DA…
```

### MTR
```
────────────────────────────────── ⟨ MTR :: 8.8.8.8 ⟩ ──────────────────────────────
  OK  Reaches target: yes
  ·  Total hops: 6
  ·  Cycles: 2
  ·  Probes per hop: 3
  OK  Hop  1: 10.10.10.1 (10.10.10.1) · 0 ms avg · 0% loss
  OK  Hop  2: 10.105.128.1 (10.105.128.1) · 2 ms avg · 0% loss
  FAIL  Hop  5: * (?) · 7 ms avg · 50% loss
  FAIL  Lossy hops: 5
  WARN  Verdict: loss upstream
```

### Upload
```
────────────────────────────── ⟨ Speed · upload ⟩ ───────────────────────────────
  83 Mbps
  ·  2 MB upload: 82.7 Mbps (in 0.19s)
  OK  Average: 82.7 Mbps
```

### Mermaid topology
```
graph LR
  10_10_10_1[('10.10.10.1')]                           # gateway
  10_10_10_3[('10.10.10.3')]                           # this host
  10_10_10_1 --- 10_10_10_3
  10_10_10_3 --- 10_10_10_42[('laptop')]               # neighbor
  10_10_10_1 -.- 8_8_8_8[('DNS · 8.8.8.8')]
```

## ✦ Tests

```bash
python3 -m pip install --user --quiet pytest pytest-mock
python3 -m pytest tests/ -v
```

The suite contains 74 tests across 7 files:

| File | Tests |
|---|---|
| `tests/test_oui.py` | OUI lookup, ping/DNS encoders, DiagResult, report writer (14) |
| `tests/test_network.py` | Network detection, ping sweep, scanner, OUI cache (9) |
| `tests/test_integration.py` | Real diagnostics: DNS, public IP, scan, full diag (8) |
| `tests/test_cli.py` | Subcommand plumbing, parser, registration (4) |
| `tests/test_extras.py` | TLS, captive, MTR, ARP, mDNS, topology, IPv6, watch/baseline (18) |
| `tests/test_termux.py` | **Termux/Linux adapters: ss, /proc/net/route, /proc/net/dev, ping parse, termux-api Wi-Fi (13)** |
| `tests/test_fixes.py` | **v1.3.1 regressions: mDNS SRV port, iperf3 no-crash, reverse-DNS timeout, IDN, watch RSSI severity (8)** |

```
========================== 74 passed in 13.87s ==========================
```

## ✦ Notes & etiquette

* TCP connect scans — no raw sockets, no sudo required.
* TLS inspection works against any TLS endpoint. On Python 3.9 we delegate to `openssl` to parse the cert (still no extra dependency).
* Watch mode stores baselines in `~/.neonscan/baseline.json` — diff any future run against it.
* Topology export emits Mermaid / Graphviz DOT — paste in your wiki, or `dot -Tsvg net.dot -o net.svg`.
* Capture live packets requires sudo and is intentionally not included.
* Be a good netizen: only scan networks you own.
* License: MIT.
