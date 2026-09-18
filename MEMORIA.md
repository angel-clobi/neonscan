# ⚡ MEMORIA — NeonScan

> Bitácora de desarrollo + guía de despliegue (incluido Termux).
> Ubicación del proyecto: `~/neonscan/`

## 📍 Ubicación absoluta del proyecto

```
~/neonscan/
```

## 🧭 Qué es NeonScan

Suite interactiva estilo **cyberpunk** para reconocimiento y diagnóstico de redes locales.
Construida en Python 3.9 + stdlib + `rich`, sin dependencias GUI ni de red externas.

## 🗂 Estructura

```
neonscan/                   ← raíz del proyecto
├── neonscan.py             entry-point (auto-bootstrap de vendor)
├── Makefile                `make bundle` / `make install-bundled` / `make test`
├── README.md               guía de uso
├── MEMORIA.md              este archivo
├── requirements.txt        rich>=13.7.0
├── vendor/                 self-contained: wheels + libs extraídas
│   ├── wheels/             4 wheels (rich + pygments + markdown-it-py + mdurl)
│   └── _lib/               extraído de los wheels — listo para import
├── neonscan/               paquete Python
│   ├── theme.py            paleta neón + rich theme
│   ├── banner.py           ASCII art + intro panel
│   ├── network.py          ip/subnet/ping sweep/ARP/+ /proc/net/arp fallback
│   ├── oui.py              caché IEEE OUI + descarga on first run
│   ├── scanner.py          TCP-connect scan + HTTP title grab
│   ├── ui.py               tablas cyberpunk + menú + prompts
│   ├── data/fallback_oui.py  ~900 vendors offline
│   └── diagnostics/        17 módulos
│       ├── result.py       dataclass canónica (DiagResult / Finding)
│       ├── wifi.py         airport (mac) / iwconfig (linux)
│       ├── ping.py         subprocess ping + parser de min/avg/max/jitter
│       ├── dns.py          multi-resolver + raw UDP DNS + dig fallback
│       ├── speed.py        download + upload (Cloudflare) + iperf3 LAN
│       ├── public_ip.py    3 endpoints, ISP, reverse DNS, proxy hint
│       ├── traceroute.py   wrapper de `traceroute -m -w`
│       ├── mtr.py          ciclo de traceroutes con %pérdida por hop
│       ├── connections.py  lsof / netstat fallback + IPv6-safe
│       ├── routes.py       default gw + DHCP lease (mac) / Linux ifconfig
│       ├── monitor.py      RSSI + bytes /sampling series
│       ├── tls.py          inspect cert (con fallback a `openssl x509`)
│       ├── captive.py      4 probes (Apple/GNOME/Google/MSFT)
│       ├── arpwatch.py     duplicados IP→MAC / MAC→IPs
│       ├── mdns.py         DNS-SD queries multicast para service discovery
│       ├── topology.py     export Mermaid / DOT + IPv6 privacy heuristic
│       ├── watch.py        baseline + diff contra run previo
│       └── report.py       writer MD/JSON + run_full_diag orchestrator
└── tests/                  53 tests (pytest)
    ├── test_oui.py           14
    ├── test_network.py        9
    ├── test_integration.py    8
    ├── test_cli.py            4
    └── test_extras.py        18
```

## 📜 Cómo se construyó

### Fase 1 — base cyberpunk (v1.0)
- Banner ASCII + tema neón rich
- Host discovery: `ping_sweep` concurrente + ARP table parse + OUI lookup (con descarga IEEE, fallback a ~900 vendors)
- TCP-connect scanner (top 200 puertos) con banner grab para HTTP/SSH/FTP/SMTP
- Reporte MD/JSON interactivo

### Fase 2 — suite de diagnósticos (v1.1)
11 módulos de diagnóstico: Wi-Fi, ping/loss/jitter, DNS multi-resolver (con impl UDP cruda para no depender de dnspython), speed Cloudflare, public IP (3 endpoints), traceroute, connections (lsof+netstat), routes+DHCP, monitor, y un FULL DIAG orchestrator.
- Subcomandos CLI para todo
- Cada diagnóstico degrada si la tool nativa falta
- 34 tests pasando

### Fase 3 — relleno de huecos (v1.2)
Lo que dijiste que faltaba: upload speed + iperf3 LAN, MTR (per-hop loss%), TLS inspection (con fallback a openssl), captive portal, ARP anomaly detection (spoofing), mDNS/Bonjour discovery, watch/baseline mode, Mermaid topology export, IPv6 privacy heuristic.
- 24 subcomandos CLI, 17 módulos de diagnóstico
- Menu interactivo extendido (D/W/P/N/T/G/C/M/U/I/X/K/O/A/B/V/F)
- 53 tests pasando

### Fase 4 — self-contained para Termux (v1.3)
- `vendor/wheels/` (1.5 MB): pip download una vez
- `vendor/_lib/` (6.7 MB): extract automático
- Bootstrap en `neonscan.py` inyecta `vendor/_lib` a `sys.path`
- Fallback para `/proc/net/arp` cuando no haya `arp -a` (Linux/Android)
- El target sólo necesita Python 3.9+; sin pip, sin internet
- Makefile: `make bundle`, `make install-bundled`, `make test`, `make clean-bundle`

### Fase 5 — paquete Termux / portabilidad Android (v1.3.0)
Endurecimiento para que la mitad de *recon* funcione en Termux (antes solo servía
bien la mitad de diagnósticos stdlib):
- **Descubrimiento paralelo**: `discover_with_progress` (ui.py) antes ignoraba
  `ping_workers` y barría secuencial → ~5 min/`/24` (Mac) y ~8 min (Termux por el
  bug de `ping -W`). Ahora usa `ThreadPoolExecutor`, lee la tabla ARP **una** vez y
  sondea puertos en paralelo → **segundos**. `topology` pasó de >120s a ~15s.
- **`ping -W` por plataforma** (network.py `_ping_once`): ms en macOS/BSD, **segundos**
  en Linux/iputils (Termux). Antes `-W 250` = 250 s en Android.
- **Detección de runtime**: `network.IS_TERMUX` / `IS_ANDROID` (`PREFIX` con
  `com.termux` o `/data/data/com.termux/files`).
- **Wi-Fi Termux** (wifi.py): `termux-wifi-connectioninfo` / `termux-wifi-scaninfo`
  (Termux:API). En macOS 14+ `airport` sólo imprime aviso de deprecación → fallback
  a `system_profiler SPAirPortDataType`, y si no hay datos, mensaje claro
  (`sudo wdutil info` / Location Services).
- **Conexiones** (connections.py): `ss -tuna` primero en Linux/Termux, luego `lsof`,
  luego `netstat` (con sintaxis Linux corregida: `-tuan`, no `-p tcp`).
- **Rutas** (routes.py): fallback puro a `/proc/net/route` (hex LE) cuando no hay
  `iproute2` en Termux.
- **Monitor** (monitor.py): índices de `netstat -I -b` corregidos (Ibytes=6/Obytes=9)
  y parser real de `/proc/net/dev`; RSSI por termux-api.
- **ping.py**: parse de "N received" (iputils) además de "N packets received" (BSD).
- Housekeeping: `LICENSE` MIT (Angel Tellez), `.gitignore`, versión única 1.3.0
  (banner lee `__version__`), `try/except` global en `main`, variable muerta borrada.
- Tests: +`tests/test_termux.py` (13) sobre los parsers puros → **66 en total**.
- Repo público en GitHub: `angel-clobi/neonscan`.

### Fase 6 — correcciones de bugs (v1.3.1)
Pase de correctness sobre los diagnósticos (encontrados en revisión a fondo):
- **mdns**: PTR era tipo 12 y 33 a la vez → la rama SRV estaba muerta y el puerto
  siempre daba 0. Ahora PTR=12, SRV=33 (puerto/host), A por hostname; slots por
  *instancia*. `discover_mdns` envía todas las queries y escucha una sola ventana,
  con `IP_ADD_MEMBERSHIP` + `SO_REUSEPORT` (mejor recepción en Linux/Termux).
- **tls**: usaba `get_verified_cert_chain` (no existe) → "Chain length" siempre 0.
  Ahora prueba `get_unverified_chain`/`get_verified_chain` (3.13+) y en 3.9 reporta
  el peer como 1 con nota.
- **speed/iperf3**: `measure_iperf3(server=...)` reventaba con `UnboundLocalError`
  (server_proc sin definir). Inicializado arriba.
- **watch**: severidad de caída de RSSI invertida para bajas <5 dBm (daba FAIL);
  y el delta de RSSI **nunca** se generaba (un `float("-67 dBm")` previo lo saltaba).
  `watch_loop` ahora recolecta y devuelve los diffs.
- **public_ip**: `setdefaulttimeout` global sin restaurar; prefijo `172.2` marcaba
  IPs públicas como privadas (ahora `ipaddress.is_private`); `"host"` fuera del hint
  de proxy (falso positivo).
- **dns**: quitado el resolver fijo `127.0.0.1` (bajaba el marcador a 6/7 WARN); los
  locales salen de `/etc/resolv.conf`. Encode tolerante a IDN (punycode).
- **scanner**: fuga de conexión `http.client` en excepción (try/finally).
- **traceroute/mtr**: "Reaches target" resolvía el hostname a IP para comparar;
  limpieza de código muerto (`_HOP_RE`, no-op de severidad).
- **report**: `datetime.utcnow()` → `datetime.now(timezone.utc)`.
- Tests: +`tests/test_fixes.py` (8) → **74 en total**.

## 🚀 Cómo correr

### Modo normal (en tu Mac / Linux con internet)

```bash
cd ~/neonscan
python3 -m pip install -r requirements.txt   # solo rich
python3 neonscan.py                           # modo interactivo
python3 neonscan.py full --out r.md           # report
python3 neonscan.py ping 8.8.4.4 -c 4
python3 neonscan.py mtr 1.1.1.1 --cycles 3
python3 neonscan.py topology mermaid > net.mmd
```

### Modo self-contained (sin `pip install` en runtime)

```bash
# En tu Mac, una sola vez:
cd ~/neonscan
make bundle              # baja wheels a vendor/wheels/
make install-bundled     # los extrae a vendor/_lib/

# Empaqueta y copia:
tar czf neonscan-vendor.tgz . --exclude='__pycache__' --exclude='.pytest_cache'
scp neonscan-vendor.tgz termux:~/   # o Termux storage, git push, USB, etc.
```

### En Termux (Android)

```bash
# 0. Instalar Termux desde F-Droid (la versión de Play Store está descontinuada).

# 1. Setup Python y tools útiles:
pkg install python traceroute lsof nmap netcat-openbsd

# 2. Clonar/copiar el proyecto:
cd ~
git clone https://.../neonscan.git   # o extrae el tar.gz
cd neonscan

# 3. Sin pip install, sin internet — el script autorresuelve:
python3 neonscan.py --offline

# 4. Sub-comandos típicos:
python3 neonscan.py routes
python3 neonscan.py dns
python3 neonscan.py ping 8.8.8.8 -c 4
python3 neonscan.py arp    # usa /proc/net/arp
python3 neonscan.py mtr 1.1.1.1
python3 neonscan.py tls google.com
```

### Resultado en Termux

Como Termux es Linux, `neonscan` corre igual que en Mac/Linux:

```
neonscan routes  → enos (puede ser wlan0 si estás en Wi-Fi)
                  default gw 10.0.0.1
                  IP 10.0.0.42
                  routes custom: 12

neonscan arp     → /proc/net/arp parseado
                  listar vecinos de /proc/net/arp
                  detectar duplicados IP/MAC

neonscan mtr     → traceroute por ciclos
                  loss% por hop, promedios

neonscan tls     → cert de cualquier host:puerto
```

## 🔧 Decisiones de diseño clave

1. **Sin raw sockets ni root.** Todo TCP-connect; ARP y traceroute via subprocess; IGMP multicast para mDNS via socket.
2. **Degradación graciosa.** Si macOS-only (airport), macOS retorna vacío sin crashear. Si no hay iperf3, mensaje claro. Si Linux no tiene `lsof`, fallback a `netstat -an`.
3. **Probador de DNS en stdlib.** Para evitar `dnspython`, `dns.py` implementa query/response UDP/DNS-SD DNS packet manual (~200 líneas). Más rápido y portable.
4. **DiagResult canónico.** Cada diagnóstico retorna `DiagResult(title, summary, findings, raw, error)`. Fácil de serializar, testear y reportear.
5. **Rich + stdlib.** Sin requests, sin dns, sin scapy. Sólo `rich` para formato.
6. **Multi-resolver DNS** cubre Google/Cloudflare/Quad9/OpenDNS + resolv.conf local.
7. **TLS-inspection sin cryptography.** Fallback a `openssl x509 -text -noout` cuando Python 3.9 retorna cert dict vacío (común con `CERT_NONE`).
8. **IPv6-safe ARP/connections** parseo cuidando hex notation y brackets.

## 🧪 Tests

```bash
make test                       # 53 tests
pytest tests/test_integration.py # 8 tests reales (DNS, public IP, scan, etc.)
pytest tests/test_extras.py    # TLS + captive + MTR + ARP + mDNS + topology + IPv6 + watch + vendor
PYTHONPATH= python3 neonscan.py --no-banner --offline routes   # smoke test vendor
```

## 📦 Dependencias

Solo `rich>=13.7.0` — y está vendoreada en `vendor/wheels/` + extraída en `vendor/_lib/`.
Transferencias para Termux: comprime el directorio entero, pesa ~8 MB extra por el vendor bundle.

## 🔍 Tareas comunes

| Quiero… | Comando |
|---|---|
| Ver toda la red ahora | `python3 neonscan.py routes` |
| Probar un DNS | `python3 neonscan.py dns` |
| Diagnóstico completo + MD | `python3 neonscan.py full --out r.md` |
| Diff contra run anterior | `python3 neonscan.py watch --save` y luego `watch` |
| Ver topología | `python3 neonscan.py topology mermaid > net.mmd` |
| Buscar ARP spoofing | `python3 neonscan.py arp` |
| Captive portal check | `python3 neonscan.py captive` |
| Bonjour discovery | `python3 neonscan.py mdns` |
| TLS cert inspection | `python3 neonscan.py tls google.com` |
| MTR con pérdida por hop | `python3 neonscan.py mtr 1.1.1.1` |

## 🛠 ¿Cómo extender?

Para añadir un nuevo diagnóstico:

1. Crea `neonscan/diagnostics/<nombre>.py` con `def medir(...) -> DiagResult`.
2. Exporta en `neonscan/diagnostics/__init__.py`.
3. Añade subcomando en `neonscan.py` (`build_parser()`) y runner (`run_<nombre>(args)`).
4. Si quieres en `full`, agrégalo a `run_full_diag()`.
5. Si quieres en menú interactivo, agrega tecla en `interactive_prompt.options`.
6. Escribe tests en `tests/test_extras.py`.

El DiagResult canónico se compone automáticamente en `report.py` (Markdown + JSON).
