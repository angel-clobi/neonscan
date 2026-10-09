"""Runtime platform and optional-command diagnostics for NeonScan."""

from __future__ import annotations

import platform
import shutil
import sys
import os
from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table


@dataclass(frozen=True)
class Dependency:
    name: str
    commands: tuple[str, ...]
    purpose: str
    fallback: str


DEPENDENCIES = (
    Dependency("Ping", ("ping",), "Pruebas de latencia y detección de equipos", "El escaneo de puertos sigue disponible"),
    Dependency("Rutas", ("ip", "netstat", "route"), "Lectura de gateway y rutas", "Linux/Termux puede leer /proc/net/route"),
    Dependency("Conexiones", ("ss", "lsof", "netstat"), "Listado de sockets y puertos locales", "Se probarán alternativas instaladas"),
    Dependency("Traceroute", ("traceroute", "tracepath"), "Traceroute y MTR", "La función reportará que falta el comando"),
    Dependency("OpenSSL", ("openssl",), "Detalles ampliados de certificados TLS", "Python conserva la conexión TLS básica"),
    Dependency("Nmap", ("nmap",), "Detección ligera de servicio/versión en los puertos TCP abiertos", "Se muestran nombres de servicio inferidos por número de puerto"),
    Dependency("iperf3", ("iperf3",), "Pruebas de ancho de banda dentro de la LAN", "Las pruebas HTTP de velocidad siguen disponibles"),
    Dependency("DNS CLI", ("dig", "nslookup"), "Consultas DNS externas opcionales", "NeonScan tiene consulta DNS propia"),
)


def _is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or os.path.isdir("/data/data/com.termux/files")


def environment_report() -> dict:
    """Inspect PATH and report optional dependencies without modifying the host."""
    system = platform.system()
    termux = _is_termux()
    entries = []
    for dependency in DEPENDENCIES:
        found = next(((cmd, shutil.which(cmd)) for cmd in dependency.commands if shutil.which(cmd)), None)
        entries.append({"dependency": dependency, "found": found})

    if termux:
        install = "pkg install iputils iproute2 traceroute openssl-tool lsof iperf3 dnsutils termux-api nmap"
        connection = shutil.which("termux-wifi-connectioninfo")
        scan = shutil.which("termux-wifi-scaninfo")
        if connection and scan:
            wifi_note = (
                "Comandos Wi-Fi de Termux:API encontrados. Si la consulta falla, "
                "revisa permisos de la app Android Termux:API y ubicación del teléfono."
            )
        else:
            missing_wifi = [name for name, path in (
                ("termux-wifi-connectioninfo", connection),
                ("termux-wifi-scaninfo", scan),
            ) if not path]
            wifi_note = (
                f"Falta(n) {', '.join(missing_wifi)} en PATH: instala los comandos "
                "con `pkg install termux-api`. La app Android Termux:API es un "
                "complemento separado y requiere permisos; tener la app instalada "
                "no instala estos comandos dentro de Termux."
            )
        system_name = "Android / Termux"
    elif system == "Linux":
        install = "Debian/Ubuntu: sudo apt install iputils-ping iproute2 traceroute openssl lsof iperf3 dnsutils nmap"
        wifi_note = "Wi-Fi puede depender de permisos y utilidades del sistema"
        system_name = f"Linux ({platform.release()})"
    elif system == "Darwin":
        install = "Opcional con Homebrew: brew install iperf3 bind nmap"
        wifi_note = "macOS puede requerir permisos de ubicación o sudo para datos Wi-Fi"
        system_name = f"macOS ({platform.mac_ver()[0] or platform.release()})"
    else:
        install = "Instala los comandos opcionales con el gestor de paquetes de tu sistema"
        wifi_note = "La disponibilidad de datos Wi-Fi depende del sistema"
        system_name = f"{system} ({platform.release()})"

    return {
        "system": system_name,
        "python": platform.python_version(),
        "termux": termux,
        "install": install,
        "wifi_note": wifi_note,
        "dependencies": entries,
        "python_package": "Rich incluida en vendor/wheels" if "vendor" in " ".join(sys.path) else "Rich importada desde el entorno Python",
    }


def render_environment_report(report: dict, console: Optional[Console] = None) -> None:
    console = console or Console()
    console.print(f"\n[bold magenta]Entorno[/]  {report['system']} · Python {report['python']}")
    console.print(f"[dim]{report['python_package']}[/]")
    table = Table(title="Herramientas opcionales detectadas", expand=True)
    table.add_column("Componente", no_wrap=True)
    table.add_column("Estado", no_wrap=True)
    table.add_column("Uso / alternativa")
    for entry in report["dependencies"]:
        dependency = entry["dependency"]
        found = entry["found"]
        status = f"Disponible: {found[0]}" if found else "No encontrada"
        note = dependency.purpose if found else f"{dependency.purpose}. {dependency.fallback}."
        table.add_row(dependency.name, status, note)
    console.print(table)
    console.print(report["wifi_note"])
    missing = [entry["dependency"].name for entry in report["dependencies"] if not entry["found"]]
    if missing:
        console.print(f"\n[bold]Instalación sugerida[/]: {report['install']}")
    else:
        console.print("\n[green]Herramientas opcionales principales disponibles.[/]")
    console.print("La revisión solo inspecciona PATH; no instala ni cambia paquetes.\n")
