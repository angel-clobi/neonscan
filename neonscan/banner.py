"""Cyberpunk ASCII art banner and intro sequence."""

import random

from rich.console import Console
from rich.box import DOUBLE
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .theme import NEON_CYAN, NEON_PINK, NEON_PURPLE, NEON_YELLOW, NEON_GREEN, NEON_MAGENTA

BANNER = r"""
    _   ______ ____                  __
   / | / / __ )/ __ \____ __________/ /
  /  |/ / __  / / / / __ `/ ___/ __  /
 / /|  / /_/ / /_/ / /_/ / /  / /_/ /
/_/ |_/_____/_____/\__,_/_/   \__,_/
           |___/   v%s
""" % __version__

SUBTITLE = "// LOCAL NET RECONNAISSANCE TERMINAL //"

TAGLINE = "// ARP ◈ OUI ◈ PORTS ◈ HTTP BANNER //"


def _glitch(line: str, intensity: float = 0.04) -> str:
    """Return the same line with a few characters randomly glitched to ░ ▒ ▓."""
    glitch_chars = "░▒▓█▌▐"
    return "".join(
        c if (c == " " or random.random() > intensity) else random.choice(glitch_chars)
        for c in line
    )


def render_banner(console: Console, animate: bool = False) -> None:
    """Print the cyberpunk banner. Optionally animated."""
    if animate:
        for line in BANNER.rstrip("\n").split("\n"):
            styled = Text(_glitch(line), style=f"{NEON_CYAN} bold")
            console.print(styled, justify="center")
        console.print()
        console.print(
            Text(SUBTITLE, style=f"{NEON_PINK} bold reverse"),
            justify="center",
        )
        console.print(
            Text(TAGLINE, style=f"{NEON_YELLOW}"),
            justify="center",
        )
        console.print()
        return

    styled = Text(BANNER, style=f"{NEON_CYAN} bold")
    console.print(styled, justify="center")
    console.print()
    console.print(
        Text(SUBTITLE, style=f"{NEON_PINK} bold reverse"),
        justify="center",
    )
    console.print(
        Text(TAGLINE, style=f"{NEON_YELLOW}"),
        justify="center",
    )
    console.print()


def render_intro_panel(console: Console, network_info: dict) -> Panel:
    """Render the network identity panel shown after the banner."""
    body = Text()
    body.append("CONNECTION_ID  ", style=f"{NEON_PINK} bold")
    body.append("user@neonscan.local\n", style=NEON_GREEN)
    body.append("SUBNET        ", style=f"{NEON_PINK} bold")
    body.append(f"{network_info.get('subnet', 'unknown')}\n", style=NEON_CYAN)
    body.append("LOCAL_IP      ", style=f"{NEON_PINK} bold")
    body.append(f"{network_info.get('local_ip', 'unknown')}\n", style=NEON_CYAN)
    body.append("INTERFACE     ", style=f"{NEON_PINK} bold")
    body.append(f"{network_info.get('interface', 'unknown')}\n", style=NEON_CYAN)
    body.append("UPTIME_UPLINK ", style=f"{NEON_PINK} bold")
    body.append("stable\n", style=NEON_GREEN)
    body.append("MODE          ", style=f"{NEON_PINK} bold")
    body.append("PASSIVE_RECON + ACTIVE_PROBE\n", style=NEON_YELLOW)

    panel = Panel(
        body,
        title="[neon.cyan]⟨ JACK IN ⟩[/neon.cyan]",
        border_style=NEON_PURPLE,
        box=DOUBLE,
        padding=(0, 2),
        expand=False,
    )
    return panel
