"""Cyberpunk color palette and rich theme definitions for NeonScan."""

from rich.style import Style
from rich.theme import Theme

# Neon palette
NEON_PINK = "#FF00C1"
NEON_CYAN = "#00F0FF"
NEON_MAGENTA = "#FF003C"
NEON_PURPLE = "#9D00FF"
NEON_YELLOW = "#F2FF00"
NEON_GREEN = "#39FF14"
NEON_ORANGE = "#FF6F00"
DIM_GRAY = "#3A3A4A"
BRIGHT_WHITE = "#F0F0FF"

CYBERPUNK_THEME = Theme(
    {
        "neon.pink": Style(color=NEON_PINK, bold=True),
        "neon.cyan": Style(color=NEON_CYAN, bold=True),
        "neon.magenta": Style(color=NEON_MAGENTA, bold=True),
        "neon.purple": Style(color=NEON_PURPLE, bold=True),
        "neon.yellow": Style(color=NEON_YELLOW, bold=True),
        "neon.green": Style(color=NEON_GREEN, bold=True),
        "neon.orange": Style(color=NEON_ORANGE, bold=True),
        "neon.dim": Style(color=DIM_GRAY),
        "neon.white": Style(color=BRIGHT_WHITE),
        "neon.title": Style(color=NEON_CYAN, bold=True, reverse=True),
        "neon.alert": Style(color=NEON_MAGENTA, bold=True, blink=True),
        "neon.ok": Style(color=NEON_GREEN, bold=True),
        "neon.warn": Style(color=NEON_YELLOW, bold=True),
        "neon.fail": Style(color=NEON_MAGENTA, bold=True),
        "panel.border": Style(color=NEON_CYAN, bold=True),
        "panel.title": Style(color=NEON_PINK, bold=True, reverse=True),
        "table.header": Style(color=NEON_CYAN, bold=True),
        "table.cell": Style(color=BRIGHT_WHITE),
        "prompt.choices": Style(color=NEON_YELLOW, bold=True),
        "prompt.label": Style(color=NEON_PINK, bold=True),
        # Aliases used by rich defaults
        "repr.number": Style(color=NEON_YELLOW),
        "repr.string": Style(color=NEON_GREEN),
        "repr.bool": Style(color=NEON_PINK, italic=True),
        "rule.line": Style(color=NEON_PURPLE),
        "rule.text": Style(color=NEON_PINK, bold=True),
    }
)

# Glow markers used in tables to fake a neon glow effect
GLOW_OPEN = "▶"
GLOW_CLOSED = "·"
GLOW_WEB = "✺"
SCAN_GLYPHS = {
    "online": "▣",
    "offline": "▢",
    "scanning": "◈",
    "complete": "◆",
    "alert": "▲",
    "padlock": "⛓",
}


def section_title(text: str) -> str:
    """Format a section title with neon brackets."""
    return f"[neon.pink]⟨[/neon.pink] [neon.cyan]{text}[/neon.cyan] [neon.pink]⟩[/neon.pink]"
