"""IEEE OUI / MAC manufacturer lookup with offline-first behavior."""

import logging
import re
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .data.fallback_oui import FALLBACK_OUI

log = logging.getLogger("neonscan.oui")

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
CACHE_FILENAME = "oui.txt"


_OUI_LINE = re.compile(
    r"^\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$",
    re.MULTILINE,
)


class OUICache:
    """Lookup helper backed by an on-disk IEEE file + small bundled fallback."""

    def __init__(
        self,
        cache_dir: Path,
        update: bool = False,
        offline: bool = False,
        timeout: float = 6.0,
    ) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = cache_dir / CACHE_FILENAME
        self.offline = offline

        if update and not offline:
            self._download_cache(timeout=timeout)

        if not self.cache_path.exists() and not offline:
            self._download_cache(timeout=timeout)

        self._table: dict[str, str] = {}
        self._load()

    # ----------------------------- Public API -------------------------------

    def lookup(self, mac: str) -> str:
        """Return vendor for the given MAC, falling back to 'Unknown'."""
        prefix = self._oui_prefix(mac)
        if not prefix:
            return "Unknown"
        if prefix in self._table:
            return self._table[prefix]
        if prefix in FALLBACK_OUI:
            return FALLBACK_OUI[prefix]
        return "Unknown"

    def size(self) -> int:
        return len(self._table) + len(FALLBACK_OUI)

    # ------------------------------ Helpers ---------------------------------

    @staticmethod
    def _oui_prefix(mac: str) -> str:
        """Return 'AABBCC' prefix from any MAC string format."""
        cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
        if len(cleaned) < 6:
            return ""
        return cleaned[:6].upper()

    def _load(self) -> None:
        if self.cache_path.exists():
            text = self.cache_path.read_text(errors="ignore")
            for m in _OUI_LINE.finditer(text):
                hex_mac, vendor = m.group(1), m.group(2).strip()
                prefix = hex_mac.replace("-", "").upper()
                self._table[prefix] = vendor
            log.info("Loaded %d OUI entries from %s", len(self._table), self.cache_path)
        else:
            log.warning(
                "No OUI cache at %s — using bundled fallback (%d entries).",
                self.cache_path,
                len(FALLBACK_OUI),
            )

    def _download_cache(self, timeout: float) -> None:
        """Download the IEEE OUI file. Fail silently (offline-mode)."""
        try:
            log.info("Fetching OUI list from %s", IEEE_OUI_URL)
            req = urllib.request.Request(
                IEEE_OUI_URL,
                headers={"User-Agent": "neonscan/1.0 (+local-recon)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                self.cache_path.write_bytes(resp.read())
            log.info("Saved OUI cache to %s", self.cache_path)
        except Exception as exc:  # noqa: BLE001
            log.warning("OUI download failed (%s); falling back to bundled list.", exc)


@lru_cache(maxsize=4096)
def _cached_lookup(cache_id: int, prefix: str) -> Optional[str]:
    """Optional memoization hook used by callers that want a real cache."""
    return None
