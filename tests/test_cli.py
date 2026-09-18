"""CLI / subcommand plumbing tests."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _load_entry():
    spec = importlib.util.spec_from_file_location("neonscan_entry", ROOT / "neonscan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_main_help_no_args():
    import subprocess
    res = subprocess.run(
        [sys.executable, "neonscan.py", "--help"],
        cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    assert res.returncode == 0
    assert "neonscan" in res.stdout.lower()


def test_subcommands_registered():
    mod = _load_entry()
    expected = {
        "wifi", "routes", "dhcp", "public", "connections", "monitor", "aps",
        "ping", "dns", "speed", "traceroute", "full", "net", "report",
    }
    assert set(mod.SUBCOMMANDS) >= expected


def test_build_parser_lists_subcommands():
    """The argparse parser exposes each subcommand listed in SUBCOMMANDS."""
    from argparse import _SubParsersAction
    mod = _load_entry()
    parser = mod.build_parser()
    sp_actions = [a for a in parser._actions if isinstance(a, _SubParsersAction)]
    assert sp_actions, "no subparsers action registered"
    choices = sp_actions[0].choices
    for name in ("wifi", "full", "ping", "dns", "speed", "traceroute", "report"):
        assert name in choices


def test_run_wifi_returns_diagresult(monkeypatch):
    """Calling run_wifi() with a stubbed get_wifi_info returns a list of DiagResult."""
    from neonscan.diagnostics.result import DiagResult
    mod = _load_entry()
    fake = DiagResult(title="stub")
    monkeypatch.setattr(mod, "get_wifi_info", lambda: fake)
    monkeypatch.setattr(mod, "list_nearby_aps", lambda limit=25: [])
    out = mod.run_wifi(None)
    assert out[0].title == "stub"
    assert len(out) == 1
