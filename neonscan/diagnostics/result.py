"""Common result dataclasses for diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Severity of a single finding."""

    OK = "ok"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Finding:
    """A single piece of information surfaced in a diagnostic."""

    label: str
    value: Any
    severity: Severity = Severity.INFO
    note: str = ""

    def format(self) -> str:
        prefix = {
            Severity.OK: "[bold green]OK[/]",
            Severity.INFO: "[cyan]·[/]",
            Severity.WARN: "[bold yellow]WARN[/]",
            Severity.FAIL: "[bold red]FAIL[/]",
        }[self.severity]
        body = f"{prefix}  [bold]{self.label}[/]: {self.value}"
        if self.note:
            body += f"  [dim]// {self.note}[/]"
        return body


@dataclass
class DiagResult:
    """Aggregated output of one diagnostic."""

    title: str
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def add(self, label: str, value: Any, severity: Severity = Severity.INFO, note: str = ""):
        self.findings.append(Finding(label=label, value=value, severity=severity, note=note))
        return self

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "summary": self.summary,
            "ok": self.ok,
            "error": self.error,
            "raw": self.raw,
            "findings": [
                {
                    "label": f.label,
                    "value": f.value,
                    "severity": f.severity.value,
                    "note": f.note,
                }
                for f in self.findings
            ],
        }
