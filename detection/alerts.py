"""Shared alert helper so every detector speaks the same language."""
from __future__ import annotations

import json
import sys as _sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone

# Ensure emoji-laden alert output does not crash on cp1252 Windows consoles.
for _stream in (_sys.stdout, _sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass


@dataclass
class Alert:
    detector: str          # which detector fired
    severity: str          # info | warning | critical
    title: str             # short headline
    what: str              # what was detected
    why: str               # why it is suspicious
    evidence: dict = field(default_factory=dict)
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    def render(self) -> str:
        icon = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(self.severity, "•")
        lines = [
            f"{icon}  [{self.severity.upper()}] {self.detector}: {self.title}",
            f"    WHAT: {self.what}",
            f"    WHY : {self.why}",
        ]
        if self.evidence:
            lines.append(f"    EVIDENCE: {json.dumps(self.evidence, default=str)}")
        return "\n".join(lines)
