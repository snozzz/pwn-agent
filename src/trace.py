from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
from typing import Any


@dataclass
class TraceEvent:
    step: str
    status: str
    details: dict[str, Any]


@dataclass
class AuditTrace:
    events: list[TraceEvent]

    def add(self, step: str, status: str, **details: Any) -> None:
        self.events.append(TraceEvent(step=step, status=status, details=details))

    def to_markdown(self) -> str:
        lines = ["## Action Trace", ""]
        if not self.events:
            lines.append("- No trace events recorded")
            return "\n".join(lines) + "\n"
        for index, event in enumerate(self.events, start=1):
            lines.append(f"### {index}. {event.step}")
            lines.append(f"- Status: **{event.status}**")
            for key, value in event.details.items():
                lines.append(f"- {key}: `{value}`")
            lines.append("")
        return "\n".join(lines) + "\n"

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([asdict(event) for event in self.events], indent=2), encoding="utf-8")


def new_trace() -> AuditTrace:
    return AuditTrace(events=[])
