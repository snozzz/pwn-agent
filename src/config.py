from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json

from .policy import DEFAULT_ALLOWLIST


@dataclass
class AgentConfig:
    allowlist: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWLIST))
    timeout_seconds: int = 20

    @classmethod
    def load(cls, path: Path | None) -> "AgentConfig":
        if path is None:
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowlist = set(data.get("allowlist", list(DEFAULT_ALLOWLIST)))
        timeout_seconds = int(data.get("timeout_seconds", 20))
        return cls(allowlist=allowlist, timeout_seconds=timeout_seconds)
