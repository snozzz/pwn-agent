from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json


@dataclass
class VerificationPlan:
    binary: str
    args: list[str]

    @classmethod
    def load(cls, path: Path) -> "VerificationPlan":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(binary=data["binary"], args=list(data.get("args", [])))
