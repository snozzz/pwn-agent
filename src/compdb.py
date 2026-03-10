from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any


@dataclass
class CompileCommand:
    directory: str
    file: str
    command: str | None = None
    arguments: list[str] | None = None


@dataclass
class CompileDatabase:
    entries: list[CompileCommand]

    @classmethod
    def load(cls, path: Path) -> "CompileDatabase":
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = [
            CompileCommand(
                directory=item["directory"],
                file=item["file"],
                command=item.get("command"),
                arguments=item.get("arguments"),
            )
            for item in raw
        ]
        return cls(entries=entries)

    def summary(self) -> dict[str, Any]:
        files = [entry.file for entry in self.entries]
        directories = sorted({entry.directory for entry in self.entries})
        return {
            "entries": len(self.entries),
            "directories": directories,
            "files": files,
        }
