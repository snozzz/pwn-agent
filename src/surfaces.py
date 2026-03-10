from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .scanner import SOURCE_SUFFIXES, iter_source_files


SURFACE_PATTERNS = {
    "cli-argv": [r"\bmain\s*\(.*argc.*argv", r"\bgetopt\s*\("],
    "filesystem-input": [r"\bfopen\s*\(", r"\bopen\s*\(", r"\bread\s*\("],
    "network-input": [r"\bsocket\s*\(", r"\brecv\s*\(", r"\baccept\s*\("],
    "env-input": [r"\bgetenv\s*\("],
    "parser-signal": [r"parse", r"decode", r"deserialize", r"token"],
}


@dataclass
class InputSurface:
    category: str
    file_path: str
    line_number: int
    line_text: str


def detect_input_surfaces(root: Path) -> list[InputSurface]:
    surfaces: list[InputSurface] = []
    for file_path in iter_source_files(root):
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for idx, line in enumerate(lines, start=1):
            for category, patterns in SURFACE_PATTERNS.items():
                if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns):
                    surfaces.append(
                        InputSurface(
                            category=category,
                            file_path=str(file_path.relative_to(root)),
                            line_number=idx,
                            line_text=line.strip(),
                        )
                    )
    return surfaces
