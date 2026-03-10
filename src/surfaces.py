from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import TYPE_CHECKING

from .scanner import iter_source_files

if TYPE_CHECKING:
    from .function_index import SourceFunctionIndex


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
    function_name: str | None = None


def detect_input_surfaces(root: Path, function_index: SourceFunctionIndex | None = None) -> list[InputSurface]:
    surfaces: list[InputSurface] = []
    if function_index is None:
        from .function_index import build_function_index

        function_index = build_function_index(root)
    for file_path in iter_source_files(root):
        relative_path = str(file_path.relative_to(root))
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
                            file_path=relative_path,
                            line_number=idx,
                            line_text=line.strip(),
                            function_name=function_index.lookup(relative_path, idx),
                        )
                    )
    return surfaces
