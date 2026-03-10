from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import TYPE_CHECKING
from typing import Iterable

if TYPE_CHECKING:
    from .function_index import SourceFunctionIndex


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}

RISK_PATTERNS = {
    "unsafe_copy": [r"\bstrcpy\s*\(", r"\bstrcat\s*\(", r"\bsprintf\s*\("],
    "shell_exec": [r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecve?\s*\("],
    "raw_memory": [r"\bmemcpy\s*\(", r"\bmemmove\s*\(", r"\bmalloc\s*\(", r"\bfree\s*\("],
    "length_math": [r"\bsize_t\b", r"\bstrlen\s*\(", r"\bsizeof\b"],
}


@dataclass
class Finding:
    category: str
    file_path: str
    line_number: int
    line_text: str
    function_name: str | None = None


@dataclass
class ScanResult:
    root: str
    files_scanned: int
    findings: list[Finding]


def iter_source_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
            yield path


def scan_project(root: Path, function_index: SourceFunctionIndex | None = None) -> ScanResult:
    findings: list[Finding] = []
    files = list(iter_source_files(root))
    if function_index is None:
        from .function_index import build_function_index

        function_index = build_function_index(root)

    for file_path in files:
        relative_path = str(file_path.relative_to(root))
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for idx, line in enumerate(lines, start=1):
            for category, patterns in RISK_PATTERNS.items():
                if any(re.search(pattern, line) for pattern in patterns):
                    findings.append(
                        Finding(
                            category=category,
                            file_path=relative_path,
                            line_number=idx,
                            line_text=line.strip(),
                            function_name=function_index.lookup(relative_path, idx),
                        )
                    )

    return ScanResult(root=str(root), files_scanned=len(files), findings=findings)
