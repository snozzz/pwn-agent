from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .scanner import iter_source_files


CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch"}
NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_:~]*)\s*\(")


@dataclass
class FunctionRegion:
    file_path: str
    name: str
    start_line: int
    end_line: int


class SourceFunctionIndex:
    def __init__(self, regions: dict[str, list[FunctionRegion]]):
        self.regions = regions

    def lookup(self, file_path: str, line_number: int) -> str | None:
        for region in self.regions.get(file_path, []):
            if region.start_line <= line_number <= region.end_line:
                return region.name
        return None

    def function_count(self) -> int:
        return sum(len(entries) for entries in self.regions.values())


def build_function_index(root: Path) -> SourceFunctionIndex:
    regions: dict[str, list[FunctionRegion]] = {}
    for path in iter_source_files(root):
        relative = str(path.relative_to(root))
        entries = detect_functions_in_file(path, relative)
        if entries:
            regions[relative] = entries
    return SourceFunctionIndex(regions)


def detect_functions_in_file(path: Path, relative_path: str) -> list[FunctionRegion]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    depth = 0
    signature_parts: list[str] = []
    signature_start_line: int | None = None
    current: FunctionRegion | None = None
    current_start_depth = 0
    in_block_comment = False
    regions: list[FunctionRegion] = []

    for line_number, raw_line in enumerate(lines, start=1):
        cleaned, in_block_comment = _strip_comments(raw_line, in_block_comment)
        stripped = cleaned.strip()

        if current is None and stripped:
            if signature_start_line is None:
                signature_start_line = line_number
            signature_parts.append(stripped)

        if current is None and "{" in cleaned:
            signature = " ".join(signature_parts).split("{", 1)[0].strip()
            name = _extract_function_name(signature)
            if name is not None and signature_start_line is not None:
                current = FunctionRegion(
                    file_path=relative_path,
                    name=name,
                    start_line=signature_start_line,
                    end_line=line_number,
                )
                current_start_depth = depth
            signature_parts = []
            signature_start_line = None
        elif current is None and ";" in cleaned:
            signature_parts = []
            signature_start_line = None
        elif current is None and not stripped:
            signature_parts = []
            signature_start_line = None

        depth += cleaned.count("{") - cleaned.count("}")

        if current is not None:
            current.end_line = line_number
            if depth <= current_start_depth:
                regions.append(current)
                current = None

    if current is not None:
        regions.append(current)

    return regions


def _extract_function_name(signature: str) -> str | None:
    if not signature or "(" not in signature or ")" not in signature:
        return None
    if "=" in signature:
        return None
    if signature.lstrip().startswith("#"):
        return None
    if "typedef" in signature or "return" in signature:
        return None
    head = signature.split("(", 1)[0].strip()
    if not head:
        return None
    token = head.split()[-1]
    if token in CONTROL_KEYWORDS:
        return None
    if token.endswith("]") or "*" in token:
        return None

    matches = NAME_RE.findall(signature)
    if not matches:
        return None
    name = matches[-1].split("::")[-1]
    if name in CONTROL_KEYWORDS:
        return None
    return name


def _strip_comments(line: str, in_block_comment: bool) -> tuple[str, bool]:
    result: list[str] = []
    i = 0
    while i < len(line):
        if in_block_comment:
            end = line.find("*/", i)
            if end == -1:
                return "".join(result), True
            i = end + 2
            in_block_comment = False
            continue
        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        if line.startswith("//", i):
            break
        result.append(line[i])
        i += 1
    return "".join(result), in_block_comment
