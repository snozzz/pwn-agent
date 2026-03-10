from __future__ import annotations

from collections import Counter
from pathlib import Path

from .scanner import ScanResult


def render_markdown(result: ScanResult) -> str:
    counts = Counter(f.category for f in result.findings)
    lines = [
        "# Scan Report",
        "",
        f"- Root: `{result.root}`",
        f"- Files scanned: **{result.files_scanned}**",
        f"- Findings: **{len(result.findings)}**",
        "",
        "## Findings by category",
        "",
    ]

    if counts:
        for category, count in sorted(counts.items()):
            lines.append(f"- `{category}`: {count}")
    else:
        lines.append("- No heuristic findings")

    lines.extend(["", "## Evidence", ""])

    if not result.findings:
        lines.append("No matching patterns found.")
        return "\n".join(lines) + "\n"

    for finding in result.findings:
        lines.extend(
            [
                f"### {finding.category}",
                f"- File: `{finding.file_path}`",
                f"- Line: {finding.line_number}",
                f"- Code: `{finding.line_text}`",
                "",
            ]
        )

    return "\n".join(lines) + "\n"


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
