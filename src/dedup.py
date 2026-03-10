from __future__ import annotations

from .classification import ClassifiedFinding


KEY_FIELDS = ("category", "file_path", "line_number")


def deduplicate_findings(findings: list[ClassifiedFinding]) -> list[ClassifiedFinding]:
    kept: dict[tuple[str, str, int], ClassifiedFinding] = {}
    for finding in findings:
        key = (finding.category, finding.file_path, finding.line_number)
        existing = kept.get(key)
        if existing is None or finding.score > existing.score:
            kept[key] = finding
    return sorted(kept.values(), key=lambda item: (-item.score, item.file_path, item.line_number))
