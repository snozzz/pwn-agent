from __future__ import annotations

from dataclasses import dataclass

from .scanner import Finding


@dataclass
class ClassifiedFinding:
    category: str
    file_path: str
    line_number: int
    line_text: str
    function_name: str | None
    severity: str
    confidence: str
    status: str
    score: int


CATEGORY_BASE = {
    "unsafe_copy": ("high", "medium", 80),
    "shell_exec": ("high", "medium", 75),
    "raw_memory": ("medium", "low", 45),
    "length_math": ("low", "low", 20),
}


def classify_finding(finding: Finding, verified_signal: bool = False) -> ClassifiedFinding:
    severity, confidence, score = CATEGORY_BASE.get(finding.category, ("low", "low", 10))
    status = "verified" if verified_signal and finding.category in {"unsafe_copy", "raw_memory", "length_math"} else "heuristic"
    if status == "verified":
        confidence = "high"
        score = max(score, 95)
    return ClassifiedFinding(
        category=finding.category,
        file_path=finding.file_path,
        line_number=finding.line_number,
        line_text=finding.line_text,
        function_name=finding.function_name,
        severity=severity,
        confidence=confidence,
        status=status,
        score=score,
    )


def classify_findings(findings: list[Finding], verified_signal: bool = False) -> list[ClassifiedFinding]:
    classified = [classify_finding(finding, verified_signal=verified_signal) for finding in findings]
    return sorted(classified, key=lambda item: (-item.score, item.file_path, item.line_number))
