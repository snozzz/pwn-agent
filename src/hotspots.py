from __future__ import annotations

from dataclasses import dataclass

from .classification import ClassifiedFinding, classify_findings
from .scanner import ScanResult
from .surfaces import InputSurface


@dataclass
class FileHotspot:
    file_path: str
    score: int
    findings: int
    surfaces: int
    verified: bool


def rank_hotspots(
    scan: ScanResult,
    input_surfaces: list[InputSurface],
    verified_signal: bool = False,
) -> list[FileHotspot]:
    classified = classify_findings(scan.findings, verified_signal=verified_signal)
    buckets: dict[str, FileHotspot] = {}

    for finding in classified:
        entry = buckets.setdefault(
            finding.file_path,
            FileHotspot(
                file_path=finding.file_path,
                score=0,
                findings=0,
                surfaces=0,
                verified=False,
            ),
        )
        entry.findings += 1
        entry.score += finding.score
        if finding.status == "verified":
            entry.verified = True

    for surface in input_surfaces:
        entry = buckets.setdefault(
            surface.file_path,
            FileHotspot(
                file_path=surface.file_path,
                score=0,
                findings=0,
                surfaces=0,
                verified=False,
            ),
        )
        entry.surfaces += 1
        entry.score += 15

    return sorted(buckets.values(), key=lambda item: (-item.score, item.file_path))
