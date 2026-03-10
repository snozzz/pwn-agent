from __future__ import annotations

from dataclasses import dataclass

from .classification import classify_findings
from .scanner import ScanResult
from .surfaces import InputSurface


@dataclass
class FileHotspot:
    file_path: str
    score: int
    findings: int
    surfaces: int
    verified: bool


@dataclass
class FunctionHotspot:
    file_path: str
    function_name: str
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


def rank_function_hotspots(
    scan: ScanResult,
    input_surfaces: list[InputSurface],
    verified_signal: bool = False,
) -> list[FunctionHotspot]:
    classified = classify_findings(scan.findings, verified_signal=verified_signal)
    buckets: dict[tuple[str, str], FunctionHotspot] = {}

    for finding in classified:
        if not finding.function_name:
            continue
        key = (finding.file_path, finding.function_name)
        entry = buckets.setdefault(
            key,
            FunctionHotspot(
                file_path=finding.file_path,
                function_name=finding.function_name,
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
        if not surface.function_name:
            continue
        key = (surface.file_path, surface.function_name)
        entry = buckets.setdefault(
            key,
            FunctionHotspot(
                file_path=surface.file_path,
                function_name=surface.function_name,
                score=0,
                findings=0,
                surfaces=0,
                verified=False,
            ),
        )
        entry.surfaces += 1
        entry.score += 15
        if verified_signal:
            entry.verified = True

    for entry in buckets.values():
        if entry.verified:
            entry.score += 20

    return sorted(buckets.values(), key=lambda item: (-item.score, item.file_path, item.function_name))
