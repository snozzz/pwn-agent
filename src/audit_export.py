from __future__ import annotations

from collections import Counter
from pathlib import Path
import json

from .classification import classify_findings
from .dedup import deduplicate_findings
from .workflow import WorkflowResult


def build_audit_summary(result: WorkflowResult) -> dict[str, object]:
    verified_signal = bool(
        (result.verification is not None and result.verification.sanitizer_signal)
        or (
            result.rebuild_verify is not None
            and result.rebuild_verify.verification is not None
            and result.rebuild_verify.verification.sanitizer_signal
        )
    )
    classified = deduplicate_findings(classify_findings(result.scan.findings, verified_signal=verified_signal))
    findings_by_category = dict(sorted(Counter(item.category for item in classified).items()))
    findings_by_severity = dict(sorted(Counter(item.severity for item in classified).items()))
    findings_by_status = dict(sorted(Counter(item.status for item in classified).items()))

    command_summary: list[dict[str, object]] = [
        {
            "kind": "policy-command",
            "argv": command.argv,
            "returncode": command.returncode,
            "stdout_lines": len(command.stdout.splitlines()),
            "stderr_lines": len(command.stderr.splitlines()),
        }
        for command in result.command_logs
    ]

    if result.verification is not None:
        command_summary.append(
            {
                "kind": "verification-run",
                "argv": result.verification.argv,
                "returncode": result.verification.returncode,
                "sanitizer_signal": result.verification.sanitizer_signal,
            }
        )

    if result.rebuild_verify is not None:
        command_summary.append(
            {
                "kind": "rebuild-target",
                "argv": result.rebuild_verify.rebuild.argv,
                "returncode": result.rebuild_verify.rebuild.returncode,
                "stdout_lines": len(result.rebuild_verify.rebuild.stdout.splitlines()),
                "stderr_lines": len(result.rebuild_verify.rebuild.stderr.splitlines()),
            }
        )
        if result.rebuild_verify.verification is not None:
            command_summary.append(
                {
                    "kind": "rebuild-verification-run",
                    "argv": result.rebuild_verify.verification.argv,
                    "returncode": result.rebuild_verify.verification.returncode,
                    "sanitizer_signal": result.rebuild_verify.verification.sanitizer_signal,
                }
            )

    return {
        "root": result.scan.root,
        "scan_summary": {
            "files_scanned": result.scan.files_scanned,
            "raw_findings": len(result.scan.findings),
            "findings": len(classified),
            "findings_by_category": findings_by_category,
            "findings_by_severity": findings_by_severity,
            "findings_by_status": findings_by_status,
            "verified_signal": verified_signal,
        },
        "classified_findings": [
            {
                "category": item.category,
                "file_path": item.file_path,
                "line_number": item.line_number,
                "function_name": item.function_name,
                "severity": item.severity,
                "confidence": item.confidence,
                "status": item.status,
                "score": item.score,
                "line_text": item.line_text,
            }
            for item in classified
        ],
        "file_hotspots": [
            {
                "file_path": hotspot.file_path,
                "score": hotspot.score,
                "findings": hotspot.findings,
                "surfaces": hotspot.surfaces,
                "verified": hotspot.verified,
            }
            for hotspot in result.hotspots
        ],
        "function_hotspots": [
            {
                "file_path": hotspot.file_path,
                "function_name": hotspot.function_name,
                "score": hotspot.score,
                "findings": hotspot.findings,
                "surfaces": hotspot.surfaces,
                "verified": hotspot.verified,
            }
            for hotspot in result.function_hotspots
        ],
        "function_coverage": dict(result.function_coverage),
        "input_surfaces": [
            {
                "category": surface.category,
                "file_path": surface.file_path,
                "line_number": surface.line_number,
                "function_name": surface.function_name,
                "line_text": surface.line_text,
            }
            for surface in result.input_surfaces
        ],
        "compile_database": result.compile_db_summary,
        "verification": (
            {
                "binary": result.verification.binary,
                "argv": result.verification.argv,
                "returncode": result.verification.returncode,
                "sanitizer_signal": result.verification.sanitizer_signal,
                "stdout_lines": len(result.verification.stdout.splitlines()),
                "stderr_lines": len(result.verification.stderr.splitlines()),
                "stderr_head": _head_line(result.verification.stderr),
            }
            if result.verification is not None
            else None
        ),
        "rebuild_verify": (
            {
                "output_binary": result.rebuild_verify.output_binary,
                "rebuild": {
                    "argv": result.rebuild_verify.rebuild.argv,
                    "returncode": result.rebuild_verify.rebuild.returncode,
                    "stdout_lines": len(result.rebuild_verify.rebuild.stdout.splitlines()),
                    "stderr_lines": len(result.rebuild_verify.rebuild.stderr.splitlines()),
                    "stderr_head": _head_line(result.rebuild_verify.rebuild.stderr),
                },
                "verification": (
                    {
                        "binary": result.rebuild_verify.verification.binary,
                        "argv": result.rebuild_verify.verification.argv,
                        "returncode": result.rebuild_verify.verification.returncode,
                        "sanitizer_signal": result.rebuild_verify.verification.sanitizer_signal,
                        "stdout_lines": len(result.rebuild_verify.verification.stdout.splitlines()),
                        "stderr_lines": len(result.rebuild_verify.verification.stderr.splitlines()),
                        "stderr_head": _head_line(result.rebuild_verify.verification.stderr),
                    }
                    if result.rebuild_verify.verification is not None
                    else None
                ),
            }
            if result.rebuild_verify is not None
            else None
        ),
        "trace": [
            {
                "step": event.step,
                "status": event.status,
                "details": event.details,
            }
            for event in result.trace.events
        ],
        "command_summary": command_summary,
    }


def write_audit_summary(path: Path, result: WorkflowResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_audit_summary(result), indent=2), encoding="utf-8")


def _head_line(text: str) -> str | None:
    stripped = text.strip()
    if not stripped:
        return None
    return stripped.splitlines()[0]
