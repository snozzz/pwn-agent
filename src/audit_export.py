from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
from typing import Any

from .classification import classify_findings
from .dedup import deduplicate_findings
from .planio import VerificationPlan
from .workflow import WorkflowResult


def build_audit_summary(result: WorkflowResult) -> dict[str, object]:
    root = Path(result.scan.root)
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
    file_rollups = _build_file_rollups(classified, result.input_surfaces)
    function_rollups = _build_function_rollups(classified, result.input_surfaces)

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

    verification_plan_path = root / "verification-plan.json"
    verification_plan = VerificationPlan.load(verification_plan_path) if verification_plan_path.exists() else None
    verification_binary_path = root / verification_plan.binary if verification_plan is not None else None
    execution_readiness = _build_execution_readiness(
        root=root,
        compile_database=result.compile_db_summary,
        verification_plan=verification_plan,
        verification_binary_path=verification_binary_path,
        verification=result.verification,
        rebuild_verify=result.rebuild_verify,
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
        "audit_digest": {
            "top_file": (file_rollups[0]["file_path"] if file_rollups else None),
            "top_function": (function_rollups[0]["function_name"] if function_rollups else None),
            "top_input_surface": (
                {
                    "category": result.input_surfaces[0].category,
                    "file_path": result.input_surfaces[0].file_path,
                    "line_number": result.input_surfaces[0].line_number,
                    "function_name": result.input_surfaces[0].function_name,
                }
                if result.input_surfaces
                else None
            ),
            "verification_state": execution_readiness["verification_state"],
            "rebuild_state": execution_readiness["rebuild_state"],
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
        "file_rollups": file_rollups,
        "function_rollups": function_rollups,
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
        "execution_readiness": execution_readiness,
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


def _build_file_rollups(classified: list[Any], input_surfaces: list[Any]) -> list[dict[str, Any]]:
    rollups: dict[str, dict[str, Any]] = {}
    for finding in classified:
        entry = rollups.setdefault(
            finding.file_path,
            {
                "file_path": finding.file_path,
                "finding_count": 0,
                "surface_count": 0,
                "max_score": 0.0,
                "categories": set(),
                "functions": set(),
                "statuses": set(),
            },
        )
        entry["finding_count"] += 1
        entry["max_score"] = max(entry["max_score"], finding.score)
        entry["categories"].add(finding.category)
        entry["statuses"].add(finding.status)
        if finding.function_name:
            entry["functions"].add(finding.function_name)

    for surface in input_surfaces:
        entry = rollups.setdefault(
            surface.file_path,
            {
                "file_path": surface.file_path,
                "finding_count": 0,
                "surface_count": 0,
                "max_score": 0.0,
                "categories": set(),
                "functions": set(),
                "statuses": set(),
            },
        )
        entry["surface_count"] += 1
        entry["categories"].add(surface.category)
        if surface.function_name:
            entry["functions"].add(surface.function_name)

    ranked = sorted(
        rollups.values(),
        key=lambda item: (item["finding_count"], item["surface_count"], item["max_score"], item["file_path"]),
        reverse=True,
    )
    return [
        {
            "file_path": item["file_path"],
            "finding_count": item["finding_count"],
            "surface_count": item["surface_count"],
            "max_score": item["max_score"],
            "categories": sorted(item["categories"]),
            "functions": sorted(item["functions"]),
            "statuses": sorted(item["statuses"]),
        }
        for item in ranked[:10]
    ]


def _build_function_rollups(classified: list[Any], input_surfaces: list[Any]) -> list[dict[str, Any]]:
    rollups: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in classified:
        if not finding.function_name:
            continue
        key = (finding.file_path, finding.function_name)
        entry = rollups.setdefault(
            key,
            {
                "file_path": finding.file_path,
                "function_name": finding.function_name,
                "finding_count": 0,
                "surface_count": 0,
                "max_score": 0.0,
                "categories": set(),
                "statuses": set(),
            },
        )
        entry["finding_count"] += 1
        entry["max_score"] = max(entry["max_score"], finding.score)
        entry["categories"].add(finding.category)
        entry["statuses"].add(finding.status)

    for surface in input_surfaces:
        if not surface.function_name:
            continue
        key = (surface.file_path, surface.function_name)
        entry = rollups.setdefault(
            key,
            {
                "file_path": surface.file_path,
                "function_name": surface.function_name,
                "finding_count": 0,
                "surface_count": 0,
                "max_score": 0.0,
                "categories": set(),
                "statuses": set(),
            },
        )
        entry["surface_count"] += 1
        entry["categories"].add(surface.category)

    ranked = sorted(
        rollups.values(),
        key=lambda item: (item["finding_count"], item["surface_count"], item["max_score"], item["function_name"]),
        reverse=True,
    )
    return [
        {
            "file_path": item["file_path"],
            "function_name": item["function_name"],
            "finding_count": item["finding_count"],
            "surface_count": item["surface_count"],
            "max_score": item["max_score"],
            "categories": sorted(item["categories"]),
            "statuses": sorted(item["statuses"]),
        }
        for item in ranked[:10]
    ]


def _build_execution_readiness(
    root: Path,
    compile_database: dict[str, Any] | None,
    verification_plan: VerificationPlan | None,
    verification_binary_path: Path | None,
    verification: Any,
    rebuild_verify: Any,
) -> dict[str, Any]:
    ready_actions: list[dict[str, Any]] = []
    blocked_actions: list[dict[str, Any]] = []
    missing_prerequisites: list[str] = []

    has_compile_database = compile_database is not None
    rebuild_targets = int(compile_database.get("targets", 0)) if compile_database is not None else 0
    has_verification_plan = verification_plan is not None
    verification_binary_present = bool(verification_binary_path is not None and verification_binary_path.exists())

    if has_verification_plan and verification_binary_present:
        ready_actions.append(
            {
                "kind": "verify-run",
                "cli": [
                    "python3",
                    "-m",
                    "src.main",
                    "verify-run",
                    "--root",
                    str(root),
                    "--binary",
                    str(root / verification_plan.binary),
                    *verification_plan.args,
                ],
                "detail": f"verification binary ready: {verification_plan.binary}",
            }
        )
    elif has_verification_plan:
        missing_prerequisites.append(f"verification binary missing: {verification_plan.binary}")
        blocked_actions.append(
            {
                "kind": "verify-run",
                "missing": [f"build binary {verification_plan.binary}"],
            }
        )
    else:
        missing_prerequisites.append("verification-plan.json missing")

    if has_compile_database and rebuild_targets > 0:
        ready_actions.append(
            {
                "kind": "rebuild-plan",
                "cli": [
                    "python3",
                    "-m",
                    "src.main",
                    "rebuild-plan",
                    "--root",
                    str(root),
                ],
                "detail": f"compile database ready with {rebuild_targets} target(s)",
            }
        )
        ready_actions.append(
            {
                "kind": "rebuild-target",
                "cli": [
                    "python3",
                    "-m",
                    "src.main",
                    "rebuild-target",
                    "--root",
                    str(root),
                    "--index",
                    "1",
                    "--output-name",
                    "planned-sanitized-target",
                ],
                "detail": f"compile database ready with {rebuild_targets} target(s)",
            }
        )
        if has_verification_plan:
            ready_actions.append(
                {
                    "kind": "rebuild-verify",
                    "cli": [
                        "python3",
                        "-m",
                        "src.main",
                        "rebuild-verify",
                        "--root",
                        str(root),
                        "--index",
                        "1",
                        "--output-name",
                        "planned-sanitized-target",
                    ],
                    "detail": "compile database and verification plan are both present",
                }
            )
        else:
            blocked_actions.append(
                {
                    "kind": "rebuild-verify",
                    "missing": ["verification-plan.json"],
                }
            )
    else:
        missing_prerequisites.append("compile_commands.json missing or empty")
        blocked_actions.append(
            {
                "kind": "rebuild-target",
                "missing": ["compile_commands.json"],
            }
        )

    verification_state = "not-configured"
    if verification is not None:
        verification_state = "signal-detected" if verification.sanitizer_signal else "completed-no-signal"
    elif has_verification_plan and verification_binary_present:
        verification_state = "ready"
    elif has_verification_plan:
        verification_state = "blocked-missing-binary"

    rebuild_state = "not-configured"
    if rebuild_verify is not None:
        if rebuild_verify.rebuild.returncode != 0:
            rebuild_state = "rebuild-failed"
        elif rebuild_verify.verification is None and has_verification_plan:
            rebuild_state = "rebuilt-verification-missing"
        elif rebuild_verify.verification is None:
            rebuild_state = "rebuilt-no-verification-plan"
        elif rebuild_verify.verification.sanitizer_signal:
            rebuild_state = "signal-detected"
        else:
            rebuild_state = "completed-no-signal"
    elif has_compile_database and rebuild_targets > 0 and has_verification_plan:
        rebuild_state = "ready"
    elif has_compile_database and rebuild_targets > 0:
        rebuild_state = "blocked-missing-verification-plan"

    return {
        "verification_state": verification_state,
        "rebuild_state": rebuild_state,
        "has_compile_database": has_compile_database,
        "rebuild_targets": rebuild_targets,
        "has_verification_plan": has_verification_plan,
        "verification_binary": (verification_plan.binary if verification_plan is not None else None),
        "verification_binary_present": verification_binary_present,
        "ready_actions": ready_actions,
        "blocked_actions": blocked_actions,
        "missing_prerequisites": sorted(set(missing_prerequisites)),
    }
