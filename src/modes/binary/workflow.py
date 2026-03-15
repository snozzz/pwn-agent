from __future__ import annotations

from pathlib import Path
import hashlib
import json
import re
import signal
import shutil
import subprocess
from typing import Any

from ...command_registry import get_command_rule
from ...config import AgentConfig
from ...policy import CommandPolicy, CommandResult, PolicyError

ANALYSIS_SCHEMA = "pwn-agent.binary-analysis.v1"
TRIAGE_SCHEMA = "pwn-agent.binary-crash-triage.v1"
PLAN_SCHEMA = "pwn-agent.binary-plan.v2"
PATCH_VALIDATION_SCHEMA = "pwn-agent.binary-patch-validation.v1"
VERIFY_SCHEMA = "pwn-agent.binary-verify.v1"
STAGE_ORDER = ["identify", "inspect", "reproduce", "triage", "patch", "validate", "summarize"]

_TOOL_SPECS = [
    {"id": "file", "tool": "file", "build_argv": lambda binary: ["file", str(binary)], "stdout_lines": 80, "stdout_chars": 12000},
    {
        "id": "checksec",
        "tool": "checksec",
        "build_argv": lambda binary: ["checksec", "--file", str(binary)],
        "stdout_lines": 80,
        "stdout_chars": 12000,
    },
    {
        "id": "readelf-header",
        "tool": "readelf",
        "build_argv": lambda binary: ["readelf", "-h", str(binary)],
        "stdout_lines": 120,
        "stdout_chars": 18000,
    },
    {
        "id": "readelf-symbols",
        "tool": "readelf",
        "build_argv": lambda binary: ["readelf", "-Ws", str(binary)],
        "stdout_lines": 400,
        "stdout_chars": 32000,
    },
    {
        "id": "objdump-headers",
        "tool": "objdump",
        "build_argv": lambda binary: ["objdump", "-x", str(binary)],
        "stdout_lines": 300,
        "stdout_chars": 32000,
    },
    {
        "id": "nm-symbols",
        "tool": "nm",
        "build_argv": lambda binary: ["nm", "-an", str(binary)],
        "stdout_lines": 400,
        "stdout_chars": 32000,
    },
    {
        "id": "strings",
        "tool": "strings",
        "build_argv": lambda binary: ["strings", "-n", "6", str(binary)],
        "stdout_lines": 200,
        "stdout_chars": 18000,
    },
]

_SUSPICIOUS_IMPORTS = {
    "strcpy",
    "strcat",
    "gets",
    "sprintf",
    "vsprintf",
    "system",
    "popen",
    "execve",
    "memcpy",
}

_STRING_MARKERS = [
    "strcpy",
    "strcat",
    "gets",
    "sprintf",
    "system(",
    "popen",
    "/bin/sh",
    "execve",
    "password",
    "token",
    "api_key",
    "secret",
    "http://",
    "https://",
]


def write_binary_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_binary_analysis(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != ANALYSIS_SCHEMA:
        raise ValueError(f"unsupported binary analysis schema: {payload.get('schema')}")
    return payload


def load_binary_artifact(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") not in {ANALYSIS_SCHEMA, TRIAGE_SCHEMA, VERIFY_SCHEMA, PATCH_VALIDATION_SCHEMA}:
        raise ValueError(f"unsupported binary artifact schema: {payload.get('schema')}")
    return payload


def scan_binary(
    *,
    root: Path,
    binary: Path,
    stdin_file: Path | None = None,
    args: list[str] | None = None,
    timeout_seconds: int | None = None,
    config: AgentConfig | None = None,
    stdin_sample: Path | None = None,
    protocol_sample: Path | None = None,
) -> dict[str, Any]:
    resolved_root = root.resolve()
    resolved_binary = binary.resolve()
    if not resolved_binary.exists() or not resolved_binary.is_file():
        raise ValueError(f"binary not found: {resolved_binary}")

    effective_stdin_file = stdin_file or stdin_sample
    runtime_args = list(args or [])

    cfg = config or AgentConfig()
    policy = CommandPolicy(
        resolved_root,
        allowlist=cfg.allowlist,
        timeout_seconds=(int(timeout_seconds) if timeout_seconds is not None else cfg.timeout_seconds),
    )

    evidence = [_collect_tool_evidence(policy, spec, resolved_binary) for spec in _TOOL_SPECS]
    evidence_by_id = {entry["id"]: entry for entry in evidence}

    file_type = _first_line(_stdout_lines(evidence_by_id.get("file")))
    elf_header = _parse_elf_header(_stdout_lines(evidence_by_id.get("readelf-header")))
    imports = _extract_imported_functions(_stdout_lines(evidence_by_id.get("readelf-symbols")))
    exported_symbol_count = _count_exported_symbols(_stdout_lines(evidence_by_id.get("nm-symbols")))
    strings_lines = _stdout_lines(evidence_by_id.get("strings"))
    strings_highlights = _extract_strings_highlights(strings_lines)
    suspicious_indicators = _build_suspicious_indicators(imports, strings_highlights)
    mitigations = _parse_checksec_mitigations(evidence_by_id.get("checksec"))

    return {
        "schema": ANALYSIS_SCHEMA,
        "schema_version": 1,
        "artifact_type": "binary_audit",
        "mode": "binary",
        "stages_supported": list(STAGE_ORDER),
        "target": {
            "root": str(resolved_root),
            "binary_path": str(resolved_binary),
            "binary_name": resolved_binary.name,
            "size_bytes": resolved_binary.stat().st_size,
            "sha256": _sha256_file(resolved_binary),
        },
        "runtime_hints": {
            "args": runtime_args,
            "stdin_file_path": str(effective_stdin_file.resolve()) if effective_stdin_file else None,
            "stdin_file_preview": _read_optional_sample(effective_stdin_file, max_bytes=256),
            "stdin_file_size_bytes": (
                int(effective_stdin_file.resolve().stat().st_size) if effective_stdin_file is not None else None
            ),
            "protocol_sample_path": str(protocol_sample.resolve()) if protocol_sample else None,
        },
        "architecture": {
            "file_type": file_type,
            "class": elf_header.get("Class"),
            "machine": elf_header.get("Machine"),
            "elf_type": elf_header.get("Type"),
            "data_encoding": elf_header.get("Data"),
            "entry_point": elf_header.get("Entry point address"),
        },
        "mitigations": mitigations,
        "symbols": {
            "imported_functions": imports[:80],
            "imported_function_count": len(imports),
            "exported_symbol_count": exported_symbol_count,
        },
        "strings": {
            "highlights": strings_highlights,
            "highlight_count": len(strings_highlights),
            "truncated": bool(evidence_by_id.get("strings", {}).get("stdout", {}).get("truncated", False)),
            "collected_line_count": int(evidence_by_id.get("strings", {}).get("stdout", {}).get("line_count_total", 0)),
        },
        "suspicious_indicators": suspicious_indicators,
        "evidence": evidence,
        # Compatibility keys retained for planner consumers that expect the previous shape.
        "root": str(resolved_root),
        "binary_path": str(resolved_binary),
        "binary_fingerprint": {
            "size_bytes": resolved_binary.stat().st_size,
            "sha256": _sha256_file(resolved_binary),
        },
        "inputs": {
            "stdin_file_path": str(effective_stdin_file.resolve()) if effective_stdin_file else None,
            "stdin_sample_path": str(effective_stdin_file.resolve()) if effective_stdin_file else None,
            "protocol_sample_path": str(protocol_sample.resolve()) if protocol_sample else None,
            "args": runtime_args,
        },
    }


def render_binary_audit_markdown(artifact: dict[str, Any]) -> str:
    if artifact.get("schema") == TRIAGE_SCHEMA:
        return render_binary_triage_markdown(artifact)

    lines = ["# Binary Audit", ""]
    target = dict(artifact.get("target") or {})
    lines.append(f"- Binary: `{target.get('binary_path')}`")
    lines.append(f"- SHA256: `{target.get('sha256')}`")
    lines.append(f"- Size: {target.get('size_bytes')} bytes")

    arch = dict(artifact.get("architecture") or {})
    lines.append(f"- File type: {arch.get('file_type')}")
    lines.append(f"- Machine: {arch.get('machine')}")
    lines.append(f"- Class: {arch.get('class')}")

    mitigations = dict(artifact.get("mitigations") or {})
    if mitigations:
        lines.append(
            "- Mitigations: "
            + ", ".join(
                f"{key}={value}"
                for key, value in sorted(mitigations.items())
                if key in {"relro", "canary", "nx", "pie", "fortify"}
            )
        )

    symbols = dict(artifact.get("symbols") or {})
    lines.append(f"- Imported functions: {symbols.get('imported_function_count', 0)}")
    lines.append(f"- Exported symbols: {symbols.get('exported_symbol_count', 0)}")

    lines.extend(["", "## Suspicious Indicators", ""])
    indicators = list(artifact.get("suspicious_indicators") or [])
    if not indicators:
        lines.append("- none")
    else:
        for indicator in indicators[:20]:
            lines.append(
                f"- [{indicator.get('kind', 'unknown')}] {indicator.get('indicator')}"
                + (f" :: {indicator.get('evidence')}" if indicator.get("evidence") else "")
            )

    lines.extend(["", "## Tool Evidence", ""])
    for entry in artifact.get("evidence", []):
        lines.append(
            f"- {entry.get('id')} ({entry.get('tool')}): status={entry.get('status')} "
            f"available={str(entry.get('available')).lower()} rc={entry.get('returncode')}"
        )
    return "\n".join(lines) + "\n"


def render_binary_triage_markdown(artifact: dict[str, Any]) -> str:
    lines = ["# Crash Triage", ""]
    target = dict(artifact.get("target") or {})
    execution = dict(artifact.get("execution_result") or {})
    crash_summary = dict(artifact.get("crash_summary") or {})
    debugger = dict(artifact.get("debugger_summary") or {})

    lines.append(f"- Binary: `{target.get('binary_path')}`")
    lines.append(f"- Exit code: {execution.get('exit_code')}")
    lines.append(f"- Signal: {execution.get('signal_name')}")
    lines.append(f"- Timed out: {str(execution.get('timed_out')).lower()}")
    lines.append(f"- Suspicious: {str(crash_summary.get('suspicious')).lower()}")
    lines.append(f"- Reason: {crash_summary.get('reason')}")
    lines.append(f"- GDB attempted: {str(debugger.get('attempted')).lower()}")
    lines.append(f"- GDB collected: {str(debugger.get('collected')).lower()}")

    lines.extend(["", "## Evidence", ""])
    for entry in artifact.get("evidence", []):
        lines.append(
            f"- {entry.get('id')} ({entry.get('tool')}): status={entry.get('status')} "
            f"available={str(entry.get('available')).lower()} rc={entry.get('returncode')}"
        )
    return "\n".join(lines) + "\n"


def build_binary_plan(
    analysis: dict[str, Any] | None = None,
    *,
    crash: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if analysis is None and crash is None and validation is None:
        raise ValueError("binary plan requires at least one artifact")

    root = _resolve_binary_root(analysis, crash, validation)
    binary_path = _resolve_binary_path(analysis, crash, validation)
    stdin_file_path, runtime_args = _extract_runtime_hints(analysis, crash)
    patch_candidate = _extract_patch_candidate(analysis, crash, validation)
    analysis_has_mitigations = _analysis_has_mitigations(analysis)
    crash_suspicious = bool(crash and dict(crash.get("crash_summary") or {}).get("suspicious"))
    debugger_collected = bool(crash and dict(crash.get("debugger_summary") or {}).get("collected"))
    validation_present = bool(_extract_validation_result(analysis, crash, validation))

    actions: list[dict[str, Any]] = []
    if not analysis_has_mitigations:
        actions.append(
            _binary_plan_action(
                action_id="collect-binary-evidence",
                stage="identify",
                kind="binary_scan",
                status="ready",
                priority=100,
                rationale="binary evidence is missing or does not include a mitigations summary yet",
                expected_artifacts=["binary-analysis.json"],
                suggested_cli=_build_binary_scan_cli(root, binary_path, stdin_file_path=stdin_file_path, runtime_args=runtime_args),
            )
        )
    else:
        actions.append(
            _binary_plan_action(
                action_id="review-binary-evidence",
                stage="inspect",
                kind="review_binary_evidence",
                status="context",
                priority=95,
                rationale="binary metadata, mitigations, imports, and strings are available for review",
                expected_artifacts=[],
                suggested_cli=[],
            )
        )

    if crash is None:
        actions.append(
            _binary_plan_action(
                action_id="reproduce-target-behavior",
                stage="reproduce",
                kind="crash_triage",
                status="ready",
                priority=90,
                rationale="no crash reproduction artifact is present yet",
                expected_artifacts=["binary-crash-triage.json"],
                suggested_cli=_build_crash_triage_cli(
                    root,
                    binary_path,
                    stdin_file_path=stdin_file_path,
                    runtime_args=runtime_args,
                    gdb_batch=False,
                ),
            )
        )
    elif crash_suspicious and not debugger_collected:
        actions.append(
            _binary_plan_action(
                action_id="collect-debugger-context",
                stage="triage",
                kind="crash_triage_gdb",
                status="ready",
                priority=92,
                rationale="the crash artifact is suspicious but does not include bounded debugger context",
                expected_artifacts=["binary-crash-triage-gdb.json"],
                suggested_cli=_build_crash_triage_cli(
                    root,
                    binary_path,
                    stdin_file_path=stdin_file_path,
                    runtime_args=runtime_args,
                    gdb_batch=True,
                ),
            )
        )

    if crash_suspicious:
        patch_status = "context" if patch_candidate is None else "context"
        actions.append(
            _binary_plan_action(
                action_id="draft-patch-hypothesis",
                stage="patch",
                kind="patch_hypothesis",
                status=patch_status,
                priority=80,
                rationale="a suspicious crash should be reduced to a concrete local patch hypothesis before validation",
                expected_artifacts=["patch-notes.md"],
                suggested_cli=[],
            )
        )

    if patch_candidate is not None and not validation_present:
        actions.append(
            _binary_plan_action(
                action_id="validate-candidate-patch",
                stage="validate",
                kind="binary_verify",
                status="ready",
                priority=85,
                depends_on=["draft-patch-hypothesis"] if any(action["id"] == "draft-patch-hypothesis" for action in actions) else [],
                blocked_by=["draft-patch-hypothesis"] if any(action["id"] == "draft-patch-hypothesis" for action in actions) else [],
                rationale="a candidate patch exists but no validation artifact confirms the behavior change yet",
                expected_artifacts=["binary-verify.json"],
                suggested_cli=_build_binary_verify_cli(root, binary_path, stdin_file_path=stdin_file_path, runtime_args=runtime_args),
            )
        )

    summarize_dependencies = [
        action["id"]
        for action in actions
        if action["status"] == "ready" and action["stage"] in {"identify", "inspect", "reproduce", "triage", "patch", "validate"}
    ]
    summarize_blocked_by = list(summarize_dependencies)
    actions.append(
        _binary_plan_action(
            action_id="summarize-local-findings",
            stage="summarize",
            kind="summarize_binary_findings",
            status="blocked" if summarize_dependencies else "context",
            priority=10,
            depends_on=summarize_dependencies,
            blocked_by=summarize_blocked_by,
            rationale="summary should happen after the immediate local evidence and validation loop stabilizes",
            expected_artifacts=["binary-summary.md"],
            suggested_cli=[],
        )
    )

    ordered_actions = sorted(
        actions,
        key=lambda item: (_binary_stage_rank(item.get("stage")), -int(item.get("priority", 0)), item.get("id", "")),
    )
    readiness = {
        "runnable_actions": sum(1 for action in ordered_actions if action.get("status") == "ready" and action.get("suggested_cli")),
        "blocked_actions": sum(1 for action in ordered_actions if action.get("status") == "blocked"),
        "context_actions": sum(1 for action in ordered_actions if action.get("status") == "context"),
    }
    plan_fingerprint = _compute_binary_plan_fingerprint(ordered_actions, binary_path=binary_path, root=root)

    return {
        "schema": PLAN_SCHEMA,
        "schema_version": 2,
        "mode": "binary",
        "root": root,
        "plan_fingerprint": plan_fingerprint,
        "stage_order": list(STAGE_ORDER),
        "source_artifacts": {
            "analysis_schema": (analysis.get("schema") if analysis is not None else None),
            "crash_schema": (crash.get("schema") if crash is not None else None),
            "validation_schema": (validation.get("schema") if validation is not None else None),
        },
        "binary_path": binary_path,
        "binary_fingerprint": (analysis.get("binary_fingerprint") if analysis is not None else None) or (analysis.get("target") if analysis is not None else None) or (crash.get("target") if crash is not None else None) or (validation.get("target") if validation is not None else None),
        "readiness": readiness,
        "next_actions": ordered_actions,
    }


def _binary_plan_action(
    *,
    action_id: str,
    stage: str,
    kind: str,
    status: str,
    priority: int,
    rationale: str,
    expected_artifacts: list[str],
    suggested_cli: list[str],
    depends_on: list[str] | None = None,
    blocked_by: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "stage": stage,
        "phase": _stage_to_phase(stage),
        "kind": kind,
        "status": status,
        "priority": priority,
        "depends_on": list(depends_on or []),
        "blocked_by": list(blocked_by or []),
        "rationale": rationale,
        "expected_artifacts": list(expected_artifacts),
        "suggested_cli": list(suggested_cli),
    }


def _resolve_binary_root(
    analysis: dict[str, Any] | None,
    crash: dict[str, Any] | None,
    validation: dict[str, Any] | None,
) -> str:
    candidates = [
        str(item)
        for item in [
            (analysis or {}).get("root"),
            (analysis or {}).get("target", {}).get("root"),
            (crash or {}).get("root"),
            (crash or {}).get("target", {}).get("root"),
            (validation or {}).get("root"),
            (validation or {}).get("target", {}).get("root"),
        ]
        if item
    ]
    unique = sorted({str(Path(candidate).resolve()) for candidate in candidates})
    if not unique:
        raise ValueError("binary plan could not determine root from artifacts")
    if len(unique) != 1:
        raise ValueError(f"binary plan artifacts disagree on root: {', '.join(unique)}")
    return unique[0]


def _resolve_binary_path(
    analysis: dict[str, Any] | None,
    crash: dict[str, Any] | None,
    validation: dict[str, Any] | None,
) -> str:
    candidates = [
        str(item)
        for item in [
            (analysis or {}).get("binary_path"),
            (analysis or {}).get("target", {}).get("binary_path"),
            (crash or {}).get("binary_path"),
            (crash or {}).get("target", {}).get("binary_path"),
            (validation or {}).get("binary_path"),
            (validation or {}).get("target", {}).get("binary_path"),
        ]
        if item
    ]
    unique = sorted({str(Path(candidate).resolve()) for candidate in candidates})
    if not unique:
        raise ValueError("binary plan could not determine binary path from artifacts")
    if len(unique) != 1:
        raise ValueError(f"binary plan artifacts disagree on binary path: {', '.join(unique)}")
    return unique[0]


def _extract_runtime_hints(analysis: dict[str, Any] | None, crash: dict[str, Any] | None) -> tuple[str | None, list[str]]:
    stdin_file_path = (
        (analysis or {}).get("runtime_hints", {}).get("stdin_file_path")
        or (analysis or {}).get("inputs", {}).get("stdin_file_path")
        or (analysis or {}).get("inputs", {}).get("stdin_sample_path")
        or (crash or {}).get("runtime_hints", {}).get("stdin_file_path")
    )
    runtime_args = list(
        (analysis or {}).get("runtime_hints", {}).get("args")
        or (analysis or {}).get("inputs", {}).get("args")
        or (crash or {}).get("runtime_hints", {}).get("args")
        or []
    )
    return (str(Path(stdin_file_path).resolve()) if stdin_file_path else None), runtime_args


def _extract_patch_candidate(
    analysis: dict[str, Any] | None,
    crash: dict[str, Any] | None,
    validation: dict[str, Any] | None,
) -> dict[str, Any] | None:
    candidate = (crash or {}).get("patch_candidate") or (analysis or {}).get("patch_candidate") or (validation or {}).get("patch_metadata")
    return dict(candidate) if isinstance(candidate, dict) else None


def _extract_validation_result(
    analysis: dict[str, Any] | None,
    crash: dict[str, Any] | None,
    validation: dict[str, Any] | None,
) -> dict[str, Any] | None:
    payload = (validation or {}).get("validation_result") or (crash or {}).get("validation_result") or (analysis or {}).get("validation_result")
    return dict(payload) if isinstance(payload, dict) else None


def _analysis_has_mitigations(analysis: dict[str, Any] | None) -> bool:
    if analysis is None:
        return False
    mitigations = dict(analysis.get("mitigations") or {})
    if not mitigations:
        return False
    return any(mitigations.get(key) not in {None, "unknown"} for key in {"relro", "canary", "nx", "pie", "fortify"})


def _build_binary_scan_cli(root: str, binary_path: str, *, stdin_file_path: str | None, runtime_args: list[str]) -> list[str]:
    argv = [
        "python3",
        "-m",
        "src.main",
        "binary-scan",
        "--root",
        root,
        "--binary",
        binary_path,
        "--output",
        _default_binary_artifact_path(root, "binary-analysis.json"),
    ]
    if stdin_file_path:
        argv.extend(["--stdin-file", stdin_file_path])
    if runtime_args:
        argv.extend(["--args", *runtime_args])
    return argv


def _build_crash_triage_cli(
    root: str,
    binary_path: str,
    *,
    stdin_file_path: str | None,
    runtime_args: list[str],
    gdb_batch: bool,
) -> list[str]:
    argv = [
        "python3",
        "-m",
        "src.main",
        "crash-triage",
        "--root",
        root,
        "--binary",
        binary_path,
        "--output",
        _default_binary_artifact_path(root, "binary-crash-triage.json" if not gdb_batch else "binary-crash-triage-gdb.json"),
    ]
    if stdin_file_path:
        argv.extend(["--stdin-file", stdin_file_path])
    if runtime_args:
        argv.extend(["--args", *runtime_args])
    if gdb_batch:
        argv.append("--gdb-batch")
    return argv


def _build_binary_verify_cli(root: str, binary_path: str, *, stdin_file_path: str | None, runtime_args: list[str]) -> list[str]:
    argv = [
        "python3",
        "-m",
        "src.main",
        "binary-verify",
        "--root",
        root,
        "--binary",
        binary_path,
        "--output",
        _default_binary_artifact_path(root, "binary-verify.json"),
    ]
    if stdin_file_path:
        argv.extend(["--stdin-file", stdin_file_path])
    if runtime_args:
        argv.extend(["--", *runtime_args])
    return argv


def _default_binary_artifact_path(root: str, filename: str) -> str:
    return str((Path(root).resolve() / ".pwn-agent" / filename).resolve())


def _stage_to_phase(stage: str) -> str:
    if stage in {"identify", "inspect", "reproduce", "triage"}:
        return "triage"
    if stage in {"patch", "validate"}:
        return "execution"
    return "synthesis"


def _binary_stage_rank(stage: str | None) -> int:
    order = {name: index for index, name in enumerate(STAGE_ORDER)}
    return order.get(stage or "", 999)


def _compute_binary_plan_fingerprint(actions: list[dict[str, Any]], *, binary_path: str, root: str) -> str:
    payload = {
        "root": root,
        "binary_path": binary_path,
        "actions": actions,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def render_binary_plan_markdown(plan: dict[str, Any]) -> str:
    lines = ["# Binary Plan", ""]
    lines.append(f"- Schema: {plan.get('schema')}")
    lines.append(f"- Plan fingerprint: `{plan.get('plan_fingerprint')}`")
    lines.append(f"- Binary: `{plan.get('binary_path')}`")
    lines.append(f"- Stage order: {', '.join(plan.get('stage_order', []))}")
    readiness = dict(plan.get("readiness") or {})
    if readiness:
        lines.append(
            "- Readiness: "
            + ", ".join(f"{key}={value}" for key, value in sorted(readiness.items()))
        )
    lines.extend(["", "## Next Actions", ""])
    for action in plan.get("next_actions", []):
        lines.append(
            f"- [{action.get('stage', 'unknown')}] [{action.get('status', 'unknown')}] "
            f"{action.get('id')} :: {action.get('kind', '')}"
        )
    return "\n".join(lines) + "\n"


def verify_binary_execution(
    *,
    root: Path,
    binary: Path,
    args: list[str] | None = None,
    stdin_file: Path | None = None,
    protocol_sample: Path | None = None,
    config: AgentConfig | None = None,
    stdin_sample: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    resolved_root = root.resolve()
    resolved_binary = binary.resolve()
    if not resolved_binary.exists() or not resolved_binary.is_file():
        raise ValueError(f"binary not found: {resolved_binary}")

    effective_stdin_file = stdin_file or stdin_sample

    cfg = config or AgentConfig()
    policy = CommandPolicy(
        resolved_root,
        allowlist=cfg.allowlist,
        timeout_seconds=cfg.timeout_seconds,
    )

    input_text = _read_optional_sample(effective_stdin_file)
    run_args = args or []
    _validate_runtime_args_for_workspace(run_args, workspace_root=resolved_root, cwd=resolved_binary.parent)
    safe_argv, safe_cwd = policy.validate([f"./{resolved_binary.name}", *run_args], cwd=resolved_binary.parent)

    try:
        proc = subprocess.run(
            safe_argv,
            cwd=safe_cwd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=policy.timeout_seconds,
            check=False,
        )
        returncode = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stderr += f"\n[policy-timeout] command exceeded {policy.timeout_seconds}s\n"

    sanitizer_signal = _has_sanitizer_signal(stderr)
    artifact = {
        "schema": VERIFY_SCHEMA,
        "schema_version": 1,
        "mode": "binary",
        "root": str(resolved_root),
        "binary_path": str(resolved_binary),
        "argv": [str(resolved_binary), *run_args],
        "stdin_file_path": str(effective_stdin_file.resolve()) if effective_stdin_file else None,
        "protocol_sample_path": str(protocol_sample.resolve()) if protocol_sample else None,
        "returncode": returncode,
        "sanitizer_signal": sanitizer_signal,
        "stdout_head": _head_lines(stdout),
        "stderr_head": _head_lines(stderr),
    }
    return returncode, artifact


def triage_binary_crash(
    *,
    root: Path,
    binary: Path,
    stdin_file: Path | None = None,
    stdin_text: str | None = None,
    args: list[str] | None = None,
    timeout_seconds: int | None = None,
    gdb_batch: bool = False,
    config: AgentConfig | None = None,
) -> dict[str, Any]:
    resolved_root = root.resolve()
    resolved_binary = binary.resolve()
    if not resolved_binary.exists() or not resolved_binary.is_file():
        raise ValueError(f"binary not found: {resolved_binary}")
    if stdin_file is not None and stdin_text is not None:
        raise ValueError("stdin_file and stdin_text are mutually exclusive")

    cfg = config or AgentConfig()
    effective_timeout = int(timeout_seconds) if timeout_seconds is not None else cfg.timeout_seconds
    policy = CommandPolicy(
        resolved_root,
        allowlist=cfg.allowlist,
        timeout_seconds=effective_timeout,
    )

    run_args = list(args or [])
    input_text = stdin_text if stdin_text is not None else _read_optional_sample(stdin_file, max_bytes=4096)
    execution = _run_bounded_binary_process(
        policy,
        binary=resolved_binary,
        args=run_args,
        input_text=input_text,
        timeout_seconds=effective_timeout,
    )
    crash_summary = _summarize_crash(execution)

    debugger_summary = {
        "backend": "gdb",
        "attempted": False,
        "available": False,
        "collected": False,
        "returncode": None,
        "timed_out": False,
        "registers": [],
        "backtrace": [],
        "disassembly": [],
        "mappings": [],
        "error": None,
    }
    evidence = [execution["evidence"]]

    if gdb_batch and crash_summary["should_debug"]:
        debugger_summary, debugger_evidence = _run_gdb_batch(
            policy,
            binary=resolved_binary,
            args=run_args,
        )
        evidence.append(debugger_evidence)

    return {
        "schema": TRIAGE_SCHEMA,
        "schema_version": 1,
        "artifact_type": "binary_crash_triage",
        "mode": "binary",
        "target": {
            "root": str(resolved_root),
            "binary_path": str(resolved_binary),
            "binary_name": resolved_binary.name,
            "size_bytes": resolved_binary.stat().st_size,
            "sha256": _sha256_file(resolved_binary),
        },
        "execution_result": {
            "argv": execution["argv"],
            "exit_code": execution["exit_code"],
            "signal": execution["signal"],
            "signal_name": execution["signal_name"],
            "timed_out": execution["timed_out"],
            "stdout_head": execution["stdout"]["lines"],
            "stderr_head": execution["stderr"]["lines"],
            "stdout_truncated": execution["stdout"]["truncated"],
            "stderr_truncated": execution["stderr"]["truncated"],
        },
        "crash_summary": {
            "crashed": crash_summary["crashed"],
            "suspicious": crash_summary["suspicious"],
            "reason": crash_summary["reason"],
            "signal": execution["signal"],
            "signal_name": execution["signal_name"],
            "exit_code": execution["exit_code"],
        },
        "debugger_summary": debugger_summary,
        "evidence": evidence,
        "runtime_hints": {
            "args": run_args,
            "stdin_file_path": str(stdin_file.resolve()) if stdin_file is not None else None,
            "stdin_text_present": stdin_text is not None,
            "timeout_seconds": effective_timeout,
            "gdb_batch": gdb_batch,
        },
        "root": str(resolved_root),
        "binary_path": str(resolved_binary),
    }


def _run_bounded_binary_process(
    policy: CommandPolicy,
    *,
    binary: Path,
    args: list[str],
    input_text: str | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    _validate_runtime_args_for_workspace(args, workspace_root=policy.workspace_root, cwd=binary.parent)
    safe_argv, safe_cwd = policy.validate([f"./{binary.name}", *args], cwd=binary.parent)

    try:
        proc = subprocess.run(
            safe_argv,
            cwd=safe_cwd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        returncode = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stderr += f"\n[policy-timeout] command exceeded {timeout_seconds}s\n"
        timed_out = True

    signal_number = abs(returncode) if returncode < 0 else None
    signal_name = _signal_name(signal_number)
    stdout_capture = _truncate_capture(stdout, max_lines=80, max_chars=12000)
    stderr_capture = _truncate_capture(stderr, max_lines=80, max_chars=12000)

    return {
        "argv": [str(binary), *args],
        "exit_code": returncode,
        "signal": signal_number,
        "signal_name": signal_name,
        "timed_out": timed_out,
        "stdout": stdout_capture,
        "stderr": stderr_capture,
        "evidence": {
            "id": "execution",
            "tool": "direct-run",
            "command": [str(binary), *args],
            "available": True,
            "status": "timeout" if timed_out else ("crash" if signal_number is not None else ("error" if returncode != 0 else "ok")),
            "returncode": returncode,
            "error": None,
            "stdout": stdout_capture,
            "stderr": stderr_capture,
            "truncation": {
                "stdout_truncated": bool(stdout_capture["truncated"]),
                "stderr_truncated": bool(stderr_capture["truncated"]),
            },
        },
    }


def _summarize_crash(execution: dict[str, Any]) -> dict[str, Any]:
    signal_number = execution.get("signal")
    exit_code = int(execution.get("exit_code", 0))
    timed_out = bool(execution.get("timed_out"))
    stderr_lines = list(execution.get("stderr", {}).get("lines") or [])
    sanitizer_signal = _has_sanitizer_signal("\n".join(stderr_lines))

    reason = "clean-exit"
    suspicious = False
    crashed = False
    should_debug = False

    if timed_out:
        reason = "timeout"
        suspicious = True
    elif signal_number is not None:
        reason = f"signal:{execution.get('signal_name') or signal_number}"
        suspicious = True
        crashed = True
        should_debug = True
    elif exit_code != 0:
        reason = f"nonzero-exit:{exit_code}"
        suspicious = True
        should_debug = True
    elif sanitizer_signal:
        reason = "sanitizer-signal"
        suspicious = True
        should_debug = True

    return {
        "crashed": crashed,
        "suspicious": suspicious,
        "reason": reason,
        "should_debug": should_debug,
    }


def _run_gdb_batch(
    policy: CommandPolicy,
    *,
    binary: Path,
    args: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    expressions = [
        "set pagination off",
        "set confirm off",
        "echo ===REGISTERS===\\n",
        "info registers pc sp bp ax bx cx dx si di",
        "echo ===BACKTRACE===\\n",
        "bt",
        "echo ===DISASSEMBLY===\\n",
        "x/8i $pc-16",
        "echo ===MAPPINGS===\\n",
        "info proc mappings",
        "echo ===END===\\n",
    ]
    argv = ["gdb", "--batch", "-q", "-nx"]
    for expression in expressions:
        argv.extend(["-ex", expression])
    argv.extend(["--args", str(binary), *args])

    evidence = {
        "id": "debugger",
        "tool": "gdb",
        "command": argv,
        "available": False,
        "status": "unavailable",
        "returncode": None,
        "error": None,
        "stdout": _empty_capture(),
        "stderr": _empty_capture(),
        "truncation": {
            "stdout_truncated": False,
            "stderr_truncated": False,
        },
    }

    if "gdb" not in policy.allowlist or get_command_rule("gdb") is None:
        summary = {
            "backend": "gdb",
            "attempted": True,
            "available": False,
            "collected": False,
            "returncode": None,
            "timed_out": False,
            "registers": [],
            "backtrace": [],
            "disassembly": [],
            "mappings": [],
            "error": "gdb blocked by policy",
        }
        evidence["error"] = summary["error"]
        return summary, evidence

    if shutil.which("gdb") is None:
        summary = {
            "backend": "gdb",
            "attempted": True,
            "available": False,
            "collected": False,
            "returncode": None,
            "timed_out": False,
            "registers": [],
            "backtrace": [],
            "disassembly": [],
            "mappings": [],
            "error": "gdb not available",
        }
        evidence["error"] = summary["error"]
        return summary, evidence

    result = policy.run(argv, cwd=binary.parent)
    stdout_capture = _truncate_capture(result.stdout, max_lines=160, max_chars=24000)
    stderr_capture = _truncate_capture(result.stderr, max_lines=80, max_chars=12000)
    stdout_text = "\n".join(stdout_capture["lines"])

    sections = _parse_gdb_sections(stdout_text)
    timed_out = result.returncode == 124
    summary = {
        "backend": "gdb",
        "attempted": True,
        "available": True,
        "collected": not timed_out,
        "returncode": result.returncode,
        "timed_out": timed_out,
        "registers": sections.get("REGISTERS", [])[:24],
        "backtrace": sections.get("BACKTRACE", [])[:40],
        "disassembly": sections.get("DISASSEMBLY", [])[:24],
        "mappings": sections.get("MAPPINGS", [])[:40],
        "error": None if result.returncode == 0 else stderr_capture["lines"][0] if stderr_capture["lines"] else None,
    }
    evidence.update(
        {
            "available": True,
            "status": "timeout" if timed_out else ("ok" if result.returncode == 0 else "error"),
            "returncode": result.returncode,
            "stdout": stdout_capture,
            "stderr": stderr_capture,
            "truncation": {
                "stdout_truncated": bool(stdout_capture["truncated"]),
                "stderr_truncated": bool(stderr_capture["truncated"]),
            },
        }
    )
    return summary, evidence


def _collect_tool_evidence(policy: CommandPolicy, spec: dict[str, Any], binary: Path) -> dict[str, Any]:
    tool = str(spec["tool"])
    argv = list(spec["build_argv"](binary))

    if tool not in policy.allowlist:
        return _unavailable_evidence(spec, argv, reason="blocked-by-policy")
    if get_command_rule(tool) is None:
        return _unavailable_evidence(spec, argv, reason="missing-command-policy")
    if shutil.which(tool) is None:
        return _unavailable_evidence(spec, argv, reason="tool-not-found")

    try:
        result = policy.run(argv)
    except PolicyError as exc:
        return _unavailable_evidence(spec, argv, reason=str(exc))
    except OSError as exc:
        return _unavailable_evidence(spec, argv, reason=f"os-error: {exc}")

    stdout_capture = _truncate_capture(
        result.stdout,
        max_lines=int(spec.get("stdout_lines", 80)),
        max_chars=int(spec.get("stdout_chars", 12000)),
    )
    stderr_capture = _truncate_capture(result.stderr, max_lines=80, max_chars=8000)
    return {
        "id": spec["id"],
        "tool": tool,
        "command": argv,
        "available": True,
        "status": "ok" if result.returncode == 0 else "error",
        "returncode": result.returncode,
        "error": None,
        "stdout": stdout_capture,
        "stderr": stderr_capture,
        "truncation": {
            "stdout_truncated": bool(stdout_capture["truncated"]),
            "stderr_truncated": bool(stderr_capture["truncated"]),
        },
    }


def _unavailable_evidence(spec: dict[str, Any], argv: list[str], *, reason: str) -> dict[str, Any]:
    return {
        "id": spec["id"],
        "tool": spec["tool"],
        "command": argv,
        "available": False,
        "status": "unavailable",
        "returncode": None,
        "error": reason,
        "stdout": _empty_capture(),
        "stderr": _empty_capture(),
        "truncation": {
            "stdout_truncated": False,
            "stderr_truncated": False,
        },
    }


def _empty_capture() -> dict[str, Any]:
    return {
        "lines": [],
        "line_count_total": 0,
        "line_count_kept": 0,
        "char_count_total": 0,
        "char_count_kept": 0,
        "truncated": False,
    }


def _truncate_capture(text: str, *, max_lines: int, max_chars: int) -> dict[str, Any]:
    lines = text.splitlines()
    kept_lines: list[str] = []
    kept_chars = 0
    for line in lines:
        if len(kept_lines) >= max_lines:
            break
        if kept_chars + len(line) > max_chars:
            break
        kept_lines.append(line)
        kept_chars += len(line)

    total_chars = sum(len(line) for line in lines)
    truncated = len(kept_lines) < len(lines) or kept_chars < total_chars
    return {
        "lines": kept_lines,
        "line_count_total": len(lines),
        "line_count_kept": len(kept_lines),
        "char_count_total": total_chars,
        "char_count_kept": kept_chars,
        "truncated": truncated,
    }


def _stdout_lines(entry: dict[str, Any] | None) -> list[str]:
    if not entry:
        return []
    return list((entry.get("stdout") or {}).get("lines") or [])


def _first_line(lines: list[str]) -> str | None:
    if not lines:
        return None
    return lines[0]


def _parse_elf_header(lines: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _parse_checksec_mitigations(entry: dict[str, Any] | None) -> dict[str, Any]:
    result = {
        "source": "checksec",
        "available": False,
        "relro": "unknown",
        "canary": "unknown",
        "nx": "unknown",
        "pie": "unknown",
        "fortify": "unknown",
    }
    if not entry or not entry.get("available"):
        return result

    result["available"] = True
    text = "\n".join(_stdout_lines(entry)).lower()

    if "full relro" in text:
        result["relro"] = "full"
    elif "partial relro" in text:
        result["relro"] = "partial"
    elif "no relro" in text:
        result["relro"] = "none"

    canary_field = _extract_field_value(text, "canary")
    if "no canary found" in text or canary_field in {"no", "none"}:
        result["canary"] = "none"
    elif "canary found" in text or canary_field in {"yes", "present", "enabled"}:
        result["canary"] = "present"

    nx_field = _extract_field_value(text, "nx")
    if "nx disabled" in text or nx_field in {"no", "disabled"}:
        result["nx"] = "disabled"
    elif "nx enabled" in text or nx_field in {"yes", "enabled"}:
        result["nx"] = "enabled"

    pie_field = _extract_field_value(text, "pie")
    if "no pie" in text or pie_field in {"no", "disabled"}:
        result["pie"] = "disabled"
    elif "pie enabled" in text or pie_field in {"yes", "enabled"}:
        result["pie"] = "enabled"

    if "fortify" in text:
        result["fortify"] = "present"

    return result


def _extract_field_value(text: str, field_name: str) -> str | None:
    match = re.search(rf"\b{re.escape(field_name)}\s*:\s*([a-z0-9_-]+)", text)
    if not match:
        return None
    return match.group(1)


def _extract_imported_functions(lines: list[str]) -> list[str]:
    imports: set[str] = set()
    for line in lines:
        if " UND " not in line:
            continue
        parts = line.split()
        if not parts:
            continue
        symbol = parts[-1].split("@", 1)[0]
        if symbol:
            imports.add(symbol)
    return sorted(imports)


def _count_exported_symbols(lines: list[str]) -> int:
    count = 0
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        symbol_type = parts[-2]
        symbol_name = parts[-1]
        if symbol_type == "U" or not symbol_name:
            continue
        count += 1
    return count


def _extract_strings_highlights(lines: list[str]) -> list[dict[str, str]]:
    highlights: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in lines:
        lowered = line.lower()
        for marker in _STRING_MARKERS:
            if marker in lowered:
                key = (marker, line.strip())
                if key in seen:
                    continue
                seen.add(key)
                highlights.append({"marker": marker, "value": line.strip()[:240]})
    return highlights[:40]


def _build_suspicious_indicators(imports: list[str], highlights: list[dict[str, str]]) -> list[dict[str, str]]:
    indicators: set[tuple[str, str, str]] = set()

    for symbol in imports:
        if symbol in _SUSPICIOUS_IMPORTS:
            indicators.add(("import", symbol, ""))

    for item in highlights:
        marker = str(item.get("marker") or "")
        value = str(item.get("value") or "")
        indicators.add(("string", marker, value))

    ordered = sorted(indicators)
    return [
        {
            "kind": kind,
            "indicator": indicator,
            "evidence": evidence,
        }
        for kind, indicator, evidence in ordered
    ]


def _head_lines(text: str, *, limit: int = 20) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[:limit]


def _read_optional_sample(path: Path | None, *, max_bytes: int = 512) -> str | None:
    if path is None:
        return None
    resolved = path.resolve()
    if not resolved.exists() or not resolved.is_file():
        raise ValueError(f"sample not found: {resolved}")
    data = resolved.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _parse_gdb_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.startswith("===") and line.endswith("==="):
            current = line.strip("=").strip()
            sections.setdefault(current, [])
            continue
        if current is not None and line:
            sections[current].append(line)
    return sections


def _signal_name(signal_number: int | None) -> str | None:
    if signal_number is None:
        return None
    try:
        return signal.Signals(signal_number).name
    except ValueError:
        return None


def _validate_runtime_args_for_workspace(args: list[str], *, workspace_root: Path, cwd: Path) -> None:
    for token in args:
        if "/" not in token and not token.startswith("."):
            continue
        path = Path(token)
        resolved = (cwd / path).resolve() if not path.is_absolute() else path.resolve()
        if workspace_root not in resolved.parents and resolved != workspace_root:
            raise ValueError(f"runtime arg escapes workspace root: {resolved}")


def _has_sanitizer_signal(stderr: str) -> bool:
    return any(
        marker in stderr
        for marker in [
            "AddressSanitizer",
            "runtime error:",
            "UndefinedBehaviorSanitizer",
            "buffer overflow detected",
            "stack smashing detected",
        ]
    )
