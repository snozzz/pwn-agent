from __future__ import annotations

from pathlib import Path
import json
import subprocess
from typing import Any

from ...config import AgentConfig
from ...policy import CommandPolicy, CommandResult

ANALYSIS_SCHEMA = "pwn-agent.binary-analysis.v1"
PLAN_SCHEMA = "pwn-agent.binary-plan.v1"
VERIFY_SCHEMA = "pwn-agent.binary-verify.v1"
STAGE_ORDER = ["identify", "inspect", "triage", "validate", "patch", "revalidate"]


def write_binary_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_binary_analysis(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != ANALYSIS_SCHEMA:
        raise ValueError(f"unsupported binary analysis schema: {payload.get('schema')}")
    return payload


def scan_binary(
    *,
    root: Path,
    binary: Path,
    stdin_sample: Path | None = None,
    protocol_sample: Path | None = None,
    config: AgentConfig | None = None,
) -> dict[str, Any]:
    resolved_root = root.resolve()
    resolved_binary = binary.resolve()
    if not resolved_binary.exists() or not resolved_binary.is_file():
        raise ValueError(f"binary not found: {resolved_binary}")

    cfg = config or AgentConfig()
    policy = CommandPolicy(
        resolved_root,
        allowlist=cfg.allowlist,
        timeout_seconds=cfg.timeout_seconds,
    )

    file_result = policy.run(["file", str(resolved_binary)])
    elf_header_result = policy.run(["readelf", "-h", str(resolved_binary)])
    symbol_result = policy.run(["readelf", "-s", str(resolved_binary)])
    string_result = policy.run(["strings", "-n", "6", str(resolved_binary)])
    nm_result = policy.run(["nm", "-an", str(resolved_binary)])

    risk_markers = _detect_risk_markers(string_result.stdout)

    return {
        "schema": ANALYSIS_SCHEMA,
        "schema_version": 1,
        "mode": "binary",
        "stages_supported": list(STAGE_ORDER),
        "root": str(resolved_root),
        "binary_path": str(resolved_binary),
        "binary_fingerprint": {
            "size_bytes": resolved_binary.stat().st_size,
        },
        "inputs": {
            "stdin_sample_path": str(stdin_sample.resolve()) if stdin_sample else None,
            "protocol_sample_path": str(protocol_sample.resolve()) if protocol_sample else None,
            "stdin_sample_preview": _read_optional_sample(stdin_sample),
            "protocol_sample_preview": _read_optional_sample(protocol_sample),
        },
        "identify": {
            "file": _summarize_command(file_result),
        },
        "inspect": {
            "elf_header": _summarize_command(elf_header_result),
            "symbols": _summarize_command(symbol_result),
            "nm_index": _summarize_command(nm_result),
        },
        "triage": {
            "risk_marker_count": len(risk_markers),
            "risk_markers": risk_markers,
            "strings": _summarize_command(string_result),
        },
        "command_logs": [
            _command_log("identify-file", file_result),
            _command_log("inspect-elf-header", elf_header_result),
            _command_log("inspect-symbols", symbol_result),
            _command_log("triage-strings", string_result),
            _command_log("inspect-nm", nm_result),
        ],
    }


def build_binary_plan(analysis: dict[str, Any]) -> dict[str, Any]:
    root = str(analysis.get("root") or "")
    binary_path = str(analysis.get("binary_path") or "")
    inputs = dict(analysis.get("inputs") or {})

    verify_cli = [
        "python3",
        "-m",
        "src.main",
        "binary-verify",
        "--root",
        root,
        "--binary",
        binary_path,
    ]
    stdin_sample_path = inputs.get("stdin_sample_path")
    protocol_sample_path = inputs.get("protocol_sample_path")
    if stdin_sample_path:
        verify_cli.extend(["--stdin-sample", str(stdin_sample_path)])
    if protocol_sample_path:
        verify_cli.extend(["--protocol-sample", str(protocol_sample_path)])

    next_actions = [
        {
            "id": "identify-binary-fingerprint",
            "kind": "binary_identify",
            "phase": "triage",
            "title": "Review binary metadata and headers",
            "status": "context",
            "priority": 100,
            "detail": "confirm architecture and linkage before runtime checks",
            "suggested_cli": [],
        },
        {
            "id": "triage-runtime-signals",
            "kind": "binary_triage",
            "phase": "triage",
            "title": "Review extracted risk markers",
            "status": "context",
            "priority": 95,
            "detail": "inspect risky strings/symbols before executing",
            "suggested_cli": [],
        },
        {
            "id": "validate-baseline-execution",
            "kind": "binary_verify",
            "phase": "execution",
            "title": "Run bounded baseline binary verification",
            "status": "ready",
            "priority": 90,
            "detail": "execute locally with bounded timeout and collect sanitizer signals",
            "suggested_cli": verify_cli,
        },
        {
            "id": "patch-hypothesis",
            "kind": "binary_patch_hypothesis",
            "phase": "synthesis",
            "title": "Draft local patch hypothesis",
            "status": "blocked",
            "priority": 80,
            "blocked_by": ["validate-baseline-execution"],
            "depends_on": ["validate-baseline-execution"],
            "detail": "human-guided patching only; no unattended binary modification",
            "suggested_cli": [],
        },
        {
            "id": "revalidate-patch",
            "kind": "binary_revalidate",
            "phase": "execution",
            "title": "Re-run bounded verification after patch",
            "status": "blocked",
            "priority": 70,
            "blocked_by": ["patch-hypothesis"],
            "depends_on": ["patch-hypothesis"],
            "detail": "confirm behavior change after an explicit patch step",
            "suggested_cli": [],
        },
    ]

    return {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "mode": "binary",
        "stage_order": list(STAGE_ORDER),
        "source_analysis_schema": analysis.get("schema"),
        "binary_path": binary_path,
        "binary_fingerprint": analysis.get("binary_fingerprint"),
        "readiness": {
            "runnable_actions": 1,
            "blocked_actions": 2,
            "context_actions": 2,
        },
        "next_actions": next_actions,
    }


def render_binary_plan_markdown(plan: dict[str, Any]) -> str:
    lines = ["# Binary Plan", ""]
    lines.append(f"- Schema: {plan.get('schema')}")
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
            f"- [{action.get('phase', 'execution')}] [{action.get('status', 'unknown')}] "
            f"{action.get('id')} :: {action.get('title', '')}"
        )
    return "\n".join(lines) + "\n"


def verify_binary_execution(
    *,
    root: Path,
    binary: Path,
    args: list[str] | None = None,
    stdin_sample: Path | None = None,
    protocol_sample: Path | None = None,
    config: AgentConfig | None = None,
) -> tuple[int, dict[str, Any]]:
    resolved_root = root.resolve()
    resolved_binary = binary.resolve()
    if not resolved_binary.exists() or not resolved_binary.is_file():
        raise ValueError(f"binary not found: {resolved_binary}")

    cfg = config or AgentConfig()
    policy = CommandPolicy(
        resolved_root,
        allowlist=cfg.allowlist,
        timeout_seconds=cfg.timeout_seconds,
    )

    input_text = _read_optional_sample(stdin_sample)
    run_args = args or []
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
        "stdin_sample_path": str(stdin_sample.resolve()) if stdin_sample else None,
        "protocol_sample_path": str(protocol_sample.resolve()) if protocol_sample else None,
        "returncode": returncode,
        "sanitizer_signal": sanitizer_signal,
        "stdout_head": _head_lines(stdout),
        "stderr_head": _head_lines(stderr),
    }
    return returncode, artifact


def _summarize_command(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "stdout_head": _head_lines(result.stdout),
        "stderr_head": _head_lines(result.stderr),
    }


def _command_log(name: str, result: CommandResult) -> dict[str, Any]:
    return {
        "name": name,
        "argv": result.argv,
        "returncode": result.returncode,
        "stdout_lines": len(result.stdout.splitlines()),
        "stderr_lines": len(result.stderr.splitlines()),
    }


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


def _detect_risk_markers(strings_output: str) -> list[dict[str, str]]:
    markers = [
        "strcpy",
        "strcat",
        "gets",
        "sprintf",
        "system",
        "popen",
        "/bin/sh",
        "execve",
    ]
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in strings_output.splitlines():
        lowered = line.lower()
        for marker in markers:
            if marker in lowered:
                key = (marker, line.strip())
                if key in seen:
                    continue
                findings.append({"marker": marker, "evidence": line.strip()[:200]})
                seen.add(key)
    return findings[:40]


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
