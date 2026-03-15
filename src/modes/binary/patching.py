from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from ...compdb import CompileDatabase
from ...config import AgentConfig
from ...policy import CommandPolicy
from ...rebuild import default_compdb_path, extract_targets, rebuild_target
from .workflow import triage_binary_crash, verify_binary_execution

PATCH_CANDIDATE_SCHEMA = "pwn-agent.binary-patch-candidate.v1"
PATCH_SCRIPT_SCHEMA = "pwn-agent.patch-script.v1"
PATCH_VALIDATION_SCHEMA = "pwn-agent.binary-patch-validation.v1"


def load_patch_input(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("patch input must be a JSON object")
    schema = payload.get("schema")
    if schema not in {None, PATCH_CANDIDATE_SCHEMA, PATCH_SCRIPT_SCHEMA}:
        raise ValueError(f"unsupported patch input schema: {schema}")
    return payload


def patch_validate(
    *,
    root: Path,
    patch_payload: dict[str, Any] | None = None,
    patch_source_path: Path | None = None,
    analysis: dict[str, Any] | None = None,
    crash: dict[str, Any] | None = None,
    binary: Path | None = None,
    target_index: int = 1,
    output_name: str = "patched-target",
    timeout_seconds: int | None = None,
    config: AgentConfig | None = None,
) -> dict[str, Any]:
    resolved_root = root.resolve()
    cfg = config or AgentConfig()
    effective_timeout = int(timeout_seconds) if timeout_seconds is not None else cfg.timeout_seconds
    payload = dict(patch_payload or {})
    patch_metadata = dict(payload.get("patch_metadata") or {})
    validation = dict(payload.get("validation") or {})
    build = dict(payload.get("build") or {})
    edits = list(payload.get("edits") or [])

    if patch_source_path is not None:
        patch_metadata.setdefault("patch_input_path", str(patch_source_path.resolve()))
    if not patch_metadata.get("source_schema"):
        patch_metadata["source_schema"] = payload.get("schema") or PATCH_SCRIPT_SCHEMA
    if not patch_metadata.get("patch_id"):
        patch_metadata["patch_id"] = "patch-candidate"
    if not patch_metadata.get("summary"):
        patch_metadata["summary"] = "bounded local patch validation"

    edit_results = _apply_edits(resolved_root, edits)
    build_result, patched_binary = _materialize_patched_binary(
        resolved_root,
        build=build,
        binary=binary,
        analysis=analysis,
        crash=crash,
        target_index=target_index,
        output_name=output_name,
        config=cfg,
        timeout_seconds=effective_timeout,
    )

    validation_result: dict[str, Any] = {
        "overall_status": "failed" if build_result.get("status") == "failed" else "partial",
        "launch_check": {"attempted": False, "passed": False, "reason": "build not completed"},
        "baseline_check": {"attempted": False, "passed": False, "reason": "baseline not configured"},
        "regression_check": {"attempted": False, "passed": False, "reason": "regression not configured"},
    }
    regression_notes: list[str] = []
    evidence: list[dict[str, Any]] = [
        {
            "id": "patch-application",
            "tool": "structured-patch",
            "status": "ok",
            "edit_count": len(edit_results),
            "patch_input_path": patch_metadata.get("patch_input_path"),
        },
        {
            "id": "build",
            "tool": build_result.get("tool", "build"),
            "status": build_result.get("status"),
            "returncode": build_result.get("returncode"),
            "output_binary": build_result.get("output_binary"),
            "stdout_head": list(build_result.get("stdout_head") or []),
            "stderr_head": list(build_result.get("stderr_head") or []),
        },
    ]

    if patched_binary is not None and build_result.get("status") != "failed":
        launch_spec = _resolve_validation_spec("launch", validation.get("launch"), fallback=validation.get("baseline"))
        launch_result, launch_evidence = _run_launch_validation(
            resolved_root,
            patched_binary,
            spec=launch_spec,
            config=cfg,
        )
        evidence.append(launch_evidence)
        validation_result["launch_check"] = launch_result

        baseline_spec = _resolve_baseline_spec(validation.get("baseline"), analysis=analysis)
        if baseline_spec is not None:
            baseline_result, baseline_evidence = _run_launch_validation(
                resolved_root,
                patched_binary,
                spec=baseline_spec,
                config=cfg,
            )
            evidence.append(baseline_evidence)
            validation_result["baseline_check"] = baseline_result
        else:
            regression_notes.append("No baseline validation inputs were provided by the patch artifact or analysis evidence.")

        regression_spec = _resolve_regression_spec(validation.get("regression"), crash=crash)
        if regression_spec is not None:
            regression_result, regression_evidence = _run_regression_validation(
                resolved_root,
                patched_binary,
                spec=regression_spec,
                config=cfg,
            )
            evidence.append(regression_evidence)
            validation_result["regression_check"] = regression_result
            if regression_result["passed"]:
                regression_notes.append("Prior regression input no longer reproduces suspicious behavior.")
            else:
                regression_notes.append(f"Prior regression input still fails: {regression_result['reason']}.")
        elif crash is not None:
            regression_notes.append("Crash evidence was present, but no replayable regression input was available.")

        validation_result["overall_status"] = _overall_validation_status(validation_result)
    else:
        regression_notes.append("Build or binary materialization failed before validation could run.")

    remaining_risk_summary = _build_remaining_risk_summary(validation_result, regression_notes)
    return {
        "schema": PATCH_VALIDATION_SCHEMA,
        "schema_version": 1,
        "artifact_type": "binary_patch_validation",
        "mode": "binary",
        "target": {
            "root": str(resolved_root),
            "binary_path": str(patched_binary) if patched_binary is not None else None,
            "original_binary_path": _resolve_original_binary_path(binary, analysis=analysis, crash=crash),
        },
        "patch_metadata": patch_metadata,
        "apply_result": {
            "edits_applied": edit_results,
            "build": build_result,
            "patched_binary_path": str(patched_binary) if patched_binary is not None else None,
        },
        "validation_result": validation_result,
        "regression_notes": regression_notes,
        "remaining_risk_summary": remaining_risk_summary,
        "evidence": evidence,
    }


def render_patch_validation_markdown(artifact: dict[str, Any]) -> str:
    lines = ["# Patch Validation", ""]
    target = dict(artifact.get("target") or {})
    patch_metadata = dict(artifact.get("patch_metadata") or {})
    apply_result = dict(artifact.get("apply_result") or {})
    validation_result = dict(artifact.get("validation_result") or {})
    risk = dict(artifact.get("remaining_risk_summary") or {})

    lines.append(f"- Patch id: `{patch_metadata.get('patch_id')}`")
    lines.append(f"- Summary: {patch_metadata.get('summary')}")
    lines.append(f"- Patched binary: `{target.get('binary_path')}`")
    lines.append(f"- Overall validation: {validation_result.get('overall_status')}")
    lines.append(f"- Remaining risk: {risk.get('level')} :: {risk.get('summary')}")
    lines.append(f"- Applied edits: {len(apply_result.get('edits_applied') or [])}")

    build = dict(apply_result.get("build") or {})
    lines.append(f"- Build status: {build.get('status')}")
    if build.get("output_binary"):
        lines.append(f"- Build output: `{build.get('output_binary')}`")

    lines.extend(["", "## Validation Checks", ""])
    for key in ["launch_check", "baseline_check", "regression_check"]:
        check = dict(validation_result.get(key) or {})
        lines.append(
            f"- {key}: attempted={str(check.get('attempted')).lower()} "
            f"passed={str(check.get('passed')).lower()} reason={check.get('reason')}"
        )

    lines.extend(["", "## Regression Notes", ""])
    notes = list(artifact.get("regression_notes") or [])
    if not notes:
        lines.append("- none")
    else:
        for note in notes:
            lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


def _apply_edits(root: Path, edits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for index, raw_edit in enumerate(edits, start=1):
        edit = dict(raw_edit)
        op = str(edit.get("op") or "replace_text")
        relative_path = str(edit.get("path") or "")
        if not relative_path:
            raise ValueError(f"edit #{index} missing path")
        target = _resolve_bound_path(root, relative_path)
        if op == "replace_text":
            old = edit.get("old")
            new = edit.get("new")
            if not isinstance(old, str) or not isinstance(new, str):
                raise ValueError(f"edit #{index} replace_text requires string old/new fields")
            count = int(edit.get("count", 1))
            original = target.read_text(encoding="utf-8")
            matches = original.count(old)
            if matches < count:
                raise ValueError(f"edit #{index} expected {count} matches in {target}, found {matches}")
            updated = original.replace(old, new, count)
            target.write_text(updated, encoding="utf-8")
            results.append(
                {
                    "op": op,
                    "path": str(target),
                    "status": "applied",
                    "replacements": count,
                }
            )
            continue
        if op == "write_file":
            content = edit.get("content")
            if not isinstance(content, str):
                raise ValueError(f"edit #{index} write_file requires string content")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            results.append(
                {
                    "op": op,
                    "path": str(target),
                    "status": "applied",
                    "bytes_written": len(content.encode("utf-8")),
                }
            )
            continue
        raise ValueError(f"edit #{index} unsupported op: {op}")
    return results


def _materialize_patched_binary(
    root: Path,
    *,
    build: dict[str, Any],
    binary: Path | None,
    analysis: dict[str, Any] | None,
    crash: dict[str, Any] | None,
    target_index: int,
    output_name: str,
    config: AgentConfig,
    timeout_seconds: int,
) -> tuple[dict[str, Any], Path | None]:
    build_kind = str(build.get("kind") or ("existing-binary" if binary is not None else "rebuild-target"))
    if build_kind == "existing-binary":
        candidate = _resolve_original_binary_path(binary, analysis=analysis, crash=crash) or build.get("binary_path")
        if not candidate:
            raise ValueError("existing-binary patch validation requires a binary path")
        resolved_binary = _resolve_bound_path(root, candidate)
        return (
            {
                "attempted": False,
                "tool": "existing-binary",
                "status": "skipped",
                "returncode": 0,
                "output_binary": str(resolved_binary),
                "stdout_head": [],
                "stderr_head": [],
            },
            resolved_binary,
        )

    if build_kind != "rebuild-target":
        raise ValueError(f"unsupported build kind: {build_kind}")

    compdb_path = _resolve_bound_path(root, build.get("compdb_path", str(default_compdb_path(root))))
    db = CompileDatabase.load(compdb_path)
    targets = extract_targets(db)
    selected_index = int(build.get("target_index", target_index))
    selected_output_name = str(build.get("output_name") or output_name)
    if selected_index < 1 or selected_index > len(targets):
        raise IndexError(f"target index out of range: {selected_index}")

    policy = CommandPolicy(root, allowlist=config.allowlist, timeout_seconds=timeout_seconds)
    rebuild = rebuild_target(policy, targets[selected_index - 1], selected_output_name)
    output_binary = (root / selected_output_name).resolve()
    return (
        {
            "attempted": True,
            "tool": "rebuild-target",
            "status": "ok" if rebuild.returncode == 0 else "failed",
            "returncode": rebuild.returncode,
            "command": list(rebuild.argv),
            "output_binary": str(output_binary),
            "stdout_head": _head_lines(rebuild.stdout),
            "stderr_head": _head_lines(rebuild.stderr),
        },
        output_binary if rebuild.returncode == 0 and output_binary.exists() else None,
    )


def _run_launch_validation(
    root: Path,
    binary: Path,
    *,
    spec: dict[str, Any] | None,
    config: AgentConfig,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = dict(spec or {})
    args = list(normalized.get("args") or [])
    stdin_file = _materialize_stdin_file(root, normalized, label="baseline")
    expected_returncode = int(normalized.get("expected_returncode", 0))
    returncode, artifact = verify_binary_execution(
        root=root,
        binary=binary,
        args=args,
        stdin_file=stdin_file,
        config=config,
    )
    passed = returncode == expected_returncode and not bool(artifact.get("sanitizer_signal"))
    reason = "passed" if passed else f"returncode={returncode} sanitizer_signal={artifact.get('sanitizer_signal')}"
    return (
        {
            "attempted": True,
            "passed": passed,
            "reason": reason,
            "expected_returncode": expected_returncode,
            "returncode": returncode,
            "args": args,
            "stdin_file_path": str(stdin_file) if stdin_file is not None else None,
        },
        {
            "id": "launch-validation" if normalized.get("_kind") == "launch" else "baseline-validation",
            "tool": "binary-verify",
            "status": "ok" if passed else "failed",
            "returncode": returncode,
            "stdout_head": list(artifact.get("stdout_head") or []),
            "stderr_head": list(artifact.get("stderr_head") or []),
        },
    )


def _run_regression_validation(
    root: Path,
    binary: Path,
    *,
    spec: dict[str, Any],
    config: AgentConfig,
) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = dict(spec)
    if normalized.get("_missing_replay_input"):
        result = {
            "attempted": False,
            "passed": False,
            "reason": "missing replayable stdin data",
            "args": list(normalized.get("args") or []),
            "stdin_file_path": normalized.get("stdin_file_path"),
        }
        evidence = {
            "id": "regression-validation",
            "tool": "crash-triage",
            "status": "not-run",
            "returncode": None,
            "stdout_head": [],
            "stderr_head": [],
        }
        return result, evidence

    args = list(normalized.get("args") or [])
    stdin_file = _materialize_stdin_file(root, normalized, label="regression")
    artifact = triage_binary_crash(
        root=root,
        binary=binary,
        stdin_file=stdin_file,
        stdin_text=(normalized.get("stdin_text") if stdin_file is None else None),
        args=args,
        config=config,
    )
    crash_summary = dict(artifact.get("crash_summary") or {})
    suspicious = bool(crash_summary.get("suspicious"))
    result = {
        "attempted": True,
        "passed": not suspicious,
        "reason": crash_summary.get("reason"),
        "args": args,
        "stdin_file_path": str(stdin_file) if stdin_file is not None else None,
        "signal_name": crash_summary.get("signal_name"),
        "exit_code": crash_summary.get("exit_code"),
    }
    evidence = {
        "id": "regression-validation",
        "tool": "crash-triage",
        "status": "ok" if not suspicious else "failed",
        "returncode": artifact.get("execution_result", {}).get("exit_code"),
        "stdout_head": list(artifact.get("execution_result", {}).get("stdout_head") or []),
        "stderr_head": list(artifact.get("execution_result", {}).get("stderr_head") or []),
    }
    return result, evidence


def _resolve_validation_spec(label: str, primary: Any, *, fallback: Any) -> dict[str, Any] | None:
    source = primary if primary is not None else fallback
    if not isinstance(source, dict):
        return None
    normalized = dict(source)
    normalized["_kind"] = label
    return normalized


def _resolve_baseline_spec(source: Any, *, analysis: dict[str, Any] | None) -> dict[str, Any] | None:
    if isinstance(source, dict):
        return dict(source)
    if analysis is None:
        return None
    runtime_hints = dict(analysis.get("runtime_hints") or {})
    inputs = dict(analysis.get("inputs") or {})
    args = list(runtime_hints.get("args") or inputs.get("args") or [])
    stdin_file_path = runtime_hints.get("stdin_file_path") or inputs.get("stdin_file_path")
    if not args and not stdin_file_path:
        return None
    return {
        "args": args,
        "stdin_file_path": stdin_file_path,
        "expected_returncode": 0,
    }


def _resolve_regression_spec(source: Any, *, crash: dict[str, Any] | None) -> dict[str, Any] | None:
    if isinstance(source, dict):
        return dict(source)
    if crash is None:
        return None
    runtime_hints = dict(crash.get("runtime_hints") or {})
    args = list(runtime_hints.get("args") or [])
    stdin_file_path = runtime_hints.get("stdin_file_path")
    if stdin_file_path:
        return {
            "args": args,
            "stdin_file_path": stdin_file_path,
        }
    if runtime_hints.get("stdin_text_present"):
        return {
            "args": args,
            "_missing_replay_input": True,
        }
    if not args:
        return None
    return {"args": args}


def _overall_validation_status(validation_result: dict[str, Any]) -> str:
    checks = [dict(validation_result.get(name) or {}) for name in ["launch_check", "baseline_check", "regression_check"]]
    attempted = [check for check in checks if check.get("attempted")]
    if attempted and all(check.get("passed") for check in attempted) and all(check.get("attempted") for check in checks):
        return "passed"
    if any(check.get("attempted") and not check.get("passed") for check in checks):
        return "failed"
    return "partial"


def _build_remaining_risk_summary(validation_result: dict[str, Any], regression_notes: list[str]) -> dict[str, Any]:
    if validation_result.get("overall_status") == "failed":
        return {
            "level": "high",
            "summary": "patched build still fails one or more bounded validation checks",
            "notes": regression_notes,
        }
    failed = [name for name in ["launch_check", "baseline_check", "regression_check"] if not dict(validation_result.get(name) or {}).get("passed", False) and dict(validation_result.get(name) or {}).get("attempted", False)]
    missing = [name for name in ["baseline_check", "regression_check"] if not dict(validation_result.get(name) or {}).get("attempted", False)]
    if failed:
        return {
            "level": "high",
            "summary": "patched build still fails one or more bounded validation checks",
            "notes": [f"{name} did not pass" for name in failed] + regression_notes,
        }
    if missing:
        return {
            "level": "medium",
            "summary": "patched build passed available checks but some regression coverage is still missing",
            "notes": [f"{name} was not attempted" for name in missing] + regression_notes,
        }
    return {
        "level": "low",
        "summary": "patched build passed the bounded launch, baseline, and regression checks",
        "notes": regression_notes,
    }


def _resolve_original_binary_path(binary: Path | None, *, analysis: dict[str, Any] | None, crash: dict[str, Any] | None) -> str | None:
    candidates = [
        str(binary.resolve()) if binary is not None else None,
        (analysis or {}).get("binary_path"),
        (analysis or {}).get("target", {}).get("binary_path"),
        (crash or {}).get("binary_path"),
        (crash or {}).get("target", {}).get("binary_path"),
    ]
    for candidate in candidates:
        if candidate:
            return str(Path(candidate).resolve())
    return None


def _resolve_bound_path(root: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if root not in resolved.parents and resolved != root:
        raise ValueError(f"path escapes root: {resolved}")
    return resolved


def _materialize_stdin_file(root: Path, spec: dict[str, Any], *, label: str) -> Path | None:
    stdin_file_path = spec.get("stdin_file_path")
    if stdin_file_path:
        return _resolve_bound_path(root, str(stdin_file_path))
    stdin_text = spec.get("stdin_text")
    if stdin_text is None:
        return None
    scratch_dir = root / ".pwn-agent" / "validation-inputs"
    scratch_dir.mkdir(parents=True, exist_ok=True)
    path = scratch_dir / f"{label}.txt"
    path.write_text(str(stdin_text), encoding="utf-8")
    return path


def _head_lines(text: str, *, limit: int = 20) -> list[str]:
    return text.splitlines()[:limit] if text else []
