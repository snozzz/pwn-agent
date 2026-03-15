from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from ...executor import execute_plan, inspect_plan
from .workflow import build_binary_plan, load_binary_artifact, write_binary_json

AGENT_LOOP_SCHEMA = "pwn-agent.agent-loop.v1"
AGENT_LOOP_STATE_SCHEMA = "pwn-agent.agent-loop-state.v1"
MODEL_CHOICE_SCHEMA = "pwn-agent.model-choice.v1"


def run_agent_loop(
    *,
    root: Path,
    plan_path: Path,
    trajectory_path: Path,
    model_response_path: Path,
    model_response_format: str,
    analysis_json: Path | None = None,
    crash_json: Path | None = None,
    patch_validation_json: Path | None = None,
    verify_json: Path | None = None,
    state_path: Path | None = None,
    executor_state_path: Path | None = None,
    plan_output_path: Path | None = None,
    max_steps: int = 1,
    max_failures: int = 1,
    dry_run: bool = False,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    if max_steps < 1:
        raise ValueError("max_steps must be >= 1")
    if max_failures < 1:
        raise ValueError("max_failures must be >= 1")

    resolved_root = root.resolve()
    resolved_plan_path = plan_path.resolve()
    resolved_plan_output = (plan_output_path or plan_path).resolve()
    resolved_trajectory = trajectory_path.resolve()
    resolved_model_response = model_response_path.resolve()
    resolved_state_path = state_path.resolve() if state_path is not None else None
    resolved_executor_state = executor_state_path.resolve() if executor_state_path is not None else None

    state = _load_or_init_loop_state(
        resolved_state_path,
        root=resolved_root,
        plan_path=resolved_plan_path,
        plan_output_path=resolved_plan_output,
        trajectory_path=resolved_trajectory,
        executor_state_path=resolved_executor_state,
        artifact_paths={
            "analysis_json": str(analysis_json.resolve()) if analysis_json is not None else None,
            "crash_json": str(crash_json.resolve()) if crash_json is not None else None,
            "patch_validation_json": (str(patch_validation_json.resolve()) if patch_validation_json is not None else None),
            "verify_json": str(verify_json.resolve()) if verify_json is not None else None,
        },
    )
    resolved_plan_path = Path(str(state["plan_path"])).resolve()
    resolved_plan_output = Path(str(state["plan_output_path"])).resolve()
    resolved_trajectory = Path(str(state["trajectory_path"])).resolve()
    if state.get("executor_state_path"):
        resolved_executor_state = Path(str(state["executor_state_path"])).resolve()
    trajectory = _load_or_init_trajectory(resolved_trajectory, state)
    responses = _load_model_responses(resolved_model_response, model_response_format)

    status = state.get("status", "running")
    while int(state["step_count"]) < max_steps and int(state["failure_count"]) < max_failures:
        current_artifacts = _load_artifact_snapshots(state["artifact_paths"])
        inspection = inspect_plan(resolved_plan_path, state_path=resolved_executor_state)
        candidate_actions = [dict(action) for action in inspection.candidate_actions]
        iteration = {
            "iteration": int(state["step_count"]) + 1,
            "artifact_snapshot": current_artifacts,
            "plan_snapshot": {
                "plan_path": inspection.plan_path,
                "plan_schema_version": inspection.plan_schema_version,
                "plan_fingerprint": inspection.plan_fingerprint,
                "candidate_actions": candidate_actions,
                "runnable_action_ids": inspection.runnable_action_ids,
                "deferred_action_ids": inspection.deferred_action_ids,
                "resumed_completed_action_ids": inspection.resumed_completed_action_ids,
            },
        }

        if not candidate_actions:
            status = "no-candidate-actions"
            iteration["status"] = status
            trajectory["iterations"].append(iteration)
            break

        response_index = int(state["consumed_model_responses"])
        if response_index >= len(responses):
            status = "awaiting-model-output"
            iteration["status"] = status
            trajectory["iterations"].append(iteration)
            break

        raw_choice = responses[response_index]
        state["consumed_model_responses"] = response_index + 1
        choice_error = _validate_model_choice(raw_choice, candidate_actions)
        iteration["model_choice"] = {
            "schema": MODEL_CHOICE_SCHEMA,
            "raw": raw_choice,
            "accepted": choice_error is None,
            "error": choice_error,
        }
        if choice_error is not None:
            state["failure_count"] = int(state["failure_count"]) + 1
            status = "invalid-model-output"
            iteration["status"] = status
            trajectory["iterations"].append(iteration)
            if int(state["failure_count"]) >= max_failures:
                break
            continue

        normalized_choice = {
            "chosen_action_id": raw_choice["chosen_action_id"],
            "rationale": raw_choice["rationale"].strip(),
            "confidence": float(raw_choice["confidence"]),
            "summary_update": raw_choice["summary_update"].strip(),
        }
        state["summary_updates"].append(normalized_choice["summary_update"])
        execution = execute_plan(
            resolved_plan_path,
            action_id=normalized_choice["chosen_action_id"],
            max_actions=1,
            dry_run=dry_run,
            timeout_seconds=timeout_seconds,
            state_path=resolved_executor_state,
        )
        iteration["model_choice"]["normalized"] = normalized_choice
        iteration["execution_result"] = execution.to_dict()

        if execution.status_counts.get("failed", 0) > 0:
            state["failure_count"] = int(state["failure_count"]) + 1

        updated_artifact_paths = _update_artifact_paths(
            state["artifact_paths"],
            candidate_actions=candidate_actions,
            chosen_action_id=normalized_choice["chosen_action_id"],
            executed=execution.executed > 0 and not dry_run,
        )
        state["artifact_paths"] = updated_artifact_paths
        replanned = _replan_from_artifacts(updated_artifact_paths, resolved_plan_output)
        if replanned is not None:
            resolved_plan_path = resolved_plan_output
            state["plan_path"] = str(resolved_plan_output)
            state["last_plan_fingerprint"] = replanned.get("plan_fingerprint")
            iteration["replanned"] = {
                "plan_path": str(resolved_plan_output),
                "plan_fingerprint": replanned.get("plan_fingerprint"),
                "next_action_ids": [action.get("id") for action in replanned.get("next_actions", []) if action.get("id")],
            }
        else:
            iteration["replanned"] = None

        state["step_count"] = int(state["step_count"]) + 1
        iteration["status"] = "dry-run" if dry_run else ("failed" if execution.status_counts.get("failed", 0) > 0 else "completed")
        trajectory["iterations"].append(iteration)

        if int(state["failure_count"]) >= max_failures:
            status = "failure-budget-exhausted"
            break
        if int(state["step_count"]) >= max_steps:
            status = "step-budget-exhausted"
            break
    else:
        status = "completed"

    trajectory["artifact_paths"] = dict(state["artifact_paths"])
    trajectory["step_count"] = int(state["step_count"])
    trajectory["failure_count"] = int(state["failure_count"])
    trajectory["status"] = status
    trajectory["final_summary"] = _build_final_summary(state, trajectory)
    state["status"] = status
    _write_json(resolved_trajectory, trajectory)
    if resolved_state_path is not None:
        _write_json(resolved_state_path, state)
    return trajectory


def render_agent_loop_markdown(artifact: dict[str, Any]) -> str:
    lines = ["# Agent Loop", ""]
    lines.append(f"- Status: {artifact.get('status')}")
    lines.append(f"- Steps: {artifact.get('step_count')}")
    lines.append(f"- Failures: {artifact.get('failure_count')}")
    final_summary = dict(artifact.get("final_summary") or {})
    if final_summary.get("summary_text"):
        lines.append(f"- Summary: {final_summary['summary_text']}")
    lines.extend(["", "## Iterations", ""])
    for iteration in artifact.get("iterations", []):
        lines.append(f"- Iteration {iteration.get('iteration')}: {iteration.get('status')}")
        model_choice = dict(iteration.get("model_choice") or {})
        normalized = dict(model_choice.get("normalized") or {})
        if normalized:
            lines.append(
                f"  choice={normalized.get('chosen_action_id')} "
                f"confidence={normalized.get('confidence')} rationale={normalized.get('rationale')}"
            )
    return "\n".join(lines) + "\n"


def _load_model_responses(path: Path, response_format: str) -> list[dict[str, Any]]:
    if response_format == "jsonl":
        responses: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError("model response lines must be JSON objects")
                responses.append(payload)
        return responses

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return list(payload)
    raise ValueError("model response json must be an object or list of objects")


def _validate_model_choice(choice: dict[str, Any], candidate_actions: list[dict[str, Any]]) -> str | None:
    if not isinstance(choice, dict):
        return "model choice must be a JSON object"
    chosen_action_id = choice.get("chosen_action_id")
    rationale = choice.get("rationale")
    confidence = choice.get("confidence")
    summary_update = choice.get("summary_update")

    candidate_ids = {action.get("id") for action in candidate_actions if action.get("id")}
    if not isinstance(chosen_action_id, str) or not chosen_action_id:
        return "chosen_action_id must be a non-empty string"
    if chosen_action_id not in candidate_ids:
        return f"chosen_action_id not present in bounded plan candidates: {chosen_action_id}"
    if not isinstance(rationale, str) or not rationale.strip():
        return "rationale must be a non-empty string"
    if not isinstance(summary_update, str) or not summary_update.strip():
        return "summary_update must be a non-empty string"
    if not isinstance(confidence, (int, float)):
        return "confidence must be numeric"
    if float(confidence) < 0.0 or float(confidence) > 1.0:
        return "confidence must be between 0.0 and 1.0"
    return None


def _update_artifact_paths(
    artifact_paths: dict[str, Any],
    *,
    candidate_actions: list[dict[str, Any]],
    chosen_action_id: str,
    executed: bool,
) -> dict[str, Any]:
    updated = dict(artifact_paths)
    if not executed:
        return updated
    action = next((item for item in candidate_actions if item.get("id") == chosen_action_id), None)
    if action is None:
        return updated
    argv = list(action.get("suggested_cli") or [])
    subcommand = argv[3] if len(argv) > 3 else None
    output_path = _extract_option(argv, "--output")
    if output_path is None:
        return updated
    if subcommand == "binary-scan":
        updated["analysis_json"] = output_path
    elif subcommand in {"crash-triage", "binary-triage"}:
        updated["crash_json"] = output_path
    elif subcommand in {"patch-validate"}:
        updated["patch_validation_json"] = output_path
    elif subcommand in {"binary-verify", "binary-validate"}:
        updated["verify_json"] = output_path
    return updated


def _replan_from_artifacts(artifact_paths: dict[str, Any], plan_output_path: Path) -> dict[str, Any] | None:
    analysis = _load_optional_artifact(artifact_paths.get("analysis_json"))
    crash = _load_optional_artifact(artifact_paths.get("crash_json"))
    validation = _load_optional_artifact(artifact_paths.get("patch_validation_json"))
    if analysis is None and crash is None and validation is None:
        return None
    plan = build_binary_plan(analysis, crash=crash, validation=validation)
    write_binary_json(plan_output_path, plan)
    return plan


def _load_optional_artifact(raw_path: Any) -> dict[str, Any] | None:
    if not raw_path:
        return None
    path = Path(str(raw_path)).resolve()
    if not path.exists():
        return None
    return load_binary_artifact(path)


def _load_artifact_snapshots(artifact_paths: dict[str, Any]) -> dict[str, Any]:
    snapshots: dict[str, Any] = {}
    for key, raw_path in dict(artifact_paths).items():
        if not raw_path:
            snapshots[key] = None
            continue
        path = Path(str(raw_path)).resolve()
        if not path.exists():
            snapshots[key] = {"path": str(path), "exists": False}
            continue
        payload = load_binary_artifact(path)
        snapshots[key] = {
            "path": str(path),
            "exists": True,
            "artifact": payload,
        }
    return snapshots


def _build_final_summary(state: dict[str, Any], trajectory: dict[str, Any]) -> dict[str, Any]:
    latest_iteration = trajectory["iterations"][-1] if trajectory.get("iterations") else {}
    plan_snapshot = dict(latest_iteration.get("plan_snapshot") or {})
    updates = list(state.get("summary_updates") or [])
    return {
        "summary_text": " ".join(updates).strip(),
        "summary_updates": updates,
        "remaining_candidate_action_ids": list(plan_snapshot.get("runnable_action_ids") or []),
        "last_plan_fingerprint": state.get("last_plan_fingerprint"),
    }


def _load_or_init_loop_state(
    state_path: Path | None,
    *,
    root: Path,
    plan_path: Path,
    plan_output_path: Path,
    trajectory_path: Path,
    executor_state_path: Path | None,
    artifact_paths: dict[str, Any],
) -> dict[str, Any]:
    if state_path is not None and state_path.exists():
        return json.loads(state_path.read_text(encoding="utf-8"))
    return {
        "schema": AGENT_LOOP_STATE_SCHEMA,
        "schema_version": 1,
        "root": str(root),
        "plan_path": str(plan_path),
        "plan_output_path": str(plan_output_path),
        "trajectory_path": str(trajectory_path),
        "executor_state_path": (str(executor_state_path) if executor_state_path is not None else None),
        "artifact_paths": dict(artifact_paths),
        "step_count": 0,
        "failure_count": 0,
        "consumed_model_responses": 0,
        "summary_updates": [],
        "status": "initialized",
        "last_plan_fingerprint": None,
    }


def _load_or_init_trajectory(path: Path, state: dict[str, Any]) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "schema": AGENT_LOOP_SCHEMA,
        "schema_version": 1,
        "mode": "binary",
        "root": state.get("root"),
        "plan_path": state.get("plan_path"),
        "artifact_paths": dict(state.get("artifact_paths") or {}),
        "step_count": 0,
        "failure_count": 0,
        "status": "initialized",
        "iterations": [],
        "final_summary": {},
    }


def _extract_option(argv: list[str], option: str) -> str | None:
    try:
        index = argv.index(option)
    except ValueError:
        return None
    if index + 1 >= len(argv):
        return None
    return argv[index + 1]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
