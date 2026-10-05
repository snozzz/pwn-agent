from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from ...executor import execute_plan, inspect_plan
from ...agent.controller import (
    AgentContext,
    AgentModel,
    ControllerError,
    ControllerExhausted,
    ScriptedController,
    build_controller,
    normalize_decision,
    validate_decision,
)
from ...agent.evidence import artifact_slot_for_command, build_evidence_record
from ...agent.progress import (
    STATUS_NO_PROGRESS,
    STATUS_REPEATED_ACTION,
    assess_progress,
    compute_progress_signature,
    no_progress_detected,
    repeated_action_detected,
)
from ...agent.state import AgentState
from .workflow import build_binary_plan, load_binary_artifact, write_binary_json

AGENT_LOOP_SCHEMA = "pwn-agent.agent-loop.v1"
AGENT_LOOP_STATE_SCHEMA = "pwn-agent.agent-loop-state.v1"
MODEL_CHOICE_SCHEMA = "pwn-agent.model-choice.v1"

# Statuses that mean the loop stopped itself for a good reason vs. a problem.
SUCCESS_STATUSES = {"completed", "step-budget-exhausted", "no-candidate-actions"}
PROBLEM_STATUSES = {"invalid-model-output", "failure-budget-exhausted", "controller-error"}


def run_agent_loop(
    *,
    root: Path,
    plan_path: Path,
    trajectory_path: Path,
    model_response_path: Path | None = None,
    model_response_format: str = "json",
    controller: Any = None,
    analysis_json: Path | None = None,
    crash_json: Path | None = None,
    patch_validation_json: Path | None = None,
    verify_json: Path | None = None,
    state_path: Path | None = None,
    executor_state_path: Path | None = None,
    plan_output_path: Path | None = None,
    objective: str | None = None,
    max_steps: int = 1,
    max_failures: int = 1,
    max_no_progress: int = 2,
    max_repeats: int = 3,
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
    resolved_model_response = model_response_path.resolve() if model_response_path is not None else None
    resolved_state_path = state_path.resolve() if state_path is not None else None
    resolved_executor_state = executor_state_path.resolve() if executor_state_path is not None else None

    state = _load_or_init_loop_state(
        resolved_state_path,
        root=resolved_root,
        plan_path=resolved_plan_path,
        plan_output_path=resolved_plan_output,
        trajectory_path=resolved_trajectory,
        executor_state_path=resolved_executor_state,
        objective=objective,
        budgets={"max_steps": max_steps, "max_failures": max_failures, "max_no_progress": max_no_progress},
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

    agent_state = AgentState.from_dict(state.get("agent_state") or {})
    agent_state.max_steps = max_steps
    agent_state.max_failures = max_failures
    agent_state.max_no_progress = max_no_progress

    controller_obj = _resolve_controller(
        controller=controller,
        model_response_path=resolved_model_response,
        model_response_format=model_response_format,
        consumed=int(state.get("consumed_model_responses", 0)),
    )

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

        context = AgentContext(
            objective=agent_state.objective,
            stage=_infer_stage(candidate_actions),
            iteration=int(state["step_count"]) + 1,
            candidate_actions=candidate_actions,
            evidence=list(agent_state.evidence[-5:]),
            action_history=list(agent_state.action_history),
            state_summary=_state_summary(state, agent_state),
        )

        try:
            raw_choice = controller_obj.decide(context)
        except ControllerExhausted:
            status = "awaiting-model-output"
            iteration["status"] = status
            trajectory["iterations"].append(iteration)
            break
        except ControllerError as exc:
            state["failure_count"] = int(state["failure_count"]) + 1
            status = "controller-error"
            iteration["model_choice"] = {
                "schema": MODEL_CHOICE_SCHEMA,
                "raw": None,
                "accepted": False,
                "error": f"controller-error: {exc}",
            }
            iteration["status"] = status
            trajectory["iterations"].append(iteration)
            agent_state.record_failure(iteration=context.iteration, reason=f"controller-error: {exc}")
            if int(state["failure_count"]) >= max_failures:
                break
            continue

        if isinstance(controller_obj, ScriptedController):
            state["consumed_model_responses"] = controller_obj.consumed

        choice_error = validate_decision(raw_choice, candidate_actions)
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
            chosen = raw_choice.get("chosen_action_id") if isinstance(raw_choice, dict) else None
            agent_state.record_action(
                iteration=context.iteration,
                action_id=str(chosen) if chosen else "unknown",
                accepted=False,
                status="rejected",
            )
            agent_state.record_failure(iteration=context.iteration, reason=choice_error)
            if int(state["failure_count"]) >= max_failures:
                break
            continue

        normalized_choice = normalize_decision(raw_choice)
        chosen_action_id = normalized_choice["chosen_action_id"]
        chosen_action = next((a for a in candidate_actions if a.get("id") == chosen_action_id), {})
        state["summary_updates"].append(normalized_choice["summary_update"])
        agent_state.add_summary_update(normalized_choice["summary_update"])
        _apply_controller_annotations(agent_state, normalized_choice)

        execution = execute_plan(
            resolved_plan_path,
            action_id=chosen_action_id,
            max_actions=1,
            dry_run=dry_run,
            timeout_seconds=timeout_seconds,
            state_path=resolved_executor_state,
        )
        execution_dict = execution.to_dict()
        iteration["model_choice"]["normalized"] = normalized_choice
        iteration["execution_result"] = execution_dict

        failed = execution.status_counts.get("failed", 0) > 0
        if failed:
            state["failure_count"] = int(state["failure_count"]) + 1

        agent_state.record_action(
            iteration=context.iteration,
            action_id=chosen_action_id,
            accepted=True,
            status="failed" if failed else ("dry-run" if dry_run else "completed"),
        )
        if failed:
            agent_state.record_failure(iteration=context.iteration, reason=f"action '{chosen_action_id}' failed")

        _record_execution_evidence(
            agent_state,
            action=chosen_action,
            execution_dict=execution_dict,
            artifact_fingerprints=state["artifact_fingerprints"],
            iteration_index=context.iteration,
            dry_run=dry_run,
        )
        state["executed_action_ids"].append(chosen_action_id)

        updated_artifact_paths = _update_artifact_paths(
            state["artifact_paths"],
            candidate_actions=candidate_actions,
            chosen_action_id=chosen_action_id,
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

        # --- loop protection: progress + fixation guards ---
        completed_ids = set(execution_dict.get("resumed_completed_action_ids") or []) | set(
            execution_dict.get("completed_action_ids") or []
        )
        signature = compute_progress_signature(
            completed_action_ids=completed_ids,
            evidence_fingerprints=[fp for fp in state["artifact_fingerprints"].values() if fp],
            candidate_ids=inspection.runnable_action_ids,
        )
        assessment = assess_progress(
            previous_signature=state.get("last_progress_signature"),
            signature=signature,
            previous_no_progress_count=int(state.get("no_progress_count", 0)),
        )
        state["last_progress_signature"] = assessment.signature
        state["no_progress_count"] = assessment.no_progress_count
        agent_state.last_progress_signature = assessment.signature
        agent_state.no_progress_count = assessment.no_progress_count
        iteration["progress"] = {
            "signature": assessment.signature,
            "progressed": assessment.progressed,
            "no_progress_count": assessment.no_progress_count,
        }

        iteration["status"] = "dry-run" if dry_run else ("failed" if failed else "completed")
        trajectory["iterations"].append(iteration)

        if int(state["failure_count"]) >= max_failures:
            status = "failure-budget-exhausted"
            break
        if repeated_action_detected(state["executed_action_ids"], threshold=max_repeats):
            status = STATUS_REPEATED_ACTION
            break
        if no_progress_detected(int(state["no_progress_count"]), threshold=max_no_progress):
            status = STATUS_NO_PROGRESS
            break
        if int(state["step_count"]) >= max_steps:
            status = "step-budget-exhausted"
            break
    else:
        status = "completed"

    agent_state.step_count = int(state["step_count"])
    agent_state.failure_count = int(state["failure_count"])

    trajectory["artifact_paths"] = dict(state["artifact_paths"])
    trajectory["step_count"] = int(state["step_count"])
    trajectory["failure_count"] = int(state["failure_count"])
    trajectory["status"] = status
    trajectory["controller"] = {"name": getattr(controller_obj, "name", "unknown")}
    trajectory["agent_state"] = agent_state.to_dict()
    trajectory["final_summary"] = _build_final_summary(state, trajectory, agent_state)
    state["status"] = status
    state["agent_state"] = agent_state.to_dict()
    _write_json(resolved_trajectory, trajectory)
    if resolved_state_path is not None:
        _write_json(resolved_state_path, state)
    return trajectory


def render_agent_loop_markdown(artifact: dict[str, Any]) -> str:
    lines = ["# Agent Loop", ""]
    lines.append(f"- Status: {artifact.get('status')}")
    lines.append(f"- Steps: {artifact.get('step_count')}")
    lines.append(f"- Failures: {artifact.get('failure_count')}")
    controller = dict(artifact.get("controller") or {})
    if controller.get("name"):
        lines.append(f"- Controller: {controller['name']}")
    final_summary = dict(artifact.get("final_summary") or {})
    if final_summary.get("summary_text"):
        lines.append(f"- Summary: {final_summary['summary_text']}")
    if final_summary.get("verified_fact_count") is not None:
        lines.append(f"- Verified facts: {final_summary['verified_fact_count']}")
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
            if normalized.get("hypothesis"):
                lines.append(f"  hypothesis={normalized['hypothesis']}")
        progress = dict(iteration.get("progress") or {})
        if progress:
            lines.append(f"  progressed={progress.get('progressed')} no_progress_count={progress.get('no_progress_count')}")
    return "\n".join(lines) + "\n"


def _resolve_controller(
    *,
    controller: Any,
    model_response_path: Path | None,
    model_response_format: str,
    consumed: int,
) -> AgentModel:
    """Pick the controller backend.

    Precedence: an explicit ``controller`` (name/dict/instance) wins; otherwise a
    pre-generated response file is replayed via a ``ScriptedController`` seeded at the
    already-consumed index so resume is exact. Requiring one of the two keeps backend
    selection explicit rather than silently defaulting.
    """
    if controller is not None:
        built = build_controller(controller)
        if isinstance(built, ScriptedController) and model_response_path is not None:
            responses = _load_model_responses(model_response_path, model_response_format)
            return ScriptedController(responses, start_index=consumed)
        return built
    if model_response_path is not None:
        responses = _load_model_responses(model_response_path, model_response_format)
        return ScriptedController(responses, start_index=consumed)
    raise ValueError("agent loop requires either a controller or a model_response_path")


def _infer_stage(candidate_actions: list[dict[str, Any]]) -> str | None:
    for action in candidate_actions:
        if action.get("stage"):
            return str(action["stage"])
    return None


def _state_summary(state: dict[str, Any], agent_state: AgentState) -> dict[str, Any]:
    return {
        "step_count": int(state.get("step_count", 0)),
        "failure_count": int(state.get("failure_count", 0)),
        "no_progress_count": int(state.get("no_progress_count", 0)),
        "verified_fact_count": len(agent_state.verified_facts),
        "open_hypothesis_count": len(agent_state.open_hypotheses),
        "evidence_count": len(agent_state.evidence),
    }


def _apply_controller_annotations(agent_state: AgentState, normalized_choice: dict[str, Any]) -> None:
    """Fold optional v2 decision fields into the belief state (never verified facts)."""
    hypothesis = normalized_choice.get("hypothesis")
    if hypothesis:
        agent_state.add_hypothesis(hypothesis, confidence=float(normalized_choice.get("confidence", 0.0)))
    state_update = normalized_choice.get("state_update")
    if isinstance(state_update, dict):
        for question in state_update.get("open_questions") or []:
            if isinstance(question, str):
                agent_state.add_open_question(question)
        for hyp in state_update.get("add_hypotheses") or []:
            if isinstance(hyp, str):
                agent_state.add_hypothesis(hyp)


def _record_execution_evidence(
    agent_state: AgentState,
    *,
    action: dict[str, Any],
    execution_dict: dict[str, Any],
    artifact_fingerprints: dict[str, Any],
    iteration_index: int,
    dry_run: bool,
) -> None:
    for record in execution_dict.get("records", []):
        command = list(record.get("command") or [])
        slot = artifact_slot_for_command(command)
        artifact_payload = None
        if not dry_run and record.get("status") == "ok" and slot:
            output_path = _extract_option(command, "--output")
            if output_path and Path(output_path).exists():
                try:
                    artifact_payload = load_binary_artifact(Path(output_path))
                except (ValueError, OSError, json.JSONDecodeError):
                    artifact_payload = None
        previous_fp = artifact_fingerprints.get(slot) if slot else None
        evidence_record = build_evidence_record(
            evidence_id=agent_state.next_evidence_id(),
            iteration=iteration_index,
            action=action,
            record=record,
            artifact_payload=artifact_payload,
            previous_fingerprint=previous_fp,
        )
        agent_state.record_evidence(evidence_record)
        if slot and evidence_record.artifact_fingerprint:
            artifact_fingerprints[slot] = evidence_record.artifact_fingerprint


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
    verify = _load_optional_artifact(artifact_paths.get("verify_json"))
    if analysis is None and crash is None and validation is None and verify is None:
        return None
    plan = build_binary_plan(analysis, crash=crash, validation=validation, verify=verify)
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


def _build_final_summary(state: dict[str, Any], trajectory: dict[str, Any], agent_state: AgentState) -> dict[str, Any]:
    latest_iteration = trajectory["iterations"][-1] if trajectory.get("iterations") else {}
    plan_snapshot = dict(latest_iteration.get("plan_snapshot") or {})
    updates = list(state.get("summary_updates") or [])
    return {
        "summary_text": " ".join(updates).strip(),
        "summary_updates": updates,
        "remaining_candidate_action_ids": list(plan_snapshot.get("runnable_action_ids") or []),
        "last_plan_fingerprint": state.get("last_plan_fingerprint"),
        "verified_fact_count": len(agent_state.verified_facts),
        "open_hypothesis_count": len(agent_state.open_hypotheses),
        "rejected_hypothesis_count": len(agent_state.rejected_hypotheses),
        "evidence_count": len(agent_state.evidence),
        "no_progress_count": int(state.get("no_progress_count", 0)),
    }


def _load_or_init_loop_state(
    state_path: Path | None,
    *,
    root: Path,
    plan_path: Path,
    plan_output_path: Path,
    trajectory_path: Path,
    executor_state_path: Path | None,
    objective: str | None,
    budgets: dict[str, Any],
    artifact_paths: dict[str, Any],
) -> dict[str, Any]:
    if state_path is not None and state_path.exists():
        loaded = json.loads(state_path.read_text(encoding="utf-8"))
        return _normalize_loop_state(loaded)
    state = {
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
        # v2 additive fields
        "no_progress_count": 0,
        "last_progress_signature": None,
        "executed_action_ids": [],
        "artifact_fingerprints": {},
        "agent_state": AgentState(
            objective=objective or AgentState.objective,
            max_steps=int(budgets.get("max_steps", 1)),
            max_failures=int(budgets.get("max_failures", 1)),
            max_no_progress=int(budgets.get("max_no_progress", 2)),
        ).to_dict(),
    }
    return state


def _normalize_loop_state(state: dict[str, Any]) -> dict[str, Any]:
    """Backfill v2 additive fields when resuming a legacy loop-state file."""
    state.setdefault("no_progress_count", 0)
    state.setdefault("last_progress_signature", None)
    state.setdefault("executed_action_ids", [])
    state.setdefault("artifact_fingerprints", {})
    state.setdefault("agent_state", {})
    return state


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
