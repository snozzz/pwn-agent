"""Trajectory evaluation harness.

Turns a recorded agent-loop trajectory (``pwn-agent.agent-loop.v1``) into measured
metrics so controllers can be compared on identical tasks (deterministic planner vs. a
Claude controller vs. a local Qwen controller vs. a future fine-tuned one).

Every field here is *measured* from the trajectory. Nothing is estimated or fabricated;
fields that the current pipeline does not record (e.g. wall-clock time, provider token
usage) are reported as ``None`` so downstream tooling can populate them later without a
schema change.
"""
from __future__ import annotations

from typing import Any

AGENT_EVAL_SCHEMA = "pwn-agent.agent-eval.v1"

# Terminal statuses that represent the loop stopping on its own terms rather than a fault.
CLEAN_TERMINAL_STATES = {"completed", "step-budget-exhausted", "no-candidate-actions"}
GUARD_TERMINAL_STATES = {"no-progress", "repeated-action"}
FAULT_TERMINAL_STATES = {"invalid-model-output", "failure-budget-exhausted", "controller-error", "awaiting-model-output"}


def evaluate_trajectory(trajectory: dict[str, Any]) -> dict[str, Any]:
    """Compute measured metrics for a single trajectory."""
    iterations = list(trajectory.get("iterations") or [])
    terminal_state = str(trajectory.get("status") or "unknown")

    successful_actions = 0
    failed_actions = 0
    rejected_decisions = 0
    no_progress_iterations = 0
    executed_choices: list[str] = []
    repeated_actions = 0
    recovered_failures = 0
    pending_failures = 0
    token_usage_total = 0
    token_usage_seen = False

    seen_action_ids: set[str] = set()

    for iteration in iterations:
        status = str(iteration.get("status") or "")
        model_choice = dict(iteration.get("model_choice") or {})
        accepted = bool(model_choice.get("accepted"))
        normalized = dict(model_choice.get("normalized") or {})
        progress = dict(iteration.get("progress") or {})

        if "progressed" in progress and not progress.get("progressed"):
            no_progress_iterations += 1

        if model_choice and not accepted:
            rejected_decisions += 1
            pending_failures += 1

        usage = dict(normalized.get("usage") or model_choice.get("usage") or {})
        if usage:
            token_usage_seen = True
            token_usage_total += int(usage.get("total_tokens") or 0)

        if accepted and normalized:
            chosen = str(normalized.get("chosen_action_id") or "")
            if chosen:
                if chosen in seen_action_ids:
                    repeated_actions += 1
                seen_action_ids.add(chosen)
                executed_choices.append(chosen)

        if status == "completed":
            successful_actions += 1
            if pending_failures:
                recovered_failures += pending_failures
                pending_failures = 0
        elif status == "failed":
            failed_actions += 1
            pending_failures += 1

    return {
        "schema": AGENT_EVAL_SCHEMA,
        "controller": dict(trajectory.get("controller") or {}).get("name"),
        "terminal_state": terminal_state,
        "clean_termination": terminal_state in CLEAN_TERMINAL_STATES,
        "guard_termination": terminal_state in GUARD_TERMINAL_STATES,
        "fault_termination": terminal_state in FAULT_TERMINAL_STATES,
        "steps_taken": int(trajectory.get("step_count") or 0),
        "failure_count": int(trajectory.get("failure_count") or 0),
        "trajectory_length": len(iterations),
        "successful_actions": successful_actions,
        "failed_actions": failed_actions,
        "rejected_decisions": rejected_decisions,
        "repeated_actions": repeated_actions,
        "no_progress_iterations": no_progress_iterations,
        "recovered_failures": recovered_failures,
        "distinct_actions": sorted(seen_action_ids),
        "executed_action_sequence": executed_choices,
        "evidence_count": _final_summary_int(trajectory, "evidence_count"),
        "verified_fact_count": _final_summary_int(trajectory, "verified_fact_count"),
        "open_hypothesis_count": _final_summary_int(trajectory, "open_hypothesis_count"),
        "rejected_hypothesis_count": _final_summary_int(trajectory, "rejected_hypothesis_count"),
        # schema-capable but not yet recorded by the pipeline
        "wall_time_seconds": trajectory.get("wall_time_seconds"),
        "token_usage_total": token_usage_total if token_usage_seen else None,
    }


def _final_summary_int(trajectory: dict[str, Any], key: str) -> int | None:
    summary = dict(trajectory.get("final_summary") or {})
    value = summary.get(key)
    if isinstance(value, int):
        return value
    return None


def compare_trajectories(named_trajectories: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    """Evaluate several trajectories and return per-trajectory metrics + a comparison.

    ``named_trajectories`` is a list of ``(label, trajectory_dict)`` pairs. Used to
    contrast controllers on the same task; it does not rank or editorialize, only reports.
    """
    per: list[dict[str, Any]] = []
    for label, trajectory in named_trajectories:
        metrics = evaluate_trajectory(trajectory)
        metrics_with_label = {"label": label}
        metrics_with_label.update(metrics)
        per.append(metrics_with_label)

    return {
        "schema": AGENT_EVAL_SCHEMA,
        "count": len(per),
        "trajectories": per,
        "comparison": {
            "labels": [row["label"] for row in per],
            "steps_taken": {row["label"]: row["steps_taken"] for row in per},
            "clean_termination": {row["label"]: row["clean_termination"] for row in per},
            "successful_actions": {row["label"]: row["successful_actions"] for row in per},
            "no_progress_iterations": {row["label"]: row["no_progress_iterations"] for row in per},
            "repeated_actions": {row["label"]: row["repeated_actions"] for row in per},
        },
    }


def render_evaluation_markdown(payload: dict[str, Any]) -> str:
    """Render either a single-trajectory metrics dict or a comparison dict as markdown."""
    if "trajectories" in payload:
        rows = list(payload.get("trajectories") or [])
    else:
        rows = [payload]

    lines = ["# Agent Loop Evaluation", ""]
    lines.append(f"- Trajectories evaluated: {len(rows)}")
    lines.extend(["", "## Metrics", ""])
    for row in rows:
        label = row.get("label") or row.get("controller") or "trajectory"
        lines.append(f"### {label}")
        for key in (
            "controller",
            "terminal_state",
            "clean_termination",
            "guard_termination",
            "fault_termination",
            "steps_taken",
            "trajectory_length",
            "successful_actions",
            "failed_actions",
            "rejected_decisions",
            "repeated_actions",
            "no_progress_iterations",
            "recovered_failures",
            "evidence_count",
            "verified_fact_count",
            "wall_time_seconds",
            "token_usage_total",
        ):
            if key in row:
                lines.append(f"- {key}: {row.get(key)}")
        sequence = row.get("executed_action_sequence")
        if sequence:
            lines.append(f"- executed_action_sequence: {', '.join(sequence)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
