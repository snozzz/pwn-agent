from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.executor import ExecutionSummary
from src.modes.binary.loop import run_agent_loop


class AgentLoopTests(unittest.TestCase):
    def test_agent_loop_valid_choice_executes_bounded_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "binary-plan.json"
            output_path = root / "trajectory.json"
            state_path = root / "loop-state.json"
            model_response_path = root / "model-choice.json"
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            plan_path.write_text(
                json.dumps(
                    {
                        "schema": "pwn-agent.binary-plan.v2",
                        "schema_version": 2,
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "list-rebuild-targets",
                                "stage": "identify",
                                "phase": "triage",
                                "kind": "list_rebuild_targets",
                                "status": "ready",
                                "priority": 50,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "enumerate bounded targets",
                                "expected_artifacts": [],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            model_response_path.write_text(
                json.dumps(
                    {
                        "chosen_action_id": "list-rebuild-targets",
                        "rationale": "Take the only bounded action.",
                        "confidence": 0.91,
                        "summary_update": "Enumerated local rebuild targets.",
                    }
                ),
                encoding="utf-8",
            )

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=output_path,
                model_response_path=model_response_path,
                model_response_format="json",
                state_path=state_path,
                max_steps=1,
                max_failures=1,
                dry_run=False,
                timeout_seconds=30,
            )

            self.assertEqual(artifact["status"], "step-budget-exhausted")
            self.assertEqual(artifact["step_count"], 1)
            self.assertEqual(artifact["failure_count"], 0)
            self.assertTrue(artifact["iterations"][0]["model_choice"]["accepted"])
            self.assertEqual(
                artifact["iterations"][0]["execution_result"]["completed_action_ids"],
                ["list-rebuild-targets"],
            )

    def test_agent_loop_rejects_invalid_model_choice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "binary-plan.json"
            output_path = root / "trajectory.json"
            state_path = root / "loop-state.json"
            model_response_path = root / "model-choice.json"

            plan_path.write_text(
                json.dumps(
                    {
                        "schema": "pwn-agent.binary-plan.v2",
                        "schema_version": 2,
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "list-rebuild-targets",
                                "stage": "identify",
                                "phase": "triage",
                                "kind": "list_rebuild_targets",
                                "status": "ready",
                                "priority": 50,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "enumerate bounded targets",
                                "expected_artifacts": [],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            model_response_path.write_text(
                json.dumps(
                    {
                        "chosen_action_id": "not-in-plan",
                        "rationale": "ignore the bounded choices",
                        "confidence": 0.7,
                        "summary_update": "Attempting an invalid choice.",
                    }
                ),
                encoding="utf-8",
            )

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=output_path,
                model_response_path=model_response_path,
                model_response_format="json",
                state_path=state_path,
                max_steps=1,
                max_failures=1,
                dry_run=True,
            )

            self.assertEqual(artifact["status"], "invalid-model-output")
            self.assertEqual(artifact["step_count"], 0)
            self.assertEqual(artifact["failure_count"], 1)
            self.assertFalse(artifact["iterations"][0]["model_choice"]["accepted"])
            self.assertIn("not present in bounded plan candidates", artifact["iterations"][0]["model_choice"]["error"])
            persisted_state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted_state["consumed_model_responses"], 1)

    def test_agent_loop_invalid_choice_increments_failure_budget_without_step_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "binary-plan.json"
            output_path = root / "trajectory.json"
            state_path = root / "loop-state.json"
            model_response_path = root / "model-choice.jsonl"

            plan_path.write_text(
                json.dumps(
                    {
                        "schema": "pwn-agent.binary-plan.v2",
                        "schema_version": 2,
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "list-rebuild-targets",
                                "stage": "identify",
                                "phase": "triage",
                                "kind": "list_rebuild_targets",
                                "status": "ready",
                                "priority": 50,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "enumerate bounded targets",
                                "expected_artifacts": [],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            model_response_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "chosen_action_id": "not-in-plan",
                                "rationale": "invalid first choice",
                                "confidence": 0.2,
                                "summary_update": "Bad choice.",
                            }
                        ),
                        json.dumps(
                            {
                                "chosen_action_id": "list-rebuild-targets",
                                "rationale": "recover with bounded action",
                                "confidence": 0.8,
                                "summary_update": "Recovered.",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=output_path,
                model_response_path=model_response_path,
                model_response_format="jsonl",
                state_path=state_path,
                max_steps=1,
                max_failures=2,
                dry_run=True,
            )

            self.assertEqual(artifact["status"], "step-budget-exhausted")
            self.assertEqual(artifact["step_count"], 1)
            self.assertEqual(artifact["failure_count"], 1)
            self.assertEqual(len(artifact["iterations"]), 2)
            self.assertFalse(artifact["iterations"][0]["model_choice"]["accepted"])
            self.assertEqual(artifact["iterations"][1]["status"], "dry-run")

    def test_agent_loop_replans_from_verify_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "binary-plan.json"
            output_path = root / "trajectory.json"
            state_path = root / "loop-state.json"
            verify_path = root / "binary-verify.json"
            model_response_path = root / "model-choice.json"
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)

            plan_path.write_text(
                json.dumps(
                    {
                        "schema": "pwn-agent.binary-plan.v2",
                        "schema_version": 2,
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "validate-candidate-patch",
                                "stage": "validate",
                                "phase": "execution",
                                "kind": "binary_verify",
                                "status": "ready",
                                "priority": 90,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "validate the patched binary",
                                "expected_artifacts": ["binary-verify.json"],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "binary-verify",
                                    "--root",
                                    str(root),
                                    "--binary",
                                    str(binary),
                                    "--output",
                                    str(verify_path),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            model_response_path.write_text(
                json.dumps(
                    {
                        "chosen_action_id": "validate-candidate-patch",
                        "rationale": "Consume the current validation slot.",
                        "confidence": 0.83,
                        "summary_update": "Validation evidence collected.",
                    }
                ),
                encoding="utf-8",
            )

            def _execute_plan_stub(*_args, **_kwargs):
                verify_path.write_text(
                    json.dumps(
                        {
                            "schema": "pwn-agent.binary-verify.v1",
                            "schema_version": 1,
                            "mode": "binary",
                            "root": str(root),
                            "binary_path": str(binary),
                            "argv": [str(binary), "seed"],
                            "stdin_file_path": None,
                            "returncode": 0,
                            "sanitizer_signal": False,
                            "stdout_head": ["ok"],
                            "stderr_head": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return ExecutionSummary(
                    plan_path=str(plan_path),
                    plan_schema_version=2,
                    plan_fingerprint="plan-v1",
                    executed=1,
                    selected_action_ids=["validate-candidate-patch"],
                    completed_action_ids=["validate-candidate-patch"],
                    previewed_action_ids=[],
                    resumed_completed_action_ids=[],
                    stale_completed_action_ids=[],
                    new_action_ids=[],
                    changed_action_ids=[],
                    stopped_reason="completed",
                    runnable_action_ids=["validate-candidate-patch"],
                    deferred_action_ids=[],
                    remaining_runnable_action_ids=[],
                    next_action_ids=[],
                    status_counts={"ok": 1, "failed": 0, "dry-run": 0},
                    action_state_counts={"completed": 1},
                    action_states={"validate-candidate-patch": "completed"},
                    transition_count=0,
                    transitions=[],
                    state_path=None,
                    resumed_from_state=False,
                    plan_changed=False,
                    previous_plan_path=None,
                    previous_plan_schema_version=None,
                    previous_plan_fingerprint=None,
                    records=[],
                )

            with patch("src.modes.binary.loop.execute_plan", side_effect=_execute_plan_stub):
                artifact = run_agent_loop(
                    root=root,
                    plan_path=plan_path,
                    trajectory_path=output_path,
                    model_response_path=model_response_path,
                    model_response_format="json",
                    state_path=state_path,
                    max_steps=1,
                    max_failures=1,
                    dry_run=False,
                )

            replanned_ids = artifact["iterations"][0]["replanned"]["next_action_ids"]
            updated_plan = json.loads(plan_path.read_text(encoding="utf-8"))
            self.assertIsNone(artifact["artifact_paths"]["analysis_json"])
            self.assertEqual(artifact["artifact_paths"]["verify_json"], str(verify_path))
            self.assertEqual(replanned_ids, ["collect-binary-evidence", "summarize-local-findings"])
            self.assertNotIn("validate-candidate-patch", [action["id"] for action in updated_plan["next_actions"]])
            self.assertEqual(
                [action["id"] for action in updated_plan["next_actions"]],
                ["collect-binary-evidence", "summarize-local-findings"],
            )

    def test_agent_loop_resumes_and_uses_executor_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "binary-plan.json"
            output_path = root / "trajectory.json"
            state_path = root / "loop-state.json"
            executor_state_path = root / "executor-state.json"
            model_response_path = root / "model-choice.jsonl"
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            plan_path.write_text(
                json.dumps(
                    {
                        "schema": "pwn-agent.binary-plan.v2",
                        "schema_version": 2,
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "list-rebuild-targets",
                                "stage": "identify",
                                "phase": "triage",
                                "kind": "list_rebuild_targets",
                                "status": "ready",
                                "priority": 50,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "enumerate bounded targets",
                                "expected_artifacts": [],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            model_response_path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "chosen_action_id": "list-rebuild-targets",
                                "rationale": "Take the only bounded action.",
                                "confidence": 0.91,
                                "summary_update": "Enumerated local rebuild targets.",
                            }
                        ),
                        json.dumps(
                            {
                                "chosen_action_id": "list-rebuild-targets",
                                "rationale": "Would retry if still available.",
                                "confidence": 0.4,
                                "summary_update": "Retrying the same action.",
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            first = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=output_path,
                model_response_path=model_response_path,
                model_response_format="jsonl",
                state_path=state_path,
                executor_state_path=executor_state_path,
                max_steps=1,
                max_failures=1,
                dry_run=False,
                timeout_seconds=30,
            )

            resumed = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=output_path,
                model_response_path=model_response_path,
                model_response_format="jsonl",
                state_path=state_path,
                executor_state_path=executor_state_path,
                max_steps=2,
                max_failures=1,
                dry_run=False,
                timeout_seconds=30,
            )

            self.assertEqual(first["status"], "step-budget-exhausted")
            self.assertEqual(first["step_count"], 1)
            self.assertEqual(first["iterations"][0]["execution_result"]["completed_action_ids"], ["list-rebuild-targets"])
            self.assertEqual(resumed["status"], "no-candidate-actions")
            self.assertEqual(resumed["step_count"], 1)
            self.assertEqual(resumed["failure_count"], 0)
            self.assertEqual(len(resumed["iterations"]), 2)
            persisted_state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted_state["consumed_model_responses"], 1)

    def test_agent_loop_dry_run_does_not_mark_execution_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "binary-plan.json"
            output_path = root / "trajectory.json"
            state_path = root / "loop-state.json"
            executor_state_path = root / "executor-state.json"
            model_response_path = root / "model-choice.json"
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            plan_path.write_text(
                json.dumps(
                    {
                        "schema": "pwn-agent.binary-plan.v2",
                        "schema_version": 2,
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "list-rebuild-targets",
                                "stage": "identify",
                                "phase": "triage",
                                "kind": "list_rebuild_targets",
                                "status": "ready",
                                "priority": 50,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "enumerate bounded targets",
                                "expected_artifacts": [],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            model_response_path.write_text(
                json.dumps(
                    {
                        "chosen_action_id": "list-rebuild-targets",
                        "rationale": "Preview the bounded action.",
                        "confidence": 0.7,
                        "summary_update": "Previewed rebuild target enumeration.",
                    }
                ),
                encoding="utf-8",
            )

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=output_path,
                model_response_path=model_response_path,
                model_response_format="json",
                state_path=state_path,
                executor_state_path=executor_state_path,
                max_steps=1,
                max_failures=1,
                dry_run=True,
            )

            persisted_executor_state = json.loads(executor_state_path.read_text(encoding="utf-8"))
            self.assertEqual(artifact["status"], "step-budget-exhausted")
            self.assertEqual(artifact["iterations"][0]["status"], "dry-run")
            self.assertEqual(artifact["iterations"][0]["execution_result"]["completed_action_ids"], [])
            self.assertEqual(artifact["iterations"][0]["execution_result"]["previewed_action_ids"], ["list-rebuild-targets"])
            self.assertEqual(persisted_executor_state["completed_action_ids"], [])


if __name__ == "__main__":
    unittest.main()
