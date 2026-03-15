from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.modes.binary.loop import run_agent_loop


class AgentLoopTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
