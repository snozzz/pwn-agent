from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.agent.controller import AgentContext, AgentModel, ControllerError
from src.modes.binary.loop import run_agent_loop


def _write_single_action_plan(plan_path: Path, root: Path) -> None:
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
                        "suggested_cli": ["python3", "-m", "src.main", "rebuild-plan", "--root", str(root)],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


class _FlakyController(AgentModel):
    """Raises ControllerError on the first N calls, then decides deterministically."""

    name = "flaky"

    def __init__(self, fail_times: int) -> None:
        self._remaining_failures = fail_times

    def decide(self, context: AgentContext):  # type: ignore[override]
        if self._remaining_failures > 0:
            self._remaining_failures -= 1
            raise ControllerError("simulated backend failure")
        action_id = context.candidate_ids[0]
        return {
            "chosen_action_id": action_id,
            "rationale": "recovered and chose a bounded action",
            "confidence": 0.8,
            "summary_update": "recovered",
        }


class DeterministicControllerLoopTests(unittest.TestCase):
    def test_runs_without_pregenerated_file_and_completes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            _write_single_action_plan(plan_path, root)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=root / "traj.json",
                controller="deterministic",
                state_path=root / "loop-state.json",
                executor_state_path=root / "exec-state.json",
                max_steps=3,
                max_failures=2,
            )

            # The single action completes on iteration 1; iteration 2 has no candidates.
            self.assertEqual(artifact["status"], "no-candidate-actions")
            self.assertEqual(artifact["step_count"], 1)
            self.assertEqual(artifact["controller"]["name"], "deterministic")
            self.assertGreaterEqual(artifact["final_summary"]["evidence_count"], 1)
            self.assertEqual(
                artifact["iterations"][0]["model_choice"]["normalized"]["chosen_action_id"],
                "list-rebuild-targets",
            )

    def test_no_progress_termination_under_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            _write_single_action_plan(plan_path, root)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=root / "traj.json",
                controller="deterministic",
                state_path=root / "loop-state.json",
                executor_state_path=root / "exec-state.json",
                max_steps=10,
                max_failures=5,
                max_no_progress=2,
                max_repeats=99,
                dry_run=True,
            )

            self.assertEqual(artifact["status"], "no-progress")
            # iter1 progressed, iter2 stall=1, iter3 stall=2 -> stop
            self.assertEqual(artifact["step_count"], 3)
            self.assertEqual(artifact["iterations"][-1]["progress"]["no_progress_count"], 2)

    def test_repeated_action_termination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            _write_single_action_plan(plan_path, root)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=root / "traj.json",
                controller="deterministic",
                state_path=root / "loop-state.json",
                executor_state_path=root / "exec-state.json",
                max_steps=10,
                max_failures=5,
                max_no_progress=99,
                max_repeats=2,
                dry_run=True,
            )

            self.assertEqual(artifact["status"], "repeated-action")
            self.assertEqual(artifact["step_count"], 2)


class ControllerErrorRecoveryTests(unittest.TestCase):
    def test_single_controller_error_terminates_when_budget_is_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            _write_single_action_plan(plan_path, root)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=root / "traj.json",
                controller=_FlakyController(fail_times=1),
                state_path=root / "loop-state.json",
                executor_state_path=root / "exec-state.json",
                max_steps=3,
                max_failures=1,
            )
            self.assertEqual(artifact["status"], "controller-error")
            self.assertEqual(artifact["failure_count"], 1)
            self.assertFalse(artifact["iterations"][0]["model_choice"]["accepted"])

    def test_controller_error_then_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            _write_single_action_plan(plan_path, root)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            artifact = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=root / "traj.json",
                controller=_FlakyController(fail_times=1),
                state_path=root / "loop-state.json",
                executor_state_path=root / "exec-state.json",
                max_steps=3,
                max_failures=2,
            )
            # iteration 1 errored and was counted; iteration 2 recovered and executed.
            self.assertEqual(artifact["failure_count"], 1)
            self.assertFalse(artifact["iterations"][0]["model_choice"]["accepted"])
            self.assertTrue(artifact["iterations"][1]["model_choice"]["accepted"])
            self.assertGreaterEqual(artifact["final_summary"]["evidence_count"], 1)


class AgentStateResumeTests(unittest.TestCase):
    def test_agent_state_round_trips_across_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            _write_single_action_plan(plan_path, root)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")

            first = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=root / "traj.json",
                controller="deterministic",
                state_path=root / "loop-state.json",
                executor_state_path=root / "exec-state.json",
                max_steps=1,
                max_failures=1,
            )
            first_evidence = len(first["agent_state"]["evidence"])
            self.assertGreaterEqual(first_evidence, 1)

            resumed = run_agent_loop(
                root=root,
                plan_path=plan_path,
                trajectory_path=root / "traj.json",
                controller="deterministic",
                state_path=root / "loop-state.json",
                executor_state_path=root / "exec-state.json",
                max_steps=2,
                max_failures=1,
            )
            # Resumed episode starts from the persisted belief state (no evidence lost).
            self.assertEqual(resumed["status"], "no-candidate-actions")
            self.assertGreaterEqual(len(resumed["agent_state"]["evidence"]), first_evidence)
            persisted = json.loads((root / "loop-state.json").read_text(encoding="utf-8"))
            self.assertIn("agent_state", persisted)
            self.assertEqual(persisted["agent_state"]["schema"], "pwn-agent.agent-state.v1")


if __name__ == "__main__":
    unittest.main()
