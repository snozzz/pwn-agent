from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.executor import ExecutorError, execute_plan


class ExecutorTests(unittest.TestCase):
    def test_execute_plan_dry_run_selects_ready_internal_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "next_actions": [
                            {
                                "id": "verify-existing-binary",
                                "kind": "verify_binary",
                                "phase": "execution",
                                "title": "Run verification",
                                "status": "ready",
                                "priority": 75,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            summary = execute_plan(plan_path, dry_run=True)

            self.assertEqual(summary.executed, 0)
            self.assertEqual(summary.stopped_reason, "dry-run")
            self.assertEqual(summary.selected_action_ids, ["verify-existing-binary"])
            self.assertEqual(summary.completed_action_ids, ["verify-existing-binary"])
            self.assertEqual(summary.runnable_action_ids, ["verify-existing-binary"])
            self.assertEqual(summary.deferred_action_ids, [])
            self.assertEqual(summary.remaining_runnable_action_ids, [])
            self.assertEqual(summary.next_action_ids, [])
            self.assertEqual(summary.status_counts["dry-run"], 1)
            self.assertEqual(summary.records[0].status, "dry-run")
            self.assertEqual(summary.records[0].phase, "execution")
            self.assertEqual(summary.action_states["verify-existing-binary"], "dry-run")
            self.assertEqual(summary.transition_count, 2)

    def test_execute_plan_runs_allowlisted_internal_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "file": "demo.c",
                            "command": "gcc -Wall demo.c -o demo",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (root / "demo.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "next_actions": [
                            {
                                "id": "run-rebuild-plan",
                                "kind": "list_rebuild_targets",
                                "phase": "execution",
                                "title": "Inspect rebuild options",
                                "status": "ready",
                                "priority": 65,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            summary = execute_plan(plan_path, timeout_seconds=30)

            self.assertEqual(summary.executed, 1)
            self.assertEqual(summary.stopped_reason, "completed")
            self.assertEqual(summary.status_counts["ok"], 1)
            self.assertEqual(summary.records[0].status, "ok")
            self.assertEqual(summary.records[0].returncode, 0)
            self.assertEqual(summary.completed_action_ids, ["run-rebuild-plan"])
            self.assertEqual(summary.remaining_runnable_action_ids, [])
            self.assertEqual(summary.next_action_ids, [])
            self.assertEqual(summary.action_states["run-rebuild-plan"], "completed")
            self.assertEqual(summary.transition_count, 3)
            self.assertIn("targets=1", summary.records[0].stdout)

    def test_execute_plan_respects_phase_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "next_actions": [
                            {
                                "id": "triage-only",
                                "kind": "inspect_file",
                                "phase": "triage",
                                "title": "Inspect a file",
                                "status": "ready",
                                "priority": 100,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                            {
                                "id": "exec-only",
                                "kind": "list_rebuild_targets",
                                "phase": "execution",
                                "title": "List targets",
                                "status": "ready",
                                "priority": 50,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            summary = execute_plan(plan_path, phase="execution", dry_run=True)

            self.assertEqual(summary.selected_action_ids, ["exec-only"])

    def test_execute_plan_skips_dependency_until_prerequisite_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "next_actions": [
                            {
                                "id": "run-rebuild-verify",
                                "kind": "run_rebuild_verify",
                                "phase": "execution",
                                "title": "Run rebuild+verify",
                                "status": "ready",
                                "priority": 100,
                                "depends_on": ["rebuild-target-1"],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                            {
                                "id": "rebuild-target-1",
                                "kind": "rebuild_target",
                                "phase": "execution",
                                "title": "Rebuild target",
                                "status": "ready",
                                "priority": 90,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            summary = execute_plan(plan_path, max_actions=2, dry_run=True)

            self.assertEqual(summary.selected_action_ids, ["rebuild-target-1", "run-rebuild-verify"])
            self.assertEqual(summary.completed_action_ids, ["rebuild-target-1", "run-rebuild-verify"])
            self.assertEqual(summary.runnable_action_ids, ["run-rebuild-verify", "rebuild-target-1"])
            self.assertEqual(summary.deferred_action_ids, [])
            self.assertEqual(summary.remaining_runnable_action_ids, [])
            self.assertEqual(summary.next_action_ids, [])

    def test_execute_plan_reports_followup_actions_after_partial_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "next_actions": [
                            {
                                "id": "run-rebuild-verify",
                                "kind": "run_rebuild_verify",
                                "phase": "execution",
                                "title": "Run rebuild+verify",
                                "status": "ready",
                                "priority": 100,
                                "depends_on": ["rebuild-target-1"],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                            {
                                "id": "rebuild-target-1",
                                "kind": "rebuild_target",
                                "phase": "execution",
                                "title": "Rebuild target",
                                "status": "ready",
                                "priority": 90,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                            {
                                "id": "verify-existing-binary",
                                "kind": "verify_binary",
                                "phase": "execution",
                                "title": "Verify current binary",
                                "status": "ready",
                                "priority": 80,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            summary = execute_plan(plan_path, max_actions=1, dry_run=True)

            self.assertEqual(summary.selected_action_ids, ["rebuild-target-1"])
            self.assertEqual(summary.completed_action_ids, ["rebuild-target-1"])
            self.assertEqual(
                summary.remaining_runnable_action_ids,
                ["run-rebuild-verify", "verify-existing-binary"],
            )
            self.assertEqual(
                summary.next_action_ids,
                ["run-rebuild-verify", "verify-existing-binary"],
            )
            self.assertEqual(summary.action_states["run-rebuild-verify"], "deferred")
            self.assertEqual(summary.action_states["verify-existing-binary"], "deferred")

    def test_execute_plan_can_resume_from_state_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "next_actions": [
                            {
                                "id": "rebuild-target-1",
                                "kind": "rebuild_target",
                                "phase": "execution",
                                "title": "Rebuild target",
                                "status": "ready",
                                "priority": 100,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                            {
                                "id": "verify-existing-binary",
                                "kind": "verify_binary",
                                "phase": "execution",
                                "title": "Verify current binary",
                                "status": "ready",
                                "priority": 90,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            first = execute_plan(plan_path, max_actions=1, dry_run=True, state_path=state_path)
            resumed = execute_plan(plan_path, max_actions=1, dry_run=True, state_path=state_path)

            self.assertFalse(first.resumed_from_state)
            self.assertTrue(resumed.resumed_from_state)
            self.assertEqual(first.selected_action_ids, ["rebuild-target-1"])
            self.assertEqual(resumed.resumed_completed_action_ids, ["rebuild-target-1"])
            self.assertEqual(resumed.selected_action_ids, ["verify-existing-binary"])
            self.assertEqual(resumed.action_states["rebuild-target-1"], "dry-run")
            self.assertEqual(resumed.action_states["verify-existing-binary"], "dry-run")
            state_payload = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state_payload["completed_action_ids"], ["rebuild-target-1", "verify-existing-binary"])
            self.assertGreaterEqual(len(state_payload["history"]), 4)

    def test_execute_plan_raises_for_missing_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps({"next_actions": []}), encoding="utf-8")

            with self.assertRaises(ExecutorError):
                execute_plan(plan_path, phase="execution", dry_run=True)


if __name__ == "__main__":
    unittest.main()
