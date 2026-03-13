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
            self.assertEqual(summary.completed_action_ids, [])
            self.assertEqual(summary.previewed_action_ids, ["verify-existing-binary"])
            self.assertEqual(summary.runnable_action_ids, ["verify-existing-binary"])
            self.assertEqual(summary.deferred_action_ids, [])
            self.assertEqual(summary.remaining_runnable_action_ids, ["verify-existing-binary"])
            self.assertEqual(summary.next_action_ids, ["verify-existing-binary"])
            self.assertEqual(summary.status_counts["dry-run"], 1)
            self.assertEqual(summary.records[0].status, "dry-run")
            self.assertEqual(summary.records[0].phase, "execution")
            self.assertEqual(summary.action_states["verify-existing-binary"], "previewed")
            self.assertEqual(summary.action_state_counts["previewed"], 1)
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
            self.assertEqual(summary.completed_action_ids, [])
            self.assertEqual(summary.previewed_action_ids, ["rebuild-target-1", "run-rebuild-verify"])
            self.assertEqual(summary.runnable_action_ids, ["run-rebuild-verify", "rebuild-target-1"])
            self.assertEqual(summary.deferred_action_ids, [])
            self.assertEqual(summary.remaining_runnable_action_ids, ["run-rebuild-verify", "rebuild-target-1"])
            self.assertEqual(summary.next_action_ids, ["rebuild-target-1", "run-rebuild-verify"])

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
            self.assertEqual(summary.completed_action_ids, [])
            self.assertEqual(summary.previewed_action_ids, ["rebuild-target-1"])
            self.assertEqual(
                summary.remaining_runnable_action_ids,
                ["run-rebuild-verify", "rebuild-target-1", "verify-existing-binary"],
            )
            self.assertEqual(
                summary.next_action_ids,
                ["rebuild-target-1", "verify-existing-binary", "run-rebuild-verify"],
            )
            self.assertEqual(summary.action_states["rebuild-target-1"], "previewed")
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
            first_state_payload = json.loads(state_path.read_text(encoding="utf-8"))
            resumed = execute_plan(plan_path, max_actions=1, dry_run=False, state_path=state_path)

            self.assertFalse(first.resumed_from_state)
            self.assertTrue(resumed.resumed_from_state)
            self.assertEqual(first.selected_action_ids, ["rebuild-target-1"])
            self.assertEqual(first.completed_action_ids, [])
            self.assertEqual(first.previewed_action_ids, ["rebuild-target-1"])
            self.assertEqual(first_state_payload["completed_action_ids"], [])
            self.assertEqual(resumed.resumed_completed_action_ids, [])
            self.assertEqual(resumed.selected_action_ids, ["rebuild-target-1"])
            self.assertEqual(resumed.completed_action_ids, ["rebuild-target-1"])
            self.assertEqual(resumed.action_states["rebuild-target-1"], "completed")
            self.assertEqual(resumed.action_states["verify-existing-binary"], "deferred")
            state_payload = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state_payload["completed_action_ids"], ["rebuild-target-1"])
            self.assertIn("action_signatures", state_payload)
            self.assertGreaterEqual(len(state_payload["history"]), 5)

    def test_execute_plan_reconciles_regenerated_plan_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            plan_path = root / "plan.json"
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "plan_fingerprint": "plan-v1",
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
                        ],
                    }
                ),
                encoding="utf-8",
            )

            first = execute_plan(plan_path, max_actions=1, dry_run=True, state_path=state_path)
            self.assertEqual(first.completed_action_ids, [])

            plan_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "plan_fingerprint": "plan-v2",
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
                                    "rebuild-target",
                                    "--root",
                                    str(root),
                                    "--index",
                                    "1",
                                    "--output-name",
                                    "planned-sanitized-target",
                                ],
                            },
                            {
                                "id": "trace-hotspot-1",
                                "kind": "trace_input_surface",
                                "phase": "triage",
                                "title": "Trace hotspot",
                                "status": "ready",
                                "priority": 95,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(root),
                                ],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            resumed = execute_plan(plan_path, max_actions=1, dry_run=True, state_path=state_path)

            self.assertTrue(resumed.resumed_from_state)
            self.assertTrue(resumed.plan_changed)
            self.assertEqual(resumed.previous_plan_fingerprint, "plan-v1")
            self.assertEqual(resumed.plan_fingerprint, "plan-v2")
            self.assertEqual(resumed.changed_action_ids, ["rebuild-target-1"])
            self.assertEqual(resumed.new_action_ids, ["trace-hotspot-1"])
            self.assertEqual(resumed.stale_completed_action_ids, [])
            self.assertEqual(resumed.resumed_completed_action_ids, [])
            self.assertEqual(resumed.selected_action_ids, ["rebuild-target-1"])
            self.assertEqual(resumed.action_states["rebuild-target-1"], "previewed")
            self.assertEqual(resumed.action_states["trace-hotspot-1"], "deferred")

    def test_execute_plan_raises_for_missing_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps({"next_actions": []}), encoding="utf-8")

            with self.assertRaises(ExecutorError):
                execute_plan(plan_path, phase="execution", dry_run=True)

    def test_execute_plan_rejects_disallowed_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "bad-subcommand",
                                "kind": "invalid",
                                "phase": "execution",
                                "title": "Bad subcommand",
                                "status": "ready",
                                "priority": 100,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "evil-command",
                                    "--root",
                                    str(root),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ExecutorError):
                execute_plan(plan_path, dry_run=True)

    def test_execute_plan_rejects_malformed_suggested_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "missing-root",
                                "kind": "invalid",
                                "phase": "execution",
                                "title": "Missing root option",
                                "status": "ready",
                                "priority": 100,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ExecutorError):
                execute_plan(plan_path, dry_run=True)

    def test_execute_plan_rejects_action_root_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            other = root / "other"
            other.mkdir()
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "wrong-root",
                                "kind": "invalid",
                                "phase": "execution",
                                "title": "Wrong root in action",
                                "status": "ready",
                                "priority": 100,
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "rebuild-plan",
                                    "--root",
                                    str(other),
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ExecutorError):
                execute_plan(plan_path, dry_run=True)


if __name__ == "__main__":
    unittest.main()
