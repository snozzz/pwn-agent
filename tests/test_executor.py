from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.executor import execute_plan


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
            self.assertEqual(summary.records[0].status, "dry-run")

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
                                "kind": "inspect_rebuild_failure",
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
            self.assertEqual(summary.records[0].status, "ok")
            self.assertEqual(summary.records[0].returncode, 0)
            self.assertIn("targets=1", summary.records[0].stdout)


if __name__ == "__main__":
    unittest.main()
