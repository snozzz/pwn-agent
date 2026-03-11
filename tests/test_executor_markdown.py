from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.executor import execute_plan, render_execution_markdown


class ExecutorMarkdownTests(unittest.TestCase):
    def test_render_execution_markdown_shows_runnable_and_deferred(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "plan.json"
            plan_path.write_text(
                """
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
                      "suggested_cli": ["python3", "-m", "src.main", "rebuild-plan", "--root", "%s"]
                    },
                    {
                      "id": "rebuild-target-1",
                      "kind": "rebuild_target",
                      "phase": "execution",
                      "title": "Rebuild target",
                      "status": "ready",
                      "priority": 90,
                      "suggested_cli": ["python3", "-m", "src.main", "rebuild-plan", "--root", "%s"]
                    }
                  ]
                }
                """ % (str(root), str(root)),
                encoding="utf-8",
            )

            summary = execute_plan(plan_path, max_actions=1, dry_run=True)
            markdown = render_execution_markdown(summary)

            self.assertIn("Runnable actions:", markdown)
            self.assertIn("Deferred actions:", markdown)
            self.assertIn("run-rebuild-verify", markdown)
            self.assertIn("rebuild-target-1", markdown)


if __name__ == "__main__":
    unittest.main()
