from __future__ import annotations

import unittest

from src.orchestrator import build_plan, render_plan_markdown


class OrchestratorTests(unittest.TestCase):
    def test_build_plan_retains_runnable_execution_actions_after_verified_signal(self) -> None:
        summary = {
            "root": "/tmp/demo",
            "scan_summary": {
                "findings": 2,
                "verified_signal": True,
            },
            "classified_findings": [
                {
                    "category": "unsafe_copy",
                    "file_path": "demo.c",
                    "line_number": 7,
                    "function_name": "greet",
                }
            ],
            "file_hotspots": [{"file_path": "demo.c", "score": 9.0, "findings": 1, "surfaces": 1, "verified": True}],
            "function_hotspots": [
                {"file_path": "demo.c", "function_name": "greet", "score": 9.0, "findings": 1, "surfaces": 1, "verified": True}
            ],
            "input_surfaces": [
                {"category": "argv", "file_path": "demo.c", "line_number": 11, "function_name": "main"}
            ],
            "verification": {"returncode": -6},
            "rebuild_verify": {
                "rebuild": {"returncode": 0},
                "verification": {"returncode": 1},
            },
            "execution_readiness": {
                "verification_state": "signal-detected",
                "rebuild_state": "signal-detected",
                "has_compile_database": True,
                "rebuild_targets": 1,
                "has_verification_plan": True,
                "verification_binary": "demo",
                "verification_binary_present": True,
                "ready_actions": [
                    {
                        "kind": "verify-run",
                        "cli": ["python3", "-m", "src.main", "verify-run", "--root", "/tmp/demo", "--binary", "/tmp/demo/demo"],
                        "detail": "verification binary ready",
                    },
                    {
                        "kind": "rebuild-plan",
                        "cli": ["python3", "-m", "src.main", "rebuild-plan", "--root", "/tmp/demo"],
                        "detail": "compile database ready",
                    },
                    {
                        "kind": "rebuild-target",
                        "cli": ["python3", "-m", "src.main", "rebuild-target", "--root", "/tmp/demo", "--index", "1", "--output-name", "planned-sanitized-target"],
                        "detail": "compile database ready",
                    },
                    {
                        "kind": "rebuild-verify",
                        "cli": ["python3", "-m", "src.main", "rebuild-verify", "--root", "/tmp/demo", "--index", "1", "--output-name", "planned-sanitized-target"],
                        "detail": "compile database and verification plan are both present",
                    },
                ],
                "blocked_actions": [],
                "missing_prerequisites": [],
            },
        }

        plan = build_plan(summary)
        runnable = [action for action in plan.next_actions if action.status == "ready" and action.suggested_cli]
        ids = [action.id for action in runnable]

        self.assertIn("verify-existing-binary", ids)
        self.assertIn("list-rebuild-targets", ids)
        self.assertIn("rebuild-target-1", ids)
        self.assertIn("run-rebuild-verify", ids)
        self.assertEqual(plan.readiness["runnable_actions"], 4)
        self.assertEqual(plan.readiness["phase_counts"]["execution"], 4)

    def test_render_plan_markdown_includes_phase_and_runnable_counts(self) -> None:
        summary = {
            "root": "/tmp/demo",
            "scan_summary": {"findings": 0, "verified_signal": False},
            "classified_findings": [],
            "file_hotspots": [],
            "function_hotspots": [],
            "input_surfaces": [],
            "execution_readiness": {
                "verification_state": "not-configured",
                "rebuild_state": "not-configured",
                "ready_actions": [],
                "blocked_actions": [],
                "missing_prerequisites": [],
            },
        }

        plan = build_plan(summary)
        rendered = render_plan_markdown(plan)

        self.assertIn("Runnable actions: 0", rendered)
        self.assertIn("Phase counts:", rendered)


if __name__ == "__main__":
    unittest.main()
