from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.agent.evaluation import (
    AGENT_EVAL_SCHEMA,
    compare_trajectories,
    evaluate_trajectory,
    render_evaluation_markdown,
)
from src.main import main


def _trajectory() -> dict:
    return {
        "schema": "pwn-agent.agent-loop.v1",
        "status": "no-progress",
        "step_count": 3,
        "failure_count": 1,
        "controller": {"name": "deterministic"},
        "final_summary": {
            "evidence_count": 2,
            "verified_fact_count": 1,
            "open_hypothesis_count": 1,
            "rejected_hypothesis_count": 0,
        },
        "iterations": [
            {
                "iteration": 1,
                "status": "completed",
                "model_choice": {"accepted": True, "normalized": {"chosen_action_id": "a"}},
                "progress": {"progressed": True, "no_progress_count": 0},
            },
            {
                "iteration": 2,
                "status": "failed",
                "model_choice": {"accepted": True, "normalized": {"chosen_action_id": "b"}},
                "progress": {"progressed": False, "no_progress_count": 1},
            },
            {
                "iteration": 3,
                "status": "completed",
                "model_choice": {"accepted": True, "normalized": {"chosen_action_id": "a"}},
                "progress": {"progressed": True, "no_progress_count": 0},
            },
            {
                "iteration": 4,
                "status": "invalid-model-output",
                "model_choice": {"accepted": False, "error": "bad", "raw": {"chosen_action_id": "zz"}},
            },
        ],
    }


class EvaluateTrajectoryTests(unittest.TestCase):
    def test_core_metrics(self) -> None:
        metrics = evaluate_trajectory(_trajectory())
        self.assertEqual(metrics["schema"], AGENT_EVAL_SCHEMA)
        self.assertEqual(metrics["controller"], "deterministic")
        self.assertEqual(metrics["terminal_state"], "no-progress")
        self.assertTrue(metrics["guard_termination"])
        self.assertFalse(metrics["clean_termination"])
        self.assertEqual(metrics["successful_actions"], 2)
        self.assertEqual(metrics["failed_actions"], 1)
        self.assertEqual(metrics["rejected_decisions"], 1)
        self.assertEqual(metrics["repeated_actions"], 1)  # "a" chosen twice
        self.assertEqual(metrics["no_progress_iterations"], 1)
        self.assertEqual(metrics["recovered_failures"], 1)  # failure at iter2 recovered at iter3
        self.assertEqual(metrics["distinct_actions"], ["a", "b"])
        self.assertEqual(metrics["executed_action_sequence"], ["a", "b", "a"])
        self.assertEqual(metrics["evidence_count"], 2)

    def test_unrecorded_fields_are_none(self) -> None:
        metrics = evaluate_trajectory(_trajectory())
        self.assertIsNone(metrics["wall_time_seconds"])
        self.assertIsNone(metrics["token_usage_total"])

    def test_token_usage_aggregated_when_present(self) -> None:
        traj = _trajectory()
        traj["iterations"][0]["model_choice"]["usage"] = {"total_tokens": 100}
        traj["iterations"][2]["model_choice"]["usage"] = {"total_tokens": 50}
        metrics = evaluate_trajectory(traj)
        self.assertEqual(metrics["token_usage_total"], 150)

    def test_clean_termination_flag(self) -> None:
        traj = _trajectory()
        traj["status"] = "no-candidate-actions"
        self.assertTrue(evaluate_trajectory(traj)["clean_termination"])


class CompareTrajectoriesTests(unittest.TestCase):
    def test_comparison_shape(self) -> None:
        a = _trajectory()
        b = _trajectory()
        b["controller"] = {"name": "scripted"}
        b["status"] = "completed"
        result = compare_trajectories([("det", a), ("scr", b)])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["comparison"]["labels"], ["det", "scr"])
        self.assertEqual(result["comparison"]["clean_termination"], {"det": False, "scr": True})
        self.assertEqual(result["trajectories"][0]["label"], "det")

    def test_markdown_renders_single_and_multi(self) -> None:
        single = render_evaluation_markdown(evaluate_trajectory(_trajectory()))
        self.assertIn("Agent Loop Evaluation", single)
        multi = render_evaluation_markdown(compare_trajectories([("x", _trajectory())]))
        self.assertIn("Trajectories evaluated: 1", multi)


class AgentEvalCliTests(unittest.TestCase):
    def test_cli_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            traj_path = root / "traj.json"
            traj_path.write_text(json.dumps(_trajectory()), encoding="utf-8")
            metrics_path = root / "metrics.json"
            report_path = root / "metrics.md"

            code = main(
                [
                    "agent-eval",
                    "--trajectory",
                    str(traj_path),
                    "--output",
                    str(metrics_path),
                    "--report",
                    str(report_path),
                ]
            )
            self.assertEqual(code, 0)
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            self.assertEqual(metrics["terminal_state"], "no-progress")
            self.assertEqual(metrics["successful_actions"], 2)
            self.assertTrue(report_path.exists())

    def test_cli_comparison_of_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "a.json"
            b = root / "b.json"
            a.write_text(json.dumps(_trajectory()), encoding="utf-8")
            tb = _trajectory()
            tb["status"] = "completed"
            b.write_text(json.dumps(tb), encoding="utf-8")
            out = root / "cmp.json"
            code = main(
                [
                    "agent-eval",
                    "--trajectory",
                    str(a),
                    "--trajectory",
                    str(b),
                    "--label",
                    "det",
                    "--label",
                    "scr",
                    "--output",
                    str(out),
                ]
            )
            self.assertEqual(code, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["count"], 2)
            self.assertEqual(payload["comparison"]["labels"], ["det", "scr"])


if __name__ == "__main__":
    unittest.main()
