from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.executor import execute_plan
from src.modes.binary.workflow import ANALYSIS_SCHEMA, PLAN_SCHEMA, TRIAGE_SCHEMA, build_binary_plan


class BinaryModeTests(unittest.TestCase):
    def test_binary_plan_uses_binary_specific_stage_schema(self) -> None:
        analysis = {
            "schema": ANALYSIS_SCHEMA,
            "schema_version": 1,
            "mode": "binary",
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "binary_fingerprint": {"size_bytes": 12345},
            "mitigations": {
                "available": True,
                "nx": "enabled",
            },
            "runtime_hints": {
                "args": ["seed"],
                "stdin_file_path": None,
            },
        }

        plan = build_binary_plan(analysis)

        self.assertEqual(plan["schema"], PLAN_SCHEMA)
        self.assertEqual(plan["schema_version"], 2)
        self.assertEqual(plan["mode"], "binary")
        self.assertEqual(
            plan["stage_order"],
            ["identify", "inspect", "reproduce", "triage", "patch", "validate", "summarize"],
        )
        self.assertTrue(plan["plan_fingerprint"])
        self.assertEqual(plan["source_artifacts"]["analysis_schema"], ANALYSIS_SCHEMA)
        self.assertIsNone(plan["source_artifacts"]["crash_schema"])
        self.assertTrue(all("stage" in action for action in plan["next_actions"]))
        self.assertTrue(all("expected_artifacts" in action for action in plan["next_actions"]))

    def test_binary_plan_prefers_binary_scan_when_mitigations_missing(self) -> None:
        analysis = {
            "schema": ANALYSIS_SCHEMA,
            "schema_version": 1,
            "mode": "binary",
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "mitigations": {
                "available": False,
                "nx": "unknown",
            },
            "runtime_hints": {
                "args": [],
                "stdin_file_path": None,
            },
        }

        plan = build_binary_plan(analysis)
        first_ready = next(action for action in plan["next_actions"] if action["status"] == "ready")

        self.assertEqual(first_ready["id"], "collect-binary-evidence")
        self.assertEqual(first_ready["stage"], "identify")
        self.assertEqual(first_ready["kind"], "binary_scan")
        self.assertEqual(first_ready["suggested_cli"][3], "binary-scan")

    def test_binary_plan_orders_actions_by_stage_before_summary(self) -> None:
        analysis = {
            "schema": ANALYSIS_SCHEMA,
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "mitigations": {
                "available": False,
                "nx": "unknown",
            },
            "runtime_hints": {
                "args": ["seed"],
                "stdin_file_path": "/tmp/demo/stdin.txt",
            },
        }

        plan = build_binary_plan(analysis)
        ordered_ids = [action["id"] for action in plan["next_actions"]]

        self.assertEqual(
            ordered_ids,
            [
                "collect-binary-evidence",
                "reproduce-target-behavior",
                "summarize-local-findings",
            ],
        )
        self.assertEqual(plan["readiness"]["runnable_actions"], 2)
        self.assertEqual(plan["next_actions"][-1]["stage"], "summarize")
        self.assertEqual(plan["next_actions"][-1]["status"], "blocked")

    def test_binary_plan_suggests_gdb_triage_after_suspicious_crash_without_debugger(self) -> None:
        analysis = {
            "schema": ANALYSIS_SCHEMA,
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "mitigations": {"available": True, "nx": "enabled"},
        }
        crash = {
            "schema": TRIAGE_SCHEMA,
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "crash_summary": {
                "suspicious": True,
            },
            "debugger_summary": {
                "attempted": False,
                "collected": False,
            },
            "runtime_hints": {
                "args": ["seed"],
                "stdin_file_path": None,
            },
        }

        plan = build_binary_plan(analysis, crash=crash)
        triage_action = next(action for action in plan["next_actions"] if action["id"] == "collect-debugger-context")

        self.assertEqual(triage_action["stage"], "triage")
        self.assertEqual(triage_action["suggested_cli"][3], "crash-triage")
        self.assertIn("--gdb-batch", triage_action["suggested_cli"])

    def test_binary_plan_adds_validation_dependency_after_patch_hypothesis(self) -> None:
        analysis = {
            "schema": ANALYSIS_SCHEMA,
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "mitigations": {"available": True, "nx": "enabled"},
            "patch_candidate": {
                "summary": "bounds check candidate",
            },
            "runtime_hints": {
                "args": ["seed"],
                "stdin_file_path": None,
            },
        }
        crash = {
            "schema": TRIAGE_SCHEMA,
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "crash_summary": {
                "suspicious": True,
            },
            "debugger_summary": {
                "attempted": True,
                "collected": True,
            },
        }

        plan = build_binary_plan(analysis, crash=crash)
        ordered_ids = [action["id"] for action in plan["next_actions"]]
        patch_index = ordered_ids.index("draft-patch-hypothesis")
        validate_action = next(action for action in plan["next_actions"] if action["id"] == "validate-candidate-patch")
        validate_index = ordered_ids.index("validate-candidate-patch")

        self.assertEqual(validate_action["stage"], "validate")
        self.assertEqual(validate_action["kind"], "binary_verify")
        self.assertEqual(validate_action["depends_on"], ["draft-patch-hypothesis"])
        self.assertEqual(validate_action["blocked_by"], ["draft-patch-hypothesis"])
        self.assertEqual(validate_action["suggested_cli"][3], "binary-verify")
        self.assertLess(patch_index, validate_index)

    def test_executor_favors_earlier_binary_stages_before_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "binary-plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "schema": PLAN_SCHEMA,
                        "schema_version": 2,
                        "root": str(root),
                        "next_actions": [
                            {
                                "id": "summarize-local-findings",
                                "stage": "summarize",
                                "phase": "synthesis",
                                "kind": "summarize_binary_findings",
                                "status": "ready",
                                "priority": 999,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "late summary",
                                "expected_artifacts": ["binary-summary.md"],
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
                                "id": "reproduce-target-behavior",
                                "stage": "reproduce",
                                "phase": "triage",
                                "kind": "crash_triage",
                                "status": "ready",
                                "priority": 10,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "earlier investigation",
                                "expected_artifacts": ["binary-crash-triage.json"],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "crash-triage",
                                    "--root",
                                    str(root),
                                    "--binary",
                                    str(binary),
                                    "--output",
                                    str(root / ".pwn-agent" / "binary-crash-triage.json"),
                                ],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            summary = execute_plan(plan_path, max_actions=1, dry_run=True)

        self.assertEqual(summary.selected_action_ids, ["reproduce-target-behavior"])

    def test_executor_respects_dependency_order_with_binary_stages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)
            (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            plan_path = root / "binary-plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "schema": PLAN_SCHEMA,
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
                                "depends_on": ["draft-patch-hypothesis"],
                                "blocked_by": ["draft-patch-hypothesis"],
                                "rationale": "validate after patch",
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
                                    str(root / ".pwn-agent" / "binary-verify.json"),
                                ],
                            },
                            {
                                "id": "collect-debugger-context",
                                "stage": "triage",
                                "phase": "triage",
                                "kind": "crash_triage_gdb",
                                "status": "ready",
                                "priority": 70,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "collect debugger context",
                                "expected_artifacts": ["binary-crash-triage-gdb.json"],
                                "suggested_cli": [
                                    "python3",
                                    "-m",
                                    "src.main",
                                    "crash-triage",
                                    "--root",
                                    str(root),
                                    "--binary",
                                    str(binary),
                                    "--output",
                                    str(root / ".pwn-agent" / "binary-crash-triage-gdb.json"),
                                    "--gdb-batch",
                                ],
                            },
                            {
                                "id": "draft-patch-hypothesis",
                                "stage": "patch",
                                "phase": "execution",
                                "kind": "patch_hypothesis_capture",
                                "status": "ready",
                                "priority": 60,
                                "depends_on": [],
                                "blocked_by": [],
                                "rationale": "human patch hypothesis",
                                "expected_artifacts": ["patch-notes.md"],
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

            summary = execute_plan(plan_path, max_actions=2, dry_run=True)

        self.assertEqual(summary.selected_action_ids, ["collect-debugger-context", "draft-patch-hypothesis"])
        self.assertEqual(
            summary.next_action_ids,
            ["collect-debugger-context", "draft-patch-hypothesis", "validate-candidate-patch"],
        )


if __name__ == "__main__":
    unittest.main()
