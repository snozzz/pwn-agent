from __future__ import annotations

import unittest

from src.modes.binary.workflow import ANALYSIS_SCHEMA, PLAN_SCHEMA, build_binary_plan


class BinaryModeTests(unittest.TestCase):
    def test_binary_plan_uses_separate_schema(self) -> None:
        analysis = {
            "schema": ANALYSIS_SCHEMA,
            "schema_version": 1,
            "mode": "binary",
            "root": "/tmp/demo",
            "binary_path": "/tmp/demo/app",
            "binary_fingerprint": {"size_bytes": 12345},
            "inputs": {
                "stdin_sample_path": None,
                "protocol_sample_path": None,
            },
        }

        plan = build_binary_plan(analysis)

        self.assertEqual(plan["schema"], PLAN_SCHEMA)
        self.assertEqual(plan["mode"], "binary")
        self.assertNotIn("scan_summary", plan)
        self.assertEqual(plan["stage_order"], ["identify", "inspect", "triage", "validate", "patch", "revalidate"])
        self.assertTrue(any(action["kind"] == "binary_verify" for action in plan["next_actions"]))


if __name__ == "__main__":
    unittest.main()
