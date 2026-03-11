from __future__ import annotations

import unittest
from types import SimpleNamespace

from src.audit_export import build_audit_summary
from src.trace import AuditTrace, TraceEvent
from src.workflow import WorkflowResult


class AuditExportTests(unittest.TestCase):
    def test_build_audit_summary_includes_staged_history(self) -> None:
        trace = AuditTrace(
            events=[
                TraceEvent(step="project-discovery", status="ok", details={"files": 3}),
                TraceEvent(step="verification-run", status="ok", details={"returncode": 1}),
                TraceEvent(step="hotspot-ranking", status="ok", details={"hotspots": 2}),
            ]
        )
        result = WorkflowResult(
            scan=SimpleNamespace(root="/tmp/demo", findings=[], files_scanned=1),
            command_logs=[],
            report_markdown="",
            trace=trace,
            input_surfaces=[],
            hotspots=[],
            function_hotspots=[],
            function_coverage={},
            compile_db_summary=None,
            verification=None,
            rebuild_verify=None,
        )

        summary = build_audit_summary(result)
        stages = {entry["name"]: entry for entry in summary["staged_history"]["stages"]}

        self.assertEqual(summary["staged_history"]["stage_order"], ["discovery", "execution", "synthesis"])
        self.assertEqual(stages["discovery"]["event_count"], 1)
        self.assertEqual(stages["execution"]["event_count"], 1)
        self.assertEqual(stages["synthesis"]["event_count"], 1)
        self.assertEqual(stages["discovery"]["status_counts"], {"ok": 1})
        self.assertEqual(stages["execution"]["events"][0]["step"], "verification-run")
        self.assertEqual(stages["synthesis"]["events"][0]["step"], "hotspot-ranking")


if __name__ == "__main__":
    unittest.main()
