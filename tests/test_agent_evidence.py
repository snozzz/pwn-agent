from __future__ import annotations

import unittest

from src.agent.evidence import (
    EVIDENCE_SCHEMA,
    EvidenceRecord,
    build_evidence_record,
    fingerprint_payload,
    normalize_observation,
)


class EvidenceTests(unittest.TestCase):
    def test_fingerprint_is_order_independent(self) -> None:
        a = {"x": 1, "y": [1, 2], "z": {"a": 1, "b": 2}}
        b = {"z": {"b": 2, "a": 1}, "y": [1, 2], "x": 1}
        self.assertEqual(fingerprint_payload(a), fingerprint_payload(b))

    def test_fingerprint_changes_with_content(self) -> None:
        self.assertNotEqual(fingerprint_payload({"x": 1}), fingerprint_payload({"x": 2}))

    def test_normalize_observation_variants(self) -> None:
        self.assertIn("previewed", normalize_observation(action_id="a", kind="k", status="dry-run", returncode=None, artifact_slot=None, artifact_changed=False))
        self.assertIn("failed", normalize_observation(action_id="a", kind="k", status="failed", returncode=1, artifact_slot=None, artifact_changed=False))
        self.assertIn("refreshed", normalize_observation(action_id="a", kind="k", status="ok", returncode=0, artifact_slot="analysis_json", artifact_changed=True))
        self.assertIn("unchanged", normalize_observation(action_id="a", kind="k", status="ok", returncode=0, artifact_slot="analysis_json", artifact_changed=False))

    def test_build_evidence_record_maps_subcommand_to_slot(self) -> None:
        action = {"id": "collect-binary-evidence", "kind": "binary_scan"}
        record = {
            "action_id": "collect-binary-evidence",
            "status": "ok",
            "returncode": 0,
            "command": ["python3", "-m", "src.main", "binary-scan", "--root", "/ws", "--binary", "/ws/app", "--output", "/ws/a.json"],
        }
        ev = build_evidence_record(
            evidence_id="ev-1",
            iteration=1,
            action=action,
            record=record,
            artifact_payload={"schema": "pwn-agent.binary-analysis.v1", "value": 1},
            previous_fingerprint=None,
        )
        self.assertEqual(ev.artifact_slot, "analysis_json")
        self.assertEqual(ev.status, "ok")
        self.assertIsNotNone(ev.artifact_fingerprint)
        self.assertIn("refreshed", ev.observation)
        self.assertEqual(ev.schema, EVIDENCE_SCHEMA)

    def test_build_evidence_record_detects_unchanged_artifact(self) -> None:
        action = {"id": "collect-binary-evidence", "kind": "binary_scan"}
        payload = {"schema": "pwn-agent.binary-analysis.v1", "value": 1}
        fp = fingerprint_payload(payload)
        record = {
            "action_id": "collect-binary-evidence",
            "status": "ok",
            "returncode": 0,
            "command": ["python3", "-m", "src.main", "binary-scan", "--root", "/ws", "--output", "/ws/a.json"],
        }
        ev = build_evidence_record(
            evidence_id="ev-2",
            iteration=2,
            action=action,
            record=record,
            artifact_payload=payload,
            previous_fingerprint=fp,
        )
        self.assertIn("unchanged", ev.observation)
        self.assertEqual(ev.artifact_fingerprint, fp)

    def test_evidence_record_round_trip(self) -> None:
        ev = EvidenceRecord(
            evidence_id="ev-1",
            iteration=1,
            source="executor",
            action_id="a",
            kind="k",
            command=["python3"],
            returncode=0,
            status="ok",
            observation="done",
        )
        restored = EvidenceRecord.from_dict(ev.to_dict())
        self.assertEqual(restored, ev)

    def test_from_dict_ignores_unknown_keys(self) -> None:
        restored = EvidenceRecord.from_dict(
            {
                "evidence_id": "ev-1",
                "iteration": 1,
                "source": "executor",
                "action_id": "a",
                "kind": "k",
                "command": [],
                "returncode": None,
                "status": "ok",
                "observation": "x",
                "unexpected": "ignored",
            }
        )
        self.assertEqual(restored.evidence_id, "ev-1")


if __name__ == "__main__":
    unittest.main()
