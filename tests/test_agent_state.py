from __future__ import annotations

import unittest

from src.agent.evidence import EvidenceRecord
from src.agent.state import AGENT_STATE_SCHEMA, AgentState


def _evidence(evidence_id: str = "ev-1", observation: str = "did a thing") -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        iteration=1,
        source="executor",
        action_id="a",
        kind="k",
        command=["python3"],
        returncode=0,
        status="ok",
        observation=observation,
    )


class AgentStateTests(unittest.TestCase):
    def test_defaults_and_schema(self) -> None:
        state = AgentState()
        self.assertEqual(state.schema, AGENT_STATE_SCHEMA)
        self.assertEqual(state.evidence, [])
        self.assertEqual(state.no_progress_count, 0)

    def test_record_evidence_also_records_observation(self) -> None:
        state = AgentState()
        eid = state.record_evidence(_evidence(observation="collected evidence"))
        self.assertEqual(eid, "ev-1")
        self.assertEqual(len(state.evidence), 1)
        self.assertIn("collected evidence", state.observations)

    def test_next_evidence_id_increments(self) -> None:
        state = AgentState()
        self.assertEqual(state.next_evidence_id(), "ev-1")
        state.record_evidence(_evidence("ev-1"))
        self.assertEqual(state.next_evidence_id(), "ev-2")

    def test_verified_fact_links_evidence(self) -> None:
        state = AgentState()
        state.record_evidence(_evidence("ev-1"))
        fid = state.add_verified_fact("binary has no stack canary", evidence_ids=["ev-1"])
        self.assertEqual(fid, "fact-1")
        self.assertEqual(state.verified_facts[0]["evidence_ids"], ["ev-1"])

    def test_hypothesis_lifecycle(self) -> None:
        state = AgentState()
        hid = state.add_hypothesis("overflow in parse()", confidence=0.4)
        self.assertEqual(len(state.open_hypotheses), 1)
        self.assertTrue(state.update_hypothesis(hid, status="rejected", confidence=0.1))
        self.assertEqual(len(state.open_hypotheses), 0)
        self.assertEqual(len(state.rejected_hypotheses), 1)

    def test_update_unknown_hypothesis_returns_false(self) -> None:
        state = AgentState()
        self.assertFalse(state.update_hypothesis("nope", status="supported"))

    def test_invalid_hypothesis_status_rejected(self) -> None:
        state = AgentState()
        hid = state.add_hypothesis("x")
        with self.assertRaises(ValueError):
            state.update_hypothesis(hid, status="maybe")

    def test_prose_is_separate_from_verified_facts(self) -> None:
        state = AgentState()
        state.add_summary_update("I think this is exploitable")
        self.assertEqual(state.verified_facts, [])
        self.assertEqual(state.summary_updates, ["I think this is exploitable"])

    def test_open_questions_dedupe(self) -> None:
        state = AgentState()
        state.add_open_question("is parse() reachable?")
        state.add_open_question("is parse() reachable?")
        self.assertEqual(len(state.open_questions), 1)

    def test_round_trip_preserves_everything(self) -> None:
        state = AgentState(objective="o", max_steps=5, max_failures=3, max_no_progress=4)
        state.record_evidence(_evidence("ev-1"))
        state.add_verified_fact("f", evidence_ids=["ev-1"])
        hid = state.add_hypothesis("h", confidence=0.5)
        state.update_hypothesis(hid, status="supported", confidence=0.8)
        state.add_summary_update("prose")
        state.add_open_question("q")
        state.record_action(iteration=1, action_id="a", accepted=True, status="ok")
        state.record_failure(iteration=1, reason="boom")
        state.no_progress_count = 2
        state.last_progress_signature = "sig"
        state.step_count = 1
        state.failure_count = 1

        restored = AgentState.from_dict(state.to_dict())
        self.assertEqual(restored.objective, "o")
        self.assertEqual(restored.max_steps, 5)
        self.assertEqual(restored.max_failures, 3)
        self.assertEqual(restored.max_no_progress, 4)
        self.assertEqual(len(restored.evidence), 1)
        self.assertEqual(len(restored.verified_facts), 1)
        self.assertEqual(restored.hypotheses[0]["status"], "supported")
        self.assertEqual(restored.summary_updates, ["prose"])
        self.assertEqual(restored.open_questions, ["q"])
        self.assertEqual(restored.action_history[0]["action_id"], "a")
        self.assertEqual(restored.failure_history[0]["reason"], "boom")
        self.assertEqual(restored.no_progress_count, 2)
        self.assertEqual(restored.last_progress_signature, "sig")

    def test_from_dict_tolerates_minimal_payload(self) -> None:
        restored = AgentState.from_dict({})
        self.assertEqual(restored.step_count, 0)
        self.assertEqual(restored.max_no_progress, 2)


if __name__ == "__main__":
    unittest.main()
