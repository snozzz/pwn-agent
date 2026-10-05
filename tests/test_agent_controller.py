from __future__ import annotations

import unittest

from src.agent.controller import (
    AgentContext,
    ControllerError,
    ControllerExhausted,
    DeterministicController,
    ModelDecision,
    ScriptedController,
    build_controller,
    normalize_decision,
    validate_decision,
)

CANDIDATES = [
    {"id": "collect-binary-evidence", "stage": "identify", "kind": "binary_scan", "priority": 100},
    {"id": "reproduce-target-behavior", "stage": "reproduce", "kind": "crash_triage", "priority": 90},
]


def _context(iteration: int = 1, action_history=None) -> AgentContext:
    return AgentContext(
        objective="analyze",
        stage="identify",
        iteration=iteration,
        candidate_actions=list(CANDIDATES),
        action_history=list(action_history or []),
    )


class ValidateDecisionTests(unittest.TestCase):
    def _valid(self):
        return {
            "chosen_action_id": "collect-binary-evidence",
            "rationale": "take the first action",
            "confidence": 0.8,
            "summary_update": "collected evidence",
        }

    def test_valid_v1(self) -> None:
        self.assertIsNone(validate_decision(self._valid(), CANDIDATES))

    def test_not_a_dict(self) -> None:
        self.assertEqual(validate_decision([], CANDIDATES), "model choice must be a JSON object")

    def test_action_not_in_candidates_preserves_legacy_message(self) -> None:
        bad = self._valid()
        bad["chosen_action_id"] = "nope"
        self.assertIn("not present in bounded plan candidates", validate_decision(bad, CANDIDATES))

    def test_empty_rationale(self) -> None:
        bad = self._valid()
        bad["rationale"] = "   "
        self.assertEqual(validate_decision(bad, CANDIDATES), "rationale must be a non-empty string")

    def test_confidence_bool_rejected(self) -> None:
        bad = self._valid()
        bad["confidence"] = True
        self.assertEqual(validate_decision(bad, CANDIDATES), "confidence must be numeric")

    def test_confidence_out_of_range(self) -> None:
        bad = self._valid()
        bad["confidence"] = 1.5
        self.assertEqual(validate_decision(bad, CANDIDATES), "confidence must be between 0.0 and 1.0")

    def test_v2_optional_fields_type_checked(self) -> None:
        bad = self._valid()
        bad["hypothesis"] = 123
        self.assertIn("hypothesis must be a string", validate_decision(bad, CANDIDATES))
        bad = self._valid()
        bad["state_update"] = "oops"
        self.assertIn("state_update must be an object", validate_decision(bad, CANDIDATES))

    def test_v2_optional_fields_valid_when_present(self) -> None:
        good = self._valid()
        good["hypothesis"] = "overflow"
        good["expected_information_gain"] = "mitigations"
        good["state_update"] = {"open_questions": ["is it reachable?"]}
        self.assertIsNone(validate_decision(good, CANDIDATES))

    def test_normalize_keeps_v2_fields(self) -> None:
        raw = self._valid()
        raw["hypothesis"] = "  overflow  "
        raw["state_update"] = {"k": "v"}
        norm = normalize_decision(raw)
        self.assertEqual(norm["hypothesis"], "overflow")
        self.assertEqual(norm["state_update"], {"k": "v"})
        self.assertEqual(norm["confidence"], 0.8)


class ModelDecisionTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        d = ModelDecision(
            chosen_action_id="a",
            rationale="r",
            confidence=0.5,
            summary_update="s",
            hypothesis="h",
            expected_information_gain="g",
            state_update={"x": 1},
            usage={"tokens": 10},
        )
        restored = ModelDecision.from_dict(d.to_dict())
        self.assertEqual(restored, d)

    def test_optional_fields_omitted_when_none(self) -> None:
        d = ModelDecision("a", "r", 0.5, "s")
        payload = d.to_dict()
        self.assertNotIn("hypothesis", payload)
        self.assertNotIn("usage", payload)


class ScriptedControllerTests(unittest.TestCase):
    def test_replays_in_order(self) -> None:
        ctrl = ScriptedController([{"chosen_action_id": "a"}, {"chosen_action_id": "b"}])
        self.assertEqual(ctrl.decide(_context())["chosen_action_id"], "a")
        self.assertEqual(ctrl.decide(_context())["chosen_action_id"], "b")
        self.assertEqual(ctrl.consumed, 2)

    def test_exhaustion_raises(self) -> None:
        ctrl = ScriptedController([{"chosen_action_id": "a"}])
        ctrl.decide(_context())
        with self.assertRaises(ControllerExhausted):
            ctrl.decide(_context())

    def test_start_index_resumes(self) -> None:
        ctrl = ScriptedController([{"chosen_action_id": "a"}, {"chosen_action_id": "b"}], start_index=1)
        self.assertEqual(ctrl.decide(_context())["chosen_action_id"], "b")

    def test_non_dict_response_raises_controller_error(self) -> None:
        ctrl = ScriptedController(["not-a-dict"])
        with self.assertRaises(ControllerError):
            ctrl.decide(_context())


class DeterministicControllerTests(unittest.TestCase):
    def test_picks_first_novel_candidate(self) -> None:
        ctrl = DeterministicController()
        decision = ctrl.decide(_context())
        self.assertEqual(decision["chosen_action_id"], "collect-binary-evidence")
        self.assertIsNone(validate_decision(decision, CANDIDATES))
        self.assertEqual(decision["confidence"], 0.7)

    def test_skips_attempted_candidate(self) -> None:
        ctrl = DeterministicController()
        history = [{"action_id": "collect-binary-evidence"}]
        decision = ctrl.decide(_context(action_history=history))
        self.assertEqual(decision["chosen_action_id"], "reproduce-target-behavior")
        self.assertEqual(decision["hypothesis"], "the target exhibits a reproducible memory-safety fault under bounded input")

    def test_falls_back_to_first_when_all_attempted(self) -> None:
        ctrl = DeterministicController()
        history = [{"action_id": "collect-binary-evidence"}, {"action_id": "reproduce-target-behavior"}]
        decision = ctrl.decide(_context(action_history=history))
        self.assertEqual(decision["chosen_action_id"], "collect-binary-evidence")
        self.assertEqual(decision["confidence"], 0.3)

    def test_empty_candidates_raises(self) -> None:
        ctrl = DeterministicController()
        ctx = AgentContext(objective="o", stage=None, iteration=1, candidate_actions=[])
        with self.assertRaises(ControllerError):
            ctrl.decide(ctx)


class BuildControllerTests(unittest.TestCase):
    def test_string_specs(self) -> None:
        self.assertIsInstance(build_controller("deterministic"), DeterministicController)
        self.assertIsInstance(build_controller("scripted"), ScriptedController)

    def test_dict_spec_with_responses(self) -> None:
        ctrl = build_controller({"kind": "scripted", "responses": [{"chosen_action_id": "a"}], "start_index": 0})
        self.assertIsInstance(ctrl, ScriptedController)
        self.assertEqual(ctrl.decide(_context())["chosen_action_id"], "a")

    def test_unknown_kind_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_controller({"kind": "mystery"})

    def test_passthrough_model_instance(self) -> None:
        inst = DeterministicController()
        self.assertIs(build_controller(inst), inst)


if __name__ == "__main__":
    unittest.main()
