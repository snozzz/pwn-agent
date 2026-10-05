from __future__ import annotations

import unittest

from src.agent.progress import (
    STATUS_NO_PROGRESS,
    STATUS_REPEATED_ACTION,
    assess_progress,
    compute_progress_signature,
    count_trailing_repeats,
    no_progress_detected,
    repeated_action_detected,
)


class ProgressSignatureTests(unittest.TestCase):
    def test_signature_is_order_independent(self) -> None:
        a = compute_progress_signature(
            completed_action_ids=["x", "y"], evidence_fingerprints=["f2", "f1"], candidate_ids=["c2", "c1"]
        )
        b = compute_progress_signature(
            completed_action_ids=["y", "x"], evidence_fingerprints=["f1", "f2"], candidate_ids=["c1", "c2"]
        )
        self.assertEqual(a, b)

    def test_signature_changes_when_evidence_changes(self) -> None:
        a = compute_progress_signature(completed_action_ids=[], evidence_fingerprints=["f1"], candidate_ids=["c1"])
        b = compute_progress_signature(completed_action_ids=[], evidence_fingerprints=["f2"], candidate_ids=["c1"])
        self.assertNotEqual(a, b)


class AssessProgressTests(unittest.TestCase):
    def test_first_iteration_counts_as_progress(self) -> None:
        result = assess_progress(previous_signature=None, signature="sig", previous_no_progress_count=0)
        self.assertTrue(result.progressed)
        self.assertEqual(result.no_progress_count, 0)

    def test_identical_signature_increments_counter(self) -> None:
        result = assess_progress(previous_signature="sig", signature="sig", previous_no_progress_count=1)
        self.assertFalse(result.progressed)
        self.assertEqual(result.no_progress_count, 2)

    def test_changed_signature_resets_counter(self) -> None:
        result = assess_progress(previous_signature="old", signature="new", previous_no_progress_count=3)
        self.assertTrue(result.progressed)
        self.assertEqual(result.no_progress_count, 0)


class RepeatDetectionTests(unittest.TestCase):
    def test_count_trailing_repeats(self) -> None:
        self.assertEqual(count_trailing_repeats([]), 0)
        self.assertEqual(count_trailing_repeats(["a"]), 1)
        self.assertEqual(count_trailing_repeats(["a", "b", "b", "b"]), 3)
        self.assertEqual(count_trailing_repeats(["b", "b", "a"]), 1)

    def test_repeated_action_threshold(self) -> None:
        self.assertFalse(repeated_action_detected(["a", "a"], threshold=3))
        self.assertTrue(repeated_action_detected(["a", "a", "a"], threshold=3))

    def test_repeated_action_threshold_below_two_never_fires(self) -> None:
        self.assertFalse(repeated_action_detected(["a", "a", "a"], threshold=1))

    def test_no_progress_detected(self) -> None:
        self.assertFalse(no_progress_detected(1, threshold=2))
        self.assertTrue(no_progress_detected(2, threshold=2))
        self.assertFalse(no_progress_detected(5, threshold=0))

    def test_status_constants(self) -> None:
        self.assertEqual(STATUS_NO_PROGRESS, "no-progress")
        self.assertEqual(STATUS_REPEATED_ACTION, "repeated-action")


if __name__ == "__main__":
    unittest.main()
