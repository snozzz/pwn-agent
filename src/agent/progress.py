"""Loop-protection primitives: duplicate-action and no-progress detection.

The legacy loop only stopped on step/failure budgets, so a controller that fixates on
one action — or an action that executes but never changes anything — would spin until the
step budget ran out (confirmed live on arm64/Mach-O targets where ``collect-binary-evidence``
is re-suggested every iteration). This module makes stagnation explicit and measurable.

Two independent guards:

- **no-progress**: a *progress signature* (completed actions + evidence fingerprints +
  runnable candidate ids) that is unchanged across consecutive iterations increments a
  counter; exceeding the budget is terminal. This catches "executing but nothing changes".
- **repeated-action**: the same executed action id chosen on N consecutive iterations is
  terminal regardless of evidence. This catches controller fixation.

The functions here are pure (no I/O, no AgentState dependency) so they unit-test cleanly;
the loop wires them to ``AgentState`` fields.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
import hashlib
import json

# Terminal statuses contributed by this module.
STATUS_NO_PROGRESS = "no-progress"
STATUS_REPEATED_ACTION = "repeated-action"


@dataclass
class ProgressAssessment:
    signature: str
    progressed: bool
    no_progress_count: int


def compute_progress_signature(
    *,
    completed_action_ids: Iterable[str],
    evidence_fingerprints: Iterable[str],
    candidate_ids: Iterable[str],
) -> str:
    """Stable signature of the agent's material situation after an iteration.

    Two iterations with the same completed set, the same evidence fingerprints, and the
    same runnable candidate set are considered to have made no progress.
    """
    payload = {
        "completed": sorted({str(x) for x in completed_action_ids if x}),
        "evidence": sorted({str(x) for x in evidence_fingerprints if x}),
        "candidates": sorted({str(x) for x in candidate_ids if x}),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def assess_progress(
    *,
    previous_signature: str | None,
    signature: str,
    previous_no_progress_count: int,
) -> ProgressAssessment:
    """Compare the new signature to the prior one and update the stall counter."""
    if previous_signature is not None and signature == previous_signature:
        return ProgressAssessment(signature=signature, progressed=False, no_progress_count=previous_no_progress_count + 1)
    return ProgressAssessment(signature=signature, progressed=True, no_progress_count=0)


def count_trailing_repeats(action_ids: list[str]) -> int:
    """Count how many times the final action id repeats consecutively at the tail.

    ``["a", "b", "b", "b"]`` -> 3; ``["a"]`` -> 1; ``[]`` -> 0.
    """
    if not action_ids:
        return 0
    last = action_ids[-1]
    count = 0
    for action_id in reversed(action_ids):
        if action_id == last:
            count += 1
        else:
            break
    return count


def repeated_action_detected(action_ids: list[str], *, threshold: int) -> bool:
    """True when the last executed action repeated >= ``threshold`` times in a row."""
    if threshold < 2:
        return False
    return count_trailing_repeats(action_ids) >= threshold


def no_progress_detected(no_progress_count: int, *, threshold: int) -> bool:
    """True when the stall counter has reached the configured budget."""
    if threshold < 1:
        return False
    return no_progress_count >= threshold
