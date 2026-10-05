"""Controller (model) abstraction for the agent loop.

This is the seam the legacy loop was missing. The loop builds an :class:`AgentContext`
from the current plan + evidence + state, hands it to an :class:`AgentModel`, and gets
back a :class:`ModelDecision` that references *one bounded candidate action id*.

Safety contract (unchanged from the legacy loop):
- A controller may only choose among ``context.candidate_actions`` — ids the planner
  already produced and the executor already deemed runnable. It never emits a shell
  command, a path, or an argv.
- The executor remains the sole authority over what actually runs. The controller
  expresses *intent*; validation + enforcement happen downstream.

Backends provided here:
- ``ScriptedController``  : replays pre-generated decision dicts (preserves the legacy
  ``--model-response-json/jsonl`` behavior exactly; used for deterministic replay tests).
- ``DeterministicController`` : a real in-process policy that reasons over the candidate
  actions, evidence, and attempt history. It lets the loop run with NO pre-generated
  file, which is the core Agent v2 capability.

Provider backends (Claude-compatible API, local Qwen, OpenAI-compatible endpoints) are
intentionally NOT shipped here: this package adds no network/model transport. A provider
is expected to implement :class:`AgentModel` as an out-of-process adapter and register via
:func:`build_controller`. ``ModelDecision.usage`` exists so such a backend can record
token/tool-call accounting later without a schema change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import abc

MODEL_CHOICE_SCHEMA_V2 = "pwn-agent.model-choice.v2"


class ControllerError(RuntimeError):
    """Raised by a controller backend when it cannot produce a decision.

    The loop treats this as a recoverable failure (it counts against the failure
    budget) rather than a crash, so a flaky backend degrades gracefully.
    """


class ControllerExhausted(ControllerError):
    """Raised by a finite controller (e.g. scripted) when no decision remains.

    The loop maps this to the terminal ``awaiting-model-output`` status, matching the
    legacy behavior when a pre-generated response list was consumed.
    """


@dataclass
class AgentContext:
    """Structured context handed to a controller each step.

    ``candidate_actions`` is the bounded, dependency-resolved action set — the only
    choices a controller is allowed to reference.
    """

    objective: str
    stage: str | None
    iteration: int
    candidate_actions: list[dict[str, Any]]
    evidence: list[dict[str, Any]] = field(default_factory=list)
    action_history: list[dict[str, Any]] = field(default_factory=list)
    state_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def candidate_ids(self) -> list[str]:
        return [str(a.get("id")) for a in self.candidate_actions if a.get("id")]

    @property
    def attempted_action_ids(self) -> set[str]:
        return {str(h.get("action_id")) for h in self.action_history if h.get("action_id")}

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "stage": self.stage,
            "iteration": self.iteration,
            "candidate_actions": list(self.candidate_actions),
            "candidate_ids": self.candidate_ids,
            "evidence": list(self.evidence),
            "action_history": list(self.action_history),
            "state_summary": dict(self.state_summary),
        }


@dataclass
class ModelDecision:
    """A controller's structured decision.

    The first four fields are the legacy ``model-choice.v1`` contract and are validated
    exactly as before. The remaining fields are optional v2 additions.
    """

    chosen_action_id: str
    rationale: str
    confidence: float
    summary_update: str
    hypothesis: str | None = None
    expected_information_gain: str | None = None
    state_update: dict[str, Any] | None = None
    usage: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": MODEL_CHOICE_SCHEMA_V2,
            "chosen_action_id": self.chosen_action_id,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "summary_update": self.summary_update,
        }
        if self.hypothesis is not None:
            payload["hypothesis"] = self.hypothesis
        if self.expected_information_gain is not None:
            payload["expected_information_gain"] = self.expected_information_gain
        if self.state_update is not None:
            payload["state_update"] = self.state_update
        if self.usage is not None:
            payload["usage"] = self.usage
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ModelDecision":
        return cls(
            chosen_action_id=str(payload.get("chosen_action_id") or ""),
            rationale=str(payload.get("rationale") or ""),
            confidence=float(payload.get("confidence")) if isinstance(payload.get("confidence"), (int, float)) else 0.0,
            summary_update=str(payload.get("summary_update") or ""),
            hypothesis=payload.get("hypothesis"),
            expected_information_gain=payload.get("expected_information_gain"),
            state_update=payload.get("state_update"),
            usage=payload.get("usage"),
        )


def validate_decision(choice: Any, candidate_actions: list[dict[str, Any]]) -> str | None:
    """Validate a raw decision dict against the bounded candidate set.

    Returns ``None`` when valid, otherwise an error string. The v1 field rules and error
    strings are preserved verbatim so existing trajectories/tests are unaffected; v2
    optional fields are validated only when present.
    """
    if not isinstance(choice, dict):
        return "model choice must be a JSON object"

    chosen_action_id = choice.get("chosen_action_id")
    rationale = choice.get("rationale")
    confidence = choice.get("confidence")
    summary_update = choice.get("summary_update")

    candidate_ids = {action.get("id") for action in candidate_actions if action.get("id")}
    if not isinstance(chosen_action_id, str) or not chosen_action_id:
        return "chosen_action_id must be a non-empty string"
    if chosen_action_id not in candidate_ids:
        return f"chosen_action_id not present in bounded plan candidates: {chosen_action_id}"
    if not isinstance(rationale, str) or not rationale.strip():
        return "rationale must be a non-empty string"
    if not isinstance(summary_update, str) or not summary_update.strip():
        return "summary_update must be a non-empty string"
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        return "confidence must be numeric"
    if float(confidence) < 0.0 or float(confidence) > 1.0:
        return "confidence must be between 0.0 and 1.0"

    # v2 optional fields
    if "hypothesis" in choice and choice["hypothesis"] is not None and not isinstance(choice["hypothesis"], str):
        return "hypothesis must be a string when provided"
    if (
        "expected_information_gain" in choice
        and choice["expected_information_gain"] is not None
        and not isinstance(choice["expected_information_gain"], str)
    ):
        return "expected_information_gain must be a string when provided"
    if "state_update" in choice and choice["state_update"] is not None and not isinstance(choice["state_update"], dict):
        return "state_update must be an object when provided"
    return None


def normalize_decision(choice: dict[str, Any]) -> dict[str, Any]:
    """Normalize a validated raw decision into the canonical stored form."""
    normalized: dict[str, Any] = {
        "chosen_action_id": choice["chosen_action_id"],
        "rationale": str(choice["rationale"]).strip(),
        "confidence": float(choice["confidence"]),
        "summary_update": str(choice["summary_update"]).strip(),
    }
    if choice.get("hypothesis"):
        normalized["hypothesis"] = str(choice["hypothesis"]).strip()
    if choice.get("expected_information_gain"):
        normalized["expected_information_gain"] = str(choice["expected_information_gain"]).strip()
    if isinstance(choice.get("state_update"), dict):
        normalized["state_update"] = dict(choice["state_update"])
    return normalized


class AgentModel(abc.ABC):
    """A controller that selects a bounded action given structured context."""

    name: str = "abstract"

    @abc.abstractmethod
    def decide(self, context: AgentContext) -> dict[str, Any]:
        """Return a raw decision dict (validated downstream by the loop).

        Returning a dict (not a validated ``ModelDecision``) is deliberate: an invalid
        decision from a backend must still flow through the loop's validation path and
        be recorded as ``invalid-model-output``, exactly like a bad pre-generated file.
        """
        raise NotImplementedError


class ScriptedController(AgentModel):
    """Replays pre-generated decision dicts in order (legacy behavior)."""

    name = "scripted"

    def __init__(self, responses: list[dict[str, Any]], *, start_index: int = 0) -> None:
        self._responses = list(responses)
        self._index = int(start_index)

    @property
    def consumed(self) -> int:
        return self._index

    def decide(self, context: AgentContext) -> dict[str, Any]:
        if self._index >= len(self._responses):
            raise ControllerExhausted("no scripted model responses remain")
        raw = self._responses[self._index]
        self._index += 1
        if not isinstance(raw, dict):
            # Preserve legacy loader guarantee that each response is an object.
            raise ControllerError("scripted model response must be a JSON object")
        return dict(raw)


class DeterministicController(AgentModel):
    """A real in-process policy over the bounded candidate set.

    Strategy (deterministic and dependency-aware, relying on the planner/executor having
    already ordered candidates best-first):
      1. prefer the first candidate not yet attempted in this episode;
      2. otherwise fall back to the first candidate (which will surface as no-progress
         downstream rather than looping silently).
    It emits a rationale, a confidence shaped by novelty, a hypothesis derived from the
    action kind, and an expected-information-gain note.
    """

    name = "deterministic"

    def decide(self, context: AgentContext) -> dict[str, Any]:
        candidates = context.candidate_actions
        if not candidates:
            raise ControllerError("no candidate actions available to decide on")

        attempted = context.attempted_action_ids
        novel = [a for a in candidates if a.get("id") not in attempted]
        chosen = novel[0] if novel else candidates[0]
        is_novel = chosen in novel

        action_id = str(chosen.get("id"))
        kind = str(chosen.get("kind") or "unknown")
        stage = str(chosen.get("stage") or context.stage or "unknown")
        rationale = (
            f"Selected the highest-priority bounded candidate '{action_id}' "
            f"(stage={stage}, kind={kind}); "
            + ("not yet attempted this episode." if is_novel else "re-selected because it is the only remaining candidate.")
        )
        decision: dict[str, Any] = {
            "schema": MODEL_CHOICE_SCHEMA_V2,
            "chosen_action_id": action_id,
            "rationale": rationale,
            "confidence": 0.7 if is_novel else 0.3,
            "summary_update": f"Advanced the {stage} stage via '{action_id}'.",
            "expected_information_gain": _expected_gain_for_kind(kind),
        }
        hypothesis = _hypothesis_for_kind(kind)
        if hypothesis is not None:
            decision["hypothesis"] = hypothesis
        return decision


_KIND_GAIN = {
    "binary_scan": "static metadata, mitigations, imports, and strings for the target",
    "crash_triage": "runtime crash/exit behavior under bounded inputs",
    "crash_triage_gdb": "bounded debugger context (registers, backtrace, mappings) for the crash",
    "binary_verify": "runtime confirmation that a candidate change alters observed behavior",
}

_KIND_HYPOTHESIS = {
    "crash_triage": "the target exhibits a reproducible memory-safety fault under bounded input",
    "crash_triage_gdb": "the crash site localizes a specific faulting instruction/function",
    "binary_verify": "the candidate patch removes the previously observed faulting behavior",
}


def _expected_gain_for_kind(kind: str) -> str:
    return _KIND_GAIN.get(kind, "additional bounded evidence about the target")


def _hypothesis_for_kind(kind: str) -> str | None:
    return _KIND_HYPOTHESIS.get(kind)


def build_controller(spec: Any) -> AgentModel:
    """Factory mapping a spec to an :class:`AgentModel`.

    Accepts a bare name (``"deterministic"`` / ``"scripted"``) or a dict such as
    ``{"kind": "scripted", "responses": [...], "start_index": 0}``. Unknown kinds raise
    ``ValueError``. This is the single registration point a future provider adapter would
    extend; no network backend is registered here.
    """
    if isinstance(spec, AgentModel):
        return spec
    if isinstance(spec, str):
        kind = spec
        config: dict[str, Any] = {}
    elif isinstance(spec, dict):
        kind = str(spec.get("kind") or "")
        config = dict(spec)
    else:
        raise ValueError(f"unsupported controller spec: {spec!r}")

    if kind == "deterministic":
        return DeterministicController()
    if kind == "scripted":
        return ScriptedController(list(config.get("responses") or []), start_index=int(config.get("start_index") or 0))
    raise ValueError(f"unknown controller kind: {kind!r}")
