"""Structured agent state for the autonomous binary-analysis loop.

``AgentState`` is the belief state the controller reasons over and the loop persists.
Unlike the legacy loop state (counters + free-form prose), it distinguishes:

- observations        : normalized things that happened
- evidence            : verified tool-derived records (see ``src.agent.evidence``)
- verified_facts      : conclusions each backed by one or more evidence ids
- hypotheses          : open/supported/rejected beliefs with confidence
- open_questions      : unresolved uncertainties
- action_history      : every attempted action and its outcome
- failure_history     : failures with reasons
- summary_updates     : free-form controller prose (kept SEPARATE from verified facts)
- progress markers    : fingerprints + no-progress counter used by loop protection
- budgets / counters  : step/failure/no-progress budgets and current counts

Design constraints:
- 3.8-compatible at runtime (annotations only use PEP 604 unions, never runtime values).
- round-trips through ``to_dict`` / ``from_dict`` for persistence and resume.
- controller prose can append to ``summary_updates`` but must never mutate
  ``verified_facts`` or ``evidence`` (enforced by the loop: only tool output calls
  :meth:`record_evidence` / :meth:`add_verified_fact`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .evidence import EvidenceRecord

AGENT_STATE_SCHEMA = "pwn-agent.agent-state.v1"

HYPOTHESIS_STATUSES = {"open", "supported", "rejected"}


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    status: str = "open"
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "statement": self.statement,
            "status": self.status,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Hypothesis":
        return cls(
            hypothesis_id=str(payload.get("hypothesis_id") or payload.get("id") or ""),
            statement=str(payload.get("statement") or ""),
            status=str(payload.get("status") or "open"),
            confidence=float(payload.get("confidence") or 0.0),
            evidence_ids=list(payload.get("evidence_ids") or []),
        )


@dataclass
class VerifiedFact:
    fact_id: str
    statement: str
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "statement": self.statement,
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "VerifiedFact":
        return cls(
            fact_id=str(payload.get("fact_id") or ""),
            statement=str(payload.get("statement") or ""),
            evidence_ids=list(payload.get("evidence_ids") or []),
        )


@dataclass
class AgentState:
    objective: str = "analyze the local binary and reach a bounded conclusion"
    stage: str | None = None
    confidence: float = 0.0

    observations: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    verified_facts: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    action_history: list[dict[str, Any]] = field(default_factory=list)
    failure_history: list[dict[str, Any]] = field(default_factory=list)
    summary_updates: list[str] = field(default_factory=list)

    # progress markers used by loop protection
    no_progress_count: int = 0
    last_progress_signature: str | None = None

    # budgets / counters (mirrors loop budgets so state alone is analyzable)
    step_count: int = 0
    failure_count: int = 0
    max_steps: int = 1
    max_failures: int = 1
    max_no_progress: int = 2

    schema: str = AGENT_STATE_SCHEMA
    schema_version: int = 1

    # -- derived helpers -------------------------------------------------

    def _next_id(self, prefix: str, existing: list[dict[str, Any]], key: str) -> str:
        return f"{prefix}-{len(existing) + 1}"

    @property
    def rejected_hypotheses(self) -> list[dict[str, Any]]:
        return [h for h in self.hypotheses if h.get("status") == "rejected"]

    @property
    def open_hypotheses(self) -> list[dict[str, Any]]:
        return [h for h in self.hypotheses if h.get("status") == "open"]

    # -- mutation (tool-derived, trusted) --------------------------------

    def record_observation(self, text: str) -> None:
        text = (text or "").strip()
        if text:
            self.observations.append(text)

    def record_evidence(self, record: EvidenceRecord) -> str:
        """Append a verified evidence record. Returns its evidence id."""
        payload = record.to_dict()
        self.evidence.append(payload)
        self.record_observation(record.observation)
        return record.evidence_id

    def add_verified_fact(self, statement: str, *, evidence_ids: list[str] | None = None) -> str:
        fact = VerifiedFact(
            fact_id=self._next_id("fact", self.verified_facts, "fact_id"),
            statement=statement.strip(),
            evidence_ids=list(evidence_ids or []),
        )
        self.verified_facts.append(fact.to_dict())
        return fact.fact_id

    def next_evidence_id(self) -> str:
        return f"ev-{len(self.evidence) + 1}"

    def record_action(self, *, iteration: int, action_id: str, accepted: bool, status: str) -> None:
        self.action_history.append(
            {
                "iteration": iteration,
                "action_id": action_id,
                "accepted": accepted,
                "status": status,
            }
        )

    def record_failure(self, *, iteration: int, reason: str) -> None:
        self.failure_history.append({"iteration": iteration, "reason": reason})

    # -- controller prose (untrusted; never touches verified data) -------

    def add_summary_update(self, text: str) -> None:
        text = (text or "").strip()
        if text:
            self.summary_updates.append(text)

    # -- hypotheses ------------------------------------------------------

    def add_hypothesis(self, statement: str, *, confidence: float = 0.0, evidence_ids: list[str] | None = None) -> str:
        hyp = Hypothesis(
            hypothesis_id=self._next_id("hyp", self.hypotheses, "hypothesis_id"),
            statement=statement.strip(),
            status="open",
            confidence=float(confidence),
            evidence_ids=list(evidence_ids or []),
        )
        self.hypotheses.append(hyp.to_dict())
        return hyp.hypothesis_id

    def update_hypothesis(
        self,
        hypothesis_id: str,
        *,
        status: str | None = None,
        confidence: float | None = None,
        evidence_ids: list[str] | None = None,
    ) -> bool:
        for hyp in self.hypotheses:
            if hyp.get("hypothesis_id") == hypothesis_id:
                if status is not None:
                    if status not in HYPOTHESIS_STATUSES:
                        raise ValueError(f"invalid hypothesis status: {status}")
                    hyp["status"] = status
                if confidence is not None:
                    hyp["confidence"] = float(confidence)
                if evidence_ids is not None:
                    merged = list(dict.fromkeys(list(hyp.get("evidence_ids") or []) + list(evidence_ids)))
                    hyp["evidence_ids"] = merged
                return True
        return False

    def add_open_question(self, text: str) -> None:
        text = (text or "").strip()
        if text and text not in self.open_questions:
            self.open_questions.append(text)

    # -- serialization ---------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "objective": self.objective,
            "stage": self.stage,
            "confidence": self.confidence,
            "observations": list(self.observations),
            "evidence": list(self.evidence),
            "verified_facts": list(self.verified_facts),
            "hypotheses": list(self.hypotheses),
            "rejected_hypotheses": list(self.rejected_hypotheses),
            "open_questions": list(self.open_questions),
            "action_history": list(self.action_history),
            "failure_history": list(self.failure_history),
            "summary_updates": list(self.summary_updates),
            "no_progress_count": self.no_progress_count,
            "last_progress_signature": self.last_progress_signature,
            "step_count": self.step_count,
            "failure_count": self.failure_count,
            "budgets": {
                "max_steps": self.max_steps,
                "max_failures": self.max_failures,
                "max_no_progress": self.max_no_progress,
            },
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentState":
        data = dict(payload or {})
        budgets = dict(data.get("budgets") or {})
        state = cls(
            objective=str(data.get("objective") or cls.objective),
            stage=data.get("stage"),
            confidence=float(data.get("confidence") or 0.0),
            observations=list(data.get("observations") or []),
            evidence=list(data.get("evidence") or []),
            verified_facts=list(data.get("verified_facts") or []),
            hypotheses=list(data.get("hypotheses") or []),
            open_questions=list(data.get("open_questions") or []),
            action_history=list(data.get("action_history") or []),
            failure_history=list(data.get("failure_history") or []),
            summary_updates=list(data.get("summary_updates") or []),
            no_progress_count=int(data.get("no_progress_count") or 0),
            last_progress_signature=data.get("last_progress_signature"),
            step_count=int(data.get("step_count") or 0),
            failure_count=int(data.get("failure_count") or 0),
            max_steps=int(budgets.get("max_steps", data.get("max_steps", 1))),
            max_failures=int(budgets.get("max_failures", data.get("max_failures", 1))),
            max_no_progress=int(budgets.get("max_no_progress", data.get("max_no_progress", 2))),
        )
        return state
