"""Evidence ledger for the agent reasoning layer.

An ``EvidenceRecord`` captures a single verified fact produced by executing a bounded
tool action: what was run, how it exited, which artifact slot it refreshed, and a stable
fingerprint of that artifact. Evidence is derived strictly from executor/tool output, so
controller prose can never overwrite it (see ``src.agent.state.AgentState``).

The normalization chain this module implements:

    tool result  ->  normalized observation  ->  evidence record

Keeping evidence separate from free-form summaries is what lets later research answer
"what did the agent actually observe, and when" without re-reading prose.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import json

EVIDENCE_SCHEMA = "pwn-agent.evidence-record.v1"

# Maps a leaf subcommand to the artifact slot it is expected to refresh. This mirrors the
# loop's artifact routing but is kept here so evidence derivation is self-contained.
SUBCOMMAND_ARTIFACT_SLOTS = {
    "binary-scan": "analysis_json",
    "crash-triage": "crash_json",
    "binary-triage": "crash_json",
    "patch-validate": "patch_validation_json",
    "binary-verify": "verify_json",
    "binary-validate": "verify_json",
}


def fingerprint_payload(payload: Any) -> str:
    """Return a stable short fingerprint for an artifact payload.

    Uses canonical JSON so semantically identical artifacts fingerprint identically
    regardless of key ordering or formatting.
    """
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = repr(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


@dataclass
class EvidenceRecord:
    """A verified observation derived from a bounded tool execution."""

    evidence_id: str
    iteration: int
    source: str
    action_id: str
    kind: str
    command: list[str]
    returncode: int | None
    status: str
    observation: str
    artifact_slot: str | None = None
    artifact_path: str | None = None
    artifact_fingerprint: str | None = None
    schema: str = EVIDENCE_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        data = {key: value for key, value in dict(payload).items() if key in known}
        data.setdefault("schema", EVIDENCE_SCHEMA)
        return cls(**data)


def _subcommand_of(command: list[str]) -> str | None:
    # Internal leaf commands look like: python3 -m src.main <subcommand> --root ...
    if len(command) >= 4 and command[0:3] == ["python3", "-m", "src.main"]:
        return command[3]
    return None


def artifact_slot_for_command(command: list[str]) -> str | None:
    """Return the artifact slot a bounded leaf command is expected to refresh, if any."""
    subcommand = _subcommand_of(list(command or []))
    return SUBCOMMAND_ARTIFACT_SLOTS.get(subcommand) if subcommand else None


def normalize_observation(
    *,
    action_id: str,
    kind: str,
    status: str,
    returncode: int | None,
    artifact_slot: str | None,
    artifact_changed: bool,
) -> str:
    """Produce a concise, machine-and-human-readable observation string."""
    if status == "dry-run":
        return f"action '{action_id}' ({kind}) previewed without execution"
    if status == "failed":
        rc = "unknown" if returncode is None else str(returncode)
        return f"action '{action_id}' ({kind}) failed with returncode {rc}"
    if status == "ok":
        if artifact_slot and artifact_changed:
            return f"action '{action_id}' ({kind}) completed and refreshed artifact '{artifact_slot}'"
        if artifact_slot and not artifact_changed:
            return f"action '{action_id}' ({kind}) completed but artifact '{artifact_slot}' was unchanged"
        return f"action '{action_id}' ({kind}) completed"
    return f"action '{action_id}' ({kind}) produced status '{status}'"


def build_evidence_record(
    *,
    evidence_id: str,
    iteration: int,
    action: dict[str, Any],
    record: dict[str, Any],
    artifact_payload: Any = None,
    previous_fingerprint: str | None = None,
) -> EvidenceRecord:
    """Derive an :class:`EvidenceRecord` from one executor record.

    ``action`` is the plan action dict; ``record`` is a single entry from an execution
    summary's ``records`` list. ``artifact_payload`` is the freshly produced artifact
    (if any) so its fingerprint and change status can be captured.
    """
    command = list(record.get("command") or action.get("suggested_cli") or [])
    status = str(record.get("status", "unknown"))
    returncode = record.get("returncode")
    kind = str(action.get("kind") or record.get("kind") or "unknown")
    subcommand = _subcommand_of(command)
    artifact_slot = SUBCOMMAND_ARTIFACT_SLOTS.get(subcommand) if subcommand else None

    artifact_fingerprint = fingerprint_payload(artifact_payload) if artifact_payload is not None else None
    artifact_changed = bool(
        artifact_fingerprint is not None and artifact_fingerprint != previous_fingerprint
    )

    observation = normalize_observation(
        action_id=str(action.get("id") or record.get("action_id") or "unknown"),
        kind=kind,
        status=status,
        returncode=returncode if isinstance(returncode, int) else None,
        artifact_slot=artifact_slot,
        artifact_changed=artifact_changed,
    )

    return EvidenceRecord(
        evidence_id=evidence_id,
        iteration=iteration,
        source="executor",
        action_id=str(action.get("id") or record.get("action_id") or "unknown"),
        kind=kind,
        command=command,
        returncode=returncode if isinstance(returncode, int) else None,
        status=status,
        observation=observation,
        artifact_slot=artifact_slot,
        artifact_path=None,
        artifact_fingerprint=artifact_fingerprint,
    )
