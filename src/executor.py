from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import subprocess
from typing import Any


MODULE_ROOT = Path(__file__).resolve().parents[1]

ALLOWED_MAIN_SUBCOMMANDS = {
    "verify-run",
    "rebuild-target",
    "rebuild-verify",
    "rebuild-plan",
}


@dataclass
class ExecutionRecord:
    action_id: str
    kind: str
    phase: str
    title: str
    command: list[str]
    returncode: int | None
    status: str
    stdout: str
    stderr: str


@dataclass
class ExecutionTransition:
    sequence: int
    action_id: str
    phase: str
    title: str
    from_state: str | None
    to_state: str
    reason: str


@dataclass
class ExecutionState:
    plan_path: str
    action_states: dict[str, str]
    completed_action_ids: list[str]
    history: list[ExecutionTransition]

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_path": self.plan_path,
            "action_states": dict(sorted(self.action_states.items())),
            "completed_action_ids": list(self.completed_action_ids),
            "history": [asdict(entry) for entry in self.history],
        }


@dataclass
class ExecutionSummary:
    plan_path: str
    executed: int
    selected_action_ids: list[str]
    completed_action_ids: list[str]
    resumed_completed_action_ids: list[str]
    stopped_reason: str
    runnable_action_ids: list[str]
    deferred_action_ids: list[str]
    remaining_runnable_action_ids: list[str]
    next_action_ids: list[str]
    status_counts: dict[str, int]
    action_state_counts: dict[str, int]
    action_states: dict[str, str]
    transition_count: int
    transitions: list[ExecutionTransition]
    state_path: str | None
    resumed_from_state: bool
    records: list[ExecutionRecord]

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_path": self.plan_path,
            "executed": self.executed,
            "selected_action_ids": self.selected_action_ids,
            "completed_action_ids": self.completed_action_ids,
            "resumed_completed_action_ids": self.resumed_completed_action_ids,
            "stopped_reason": self.stopped_reason,
            "runnable_action_ids": self.runnable_action_ids,
            "deferred_action_ids": self.deferred_action_ids,
            "remaining_runnable_action_ids": self.remaining_runnable_action_ids,
            "next_action_ids": self.next_action_ids,
            "status_counts": self.status_counts,
            "action_state_counts": self.action_state_counts,
            "action_states": self.action_states,
            "transition_count": self.transition_count,
            "transitions": [asdict(entry) for entry in self.transitions],
            "state_path": self.state_path,
            "resumed_from_state": self.resumed_from_state,
            "records": [asdict(record) for record in self.records],
        }


class ExecutorError(RuntimeError):
    pass


def execute_plan(
    plan_path: Path,
    *,
    action_id: str | None = None,
    phase: str | None = None,
    max_actions: int = 1,
    dry_run: bool = False,
    timeout_seconds: int = 30,
    state_path: Path | None = None,
) -> ExecutionSummary:
    if max_actions < 1:
        raise ExecutorError("max_actions must be >= 1")

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    actions = list(plan.get("next_actions", []))
    state, resumed_from_state = _load_state(state_path, plan_path=plan_path, actions=actions)
    resumed_completed_ids = set(state.completed_action_ids)

    filtered_actions = _filter_runnable_actions(
        actions,
        action_id=action_id,
        phase=phase,
        completed_ids=resumed_completed_ids,
    )
    selected, runnable_ids, deferred_ids = _select_actions(
        filtered_actions,
        max_actions=max_actions,
        completed_ids=resumed_completed_ids,
    )
    records: list[ExecutionRecord] = []
    transitions: list[ExecutionTransition] = []
    stopped_reason = "no-executable-actions"
    completed_ids: set[str] = set(resumed_completed_ids)

    _refresh_passive_states(state, actions, runnable_ids=runnable_ids, deferred_ids=deferred_ids)

    for action in selected:
        argv = _validate_suggested_cli(action)
        _transition(state, transitions, action, "selected", reason="selected-for-execution")
        if dry_run:
            records.append(
                ExecutionRecord(
                    action_id=action["id"],
                    kind=action.get("kind", "unknown"),
                    phase=action.get("phase", "execution"),
                    title=action.get("title", action["id"]),
                    command=argv,
                    returncode=None,
                    status="dry-run",
                    stdout="",
                    stderr="",
                )
            )
            _transition(state, transitions, action, "dry-run", reason="validated-without-execution")
            stopped_reason = "dry-run"
            completed_ids.add(action["id"])
            continue

        _transition(state, transitions, action, "running", reason="command-started")
        proc = subprocess.run(
            argv,
            cwd=MODULE_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        status = "ok" if proc.returncode == 0 else "failed"
        records.append(
            ExecutionRecord(
                action_id=action["id"],
                kind=action.get("kind", "unknown"),
                phase=action.get("phase", "execution"),
                title=action.get("title", action["id"]),
                command=argv,
                returncode=proc.returncode,
                status=status,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        )
        if proc.returncode != 0:
            _transition(state, transitions, action, "failed", reason=f"command-returncode-{proc.returncode}")
            stopped_reason = "command-failed"
            break
        _transition(state, transitions, action, "completed", reason="command-succeeded")
        completed_ids.add(action["id"])
    else:
        if records and stopped_reason == "no-executable-actions":
            stopped_reason = "completed"

    state.completed_action_ids = sorted(completed_ids)
    if state_path is not None:
        write_execution_state(state_path, state)

    status_counts = {
        "ok": sum(1 for record in records if record.status == "ok"),
        "failed": sum(1 for record in records if record.status == "failed"),
        "dry-run": sum(1 for record in records if record.status == "dry-run"),
    }
    remaining_runnable_ids = [candidate_id for candidate_id in runnable_ids if candidate_id not in completed_ids]
    next_action_ids = _select_followup_actions(
        filtered_actions,
        completed_ids=completed_ids,
        limit=3,
    )
    action_state_counts = _count_states(state.action_states)
    return ExecutionSummary(
        plan_path=str(plan_path),
        executed=sum(1 for record in records if record.status in {"ok", "failed"}),
        selected_action_ids=[action["id"] for action in selected],
        completed_action_ids=[action["id"] for action in selected if action["id"] in completed_ids],
        resumed_completed_action_ids=sorted(resumed_completed_ids),
        stopped_reason=stopped_reason,
        runnable_action_ids=runnable_ids,
        deferred_action_ids=deferred_ids,
        remaining_runnable_action_ids=remaining_runnable_ids,
        next_action_ids=next_action_ids,
        status_counts=status_counts,
        action_state_counts=action_state_counts,
        action_states=dict(sorted(state.action_states.items())),
        transition_count=len(transitions),
        transitions=transitions,
        state_path=(str(state_path) if state_path is not None else None),
        resumed_from_state=resumed_from_state,
        records=records,
    )


def write_execution_summary(path: Path, summary: ExecutionSummary) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")


def write_execution_state(path: Path, state: ExecutionState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")


def render_execution_markdown(summary: ExecutionSummary) -> str:
    lines = ["# Plan Execution", ""]
    lines.append(f"- Plan: `{summary.plan_path}`")
    lines.append(f"- Executed: {summary.executed}")
    lines.append(f"- Stopped reason: {summary.stopped_reason}")
    lines.append(f"- Resumed from state: {str(summary.resumed_from_state).lower()}")
    if summary.state_path:
        lines.append(f"- State file: `{summary.state_path}`")
    if summary.selected_action_ids:
        lines.append(f"- Selected actions: {', '.join(summary.selected_action_ids)}")
    if summary.completed_action_ids:
        lines.append(f"- Completed actions: {', '.join(summary.completed_action_ids)}")
    if summary.resumed_completed_action_ids:
        lines.append(f"- Previously completed actions: {', '.join(summary.resumed_completed_action_ids)}")
    if summary.runnable_action_ids:
        lines.append(f"- Runnable actions: {', '.join(summary.runnable_action_ids)}")
    if summary.deferred_action_ids:
        lines.append(f"- Deferred actions: {', '.join(summary.deferred_action_ids)}")
    if summary.remaining_runnable_action_ids:
        lines.append(f"- Remaining runnable actions: {', '.join(summary.remaining_runnable_action_ids)}")
    if summary.next_action_ids:
        lines.append(f"- Next actions: {', '.join(summary.next_action_ids)}")
    if summary.status_counts:
        lines.append(
            "- Status counts: " + ", ".join(f"{key}={value}" for key, value in sorted(summary.status_counts.items()))
        )
    if summary.action_state_counts:
        lines.append(
            "- Action states: " + ", ".join(f"{key}={value}" for key, value in sorted(summary.action_state_counts.items()))
        )
    lines.append(f"- Transition count: {summary.transition_count}")
    lines.extend(["", "## State Transitions", ""])
    if summary.transitions:
        for transition in summary.transitions:
            lines.append(
                f"- [{transition.sequence}] `{transition.action_id}`: "
                f"{transition.from_state or 'none'} -> {transition.to_state} ({transition.reason})"
            )
    else:
        lines.append("- none")
    lines.extend(["", "## Records", ""])
    if not summary.records:
        lines.append("- none")
        return "\n".join(lines) + "\n"

    for record in summary.records:
        lines.append(f"- [{record.phase}] [{record.status}] {record.title}")
        lines.append(f"  action-id: `{record.action_id}`")
        lines.append(f"  kind: `{record.kind}`")
        lines.append(f"  command: `{_shell_join(record.command)}`")
        if record.returncode is not None:
            lines.append(f"  returncode: {record.returncode}")
        if record.stdout.strip():
            lines.append("  stdout:")
            for line in record.stdout.strip().splitlines()[:12]:
                lines.append(f"    {line}")
        if record.stderr.strip():
            lines.append("  stderr:")
            for line in record.stderr.strip().splitlines()[:12]:
                lines.append(f"    {line}")
    return "\n".join(lines) + "\n"


def _load_state(
    state_path: Path | None,
    *,
    plan_path: Path,
    actions: list[dict[str, Any]],
) -> tuple[ExecutionState, bool]:
    if state_path is None or not state_path.exists():
        return _initial_state(plan_path, actions), False

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    history = [ExecutionTransition(**entry) for entry in payload.get("history", [])]
    state = ExecutionState(
        plan_path=payload.get("plan_path", str(plan_path)),
        action_states=dict(payload.get("action_states", {})),
        completed_action_ids=list(payload.get("completed_action_ids", [])),
        history=history,
    )
    _merge_missing_actions(state, actions)
    return state, True


def _initial_state(plan_path: Path, actions: list[dict[str, Any]]) -> ExecutionState:
    state = ExecutionState(
        plan_path=str(plan_path),
        action_states={},
        completed_action_ids=[],
        history=[],
    )
    _merge_missing_actions(state, actions)
    return state


def _merge_missing_actions(state: ExecutionState, actions: list[dict[str, Any]]) -> None:
    for action in actions:
        action_id = action.get("id")
        if not action_id or action_id in state.action_states:
            continue
        state.action_states[action_id] = _initial_action_state(action)


def _initial_action_state(action: dict[str, Any]) -> str:
    status = action.get("status")
    if status == "blocked":
        return "blocked"
    if status == "context":
        return "context"
    if status == "ready" and action.get("suggested_cli"):
        return "queued"
    return status or "unknown"


def _refresh_passive_states(
    state: ExecutionState,
    actions: list[dict[str, Any]],
    *,
    runnable_ids: list[str],
    deferred_ids: list[str],
) -> None:
    deferred = set(deferred_ids)
    runnable = set(runnable_ids)
    completed = set(state.completed_action_ids)
    for action in actions:
        action_id = action.get("id")
        if not action_id or action_id in completed:
            continue
        current = state.action_states.get(action_id)
        if action_id in deferred and current not in {"running", "failed", "completed"}:
            state.action_states[action_id] = "deferred"
        elif action_id in runnable and current not in {"running", "failed", "completed", "selected", "dry-run"}:
            state.action_states[action_id] = "queued"


def _transition(
    state: ExecutionState,
    transitions: list[ExecutionTransition],
    action: dict[str, Any],
    to_state: str,
    *,
    reason: str,
) -> None:
    action_id = action.get("id", "unknown")
    previous = state.action_states.get(action_id)
    if previous == to_state:
        return
    transition = ExecutionTransition(
        sequence=len(state.history) + len(transitions) + 1,
        action_id=action_id,
        phase=action.get("phase", "execution"),
        title=action.get("title", action_id),
        from_state=previous,
        to_state=to_state,
        reason=reason,
    )
    state.action_states[action_id] = to_state
    state.history.append(transition)
    transitions.append(transition)


def _count_states(action_states: dict[str, str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for state in action_states.values():
        counts[state] = counts.get(state, 0) + 1
    return dict(sorted(counts.items()))


def _filter_runnable_actions(
    actions: list[dict[str, Any]],
    *,
    action_id: str | None,
    phase: str | None,
    completed_ids: set[str],
) -> list[dict[str, Any]]:
    runnable = [
        action
        for action in actions
        if action.get("status") == "ready" and action.get("suggested_cli") and action.get("id") not in completed_ids
    ]
    if phase is not None:
        runnable = [action for action in runnable if action.get("phase") == phase]
        if not runnable:
            raise ExecutorError(f"ready phase not found: {phase}")
    if action_id is not None:
        runnable = [action for action in runnable if action.get("id") == action_id]
        if not runnable:
            raise ExecutorError(f"ready action not found: {action_id}")
    return runnable


def _select_actions(
    runnable: list[dict[str, Any]],
    *,
    max_actions: int,
    completed_ids: set[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:

    indexed = {action.get("id"): action for action in runnable if action.get("id")}
    ordered = sorted(
        runnable,
        key=lambda item: (_phase_rank(item.get("phase")), int(item.get("priority", 0)), item.get("id", "")),
        reverse=True,
    )
    selected: list[dict[str, Any]] = []
    progressed_ids: set[str] = set(completed_ids)
    remaining = list(ordered)
    deferred_ids: list[str] = []

    while remaining and len(selected) < max_actions:
        progressed = False
        deferred: list[dict[str, Any]] = []
        skipped_tail: list[dict[str, Any]] = []
        for index, action in enumerate(remaining):
            depends_on = list(action.get("depends_on") or [])
            if any(dependency in indexed and dependency not in progressed_ids for dependency in depends_on):
                deferred.append(action)
                continue
            selected.append(action)
            progressed_ids.add(action["id"])
            progressed = True
            if len(selected) >= max_actions:
                skipped_tail = remaining[index + 1 :]
                break
        if not progressed:
            deferred_ids = [action["id"] for action in deferred if action.get("id")]
            break
        remaining = deferred + skipped_tail

    if not deferred_ids and remaining:
        deferred_ids = [action["id"] for action in remaining if action.get("id")]

    runnable_ids = [action["id"] for action in ordered if action.get("id")]
    return selected, runnable_ids, deferred_ids


def _select_followup_actions(
    runnable: list[dict[str, Any]],
    *,
    completed_ids: set[str],
    limit: int,
) -> list[str]:
    remaining = [action for action in runnable if action.get("id") not in completed_ids]
    if not remaining or limit < 1:
        return []

    indexed = {action.get("id"): action for action in remaining if action.get("id")}
    ordered = sorted(
        remaining,
        key=lambda item: (_phase_rank(item.get("phase")), int(item.get("priority", 0)), item.get("id", "")),
        reverse=True,
    )
    selected: list[str] = []
    progressed_ids = set(completed_ids)

    while ordered and len(selected) < limit:
        progressed = False
        deferred: list[dict[str, Any]] = []
        skipped_tail: list[dict[str, Any]] = []
        for index, action in enumerate(ordered):
            depends_on = list(action.get("depends_on") or [])
            if any(dependency in indexed and dependency not in progressed_ids for dependency in depends_on):
                deferred.append(action)
                continue
            action_id = action.get("id")
            if action_id:
                selected.append(action_id)
                progressed_ids.add(action_id)
            progressed = True
            if len(selected) >= limit:
                skipped_tail = ordered[index + 1 :]
                break
        if not progressed:
            break
        ordered = deferred + skipped_tail

    return selected


def _phase_rank(phase: str | None) -> int:
    order = {
        "triage": 1,
        "execution": 2,
        "synthesis": 3,
    }
    return order.get(phase or "execution", 0)


def _validate_suggested_cli(action: dict[str, Any]) -> list[str]:
    argv = list(action.get("suggested_cli") or [])
    if len(argv) < 4:
        raise ExecutorError(f"unsupported suggested_cli for action {action.get('id')}: too short")
    if argv[0] != "python3" or argv[1:3] != ["-m", "src.main"]:
        raise ExecutorError(f"unsupported suggested_cli for action {action.get('id')}: {_shell_join(argv)}")
    if argv[3] not in ALLOWED_MAIN_SUBCOMMANDS:
        raise ExecutorError(
            f"subcommand not allowed for action {action.get('id')}: {argv[3]}"
        )
    root = _extract_root(argv)
    if not root.exists() or not root.is_dir():
        raise ExecutorError(f"invalid --root for action {action.get('id')}: {root}")
    return argv


def _extract_root(argv: list[str]) -> Path:
    try:
        root_index = argv.index("--root")
    except ValueError as exc:
        raise ExecutorError(f"suggested_cli missing --root: {_shell_join(argv)}") from exc
    if root_index + 1 >= len(argv):
        raise ExecutorError(f"suggested_cli has empty --root: {_shell_join(argv)}")
    return Path(argv[root_index + 1]).resolve()


def _shell_join(argv: list[str]) -> str:
    quoted: list[str] = []
    for token in argv:
        if not token or any(char.isspace() for char in token):
            quoted.append(json.dumps(token))
        else:
            quoted.append(token)
    return " ".join(quoted)
