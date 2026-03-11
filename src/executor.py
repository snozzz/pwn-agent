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
class ExecutionSummary:
    plan_path: str
    executed: int
    selected_action_ids: list[str]
    stopped_reason: str
    records: list[ExecutionRecord]

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_path": self.plan_path,
            "executed": self.executed,
            "selected_action_ids": self.selected_action_ids,
            "stopped_reason": self.stopped_reason,
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
) -> ExecutionSummary:
    if max_actions < 1:
        raise ExecutorError("max_actions must be >= 1")

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    actions = list(plan.get("next_actions", []))

    selected = _select_actions(actions, action_id=action_id, phase=phase, max_actions=max_actions)
    records: list[ExecutionRecord] = []
    stopped_reason = "no-executable-actions"
    completed_ids: set[str] = set()

    for action in selected:
        argv = _validate_suggested_cli(action)
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
            stopped_reason = "dry-run"
            completed_ids.add(action["id"])
            continue

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
            stopped_reason = "command-failed"
            break
        completed_ids.add(action["id"])
    else:
        if records and stopped_reason == "no-executable-actions":
            stopped_reason = "completed"

    return ExecutionSummary(
        plan_path=str(plan_path),
        executed=sum(1 for record in records if record.status in {"ok", "failed"}),
        selected_action_ids=[action["id"] for action in selected],
        stopped_reason=stopped_reason,
        records=records,
    )


def write_execution_summary(path: Path, summary: ExecutionSummary) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")


def render_execution_markdown(summary: ExecutionSummary) -> str:
    lines = ["# Plan Execution", ""]
    lines.append(f"- Plan: `{summary.plan_path}`")
    lines.append(f"- Executed: {summary.executed}")
    lines.append(f"- Stopped reason: {summary.stopped_reason}")
    if summary.selected_action_ids:
        lines.append(f"- Selected actions: {', '.join(summary.selected_action_ids)}")
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


def _select_actions(
    actions: list[dict[str, Any]],
    *,
    action_id: str | None,
    phase: str | None,
    max_actions: int,
) -> list[dict[str, Any]]:
    runnable = [
        action
        for action in actions
        if action.get("status") == "ready" and action.get("suggested_cli")
    ]
    if phase is not None:
        runnable = [action for action in runnable if action.get("phase") == phase]
        if not runnable:
            raise ExecutorError(f"ready phase not found: {phase}")
    if action_id is not None:
        runnable = [action for action in runnable if action.get("id") == action_id]
        if not runnable:
            raise ExecutorError(f"ready action not found: {action_id}")

    indexed = {action.get("id"): action for action in runnable if action.get("id")}
    ordered = sorted(
        runnable,
        key=lambda item: (_phase_rank(item.get("phase")), int(item.get("priority", 0)), item.get("id", "")),
        reverse=True,
    )
    selected: list[dict[str, Any]] = []
    completed: set[str] = set()
    remaining = list(ordered)

    while remaining and len(selected) < max_actions:
        progressed = False
        deferred: list[dict[str, Any]] = []
        for action in remaining:
            depends_on = list(action.get("depends_on") or [])
            if any(dependency in indexed and dependency not in completed for dependency in depends_on):
                deferred.append(action)
                continue
            selected.append(action)
            completed.add(action["id"])
            progressed = True
            if len(selected) >= max_actions:
                break
        if not progressed:
            break
        remaining = deferred

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
