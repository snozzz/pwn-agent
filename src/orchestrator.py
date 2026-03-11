from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json
from typing import Any


PLAN_SCHEMA_VERSION = 2


@dataclass
class PlannedAction:
    id: str
    kind: str
    phase: str
    title: str
    status: str
    priority: int
    rationale: str
    depends_on: list[str]
    blocked_by: list[str]
    prerequisites: list[dict[str, Any]]
    suggested_cli: list[str] | None
    expected_outcome: str | None
    params: dict[str, Any]


@dataclass
class OrchestrationPlan:
    schema_version: int
    plan_fingerprint: str
    assessment: str
    top_risks: list[str]
    evidence_used: list[str]
    readiness: dict[str, Any]
    stage_guidance: dict[str, Any]
    next_actions: list[PlannedAction]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_fingerprint": self.plan_fingerprint,
            "assessment": self.assessment,
            "top_risks": self.top_risks,
            "evidence_used": self.evidence_used,
            "readiness": self.readiness,
            "stage_guidance": self.stage_guidance,
            "next_actions": [asdict(action) for action in self.next_actions],
        }


def load_audit_summary(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_plan(summary: dict[str, Any]) -> OrchestrationPlan:
    scan_summary = summary.get("scan_summary", {})
    findings = summary.get("classified_findings", [])
    file_hotspots = summary.get("file_hotspots", [])
    function_hotspots = summary.get("function_hotspots", [])
    input_surfaces = summary.get("input_surfaces", [])
    file_rollups = summary.get("file_rollups", [])
    function_rollups = summary.get("function_rollups", [])
    verification = summary.get("verification")
    rebuild_verify = summary.get("rebuild_verify")
    readiness = summary.get("execution_readiness", {})
    root = summary.get("root", ".")

    verified_signal = bool(scan_summary.get("verified_signal"))
    top_risks = []
    evidence_used = []
    actions: list[PlannedAction] = []

    for finding in findings[:3]:
        label = f"{finding['category']} at {finding['file_path']}:{finding['line_number']}"
        if finding.get("function_name"):
            label += f" ({finding['function_name']})"
        top_risks.append(label)

    if verified_signal:
        evidence_used.append("runtime verification signal detected")
    if verification:
        evidence_used.append(f"verification rc={verification.get('returncode')}")
    if rebuild_verify and rebuild_verify.get("verification"):
        evidence_used.append(f"rebuild-verify rc={rebuild_verify['verification'].get('returncode')}")
    if function_hotspots:
        evidence_used.append("function hotspot ranking available")
    if input_surfaces:
        evidence_used.append("input surface detection available")
    if readiness.get("missing_prerequisites"):
        evidence_used.append("missing prerequisites tracked for execution paths")

    actions.extend(_build_context_actions(function_hotspots, function_rollups, file_hotspots, file_rollups, input_surfaces))
    actions.extend(_build_execution_actions(summary, readiness, root=root))

    if rebuild_verify and rebuild_verify.get("rebuild", {}).get("returncode") not in (None, 0):
        actions.append(
            PlannedAction(
                id="inspect-rebuild-failure",
                kind="inspect_rebuild_failure",
                phase="execution",
                title="Inspect the sanitizer rebuild failure before retrying verification",
                status="ready",
                priority=65,
                rationale="rebuild failed, so the verification path is blocked on build issues",
                depends_on=[],
                blocked_by=[],
                prerequisites=_prerequisites(("compile_commands.json", True, "build metadata already loaded")),
                suggested_cli=[
                    "python3",
                    "-m",
                    "src.main",
                    "rebuild-plan",
                    "--root",
                    str(root),
                ],
                expected_outcome="identify the failing target or unsupported build flags",
                params={"stderr_head": rebuild_verify.get("rebuild", {}).get("stderr_head")},
            )
        )

    if verified_signal:
        actions.append(
            PlannedAction(
                id="explain-root-cause",
                kind="explain_root_cause",
                phase="synthesis",
                title="Summarize the likely root cause from verified evidence",
                status="ready",
                priority=60,
                rationale="verification evidence exists; summarize likely root cause before deeper expansion",
                depends_on=[],
                blocked_by=[],
                prerequisites=[],
                suggested_cli=None,
                expected_outcome="turn sanitizer output and static findings into a concise bug hypothesis",
                params={
                    "max_findings": 3,
                },
            )
        )

    for index, blocked in enumerate(readiness.get("blocked_actions", []), start=1):
        actions.append(
            PlannedAction(
                id=f"blocked-{blocked.get('kind', 'action')}-{index}",
                kind=blocked.get("kind", "blocked_action"),
                phase="execution",
                title=f"Blocked: {blocked.get('kind', 'action')}",
                status="blocked",
                priority=40 - index,
                rationale="required execution path is not runnable until missing prerequisites are satisfied",
                depends_on=[],
                blocked_by=list(blocked.get("missing", [])),
                prerequisites=[
                    {"label": item, "present": False, "detail": "missing prerequisite"}
                    for item in blocked.get("missing", [])
                ],
                suggested_cli=None,
                expected_outcome="unblock a runnable verification or rebuild step",
                params=blocked,
            )
        )

    actions.sort(key=lambda action: (int(action.priority), action.id), reverse=True)
    phase_counts = _count_by_phase(actions)
    ready_actions = sum(1 for action in actions if action.status == "ready")
    runnable_actions = sum(1 for action in actions if action.status == "ready" and action.suggested_cli)
    blocked_actions = sum(1 for action in actions if action.status == "blocked")
    context_actions = sum(1 for action in actions if action.status == "context")
    stage_guidance = _build_stage_guidance(actions)

    assessment = _build_assessment(scan_summary, verified_signal, file_hotspots, function_hotspots)
    plan_fingerprint = _compute_plan_fingerprint(actions)
    return OrchestrationPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        plan_fingerprint=plan_fingerprint,
        assessment=assessment,
        top_risks=top_risks,
        evidence_used=evidence_used,
        readiness={
            "ready_actions": ready_actions,
            "runnable_actions": runnable_actions,
            "blocked_actions": blocked_actions,
            "context_actions": context_actions,
            "phase_counts": phase_counts,
            "missing_prerequisites": readiness.get("missing_prerequisites", []),
            "verification_state": readiness.get("verification_state"),
            "rebuild_state": readiness.get("rebuild_state"),
        },
        stage_guidance=stage_guidance,
        next_actions=actions,
    )


def write_plan(path: Path, plan: OrchestrationPlan) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan.to_dict(), indent=2), encoding="utf-8")


def render_plan_markdown(plan: OrchestrationPlan) -> str:
    lines = [
        "# Orchestration Plan",
        "",
        f"- Schema version: {plan.schema_version}",
        f"- Plan fingerprint: `{plan.plan_fingerprint}`",
        f"- Assessment: {plan.assessment}",
        "",
    ]
    lines.extend(["## Readiness", ""])
    lines.append(f"- Ready actions: {plan.readiness.get('ready_actions', 0)}")
    lines.append(f"- Runnable actions: {plan.readiness.get('runnable_actions', 0)}")
    lines.append(f"- Blocked actions: {plan.readiness.get('blocked_actions', 0)}")
    lines.append(f"- Context actions: {plan.readiness.get('context_actions', 0)}")
    phase_counts = plan.readiness.get("phase_counts", {})
    if phase_counts:
        lines.append(
            "- Phase counts: "
            + ", ".join(f"{phase}={count}" for phase, count in sorted(phase_counts.items()))
        )
    else:
        lines.append("- Phase counts: none")
    if plan.readiness.get("verification_state"):
        lines.append(f"- Verification state: {plan.readiness['verification_state']}")
    if plan.readiness.get("rebuild_state"):
        lines.append(f"- Rebuild state: {plan.readiness['rebuild_state']}")
    missing = plan.readiness.get("missing_prerequisites", [])
    if missing:
        lines.append(f"- Missing prerequisites: {', '.join(missing)}")
    lines.append("")
    lines.append("## Top Risks")
    lines.append("")
    if plan.top_risks:
        lines.extend([f"- {item}" for item in plan.top_risks])
    else:
        lines.append("- none")
    lines.extend(["", "## Evidence Used", ""])
    if plan.evidence_used:
        lines.extend([f"- {item}" for item in plan.evidence_used])
    else:
        lines.append("- none")
    lines.extend(["", "## Stage Guidance", ""])
    recommended = plan.stage_guidance.get("recommended_action_ids", [])
    if recommended:
        lines.append(f"- Recommended next actions: {', '.join(recommended)}")
    else:
        lines.append("- Recommended next actions: none")
    if plan.stage_guidance.get("recommended_phase"):
        lines.append(f"- Recommended phase: {plan.stage_guidance['recommended_phase']}")
    stage_heads = plan.stage_guidance.get("stage_heads", {})
    if stage_heads:
        lines.append(
            "- Stage heads: "
            + ", ".join(f"{phase}={action_id}" for phase, action_id in sorted(stage_heads.items()))
        )
    else:
        lines.append("- Stage heads: none")
    blocked = plan.stage_guidance.get("blocked_action_ids", [])
    if blocked:
        lines.append(f"- Blocked candidates: {', '.join(blocked)}")
    lines.extend(["", "## Next Actions", ""])
    if plan.next_actions:
        for action in plan.next_actions:
            lines.append(f"- [{action.priority}] [{action.phase}] [{action.status}] {action.title}")
            lines.append(f"  kind: `{action.kind}`")
            lines.append(f"  rationale: {action.rationale}")
            if action.depends_on:
                lines.append(f"  depends-on: {', '.join(action.depends_on)}")
            if action.blocked_by:
                lines.append(f"  blocked-by: {', '.join(action.blocked_by)}")
            if action.prerequisites:
                formatted = ", ".join(
                    f"{item['label']}={'yes' if item['present'] else 'no'}" for item in action.prerequisites
                )
                lines.append(f"  prerequisites: {formatted}")
            if action.suggested_cli:
                lines.append(f"  command: `{_shell_join(action.suggested_cli)}`")
            if action.expected_outcome:
                lines.append(f"  outcome: {action.expected_outcome}")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def _build_context_actions(
    function_hotspots: list[dict[str, Any]],
    function_rollups: list[dict[str, Any]],
    file_hotspots: list[dict[str, Any]],
    file_rollups: list[dict[str, Any]],
    input_surfaces: list[dict[str, Any]],
) -> list[PlannedAction]:
    actions: list[PlannedAction] = []

    if function_hotspots:
        top_function = function_hotspots[0]
        actions.append(
            PlannedAction(
                id="focus-function-1",
                kind="focus_functions",
                phase="triage",
                title=f"Inspect highest-ranked function hotspot: {top_function['function_name']}",
                status="context",
                priority=100,
                rationale="highest-ranked function hotspot should be inspected first",
                depends_on=[],
                blocked_by=[],
                prerequisites=[],
                suggested_cli=None,
                expected_outcome="identify the local code path most likely to explain current findings",
                params={
                    "file_path": top_function["file_path"],
                    "function_name": top_function["function_name"],
                    "score": top_function["score"],
                },
            )
        )
    elif function_rollups:
        top_function = function_rollups[0]
        actions.append(
            PlannedAction(
                id="focus-function-rollup-1",
                kind="focus_functions",
                phase="triage",
                title=f"Inspect top function rollup: {top_function['function_name']}",
                status="context",
                priority=95,
                rationale="function-level aggregation exists even when hotspot ranking is sparse",
                depends_on=[],
                blocked_by=[],
                prerequisites=[],
                suggested_cli=None,
                expected_outcome="map clustered findings and surfaces to one function scope",
                params=top_function,
            )
        )

    if file_hotspots:
        top_file = file_hotspots[0]
        actions.append(
            PlannedAction(
                id="inspect-file-1",
                kind="inspect_file",
                phase="triage",
                title=f"Inspect highest-ranked file hotspot: {top_file['file_path']}",
                status="context",
                priority=90,
                rationale="top file hotspot concentrates current findings and surfaces",
                depends_on=[],
                blocked_by=[],
                prerequisites=[],
                suggested_cli=None,
                expected_outcome="confirm whether the file contains the shortest path to a fix or proof",
                params={"file_path": top_file["file_path"]},
            )
        )
    elif file_rollups:
        top_file = file_rollups[0]
        actions.append(
            PlannedAction(
                id="inspect-file-rollup-1",
                kind="inspect_file",
                phase="triage",
                title=f"Inspect top file rollup: {top_file['file_path']}",
                status="context",
                priority=85,
                rationale="file-level aggregation captures combined finding and surface density",
                depends_on=[],
                blocked_by=[],
                prerequisites=[],
                suggested_cli=None,
                expected_outcome="confirm the file-level concentration of suspicious behavior",
                params=top_file,
            )
        )

    if input_surfaces:
        surface = input_surfaces[0]
        actions.append(
            PlannedAction(
                id="trace-input-1",
                kind="trace_input_surface",
                phase="triage",
                title=f"Trace top input surface from {surface['file_path']}:{surface['line_number']}",
                status="context",
                priority=80,
                rationale="input entrypoints are the best place to start dataflow review",
                depends_on=[],
                blocked_by=[],
                prerequisites=[],
                suggested_cli=None,
                expected_outcome="connect attacker-controlled input to the finding cluster",
                params={
                    "file_path": surface["file_path"],
                    "line_number": surface["line_number"],
                    "category": surface["category"],
                    "function_name": surface.get("function_name"),
                },
            )
        )

    return actions


def _build_execution_actions(summary: dict[str, Any], readiness: dict[str, Any], *, root: str) -> list[PlannedAction]:
    actions: list[PlannedAction] = []
    verification_state = readiness.get("verification_state")
    rebuild_state = readiness.get("rebuild_state")

    for action in readiness.get("ready_actions", []):
        kind = action.get("kind", "ready-action")
        suggested_cli = list(action.get("cli") or []) or None
        detail = action.get("detail")

        if kind == "verify-run":
            title = "Run the configured verification binary"
            rationale = "verification inputs are configured and can be executed immediately"
            expected_outcome = "capture runtime evidence before changing the build"
            priority = 75
            if verification_state in {"signal-detected", "completed-no-signal"}:
                title = "Re-run the configured verification binary"
                rationale = "verification can still be replayed to confirm reproducibility or compare later edits"
                expected_outcome = "refresh the runtime signal using the current binary and inputs"
                priority = 58
            actions.append(
                PlannedAction(
                    id="verify-existing-binary",
                    kind="verify_binary",
                    phase="execution",
                    title=title,
                    status="ready",
                    priority=priority,
                    rationale=rationale,
                    depends_on=[],
                    blocked_by=[],
                    prerequisites=_prerequisites(
                        ("verification-plan.json", readiness.get("has_verification_plan", False), "argv is available"),
                        (
                            readiness.get("verification_binary") or "verification binary",
                            readiness.get("verification_binary_present", False),
                            "binary exists in the workspace",
                        ),
                    ),
                    suggested_cli=suggested_cli,
                    expected_outcome=expected_outcome,
                    params={
                        "binary": readiness.get("verification_binary"),
                        "detail": detail,
                    },
                )
            )
        elif kind == "rebuild-plan":
            actions.append(
                PlannedAction(
                    id="list-rebuild-targets",
                    kind="list_rebuild_targets",
                    phase="execution",
                    title="Enumerate sanitizer rebuild targets from compile_commands.json",
                    status="ready",
                    priority=72,
                    rationale="compile database metadata is available and should stay visible to the planner",
                    depends_on=[],
                    blocked_by=[],
                    prerequisites=_prerequisites(
                        ("compile_commands.json", readiness.get("has_compile_database", False), "rebuild target metadata available"),
                    ),
                    suggested_cli=suggested_cli,
                    expected_outcome="show which compile database targets can be rebuilt under sanitizers",
                    params={"detail": detail},
                )
            )
        elif kind == "rebuild-target":
            depends_on = ["list-rebuild-targets"] if readiness.get("has_compile_database") else []
            priority = 68
            title = "Rebuild target 1 with sanitizer flags"
            rationale = "the compile database is present, so a bounded sanitizer rebuild is available"
            expected_outcome = "produce a sanitized binary for follow-up execution"
            if rebuild_state in {"signal-detected", "completed-no-signal", "rebuilt-no-verification-plan"}:
                title = "Rebuild target 1 again with sanitizer flags"
                rationale = "rebuilding remains useful after audit iterations or source edits"
                priority = 54
                expected_outcome = "refresh the sanitized binary used for downstream validation"
            actions.append(
                PlannedAction(
                    id="rebuild-target-1",
                    kind="rebuild_target",
                    phase="execution",
                    title=title,
                    status="ready",
                    priority=priority,
                    rationale=rationale,
                    depends_on=depends_on,
                    blocked_by=[],
                    prerequisites=_prerequisites(
                        ("compile_commands.json", readiness.get("has_compile_database", False), "rebuild target metadata available"),
                    ),
                    suggested_cli=suggested_cli,
                    expected_outcome=expected_outcome,
                    params={"target_index": 1, "detail": detail},
                )
            )
        elif kind == "rebuild-verify":
            depends_on = ["rebuild-target-1"] if readiness.get("has_compile_database") else []
            priority = 70
            title = "Rebuild target 1 with sanitizers and execute the verification plan"
            rationale = "compile database and verification inputs are both present"
            expected_outcome = "produce a sanitized binary and runtime signal if the bug is reproducible"
            if rebuild_state in {"signal-detected", "completed-no-signal"}:
                title = "Re-run rebuild plus verification for target 1"
                rationale = "the rebuild+verify flow remains a useful replayable proof step"
                priority = 56
                expected_outcome = "refresh the sanitized execution evidence after later changes"
            actions.append(
                PlannedAction(
                    id="run-rebuild-verify",
                    kind="run_rebuild_verify",
                    phase="execution",
                    title=title,
                    status="ready",
                    priority=priority,
                    rationale=rationale,
                    depends_on=depends_on,
                    blocked_by=[],
                    prerequisites=_prerequisites(
                        ("compile_commands.json", readiness.get("has_compile_database", False), "rebuild target metadata available"),
                        ("verification-plan.json", readiness.get("has_verification_plan", False), "verification args available"),
                    ),
                    suggested_cli=suggested_cli,
                    expected_outcome=expected_outcome,
                    params={"target_index": 1, "output_name": "planned-sanitized-target", "detail": detail},
                )
            )
        else:
            actions.append(
                PlannedAction(
                    id=f"ready-{kind}",
                    kind=kind,
                    phase="execution",
                    title=detail or f"Run {kind}",
                    status="ready",
                    priority=50,
                    rationale="execution readiness surfaced a directly runnable internal action",
                    depends_on=[],
                    blocked_by=[],
                    prerequisites=[],
                    suggested_cli=suggested_cli,
                    expected_outcome="advance the audit through a bounded internal command",
                    params={"detail": detail},
                )
            )

    return actions


def _compute_plan_fingerprint(actions: list[PlannedAction]) -> str:
    payload = [
        {
            "id": action.id,
            "kind": action.kind,
            "phase": action.phase,
            "status": action.status,
            "priority": action.priority,
            "depends_on": action.depends_on,
            "blocked_by": action.blocked_by,
            "suggested_cli": action.suggested_cli,
            "params": action.params,
        }
        for action in actions
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _count_by_phase(actions: list[PlannedAction]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for action in actions:
        counts[action.phase] = counts.get(action.phase, 0) + 1
    return counts


def _build_stage_guidance(actions: list[PlannedAction]) -> dict[str, Any]:
    stage_heads: dict[str, str] = {}
    blocked_action_ids: list[str] = []

    for phase in ("triage", "execution", "synthesis"):
        candidates = [action for action in actions if action.phase == phase]
        if not candidates:
            continue
        ranked = sorted(candidates, key=lambda item: (int(item.priority), item.id), reverse=True)
        stage_heads[phase] = ranked[0].id

    runnable = [action for action in actions if action.status == "ready" and action.suggested_cli]
    recommended = _select_recommended_actions(runnable, max_actions=3)
    if not recommended:
        context_actions = [action for action in actions if action.status == "context"]
        recommended = [action.id for action in sorted(context_actions, key=lambda item: (int(item.priority), item.id), reverse=True)[:3]]

    blocked_action_ids = [
        action.id
        for action in sorted(
            [action for action in actions if action.status == "blocked"],
            key=lambda item: (int(item.priority), item.id),
            reverse=True,
        )[:3]
    ]

    recommended_phase = None
    if recommended:
        recommended_phase = next((action.phase for action in actions if action.id == recommended[0]), None)

    return {
        "recommended_action_ids": recommended,
        "recommended_phase": recommended_phase,
        "stage_heads": stage_heads,
        "blocked_action_ids": blocked_action_ids,
    }


def _select_recommended_actions(actions: list[PlannedAction], *, max_actions: int) -> list[str]:
    indexed = {action.id: action for action in actions}
    ordered = sorted(actions, key=lambda item: (_phase_rank(item.phase), int(item.priority), item.id), reverse=True)
    selected: list[str] = []
    completed: set[str] = set()
    remaining = list(ordered)

    while remaining and len(selected) < max_actions:
        progressed = False
        deferred: list[PlannedAction] = []
        skipped_tail: list[PlannedAction] = []
        for index, action in enumerate(remaining):
            if any(dep in indexed and dep not in completed for dep in action.depends_on):
                deferred.append(action)
                continue
            selected.append(action.id)
            completed.add(action.id)
            progressed = True
            if len(selected) >= max_actions:
                skipped_tail = remaining[index + 1 :]
                break
        if not progressed:
            break
        remaining = deferred + skipped_tail

    return selected


def _phase_rank(phase: str | None) -> int:
    order = {
        "triage": 1,
        "execution": 2,
        "synthesis": 3,
    }
    return order.get(phase or "execution", 0)


def _build_assessment(
    scan_summary: dict[str, Any],
    verified_signal: bool,
    file_hotspots: list[dict[str, Any]],
    function_hotspots: list[dict[str, Any]],
) -> str:
    findings = scan_summary.get("findings", 0)
    if findings == 0:
        return "no current findings; keep monitoring input surfaces and build metadata"
    if verified_signal:
        if function_hotspots:
            return f"verified memory-safety risk present; start from function hotspot {function_hotspots[0]['function_name']}"
        if file_hotspots:
            return f"verified risk present; start from top file hotspot {file_hotspots[0]['file_path']}"
        return "verified risk present; inspect top findings first"
    if file_hotspots:
        return f"heuristic risk cluster present; start from {file_hotspots[0]['file_path']}"
    return "heuristic findings present; inspect top findings first"


def _prerequisites(*items: tuple[str, bool, str]) -> list[dict[str, Any]]:
    return [{"label": label, "present": present, "detail": detail} for label, present, detail in items]


def _shell_join(argv: list[str]) -> str:
    quoted: list[str] = []
    for token in argv:
        if not token or any(char.isspace() for char in token):
            quoted.append(json.dumps(token))
        else:
            quoted.append(token)
    return " ".join(quoted)
