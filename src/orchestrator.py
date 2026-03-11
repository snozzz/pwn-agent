from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
from typing import Any


@dataclass
class PlannedAction:
    kind: str
    priority: int
    rationale: str
    params: dict[str, Any]


@dataclass
class OrchestrationPlan:
    assessment: str
    top_risks: list[str]
    evidence_used: list[str]
    next_actions: list[PlannedAction]

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment,
            "top_risks": self.top_risks,
            "evidence_used": self.evidence_used,
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
    verification = summary.get("verification")
    rebuild_verify = summary.get("rebuild_verify")

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

    if function_hotspots:
        top_function = function_hotspots[0]
        actions.append(
            PlannedAction(
                kind="focus_functions",
                priority=100,
                rationale="highest-ranked function hotspot should be inspected first",
                params={
                    "file_path": top_function["file_path"],
                    "function_name": top_function["function_name"],
                },
            )
        )

    if file_hotspots:
        top_file = file_hotspots[0]
        actions.append(
            PlannedAction(
                kind="inspect_file",
                priority=90,
                rationale="top file hotspot concentrates current findings and surfaces",
                params={"file_path": top_file["file_path"]},
            )
        )

    if input_surfaces:
        surface = input_surfaces[0]
        actions.append(
            PlannedAction(
                kind="trace_input_surface",
                priority=80,
                rationale="input entrypoints are the best place to start dataflow review",
                params={
                    "file_path": surface["file_path"],
                    "line_number": surface["line_number"],
                    "category": surface["category"],
                    "function_name": surface.get("function_name"),
                },
            )
        )

    if summary.get("compile_database") and not rebuild_verify:
        actions.append(
            PlannedAction(
                kind="run_rebuild_verify",
                priority=70,
                rationale="compile database exists but rebuild verification evidence is missing",
                params={"target_index": 1, "output_name": "planned-sanitized-target"},
            )
        )

    if verified_signal:
        actions.append(
            PlannedAction(
                kind="explain_root_cause",
                priority=60,
                rationale="verification evidence exists; summarize likely root cause before deeper expansion",
                params={
                    "max_findings": 3,
                },
            )
        )

    assessment = _build_assessment(scan_summary, verified_signal, file_hotspots, function_hotspots)
    return OrchestrationPlan(
        assessment=assessment,
        top_risks=top_risks,
        evidence_used=evidence_used,
        next_actions=actions,
    )


def write_plan(path: Path, plan: OrchestrationPlan) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan.to_dict(), indent=2), encoding="utf-8")


def render_plan_markdown(plan: OrchestrationPlan) -> str:
    lines = ["# Orchestration Plan", "", f"- Assessment: {plan.assessment}", ""]
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
    lines.extend(["", "## Next Actions", ""])
    if plan.next_actions:
        for action in plan.next_actions:
            lines.append(f"- [{action.priority}] {action.kind}: {action.rationale}")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


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
