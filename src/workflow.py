from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compdb import CompileDatabase
from .config import AgentConfig
from .function_index import build_function_index
from .hotspots import FileHotspot, FunctionHotspot, rank_function_hotspots, rank_hotspots
from .pipeline import RebuildVerifyResult, rebuild_and_verify
from .planio import VerificationPlan
from .policy import CommandPolicy, CommandResult
from .reporting import render_markdown
from .rebuild import extract_targets
from .scanner import ScanResult, scan_project
from .surfaces import InputSurface, detect_input_surfaces
from .trace import AuditTrace, new_trace
from .verification import VerificationResult, run_binary


@dataclass
class WorkflowResult:
    scan: ScanResult
    command_logs: list[CommandResult]
    report_markdown: str
    trace: AuditTrace
    input_surfaces: list[InputSurface]
    hotspots: list[FileHotspot]
    function_hotspots: list[FunctionHotspot]
    function_coverage: dict[str, int]
    compile_db_summary: dict[str, Any] | None = None
    verification: VerificationResult | None = None
    rebuild_verify: RebuildVerifyResult | None = None


class AuditWorkflow:
    def __init__(self, root: Path, config: AgentConfig | None = None):
        self.root = root.resolve()
        self.config = config or AgentConfig()
        self.policy = CommandPolicy(
            self.root,
            allowlist=self.config.allowlist,
            timeout_seconds=self.config.timeout_seconds,
        )

    def run(self) -> WorkflowResult:
        trace = new_trace()
        command_logs: list[CommandResult] = []
        discovery = self.policy.run(["find", ".", "-maxdepth", "2", "-type", "f"])
        command_logs.append(discovery)
        trace.add("project-discovery", "ok", command="find . -maxdepth 2 -type f", returncode=discovery.returncode)
        function_index = build_function_index(self.root)
        trace.add("function-detection", "ok", functions=function_index.function_count())
        scan = scan_project(self.root, function_index=function_index)
        trace.add("source-scan", "ok", files_scanned=scan.files_scanned, findings=len(scan.findings))
        input_surfaces = detect_input_surfaces(self.root, function_index=function_index)
        trace.add("input-surface-detection", "ok", surfaces=len(input_surfaces))

        compile_db_summary = None
        compdb_path = self.root / "compile_commands.json"
        if compdb_path.exists():
            compdb = CompileDatabase.load(compdb_path)
            compile_db_summary = compdb.summary()
            compile_db_summary["targets"] = len(extract_targets(compdb))
            trace.add(
                "compile-db",
                "found",
                entries=compile_db_summary["entries"],
                targets=compile_db_summary["targets"],
            )
        else:
            trace.add("compile-db", "missing")

        verification = None
        rebuild_verify = None
        plan_path = self.root / "verification-plan.json"
        if plan_path.exists():
            plan = VerificationPlan.load(plan_path)
            binary_path = self.root / plan.binary
            trace.add("verification-plan", "found", binary=plan.binary, argc=len(plan.args))
            if binary_path.exists():
                trace.add("verification-binary", "found", binary=plan.binary)
                verification = run_binary(self.policy, binary_path, args=plan.args)
                trace.add(
                    "verification-run",
                    "ok",
                    binary=plan.binary,
                    returncode=verification.returncode,
                    sanitizer_signal=verification.sanitizer_signal,
                )
            else:
                trace.add("verification-binary", "missing", binary=plan.binary)
                trace.add("verification-run", "skipped", reason="binary missing", binary=plan.binary)
        else:
            trace.add("verification-plan", "missing")

        compdb_path = self.root / "compile_commands.json"
        if compdb_path.exists():
            trace.add("rebuild-target-selection", "ready", target_index=1)
            rebuild_verify = rebuild_and_verify(
                root=self.root,
                config=self.config,
                target_index=1,
                output_name="audit-sanitized-target",
                compdb_path=compdb_path,
                plan_path=plan_path if plan_path.exists() else None,
            )
            rebuild_status = "ok"
            rebuild_reason = None
            if rebuild_verify.rebuild.returncode != 0:
                rebuild_status = "failed"
                rebuild_reason = "rebuild command failed"
            elif not plan_path.exists():
                rebuild_status = "partial"
                rebuild_reason = "verification plan missing"
            elif rebuild_verify.verification is None:
                rebuild_status = "partial"
                rebuild_reason = "verification did not execute"
            trace.add(
                "rebuild-verify",
                rebuild_status,
                rebuild_returncode=rebuild_verify.rebuild.returncode,
                verify_returncode=(rebuild_verify.verification.returncode if rebuild_verify.verification is not None else "none"),
                verify_signal=(rebuild_verify.verification.sanitizer_signal if rebuild_verify.verification is not None else False),
                reason=rebuild_reason,
            )

        verified_signal = bool(
            (verification is not None and verification.sanitizer_signal)
            or (rebuild_verify is not None and rebuild_verify.verification is not None and rebuild_verify.verification.sanitizer_signal)
        )
        hotspots = rank_hotspots(scan, input_surfaces, verified_signal=verified_signal)
        function_hotspots = rank_function_hotspots(scan, input_surfaces, verified_signal=verified_signal)
        function_coverage = {
            "detected_functions": function_index.function_count(),
            "mapped_findings": sum(1 for finding in scan.findings if finding.function_name is not None),
            "unmapped_findings": sum(1 for finding in scan.findings if finding.function_name is None),
            "mapped_surfaces": sum(1 for surface in input_surfaces if surface.function_name is not None),
            "unmapped_surfaces": sum(1 for surface in input_surfaces if surface.function_name is None),
        }
        trace.add("hotspot-ranking", "ok", hotspots=len(hotspots), top=(hotspots[0].file_path if hotspots else "none"))
        trace.add(
            "function-hotspot-ranking",
            "ok",
            hotspots=len(function_hotspots),
            mapped_findings=function_coverage["mapped_findings"],
            mapped_surfaces=function_coverage["mapped_surfaces"],
        )
        report = render_markdown(scan, verified_signal=verified_signal)
        if hotspots:
            report += "\n## Risk Hotspots\n\n"
            for hotspot in hotspots[:10]:
                report += (
                    f"- `{hotspot.file_path}` score=**{hotspot.score}** findings={hotspot.findings} "
                    f"surfaces={hotspot.surfaces} verified={str(hotspot.verified).lower()}\n"
                )

        if function_hotspots:
            report += "\n## Function Focus\n\n"
            report += (
                f"- Coverage: functions={function_coverage['detected_functions']} "
                f"mapped-findings={function_coverage['mapped_findings']} "
                f"mapped-surfaces={function_coverage['mapped_surfaces']}\n"
            )
            for hotspot in function_hotspots[:10]:
                report += (
                    f"- `{hotspot.function_name}` in `{hotspot.file_path}` score=**{hotspot.score}** "
                    f"findings={hotspot.findings} surfaces={hotspot.surfaces} "
                    f"verified={str(hotspot.verified).lower()}\n"
                )

        if input_surfaces:
            report += "\n## Input Surfaces\n\n"
            for surface in input_surfaces[:20]:
                location = f"{surface.file_path}:{surface.line_number}"
                if surface.function_name is not None:
                    location += f" ({surface.function_name})"
                report += f"- `{surface.category}` in `{location}` → `{surface.line_text}`\n"

        if compile_db_summary:
            report += "\n## Compile Database\n\n"
            report += f"- Entries: **{compile_db_summary['entries']}**\n"
            report += f"- Targets: **{compile_db_summary['targets']}**\n"
            report += f"- Directories: `{', '.join(compile_db_summary['directories'])}`\n"
            report += f"- Files: `{', '.join(compile_db_summary['files'])}`\n"

        if verification is not None:
            report += "\n## Verification\n\n"
            report += f"- Binary: `{plan.binary}`\n"
            report += f"- Return code: **{verification.returncode}**\n"
            report += f"- Verification signal: **{str(verification.sanitizer_signal).lower()}**\n"
            if verification.stderr.strip():
                snippet = verification.stderr.strip().splitlines()[0]
                report += f"- Stderr head: `{snippet}`\n"
            if verification.returncode == 124:
                report += "- Note: verification command hit the policy timeout\n"

        if rebuild_verify is not None:
            report += "\n## Rebuild + Verify Pipeline\n\n"
            report += f"- Rebuild return code: **{rebuild_verify.rebuild.returncode}**\n"
            report += f"- Output binary: `{Path(rebuild_verify.output_binary).name}`\n"
            if rebuild_verify.verification is not None:
                report += f"- Verify return code: **{rebuild_verify.verification.returncode}**\n"
                report += f"- Verify signal: **{str(rebuild_verify.verification.sanitizer_signal).lower()}**\n"
                if rebuild_verify.verification.stderr.strip():
                    snippet = rebuild_verify.verification.stderr.strip().splitlines()[0]
                    report += f"- Verify stderr head: `{snippet}`\n"

        report += "\n" + trace.to_markdown()

        return WorkflowResult(
            scan=scan,
            command_logs=command_logs,
            report_markdown=report,
            trace=trace,
            input_surfaces=input_surfaces,
            hotspots=hotspots,
            function_hotspots=function_hotspots,
            function_coverage=function_coverage,
            compile_db_summary=compile_db_summary,
            verification=verification,
            rebuild_verify=rebuild_verify,
        )
