from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compdb import CompileDatabase
from .config import AgentConfig
from .hotspots import FileHotspot, rank_hotspots
from .pipeline import RebuildVerifyResult, rebuild_and_verify
from .planio import VerificationPlan
from .policy import CommandPolicy, CommandResult
from .reporting import render_markdown
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
        scan = scan_project(self.root)
        trace.add("source-scan", "ok", files_scanned=scan.files_scanned, findings=len(scan.findings))
        input_surfaces = detect_input_surfaces(self.root)
        trace.add("input-surface-detection", "ok", surfaces=len(input_surfaces))

        compile_db_summary = None
        compdb_path = self.root / "compile_commands.json"
        if compdb_path.exists():
            compile_db_summary = CompileDatabase.load(compdb_path).summary()
            trace.add("compile-db", "found", entries=compile_db_summary["entries"])
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
                verification = run_binary(self.policy, binary_path, args=plan.args)
                trace.add(
                    "verification-run",
                    "ok",
                    binary=plan.binary,
                    returncode=verification.returncode,
                    sanitizer_signal=verification.sanitizer_signal,
                )
            else:
                trace.add("verification-run", "skipped", reason="binary missing", binary=plan.binary)
        else:
            trace.add("verification-plan", "missing")

        compdb_path = self.root / "compile_commands.json"
        if compdb_path.exists():
            rebuild_verify = rebuild_and_verify(
                root=self.root,
                config=self.config,
                target_index=1,
                output_name="audit-sanitized-target",
                compdb_path=compdb_path,
                plan_path=plan_path if plan_path.exists() else None,
            )
            trace.add(
                "rebuild-verify",
                "ok",
                rebuild_returncode=rebuild_verify.rebuild.returncode,
                verify_returncode=(rebuild_verify.verification.returncode if rebuild_verify.verification is not None else "none"),
                verify_signal=(rebuild_verify.verification.sanitizer_signal if rebuild_verify.verification is not None else False),
            )

        verified_signal = bool(
            (verification is not None and verification.sanitizer_signal)
            or (rebuild_verify is not None and rebuild_verify.verification is not None and rebuild_verify.verification.sanitizer_signal)
        )
        hotspots = rank_hotspots(scan, input_surfaces, verified_signal=verified_signal)
        trace.add("hotspot-ranking", "ok", hotspots=len(hotspots), top=(hotspots[0].file_path if hotspots else "none"))
        report = render_markdown(scan, verified_signal=verified_signal)
        if hotspots:
            report += "\n## Risk Hotspots\n\n"
            for hotspot in hotspots[:10]:
                report += (
                    f"- `{hotspot.file_path}` score=**{hotspot.score}** findings={hotspot.findings} "
                    f"surfaces={hotspot.surfaces} verified={str(hotspot.verified).lower()}\n"
                )

        if input_surfaces:
            report += "\n## Input Surfaces\n\n"
            for surface in input_surfaces[:20]:
                report += f"- `{surface.category}` in `{surface.file_path}:{surface.line_number}` → `{surface.line_text}`\n"

        if compile_db_summary:
            report += "\n## Compile Database\n\n"
            report += f"- Entries: **{compile_db_summary['entries']}**\n"
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
            compile_db_summary=compile_db_summary,
            verification=verification,
            rebuild_verify=rebuild_verify,
        )
