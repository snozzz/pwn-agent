from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compdb import CompileDatabase
from .config import AgentConfig
from .pipeline import RebuildVerifyResult, rebuild_and_verify
from .planio import VerificationPlan
from .policy import CommandPolicy, CommandResult
from .reporting import render_markdown
from .scanner import ScanResult, scan_project
from .verification import VerificationResult, run_binary


@dataclass
class WorkflowResult:
    scan: ScanResult
    command_logs: list[CommandResult]
    report_markdown: str
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
        command_logs: list[CommandResult] = []
        command_logs.append(self.policy.run(["find", ".", "-maxdepth", "2", "-type", "f"]))
        scan = scan_project(self.root)

        compile_db_summary = None
        compdb_path = self.root / "compile_commands.json"
        if compdb_path.exists():
            compile_db_summary = CompileDatabase.load(compdb_path).summary()

        report = render_markdown(scan)
        if compile_db_summary:
            report += "\n## Compile Database\n\n"
            report += f"- Entries: **{compile_db_summary['entries']}**\n"
            report += f"- Directories: `{', '.join(compile_db_summary['directories'])}`\n"
            report += f"- Files: `{', '.join(compile_db_summary['files'])}`\n"

        verification = None
        rebuild_verify = None
        plan_path = self.root / "verification-plan.json"
        if plan_path.exists():
            plan = VerificationPlan.load(plan_path)
            binary_path = self.root / plan.binary
            if binary_path.exists():
                verification = run_binary(self.policy, binary_path, args=plan.args)
                report += "\n## Verification\n\n"
                report += f"- Binary: `{plan.binary}`\n"
                report += f"- Return code: **{verification.returncode}**\n"
                report += f"- Verification signal: **{str(verification.sanitizer_signal).lower()}**\n"
                if verification.stderr.strip():
                    snippet = verification.stderr.strip().splitlines()[0]
                    report += f"- Stderr head: `{snippet}`\n"
                if verification.returncode == 124:
                    report += "- Note: verification command hit the policy timeout\n"

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
            report += "\n## Rebuild + Verify Pipeline\n\n"
            report += f"- Rebuild return code: **{rebuild_verify.rebuild.returncode}**\n"
            report += f"- Output binary: `{Path(rebuild_verify.output_binary).name}`\n"
            if rebuild_verify.verification is not None:
                report += f"- Verify return code: **{rebuild_verify.verification.returncode}**\n"
                report += f"- Verify signal: **{str(rebuild_verify.verification.sanitizer_signal).lower()}**\n"
                if rebuild_verify.verification.stderr.strip():
                    snippet = rebuild_verify.verification.stderr.strip().splitlines()[0]
                    report += f"- Verify stderr head: `{snippet}`\n"

        return WorkflowResult(
            scan=scan,
            command_logs=command_logs,
            report_markdown=report,
            compile_db_summary=compile_db_summary,
            verification=verification,
            rebuild_verify=rebuild_verify,
        )
