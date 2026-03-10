from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compdb import CompileDatabase
from .config import AgentConfig
from .policy import CommandPolicy, CommandResult
from .reporting import render_markdown
from .scanner import ScanResult, scan_project


@dataclass
class WorkflowResult:
    scan: ScanResult
    command_logs: list[CommandResult]
    report_markdown: str
    compile_db_summary: dict[str, Any] | None = None


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

        return WorkflowResult(
            scan=scan,
            command_logs=command_logs,
            report_markdown=report,
            compile_db_summary=compile_db_summary,
        )
