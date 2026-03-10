from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import AgentConfig
from .policy import CommandPolicy, CommandResult
from .reporting import render_markdown
from .scanner import ScanResult, scan_project


@dataclass
class WorkflowResult:
    scan: ScanResult
    command_logs: list[CommandResult]
    report_markdown: str


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
        report = render_markdown(scan)
        return WorkflowResult(scan=scan, command_logs=command_logs, report_markdown=report)
