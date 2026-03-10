from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .compdb import CompileDatabase
from .config import AgentConfig
from .planio import VerificationPlan
from .policy import CommandPolicy, CommandResult
from .rebuild import default_compdb_path, extract_targets, rebuild_target
from .verification import VerificationResult, run_binary


@dataclass
class RebuildVerifyResult:
    rebuild: CommandResult
    verification: VerificationResult | None
    output_binary: str


def rebuild_and_verify(
    root: Path,
    config: AgentConfig,
    target_index: int = 1,
    output_name: str = "sanitized-target",
    compdb_path: Path | None = None,
    plan_path: Path | None = None,
) -> RebuildVerifyResult:
    policy = CommandPolicy(root, allowlist=config.allowlist, timeout_seconds=config.timeout_seconds)
    db_path = compdb_path or default_compdb_path(root)
    compdb = CompileDatabase.load(db_path)
    targets = extract_targets(compdb)
    if target_index < 1 or target_index > len(targets):
        raise IndexError(f"target index out of range: {target_index}")

    target = targets[target_index - 1]
    rebuild = rebuild_target(policy, target, output_name)

    verification = None
    selected_plan = plan_path or (root / "verification-plan.json")
    output_binary = root / output_name
    if rebuild.returncode == 0 and selected_plan.exists() and output_binary.exists():
        plan = VerificationPlan.load(selected_plan)
        verification = run_binary(policy, output_binary, args=plan.args)

    return RebuildVerifyResult(rebuild=rebuild, verification=verification, output_binary=str(output_binary))
