from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil

from .policy import CommandPolicy, CommandResult


@dataclass
class SanitizerPlan:
    compiler: str | None = None
    cflags: tuple[str, ...] = (
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
    )


def resolve_compiler(preferred: str | None = None) -> str | None:
    candidates = [preferred] if preferred else []
    candidates.extend(["clang", "gcc", "cc"])
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if shutil.which(candidate):
            return candidate
    return None


def build_single_c_file(policy: CommandPolicy, source: Path, output: Path, plan: SanitizerPlan | None = None) -> CommandResult:
    plan = plan or SanitizerPlan()
    compiler = resolve_compiler(plan.compiler)
    if compiler is None:
        return CommandResult(
            argv=[],
            returncode=127,
            stdout="",
            stderr="no supported compiler found; tried clang/gcc/cc\n",
        )
    argv = [compiler, *plan.cflags, str(source.name), "-o", str(output.name)]
    return policy.run(argv, cwd=source.parent)
