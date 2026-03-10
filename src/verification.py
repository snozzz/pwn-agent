from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .policy import CommandPolicy, CommandResult


@dataclass
class VerificationResult:
    binary: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    sanitizer_signal: bool


def run_binary(policy: CommandPolicy, binary: Path, args: list[str] | None = None) -> VerificationResult:
    run_args = args or []
    result: CommandResult = policy.run([f"./{binary.name}", *run_args], cwd=binary.parent)
    stderr = result.stderr or ""
    stdout = result.stdout or ""
    sanitizer_signal = any(
        marker in stderr
        for marker in [
            "AddressSanitizer",
            "runtime error:",
            "UndefinedBehaviorSanitizer",
            "buffer overflow detected",
            "stack smashing detected",
        ]
    )
    return VerificationResult(
        binary=str(binary),
        argv=[str(binary), *run_args],
        returncode=result.returncode,
        stdout=stdout,
        stderr=stderr,
        sanitizer_signal=sanitizer_signal,
    )
