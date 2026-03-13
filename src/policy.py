from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
import subprocess
from typing import Sequence

from .command_registry import COMMAND_POLICY_REGISTRY, get_command_rule, validate_registered_command


DEFAULT_ALLOWLIST = {
    *COMMAND_POLICY_REGISTRY.keys(),
}


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


class PolicyError(RuntimeError):
    pass


class CommandPolicy:
    def __init__(self, workspace_root: Path, allowlist: set[str] | None = None, timeout_seconds: int = 20):
        self.workspace_root = workspace_root.resolve()
        self.allowlist = allowlist or set(DEFAULT_ALLOWLIST)
        self.timeout_seconds = timeout_seconds

    def _resolve_cwd(self, cwd: Path | None) -> Path:
        candidate = (cwd or self.workspace_root).resolve()
        if self.workspace_root not in candidate.parents and candidate != self.workspace_root:
            raise PolicyError(f"cwd escapes workspace root: {candidate}")
        return candidate

    def validate(self, argv: Sequence[str], cwd: Path | None = None) -> tuple[list[str], Path]:
        if not argv:
            raise PolicyError("empty command")

        command = argv[0]
        safe_cwd = self._resolve_cwd(cwd)

        if command.startswith("./"):
            binary_path = (safe_cwd / command[2:]).resolve()
            if safe_cwd not in binary_path.parents and binary_path != safe_cwd:
                raise PolicyError(f"binary escapes cwd: {binary_path}")
            if self.workspace_root not in binary_path.parents and binary_path != self.workspace_root:
                raise PolicyError(f"binary escapes workspace root: {binary_path}")
            if not binary_path.exists():
                raise PolicyError(f"binary not found: {binary_path}")
            return list(argv), safe_cwd

        if command not in self.allowlist:
            raise PolicyError(f"command not allowed: {command}")

        try:
            validate_registered_command(list(argv), workspace_root=self.workspace_root, cwd=safe_cwd)
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc
        return list(argv), safe_cwd

    def run(self, argv: Sequence[str], cwd: Path | None = None) -> CommandResult:
        safe_argv, safe_cwd = self.validate(argv, cwd)
        rule = get_command_rule(safe_argv[0]) if safe_argv and not safe_argv[0].startswith("./") else None
        timeout_seconds = rule.timeout_seconds if (rule is not None and rule.timeout_seconds is not None) else self.timeout_seconds
        try:
            proc = subprocess.run(
                safe_argv,
                cwd=safe_cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            if rule is not None:
                truncation = rule.output_truncation
                if truncation.max_stdout_chars is not None:
                    stdout = _truncate_output(stdout, truncation.max_stdout_chars)
                if truncation.max_stderr_chars is not None:
                    stderr = _truncate_output(stderr, truncation.max_stderr_chars)
            return CommandResult(
                argv=safe_argv,
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            stderr += f"\n[policy-timeout] command exceeded {timeout_seconds}s\n"
            return CommandResult(
                argv=safe_argv,
                returncode=124,
                stdout=stdout,
                stderr=stderr,
            )

    def run_shell_like(self, command: str, cwd: Path | None = None) -> CommandResult:
        return self.run(shlex.split(command), cwd=cwd)


def _truncate_output(text: str, max_chars: int) -> str:
    if max_chars < 0:
        return text
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[policy-truncated]\n"
