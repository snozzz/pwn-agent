from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
import subprocess
from typing import Sequence


DEFAULT_ALLOWLIST = {
    "ls",
    "find",
    "rg",
    "grep",
    "file",
    "strings",
    "nm",
    "objdump",
    "readelf",
    "cmake",
    "make",
    "ninja",
    "clang",
    "clang++",
    "gcc",
    "g++",
    "cc",
    "clang-tidy",
    "cppcheck",
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
            if not binary_path.exists():
                raise PolicyError(f"binary not found: {binary_path}")
            return list(argv), safe_cwd

        if command not in self.allowlist:
            raise PolicyError(f"command not allowed: {command}")

        return list(argv), safe_cwd

    def run(self, argv: Sequence[str], cwd: Path | None = None) -> CommandResult:
        safe_argv, safe_cwd = self.validate(argv, cwd)
        proc = subprocess.run(
            safe_argv,
            cwd=safe_cwd,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        return CommandResult(
            argv=safe_argv,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def run_shell_like(self, command: str, cwd: Path | None = None) -> CommandResult:
        return self.run(shlex.split(command), cwd=cwd)
