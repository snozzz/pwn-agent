from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import re


@dataclass(frozen=True)
class OutputTruncationPolicy:
    max_stdout_chars: int | None = None
    max_stderr_chars: int | None = None


@dataclass(frozen=True)
class CommandRule:
    kind: str
    executable: str
    cwd_policy: str
    timeout_seconds: int | None
    output_truncation: OutputTruncationPolicy
    validator: Callable[[list[str], Path, Path], None]


ALLOWED_MAIN_SUBCOMMANDS = {
    "verify-run",
    "rebuild-target",
    "rebuild-verify",
    "rebuild-plan",
    "binary-verify",
    "binary-scan",
    "binary-plan",
    "binary-run",
    "crash-triage",
    "binary-validate",
}


def _require_workspace_bound_path(token: str, *, workspace_root: Path, cwd: Path, label: str) -> Path:
    path = Path(token)
    resolved = (cwd / path).resolve() if not path.is_absolute() else path.resolve()
    if workspace_root not in resolved.parents and resolved != workspace_root:
        raise ValueError(f"{label} escapes workspace root: {resolved}")
    return resolved


def _validate_any(_argv: list[str], _workspace_root: Path, _cwd: Path) -> None:
    return


def _validate_find(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    if len(argv) < 2:
        raise ValueError("find requires a target path")
    _require_workspace_bound_path(argv[1], workspace_root=workspace_root, cwd=cwd, label="find target")


def _validate_single_target(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    if len(argv) != 2:
        raise ValueError(f"{argv[0]} expects exactly one target path")
    _require_workspace_bound_path(argv[1], workspace_root=workspace_root, cwd=cwd, label=f"{argv[0]} target")


def _validate_checksec(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    if len(argv) != 3 or argv[1] != "--file":
        raise ValueError("checksec must use '--file <target>'")
    _require_workspace_bound_path(argv[2], workspace_root=workspace_root, cwd=cwd, label="checksec target")


def _validate_readelf(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    if len(argv) != 3 or argv[1] not in {"-h", "-s", "-Ws"}:
        raise ValueError("readelf must use one of: -h, -s, -Ws")
    _require_workspace_bound_path(argv[2], workspace_root=workspace_root, cwd=cwd, label="readelf target")


def _validate_objdump(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    if len(argv) != 3 or argv[1] != "-x":
        raise ValueError("objdump must use '-x <target>'")
    _require_workspace_bound_path(argv[2], workspace_root=workspace_root, cwd=cwd, label="objdump target")


def _validate_nm(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    if len(argv) != 3 or argv[1] != "-an":
        raise ValueError("nm must use '-an <target>'")
    _require_workspace_bound_path(argv[2], workspace_root=workspace_root, cwd=cwd, label="nm target")


def _validate_strings(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    if len(argv) != 4 or argv[1] != "-n" or not re.fullmatch(r"\d+", argv[2]):
        raise ValueError("strings must use '-n <number> <target>'")
    _require_workspace_bound_path(argv[3], workspace_root=workspace_root, cwd=cwd, label="strings target")


def _validate_python_main(argv: list[str], workspace_root: Path, cwd: Path) -> None:
    _validate_main_cli(argv, workspace_root=workspace_root, expected_root=None, cwd=cwd)


COMMAND_POLICY_REGISTRY: dict[str, CommandRule] = {
    "ls": CommandRule("enumeration", "ls", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "find": CommandRule("enumeration", "find", "workspace", None, OutputTruncationPolicy(), _validate_find),
    "rg": CommandRule("search", "rg", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "grep": CommandRule("search", "grep", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "file": CommandRule("binary-inspect", "file", "workspace", None, OutputTruncationPolicy(), _validate_single_target),
    "checksec": CommandRule(
        "binary-inspect", "checksec", "workspace", None, OutputTruncationPolicy(max_stdout_chars=24000), _validate_checksec
    ),
    "readelf": CommandRule(
        "binary-inspect", "readelf", "workspace", None, OutputTruncationPolicy(max_stdout_chars=36000), _validate_readelf
    ),
    "objdump": CommandRule(
        "binary-inspect", "objdump", "workspace", None, OutputTruncationPolicy(max_stdout_chars=36000), _validate_objdump
    ),
    "nm": CommandRule("binary-inspect", "nm", "workspace", None, OutputTruncationPolicy(max_stdout_chars=36000), _validate_nm),
    "strings": CommandRule(
        "binary-inspect", "strings", "workspace", None, OutputTruncationPolicy(max_stdout_chars=24000), _validate_strings
    ),
    "cmake": CommandRule("build", "cmake", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "make": CommandRule("build", "make", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "ninja": CommandRule("build", "ninja", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "clang": CommandRule("build", "clang", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "clang++": CommandRule("build", "clang++", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "gcc": CommandRule("build", "gcc", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "g++": CommandRule("build", "g++", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "cc": CommandRule("build", "cc", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "clang-tidy": CommandRule("lint", "clang-tidy", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "cppcheck": CommandRule("lint", "cppcheck", "workspace", None, OutputTruncationPolicy(), _validate_any),
    "python3": CommandRule("internal-main", "python3", "workspace", None, OutputTruncationPolicy(), _validate_python_main),
}


def get_command_rule(executable: str) -> CommandRule | None:
    return COMMAND_POLICY_REGISTRY.get(executable)


def validate_registered_command(argv: list[str], *, workspace_root: Path, cwd: Path) -> None:
    if not argv:
        raise ValueError("empty command")
    rule = get_command_rule(argv[0])
    if rule is None:
        raise ValueError(f"command policy not found: {argv[0]}")
    rule.validator(argv, workspace_root, cwd)


def validate_main_cli(
    argv: list[str],
    *,
    workspace_root: Path | None,
    expected_root: Path | None,
    cwd: Path,
) -> tuple[list[str], Path]:
    if len(argv) < 6:
        raise ValueError("unsupported suggested_cli: too short")
    if argv[0] != "python3" or argv[1:3] != ["-m", "src.main"]:
        raise ValueError("unsupported suggested_cli prefix")

    subcommand = argv[3]
    if subcommand not in ALLOWED_MAIN_SUBCOMMANDS:
        raise ValueError(f"subcommand not allowed: {subcommand}")

    root = _extract_root(argv)
    if workspace_root is not None:
        _require_workspace_bound_path(str(root), workspace_root=workspace_root, cwd=cwd, label="--root")

    if expected_root is not None and root != expected_root.resolve():
        raise ValueError(f"suggested_cli root does not match plan root: {root} != {expected_root.resolve()}")

    _validate_path_options(argv[4:], root)
    return list(argv), root


def _extract_root(argv: list[str]) -> Path:
    try:
        root_index = argv.index("--root")
    except ValueError as exc:
        raise ValueError("suggested_cli missing --root") from exc
    if root_index + 1 >= len(argv):
        raise ValueError("suggested_cli has empty --root")
    root = Path(argv[root_index + 1]).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"invalid --root: {root}")
    return root


def _validate_path_options(args: list[str], root: Path) -> None:
    path_options = {
        "--root",
        "--binary",
        "--source",
        "--output",
        "--compdb",
        "--plan",
        "--state",
        "--audit-json",
        "--analysis-json",
        "--stdin-file",
        "--stdin-sample",
        "--protocol-sample",
        "--report",
        "--trace-json",
        "--config",
    }

    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            break
        if token in path_options:
            if index + 1 >= len(args):
                raise ValueError(f"missing value for {token}")
            value = Path(args[index + 1])
            resolved = (root / value).resolve() if not value.is_absolute() else value.resolve()
            if root not in resolved.parents and resolved != root:
                raise ValueError(f"path option escapes --root: {token}={resolved}")
            index += 2
            continue
        index += 1
