from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .compdb import CompileDatabase, CompileCommand


@dataclass
class RebuildTarget:
    source_file: str
    directory: str
    compiler_argv: list[str]


def _tokenize(entry: CompileCommand) -> list[str]:
    if entry.arguments:
        return list(entry.arguments)
    if entry.command:
        import shlex

        return shlex.split(entry.command)
    return []


def extract_targets(compdb: CompileDatabase) -> list[RebuildTarget]:
    targets: list[RebuildTarget] = []
    for entry in compdb.entries:
        argv = _tokenize(entry)
        if not argv:
            continue
        targets.append(
            RebuildTarget(
                source_file=entry.file,
                directory=entry.directory,
                compiler_argv=argv,
            )
        )
    return targets


def rewrite_for_sanitizers(target: RebuildTarget, output_name: str) -> list[str]:
    argv = list(target.compiler_argv)
    if not argv:
        return []

    sanitized = [argv[0]]
    sanitized.extend(["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1"])

    skip_next = False
    for idx, token in enumerate(argv[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        if token == "-o":
            skip_next = True
            continue
        if token.startswith("-o") and token != "-o":
            continue
        sanitized.append(token)

    sanitized.extend(["-o", output_name])
    return sanitized


def default_compdb_path(root: Path) -> Path:
    return root / "compile_commands.json"
