from __future__ import annotations

import argparse

from .modes.audit.cli import handle_command as handle_audit_command
from .modes.audit.cli import register_subcommands as register_audit_subcommands
from .modes.binary.cli import handle_command as handle_binary_command
from .modes.binary.cli import register_subcommands as register_binary_subcommands


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="pwn-agent MVP CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_audit_subcommands(subparsers)
    register_binary_subcommands(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    audit_returncode = handle_audit_command(args)
    if audit_returncode is not None:
        return audit_returncode

    binary_returncode = handle_binary_command(args)
    if binary_returncode is not None:
        return binary_returncode

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
