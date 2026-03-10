from __future__ import annotations

import argparse
from pathlib import Path

from .config import AgentConfig
from .compdb import CompileDatabase
from .reporting import render_markdown, write_report
from .rebuild import default_compdb_path, extract_targets, rebuild_target, rewrite_for_sanitizers
from .sanitizers import build_single_c_file
from .scanner import scan_project
from .verification import run_binary
from .workflow import AuditWorkflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="pwn-agent MVP CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a C/C++ project")
    scan.add_argument("--root", type=Path, required=True, help="project root to scan")
    scan.add_argument("--report", type=Path, required=True, help="markdown report output path")

    audit = subparsers.add_parser("audit", help="run the constrained audit workflow")
    audit.add_argument("--root", type=Path, required=True, help="project root to audit")
    audit.add_argument("--report", type=Path, required=True, help="markdown report output path")
    audit.add_argument("--config", type=Path, help="optional JSON config path")

    sanitize = subparsers.add_parser("sanitize-build", help="build a single C file with sanitizers")
    sanitize.add_argument("--root", type=Path, required=True, help="workspace root")
    sanitize.add_argument("--source", type=Path, required=True, help="single C source file to compile")
    sanitize.add_argument("--output", type=Path, required=True, help="output binary path")
    sanitize.add_argument("--config", type=Path, help="optional JSON config path")

    verify = subparsers.add_parser("verify-run", help="run a local binary and look for sanitizer output")
    verify.add_argument("--root", type=Path, required=True, help="workspace root")
    verify.add_argument("--binary", type=Path, required=True, help="binary path to execute")
    verify.add_argument("args", nargs="*", help="arguments for the binary")
    verify.add_argument("--config", type=Path, help="optional JSON config path")

    plan = subparsers.add_parser("rebuild-plan", help="show sanitizer rebuild targets from compile_commands.json")
    plan.add_argument("--root", type=Path, required=True, help="project root")
    plan.add_argument("--compdb", type=Path, help="optional compile_commands.json path")

    rebuild = subparsers.add_parser("rebuild-target", help="rebuild one compile database target with sanitizer flags")
    rebuild.add_argument("--root", type=Path, required=True, help="project root")
    rebuild.add_argument("--index", type=int, default=1, help="1-based target index from rebuild-plan")
    rebuild.add_argument("--output-name", default="sanitized-target", help="output binary name")
    rebuild.add_argument("--compdb", type=Path, help="optional compile_commands.json path")
    rebuild.add_argument("--config", type=Path, help="optional JSON config path")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        result = scan_project(args.root)
        report = render_markdown(result)
        write_report(args.report, report)
        print(f"scanned {result.files_scanned} files; wrote {args.report}")
        return 0

    if args.command == "audit":
        config = AgentConfig.load(args.config)
        workflow = AuditWorkflow(args.root, config=config)
        result = workflow.run()
        write_report(args.report, result.report_markdown)
        print(
            f"audited {result.scan.files_scanned} files; findings={len(result.scan.findings)}; "
            f"commands={len(result.command_logs)}; wrote {args.report}"
        )
        return 0

    if args.command == "sanitize-build":
        config = AgentConfig.load(args.config)
        from .policy import CommandPolicy

        policy = CommandPolicy(
            args.root,
            allowlist=config.allowlist,
            timeout_seconds=config.timeout_seconds,
        )
        result = build_single_c_file(policy, args.source, args.output)
        print(f"sanitize build rc={result.returncode}")
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        return result.returncode

    if args.command == "verify-run":
        config = AgentConfig.load(args.config)
        from .policy import CommandPolicy

        policy = CommandPolicy(
            args.root,
            allowlist=config.allowlist,
            timeout_seconds=config.timeout_seconds,
        )
        result = run_binary(policy, args.binary, args=args.args)
        print(f"verify run rc={result.returncode} sanitizer_signal={str(result.sanitizer_signal).lower()}")
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        return result.returncode

    if args.command == "rebuild-plan":
        compdb_path = args.compdb or default_compdb_path(args.root)
        compdb = CompileDatabase.load(compdb_path)
        targets = extract_targets(compdb)
        print(f"targets={len(targets)}")
        for index, target in enumerate(targets, start=1):
            rewritten = rewrite_for_sanitizers(target, f"sanitized-target-{index}")
            print(f"[{index}] source={target.source_file} dir={target.directory}")
            print("    original:", " ".join(target.compiler_argv))
            print("    rewritten:", " ".join(rewritten))
        return 0

    if args.command == "rebuild-target":
        config = AgentConfig.load(args.config)
        from .policy import CommandPolicy

        compdb_path = args.compdb or default_compdb_path(args.root)
        compdb = CompileDatabase.load(compdb_path)
        targets = extract_targets(compdb)
        if args.index < 1 or args.index > len(targets):
            raise SystemExit(f"target index out of range: {args.index}")
        policy = CommandPolicy(
            args.root,
            allowlist=config.allowlist,
            timeout_seconds=config.timeout_seconds,
        )
        target = targets[args.index - 1]
        result = rebuild_target(policy, target, args.output_name)
        print(f"rebuild rc={result.returncode}")
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        return result.returncode

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
