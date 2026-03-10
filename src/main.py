from __future__ import annotations

import argparse
from pathlib import Path

from .config import AgentConfig
from .reporting import render_markdown, write_report
from .sanitizers import build_single_c_file
from .scanner import scan_project
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

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
