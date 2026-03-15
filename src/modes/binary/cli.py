from __future__ import annotations

import argparse
from pathlib import Path

from ...config import AgentConfig
from ...executor import execute_plan, render_execution_markdown, write_execution_summary
from ...reporting import write_report
from .workflow import (
    build_binary_plan,
    load_binary_analysis,
    render_binary_audit_markdown,
    render_binary_plan_markdown,
    scan_binary,
    triage_binary_crash,
    verify_binary_execution,
    write_binary_json,
)

BINARY_COMMANDS = {
    "binary-scan",
    "binary-plan",
    "binary-run",
    "binary-verify",
    "binary-validate",
    "crash-triage",
    "binary-triage",
}


def register_subcommands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    binary_scan = subparsers.add_parser("binary-scan", help="collect bounded local evidence for a binary")
    binary_scan.add_argument("--root", type=Path, required=True, help="workspace root")
    binary_scan.add_argument("--binary", type=Path, required=True, help="path to local ELF/binary")
    binary_scan.add_argument("--output", type=Path, required=True, help="output binary audit json")
    binary_scan.add_argument("--report", type=Path, help="optional markdown audit report")
    binary_scan.add_argument("--stdin-file", dest="stdin_file", type=Path, help="optional stdin file metadata hint")
    binary_scan.add_argument("--stdin-sample", dest="stdin_file", type=Path, help=argparse.SUPPRESS)
    binary_scan.add_argument("--protocol-sample", type=Path, help="optional protocol/input sample file")
    binary_scan.add_argument("--args", nargs="*", default=[], help="optional runtime argument hint list")
    binary_scan.add_argument("--timeout", type=int, help="optional scan timeout override in seconds")
    binary_scan.add_argument("--config", type=Path, help="optional JSON config path")

    binary_plan = subparsers.add_parser("binary-plan", help="build a binary workflow plan from a binary analysis artifact")
    binary_plan.add_argument("--analysis-json", type=Path, required=True, help="input binary analysis json")
    binary_plan.add_argument("--output", type=Path, required=True, help="output binary plan json")
    binary_plan.add_argument("--report", type=Path, help="optional markdown plan report")

    binary_run = subparsers.add_parser("binary-run", help="execute bounded ready actions from a binary plan")
    binary_run.add_argument("--plan", type=Path, required=True, help="input binary plan json")
    binary_run.add_argument("--output", type=Path, required=True, help="output binary run summary json")
    binary_run.add_argument("--report", type=Path, help="optional markdown run report")
    binary_run.add_argument("--state", type=Path, help="optional persisted execution state json")
    binary_run.add_argument("--action-id", help="optional specific ready action id to execute")
    binary_run.add_argument("--phase", choices=["triage", "execution", "synthesis"], help="optional phase filter")
    binary_run.add_argument("--max-actions", type=int, default=1, help="maximum ready actions to execute")
    binary_run.add_argument("--dry-run", action="store_true", help="validate and preview runnable actions without execution")
    binary_run.add_argument("--timeout", type=int, default=30, help="per-action timeout in seconds")

    binary_verify = subparsers.add_parser("binary-verify", help="run bounded local binary verification")
    binary_verify.add_argument("--root", type=Path, required=True, help="workspace root")
    binary_verify.add_argument("--binary", type=Path, required=True, help="path to local binary")
    binary_verify.add_argument("--stdin-file", dest="stdin_file", type=Path, help="optional stdin file")
    binary_verify.add_argument("--stdin-sample", dest="stdin_file", type=Path, help=argparse.SUPPRESS)
    binary_verify.add_argument("--protocol-sample", type=Path, help="optional protocol/input sample file")
    binary_verify.add_argument("--output", type=Path, help="optional binary verify artifact json")
    binary_verify.add_argument("--config", type=Path, help="optional JSON config path")
    binary_verify.add_argument("args", nargs="*", help="arguments passed to the binary")

    binary_validate = subparsers.add_parser("binary-validate", help="alias of binary-verify for validation stage")
    binary_validate.add_argument("--root", type=Path, required=True, help="workspace root")
    binary_validate.add_argument("--binary", type=Path, required=True, help="path to local binary")
    binary_validate.add_argument("--stdin-file", dest="stdin_file", type=Path, help="optional stdin file")
    binary_validate.add_argument("--protocol-sample", type=Path, help="optional protocol/input sample file")
    binary_validate.add_argument("--output", type=Path, help="optional binary verify artifact json")
    binary_validate.add_argument("--config", type=Path, help="optional JSON config path")
    binary_validate.add_argument("args", nargs="*", help="arguments passed to the binary")

    crash_triage = subparsers.add_parser("crash-triage", help="run bounded crash triage for a local binary")
    crash_triage.add_argument("--root", type=Path, required=True, help="workspace root")
    crash_triage.add_argument("--binary", type=Path, required=True, help="path to local ELF/binary")
    crash_triage.add_argument("--output", type=Path, required=True, help="output crash triage json")
    crash_triage.add_argument("--report", type=Path, help="optional markdown crash triage report")
    crash_stdin = crash_triage.add_mutually_exclusive_group()
    crash_stdin.add_argument("--stdin-file", dest="stdin_file", type=Path, help="optional stdin file")
    crash_stdin.add_argument("--stdin-text", dest="stdin_text", help="optional literal stdin text")
    crash_triage.add_argument("--args", nargs="*", default=[], help="optional runtime argument list")
    crash_triage.add_argument("--timeout", type=int, help="optional execution timeout override in seconds")
    crash_triage.add_argument("--gdb-batch", action="store_true", help="collect bounded gdb batch evidence on suspicious exits")
    crash_triage.add_argument("--config", type=Path, help="optional JSON config path")

    binary_triage = subparsers.add_parser("binary-triage", help="alias of crash-triage")
    binary_triage.add_argument("--root", type=Path, required=True, help="workspace root")
    binary_triage.add_argument("--binary", type=Path, required=True, help="path to local ELF/binary")
    binary_triage.add_argument("--output", type=Path, required=True, help="output crash triage json")
    binary_triage.add_argument("--report", type=Path, help="optional markdown crash triage report")
    binary_triage_stdin = binary_triage.add_mutually_exclusive_group()
    binary_triage_stdin.add_argument("--stdin-file", dest="stdin_file", type=Path, help="optional stdin file")
    binary_triage_stdin.add_argument("--stdin-text", dest="stdin_text", help="optional literal stdin text")
    binary_triage.add_argument("--args", nargs="*", default=[], help="optional runtime argument list")
    binary_triage.add_argument("--timeout", type=int, help="optional execution timeout override in seconds")
    binary_triage.add_argument("--gdb-batch", action="store_true", help="collect bounded gdb batch evidence on suspicious exits")
    binary_triage.add_argument("--config", type=Path, help="optional JSON config path")


def handle_command(args: argparse.Namespace) -> int | None:
    if args.command not in BINARY_COMMANDS:
        return None

    if args.command == "binary-scan":
        config = AgentConfig.load(args.config)
        artifact = scan_binary(
            root=args.root,
            binary=args.binary,
            stdin_file=args.stdin_file,
            args=args.args,
            timeout_seconds=args.timeout,
            protocol_sample=args.protocol_sample,
            config=config,
        )
        write_binary_json(args.output, artifact)
        if args.report:
            write_report(args.report, render_binary_audit_markdown(artifact))
        print(f"binary scan complete; wrote {args.output}")
        return 0

    if args.command in {"crash-triage", "binary-triage"}:
        config = AgentConfig.load(args.config)
        artifact = triage_binary_crash(
            root=args.root,
            binary=args.binary,
            stdin_file=args.stdin_file,
            stdin_text=args.stdin_text,
            args=args.args,
            timeout_seconds=args.timeout,
            gdb_batch=args.gdb_batch,
            config=config,
        )
        write_binary_json(args.output, artifact)
        if args.report:
            write_report(args.report, render_binary_audit_markdown(artifact))
        print(f"crash triage complete; wrote {args.output}")
        return 0

    if args.command == "binary-plan":
        analysis = load_binary_analysis(args.analysis_json)
        plan = build_binary_plan(analysis)
        write_binary_json(args.output, plan)
        if args.report:
            write_report(args.report, render_binary_plan_markdown(plan))
        print(f"binary plan has {len(plan.get('next_actions', []))} actions; wrote {args.output}")
        return 0

    if args.command == "binary-run":
        summary = execute_plan(
            args.plan,
            action_id=args.action_id,
            phase=args.phase,
            max_actions=args.max_actions,
            dry_run=args.dry_run,
            timeout_seconds=args.timeout,
            state_path=args.state,
        )
        write_execution_summary(args.output, summary)
        if args.report:
            write_report(args.report, render_execution_markdown(summary))
        print(f"binary run executed {summary.executed} action(s); wrote {args.output}")
        return 0

    if args.command in {"binary-verify", "binary-validate"}:
        config = AgentConfig.load(args.config)
        returncode, artifact = verify_binary_execution(
            root=args.root,
            binary=args.binary,
            args=args.args,
            stdin_file=args.stdin_file,
            protocol_sample=args.protocol_sample,
            config=config,
        )
        if args.output:
            write_binary_json(args.output, artifact)
        print(f"binary verify rc={returncode} sanitizer_signal={str(artifact['sanitizer_signal']).lower()}")
        for line in artifact.get("stdout_head", []):
            print(line)
        for line in artifact.get("stderr_head", []):
            print(line)
        return returncode

    return None
