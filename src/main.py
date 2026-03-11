from __future__ import annotations

import argparse
from pathlib import Path

from .audit_export import write_audit_summary
from .config import AgentConfig
from .compdb import CompileDatabase
from .executor import execute_plan, render_execution_markdown, write_execution_summary
from .orchestrator import build_plan, load_audit_summary, render_plan_markdown, write_plan
from .pipeline import rebuild_and_verify
from .reporting import render_markdown, write_report
from .rebuild import default_compdb_path, extract_targets, rebuild_target, rewrite_for_sanitizers
from .sanitizers import build_single_c_file
from .sarif import write_sarif
from .scanner import scan_project
from .verification import run_binary
from .workflow import AuditWorkflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="pwn-agent MVP CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a C/C++ project")
    scan.add_argument("--root", type=Path, required=True, help="project root to scan")
    scan.add_argument("--report", type=Path, required=True, help="markdown report output path")

    sarif = subparsers.add_parser("scan-sarif", help="scan a C/C++ project and export SARIF")
    sarif.add_argument("--root", type=Path, required=True, help="project root to scan")
    sarif.add_argument("--output", type=Path, required=True, help="SARIF output path")

    audit = subparsers.add_parser("audit", help="run the constrained audit workflow")
    audit.add_argument("--root", type=Path, required=True, help="project root to audit")
    audit.add_argument("--report", type=Path, required=True, help="markdown report output path")
    audit.add_argument("--trace-json", type=Path, help="optional trace json output path")
    audit.add_argument("--audit-json", type=Path, help="optional structured audit summary output path")
    audit.add_argument("--config", type=Path, help="optional JSON config path")

    plan_audit = subparsers.add_parser("plan-audit", help="build an orchestration plan from audit json")
    plan_audit.add_argument("--audit-json", type=Path, required=True, help="input audit summary json")
    plan_audit.add_argument("--output", type=Path, required=True, help="output orchestration plan json")
    plan_audit.add_argument("--report", type=Path, help="optional markdown plan report")

    run_plan = subparsers.add_parser("run-plan", help="execute bounded ready actions from a generated plan")
    run_plan.add_argument("--plan", type=Path, required=True, help="input orchestration plan json")
    run_plan.add_argument("--output", type=Path, required=True, help="output execution summary json")
    run_plan.add_argument("--report", type=Path, help="optional markdown execution report")
    run_plan.add_argument("--state", type=Path, help="optional persisted execution state json for resume support")
    run_plan.add_argument("--action-id", help="optional specific ready action id to execute")
    run_plan.add_argument("--phase", choices=["triage", "execution", "synthesis"], help="optional phase filter for ready actions")
    run_plan.add_argument("--max-actions", type=int, default=1, help="maximum number of ready actions to execute")
    run_plan.add_argument("--dry-run", action="store_true", help="validate and render runnable actions without executing them")
    run_plan.add_argument("--timeout", type=int, default=30, help="per-action timeout in seconds")

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

    rv = subparsers.add_parser("rebuild-verify", help="rebuild a target and run verification plan")
    rv.add_argument("--root", type=Path, required=True, help="project root")
    rv.add_argument("--index", type=int, default=1, help="1-based target index from rebuild-plan")
    rv.add_argument("--output-name", default="sanitized-target", help="output binary name")
    rv.add_argument("--compdb", type=Path, help="optional compile_commands.json path")
    rv.add_argument("--plan", type=Path, help="optional verification plan path")
    rv.add_argument("--config", type=Path, help="optional JSON config path")

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

    if args.command == "scan-sarif":
        result = scan_project(args.root)
        write_sarif(args.output, result)
        print(f"scanned {result.files_scanned} files; wrote {args.output}")
        return 0

    if args.command == "audit":
        config = AgentConfig.load(args.config)
        workflow = AuditWorkflow(args.root, config=config)
        result = workflow.run()
        write_report(args.report, result.report_markdown)
        if args.trace_json:
            result.trace.write_json(args.trace_json)
        if args.audit_json:
            write_audit_summary(args.audit_json, result)
        print(
            f"audited {result.scan.files_scanned} files; findings={len(result.scan.findings)}; "
            f"commands={len(result.command_logs)}; wrote {args.report}"
        )
        return 0

    if args.command == "plan-audit":
        summary = load_audit_summary(args.audit_json)
        plan = build_plan(summary)
        write_plan(args.output, plan)
        if args.report:
            write_report(args.report, render_plan_markdown(plan))
        print(f"planned {len(plan.next_actions)} actions; wrote {args.output}")
        return 0

    if args.command == "run-plan":
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
        print(f"executed {summary.executed} action(s); wrote {args.output}")
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

    if args.command == "rebuild-verify":
        config = AgentConfig.load(args.config)
        result = rebuild_and_verify(
            root=args.root,
            config=config,
            target_index=args.index,
            output_name=args.output_name,
            compdb_path=args.compdb,
            plan_path=args.plan,
        )
        print(f"rebuild rc={result.rebuild.returncode}")
        if result.rebuild.stdout:
            print(result.rebuild.stdout, end="")
        if result.rebuild.stderr:
            print(result.rebuild.stderr, end="")
        if result.verification is not None:
            print(
                f"verify rc={result.verification.returncode} "
                f"sanitizer_signal={str(result.verification.sanitizer_signal).lower()}"
            )
            if result.verification.stdout:
                print(result.verification.stdout, end="")
            if result.verification.stderr:
                print(result.verification.stderr, end="")
        return result.rebuild.returncode

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
