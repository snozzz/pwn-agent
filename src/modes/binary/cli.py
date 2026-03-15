from __future__ import annotations

import argparse
from pathlib import Path

from ...config import AgentConfig
from ...executor import execute_plan, render_execution_markdown, write_execution_summary
from ...reporting import write_report
from .workflow import (
    build_binary_plan,
    load_binary_artifact,
    render_binary_audit_markdown,
    render_binary_plan_markdown,
    scan_binary,
    triage_binary_crash,
    verify_binary_execution,
    write_binary_json,
)
from .patching import load_patch_input, patch_validate, render_patch_validation_markdown
from .loop import render_agent_loop_markdown, run_agent_loop

BINARY_COMMANDS = {
    "agent-loop",
    "binary-scan",
    "binary-plan",
    "binary-run",
    "binary-verify",
    "binary-validate",
    "patch-validate",
    "crash-triage",
    "binary-triage",
}


def register_subcommands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    agent_loop = subparsers.add_parser("agent-loop", help="run a bounded local analysis loop from a binary plan")
    agent_loop.add_argument("--root", type=Path, required=True, help="workspace root")
    agent_loop.add_argument("--plan", type=Path, required=True, help="current binary plan json")
    agent_loop.add_argument("--plan-output", type=Path, help="optional updated plan output path")
    agent_loop.add_argument("--analysis-json", type=Path, help="optional binary analysis json")
    agent_loop.add_argument("--crash-json", type=Path, help="optional crash triage json")
    agent_loop.add_argument("--patch-validation-json", type=Path, help="optional patch validation json")
    agent_loop.add_argument("--verify-json", type=Path, help="optional binary verify json")
    model_group = agent_loop.add_mutually_exclusive_group(required=True)
    model_group.add_argument("--model-response-json", type=Path, help="single model response json")
    model_group.add_argument("--model-response-jsonl", type=Path, help="stream of model response json objects")
    agent_loop.add_argument("--output", type=Path, required=True, help="output loop trajectory json")
    agent_loop.add_argument("--report", type=Path, help="optional markdown loop report")
    agent_loop.add_argument("--state", type=Path, help="optional persisted loop state json")
    agent_loop.add_argument("--executor-state", type=Path, help="optional persisted executor state json")
    agent_loop.add_argument("--max-steps", type=int, default=1, help="maximum loop iterations")
    agent_loop.add_argument("--max-failures", type=int, default=1, help="maximum rejected/failed iterations")
    agent_loop.add_argument("--dry-run", action="store_true", help="preview chosen actions without execution")
    agent_loop.add_argument("--timeout", type=int, default=30, help="per-action timeout in seconds")

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
    binary_plan.add_argument("--analysis-json", type=Path, help="input binary analysis json")
    binary_plan.add_argument("--crash-json", type=Path, help="optional binary crash triage json")
    binary_plan.add_argument("--patch-validation-json", type=Path, help="optional patch validation json")
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

    patch_validate_parser = subparsers.add_parser("patch-validate", help="apply a bounded patch artifact/script and run validation")
    patch_validate_parser.add_argument("--root", type=Path, required=True, help="workspace root")
    patch_validate_input = patch_validate_parser.add_mutually_exclusive_group(required=True)
    patch_validate_input.add_argument("--patch-json", type=Path, help="candidate patch artifact json")
    patch_validate_input.add_argument("--patch-script", type=Path, help="structured patch script json")
    patch_validate_parser.add_argument("--analysis-json", type=Path, help="optional binary analysis json")
    patch_validate_parser.add_argument("--crash-json", type=Path, help="optional crash triage json")
    patch_validate_parser.add_argument("--binary", type=Path, help="optional existing binary path")
    patch_validate_parser.add_argument("--target-index", type=int, default=1, help="compile database rebuild target index")
    patch_validate_parser.add_argument("--output-name", default="patched-target", help="rebuilt output binary name")
    patch_validate_parser.add_argument("--output", type=Path, required=True, help="output patch validation json")
    patch_validate_parser.add_argument("--report", type=Path, help="optional markdown patch validation report")
    patch_validate_parser.add_argument("--timeout", type=int, help="optional timeout override in seconds")
    patch_validate_parser.add_argument("--config", type=Path, help="optional JSON config path")

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

    if args.command == "agent-loop":
        model_response_path = args.model_response_json if args.model_response_json is not None else args.model_response_jsonl
        model_response_format = "json" if args.model_response_json is not None else "jsonl"
        artifact = run_agent_loop(
            root=args.root,
            plan_path=args.plan,
            plan_output_path=args.plan_output,
            trajectory_path=args.output,
            model_response_path=model_response_path,
            model_response_format=model_response_format,
            analysis_json=args.analysis_json,
            crash_json=args.crash_json,
            patch_validation_json=args.patch_validation_json,
            verify_json=args.verify_json,
            state_path=args.state,
            executor_state_path=args.executor_state,
            max_steps=args.max_steps,
            max_failures=args.max_failures,
            dry_run=args.dry_run,
            timeout_seconds=args.timeout,
        )
        if args.report:
            write_report(args.report, render_agent_loop_markdown(artifact))
        write_binary_json(args.output, artifact)
        print(f"agent loop status={artifact.get('status')} wrote {args.output}")
        return 0 if artifact.get("status") not in {"invalid-model-output", "failure-budget-exhausted"} else 2

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
        if args.analysis_json is None and args.crash_json is None and args.patch_validation_json is None:
            raise ValueError("binary-plan requires --analysis-json, --crash-json, --patch-validation-json, or a combination")
        analysis = load_binary_artifact(args.analysis_json) if args.analysis_json is not None else None
        crash = load_binary_artifact(args.crash_json) if args.crash_json is not None else None
        validation = load_binary_artifact(args.patch_validation_json) if args.patch_validation_json is not None else None
        plan = build_binary_plan(analysis, crash=crash, validation=validation)
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

    if args.command == "patch-validate":
        config = AgentConfig.load(args.config)
        patch_path = args.patch_json if args.patch_json is not None else args.patch_script
        patch_payload = load_patch_input(patch_path)
        analysis = load_binary_artifact(args.analysis_json) if args.analysis_json is not None else None
        crash = load_binary_artifact(args.crash_json) if args.crash_json is not None else None
        artifact = patch_validate(
            root=args.root,
            patch_payload=patch_payload,
            patch_source_path=patch_path,
            analysis=analysis,
            crash=crash,
            binary=args.binary,
            target_index=args.target_index,
            output_name=args.output_name,
            timeout_seconds=args.timeout,
            config=config,
        )
        write_binary_json(args.output, artifact)
        if args.report:
            write_report(args.report, render_patch_validation_markdown(artifact))
        print(f"patch validation complete; wrote {args.output}")
        return 0

    return None
