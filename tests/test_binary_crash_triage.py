from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import AgentConfig
from src.modes.binary.workflow import TRIAGE_SCHEMA, triage_binary_crash


class BinaryCrashTriageTests(unittest.TestCase):
    def test_triage_binary_crash_records_normal_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)

            with patch(
                "src.modes.binary.workflow.subprocess.run",
                return_value=subprocess.CompletedProcess(args=["./demo.bin"], returncode=0, stdout="ok\n", stderr=""),
            ):
                artifact = triage_binary_crash(
                    root=root,
                    binary=binary,
                    stdin_text="hello",
                    args=["arg1"],
                    config=AgentConfig(),
                )

            self.assertEqual(artifact["schema"], TRIAGE_SCHEMA)
            self.assertEqual(artifact["execution_result"]["exit_code"], 0)
            self.assertFalse(artifact["execution_result"]["timed_out"])
            self.assertFalse(artifact["crash_summary"]["suspicious"])
            self.assertFalse(artifact["debugger_summary"]["attempted"])

    def test_triage_binary_crash_records_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)

            timeout_exc = subprocess.TimeoutExpired(cmd=["./demo.bin"], timeout=2, output="waiting", stderr="hang")
            with patch("src.modes.binary.workflow.subprocess.run", side_effect=timeout_exc):
                artifact = triage_binary_crash(
                    root=root,
                    binary=binary,
                    timeout_seconds=2,
                    config=AgentConfig(),
                )

            self.assertTrue(artifact["execution_result"]["timed_out"])
            self.assertEqual(artifact["crash_summary"]["reason"], "timeout")
            self.assertFalse(artifact["debugger_summary"]["attempted"])

    def test_triage_binary_crash_collects_gdb_on_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)

            direct_result = subprocess.CompletedProcess(args=["./demo.bin"], returncode=-11, stdout="", stderr="segv\n")
            gdb_result = subprocess.CompletedProcess(
                args=["gdb"],
                returncode=0,
                stdout=(
                    "===REGISTERS===\n"
                    "pc 0x401000\n"
                    "sp 0x7fffffffe000\n"
                    "===BACKTRACE===\n"
                    "#0 0x401000 in main\n"
                    "===DISASSEMBLY===\n"
                    "=> 0x401000 <main+0>: ret\n"
                    "===MAPPINGS===\n"
                    "0x400000 0x401000 /tmp/demo.bin\n"
                    "===END===\n"
                ),
                stderr="",
            )

            def _run_side_effect(argv, **kwargs):
                if argv and argv[0] == "gdb":
                    return gdb_result
                return direct_result

            with patch("src.modes.binary.workflow.subprocess.run", side_effect=_run_side_effect):
                with patch("src.modes.binary.workflow.shutil.which", side_effect=lambda tool: f"/usr/bin/{tool}"):
                    artifact = triage_binary_crash(
                        root=root,
                        binary=binary,
                        gdb_batch=True,
                        config=AgentConfig(),
                    )

            self.assertTrue(artifact["crash_summary"]["crashed"])
            self.assertEqual(artifact["execution_result"]["signal_name"], "SIGSEGV")
            self.assertTrue(artifact["debugger_summary"]["attempted"])
            self.assertTrue(artifact["debugger_summary"]["collected"])
            self.assertIn("pc 0x401000", artifact["debugger_summary"]["registers"])
            self.assertEqual(len(artifact["evidence"]), 2)

    def test_triage_binary_crash_handles_gdb_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)

            direct_result = subprocess.CompletedProcess(args=["./demo.bin"], returncode=-6, stdout="", stderr="abort\n")
            with patch("src.modes.binary.workflow.subprocess.run", return_value=direct_result):
                with patch("src.modes.binary.workflow.shutil.which", side_effect=lambda tool: None if tool == "gdb" else f"/usr/bin/{tool}"):
                    artifact = triage_binary_crash(
                        root=root,
                        binary=binary,
                        gdb_batch=True,
                        config=AgentConfig(),
                    )

            self.assertTrue(artifact["debugger_summary"]["attempted"])
            self.assertFalse(artifact["debugger_summary"]["available"])
            self.assertEqual(artifact["debugger_summary"]["error"], "gdb not available")


if __name__ == "__main__":
    unittest.main()
