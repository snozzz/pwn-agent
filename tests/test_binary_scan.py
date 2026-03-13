from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import AgentConfig
from src.policy import CommandResult
from src.modes.binary.workflow import render_binary_audit_markdown, scan_binary


class BinaryScanTests(unittest.TestCase):
    def test_scan_binary_happy_path_collects_structured_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 128)

            outputs = {
                "file": CommandResult(
                    argv=["file", str(binary)],
                    returncode=0,
                    stdout=f"{binary}: ELF 64-bit LSB executable, x86-64\n",
                    stderr="",
                ),
                "checksec": CommandResult(
                    argv=["checksec", "--file", str(binary)],
                    returncode=0,
                    stdout="RELRO: Full RELRO\nCanary: yes\nNX: enabled\nPIE: enabled\nFORTIFY: present\n",
                    stderr="",
                ),
                "readelf": CommandResult(
                    argv=["readelf", "-h", str(binary)],
                    returncode=0,
                    stdout=(
                        "Class: ELF64\n"
                        "Data: 2's complement, little endian\n"
                        "Type: DYN (Shared object file)\n"
                        "Machine: Advanced Micro Devices X86-64\n"
                        "Entry point address: 0x401000\n"
                    ),
                    stderr="",
                ),
                "objdump": CommandResult(argv=["objdump", "-x", str(binary)], returncode=0, stdout="header\n", stderr=""),
                "nm": CommandResult(
                    argv=["nm", "-an", str(binary)],
                    returncode=0,
                    stdout="0000000000001130 T main\n                 U strcpy\n",
                    stderr="",
                ),
                "strings": CommandResult(
                    argv=["strings", "-n", "6", str(binary)],
                    returncode=0,
                    stdout="hello\n/bin/sh\npassword=demo\n",
                    stderr="",
                ),
            }

            with patch("src.modes.binary.workflow.shutil.which", side_effect=lambda tool: f"/usr/bin/{tool}"):
                with patch("src.modes.binary.workflow.CommandPolicy.run") as run_mock:
                    def _side_effect(argv, cwd=None):
                        cmd = argv[0]
                        if cmd == "readelf" and "-Ws" in argv:
                            return CommandResult(
                                argv=argv,
                                returncode=0,
                                stdout="   12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND strcpy\n",
                                stderr="",
                            )
                        return outputs[cmd]

                    run_mock.side_effect = _side_effect
                    artifact = scan_binary(root=root, binary=binary, args=["--demo"], timeout_seconds=10, config=AgentConfig())

            self.assertEqual(artifact["artifact_type"], "binary_audit")
            self.assertEqual(artifact["target"]["binary_path"], str(binary.resolve()))
            self.assertEqual(artifact["architecture"]["machine"], "Advanced Micro Devices X86-64")
            self.assertEqual(artifact["mitigations"]["nx"], "enabled")
            self.assertGreaterEqual(artifact["symbols"]["imported_function_count"], 1)
            self.assertTrue(any(item["indicator"] == "strcpy" for item in artifact["suspicious_indicators"]))
            self.assertTrue(any(entry["tool"] == "checksec" for entry in artifact["evidence"]))
            self.assertEqual(artifact["runtime_hints"]["args"], ["--demo"])

            markdown = render_binary_audit_markdown(artifact)
            self.assertIn("# Binary Audit", markdown)
            self.assertIn("Mitigations:", markdown)

    def test_scan_binary_marks_missing_tool_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)

            with patch(
                "src.modes.binary.workflow.shutil.which",
                side_effect=lambda tool: None if tool == "checksec" else f"/usr/bin/{tool}",
            ):
                with patch("src.modes.binary.workflow.CommandPolicy.run") as run_mock:
                    run_mock.return_value = CommandResult(argv=["file", str(binary)], returncode=0, stdout="ok\n", stderr="")
                    artifact = scan_binary(root=root, binary=binary, config=AgentConfig())

            checksec_entries = [entry for entry in artifact["evidence"] if entry["id"] == "checksec"]
            self.assertEqual(len(checksec_entries), 1)
            self.assertFalse(checksec_entries[0]["available"])
            self.assertEqual(checksec_entries[0]["status"], "unavailable")

    def test_scan_binary_rejects_missing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_binary = root / "missing.bin"
            with self.assertRaises(ValueError):
                scan_binary(root=root, binary=missing_binary, config=AgentConfig())

    def test_scan_binary_truncates_large_strings_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 64)
            long_strings = "\n".join(f"line-{index:03d}" for index in range(260)) + "\n"

            def _which(tool: str) -> str:
                return f"/usr/bin/{tool}"

            def _run(argv, cwd=None):
                if argv[0] == "strings":
                    return CommandResult(argv=argv, returncode=0, stdout=long_strings, stderr="")
                if argv[0] == "readelf" and "-Ws" in argv:
                    return CommandResult(argv=argv, returncode=0, stdout="", stderr="")
                return CommandResult(argv=argv, returncode=0, stdout="ok\n", stderr="")

            with patch("src.modes.binary.workflow.shutil.which", side_effect=_which):
                with patch("src.modes.binary.workflow.CommandPolicy.run", side_effect=_run):
                    artifact = scan_binary(root=root, binary=binary, config=AgentConfig())

            strings_entry = [entry for entry in artifact["evidence"] if entry["id"] == "strings"][0]
            self.assertTrue(strings_entry["stdout"]["truncated"])
            self.assertEqual(strings_entry["stdout"]["line_count_total"], 260)
            self.assertEqual(strings_entry["stdout"]["line_count_kept"], 200)


if __name__ == "__main__":
    unittest.main()
