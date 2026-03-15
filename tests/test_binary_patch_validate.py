from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import AgentConfig
from src.policy import CommandResult
from src.modes.binary.patching import PATCH_VALIDATION_SCHEMA, load_patch_input, patch_validate


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


class BinaryPatchValidateTests(unittest.TestCase):
    def test_patch_validate_applies_structured_patch_and_runs_bounded_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_dir = root / "src"
            source_dir.mkdir()
            source_file = source_dir / "demo.c"
            source_file.write_text("int main(void) { strcpy(buf, input); return 0; }\n", encoding="utf-8")
            (root / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "file": "src/demo.c",
                            "command": "cc src/demo.c -o demo_patched",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            patch_payload = load_patch_input(FIXTURE_DIR / "patch_script_replace_text.json")

            def _rebuild(_policy, _target, output_name):
                output_binary = root / output_name
                output_binary.write_bytes(b"\x7fELF" + b"A" * 32)
                return CommandResult(argv=["cc", "src/demo.c", "-o", output_name], returncode=0, stdout="rebuilt\n", stderr="")

            with patch("src.modes.binary.patching.rebuild_target", side_effect=_rebuild):
                with patch(
                    "src.modes.binary.patching.verify_binary_execution",
                    return_value=(0, {"sanitizer_signal": False, "stdout_head": ["ok"], "stderr_head": []}),
                ) as verify_mock:
                    with patch(
                        "src.modes.binary.patching.triage_binary_crash",
                        return_value={
                            "crash_summary": {
                                "suspicious": False,
                                "reason": "clean-exit",
                                "signal_name": None,
                                "exit_code": 0,
                            },
                            "execution_result": {
                                "exit_code": 0,
                                "stdout_head": ["ok"],
                                "stderr_head": [],
                            },
                        },
                    ) as triage_mock:
                        artifact = patch_validate(
                            root=root,
                            patch_payload=patch_payload,
                            patch_source_path=FIXTURE_DIR / "patch_script_replace_text.json",
                            config=AgentConfig(),
                        )

            self.assertEqual(artifact["schema"], PATCH_VALIDATION_SCHEMA)
            self.assertIn("snprintf(buf, sizeof(buf), \"%s\", input);", source_file.read_text(encoding="utf-8"))
            self.assertEqual(artifact["apply_result"]["build"]["status"], "ok")
            self.assertEqual(artifact["validation_result"]["overall_status"], "passed")
            self.assertEqual(artifact["remaining_risk_summary"]["level"], "low")
            self.assertIn("no longer reproduces suspicious behavior", artifact["regression_notes"][0])
            self.assertEqual(verify_mock.call_count, 2)
            triage_mock.assert_called_once()

    def test_patch_validate_supports_existing_binary_without_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            binary = binary_dir / "demo.bin"
            binary.write_bytes(b"\x7fELF" + b"A" * 32)
            patch_payload = {
                "schema": "pwn-agent.binary-patch-candidate.v1",
                "patch_metadata": {
                    "patch_id": "existing-binary",
                    "summary": "Validate an already-patched binary",
                },
                "build": {
                    "kind": "existing-binary",
                    "binary_path": str(binary),
                },
                "validation": {
                    "baseline": {
                        "args": ["smoke"],
                    }
                },
            }

            with patch(
                "src.modes.binary.patching.verify_binary_execution",
                return_value=(0, {"sanitizer_signal": False, "stdout_head": ["ok"], "stderr_head": []}),
            ):
                artifact = patch_validate(
                    root=root,
                    patch_payload=patch_payload,
                    patch_source_path=root / "patch.json",
                    config=AgentConfig(),
                )

            self.assertEqual(artifact["apply_result"]["build"]["status"], "skipped")
            self.assertEqual(artifact["target"]["binary_path"], str(binary))
            self.assertEqual(artifact["validation_result"]["overall_status"], "partial")
            self.assertEqual(artifact["remaining_risk_summary"]["level"], "medium")

    def test_patch_validate_reports_rebuild_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_dir = root / "src"
            source_dir.mkdir()
            (source_dir / "demo.c").write_text("int main(void) { strcpy(buf, input); return 0; }\n", encoding="utf-8")
            (root / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "file": "src/demo.c",
                            "command": "cc src/demo.c -o demo_patched",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            patch_payload = load_patch_input(FIXTURE_DIR / "patch_script_replace_text.json")

            with patch(
                "src.modes.binary.patching.rebuild_target",
                return_value=CommandResult(argv=["cc"], returncode=1, stdout="", stderr="compile failed"),
            ):
                artifact = patch_validate(
                    root=root,
                    patch_payload=patch_payload,
                    patch_source_path=FIXTURE_DIR / "patch_script_replace_text.json",
                    config=AgentConfig(),
                )

            self.assertEqual(artifact["apply_result"]["build"]["status"], "failed")
            self.assertEqual(artifact["validation_result"]["overall_status"], "failed")
            self.assertEqual(artifact["remaining_risk_summary"]["level"], "high")
            self.assertIn("Build or binary materialization failed", artifact["regression_notes"][0])

    def test_patch_validate_rejects_root_escape_in_edit_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patch_payload = {
                "schema": "pwn-agent.patch-script.v1",
                "patch_metadata": {"patch_id": "escape"},
                "edits": [
                    {
                        "op": "write_file",
                        "path": "../escape.txt",
                        "content": "nope",
                    }
                ],
                "build": {
                    "kind": "existing-binary",
                    "binary_path": str(root / "demo.bin"),
                },
            }
            (root / "demo.bin").write_bytes(b"\x7fELF" + b"A" * 32)

            with self.assertRaises(ValueError):
                patch_validate(root=root, patch_payload=patch_payload, config=AgentConfig())


if __name__ == "__main__":
    unittest.main()
