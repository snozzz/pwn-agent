from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.main import build_parser, main


class MainModeTests(unittest.TestCase):
    def test_build_parser_supports_binary_commands(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "binary-scan",
                "--root",
                "/tmp/demo",
                "--binary",
                "/tmp/demo/app",
                "--output",
                "/tmp/demo/binary-analysis.json",
            ]
        )

        self.assertEqual(args.command, "binary-scan")
        self.assertEqual(args.binary, Path("/tmp/demo/app"))

    def test_main_routes_audit_commands_to_audit_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("src.main.handle_audit_command", return_value=0) as audit_handler:
                with patch("src.main.handle_binary_command", return_value=None) as binary_handler:
                    returncode = main(["scan", "--root", str(root), "--report", str(root / "report.md")])

        self.assertEqual(returncode, 0)
        audit_handler.assert_called_once()
        binary_handler.assert_not_called()

    def test_main_routes_binary_commands_to_binary_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("src.main.handle_audit_command", return_value=None) as audit_handler:
                with patch("src.main.handle_binary_command", return_value=7) as binary_handler:
                    returncode = main(
                        [
                            "binary-plan",
                            "--analysis-json",
                            str(root / "binary-analysis.json"),
                            "--output",
                            str(root / "binary-plan.json"),
                        ]
                    )

        self.assertEqual(returncode, 7)
        audit_handler.assert_called_once()
        binary_handler.assert_called_once()


if __name__ == "__main__":
    unittest.main()
