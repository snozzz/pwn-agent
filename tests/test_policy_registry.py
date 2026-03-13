from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.policy import CommandPolicy, PolicyError


class PolicyRegistryTests(unittest.TestCase):
    def test_policy_rejects_root_escape_path_argument(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = CommandPolicy(root)
            with self.assertRaises(PolicyError):
                policy.validate(["file", "/etc/passwd"])

    def test_policy_returns_timeout_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = CommandPolicy(root, timeout_seconds=1)

            with patch("src.policy.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["find"], timeout=1)):
                result = policy.run(["find", "."])

            self.assertEqual(result.returncode, 124)
            self.assertIn("[policy-timeout]", result.stderr)


if __name__ == "__main__":
    unittest.main()
