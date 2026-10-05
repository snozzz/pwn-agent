#!/usr/bin/env python3
"""Run the pwn-agent unittest suite without requiring pytest.

The ``tests/`` directory is intentionally not a package, so ``unittest discover``
cannot import it directly on every interpreter. This runner adds the repository
root to ``sys.path`` and loads each ``tests/test_*.py`` module explicitly.

Usage:
    python3 scripts/run_tests.py [repo_root]

The canonical interpreter is CPython 3.11 (see ``pyproject.toml``). Product code
must also remain importable/runnable under the ``python3`` the executor spawns
for internal leaf commands.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


def main(argv: list[str]) -> int:
    repo = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo))

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    load_errors: list[str] = []
    for test_file in sorted((repo / "tests").glob("test_*.py")):
        module_name = "tests." + test_file.stem
        try:
            suite.addTests(loader.loadTestsFromName(module_name))
        except Exception as exc:  # pragma: no cover - surfaced in output
            load_errors.append(f"LOAD-ERROR {module_name}: {exc}")

    for line in load_errors:
        print(line)

    result = unittest.TextTestRunner(verbosity=1).run(suite)
    print(
        f"\nSUMMARY: ran={result.testsRun} "
        f"failures={len(result.failures)} errors={len(result.errors)} "
        f"skipped={len(result.skipped)} load_errors={len(load_errors)}"
    )
    return 0 if (result.wasSuccessful() and not load_errors) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
