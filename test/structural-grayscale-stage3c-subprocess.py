#!/usr/bin/env python3
"""Regression tests for fail-closed Stage 3C subprocess diagnostics."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "experiments" / "structural_grayscale_subprocess.py"
SPEC = importlib.util.spec_from_file_location("structural_grayscale_subprocess_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Stage 3C subprocess diagnostics")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SubprocessDiagnosticsTests(unittest.TestCase):
    def test_success_is_returned_normally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = MODULE.run_checked(
                [sys.executable, "-c", "print('ok')"],
                operation="pdfjs-text-extraction",
                cwd=Path(directory),
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "ok")

    def test_failure_reports_operation_and_status_without_sensitive_values(self) -> None:
        secret = "STAGE3C_DIAGNOSTIC_SECRET"
        command = (
            "import sys; "
            "sys.stderr.write('password=" + secret + " document=/private/customer.pdf'); "
            "raise SystemExit(17)"
        )
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"DIP_TEST_SECRET": secret}, clear=False
        ):
            with self.assertRaisesRegex(RuntimeError, '"exit_status":17') as raised:
                MODULE.run_checked(
                    [sys.executable, "-c", command],
                    operation="pdfjs-text-extraction",
                    cwd=Path(directory),
                )
        diagnostic = str(raised.exception)
        self.assertIn('"operation":"pdfjs-text-extraction"', diagnostic)
        self.assertIn("[REDACTED]", diagnostic)
        self.assertIn("[PDF_PATH]", diagnostic)
        self.assertNotIn(secret, diagnostic)
        self.assertNotIn("/private/customer.pdf", diagnostic)

    def test_unexpected_launch_exception_is_not_silently_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, '"exit_status":null') as raised:
                MODULE.run_checked(
                    [str(Path(directory) / "missing-executable")],
                    operation="pdfjs-text-extraction",
                    cwd=Path(directory),
                )
        self.assertIn('"operation":"pdfjs-text-extraction"', str(raised.exception))
        self.assertIn("subprocess launch failed", str(raised.exception))
        self.assertNotIn("missing-executable", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
