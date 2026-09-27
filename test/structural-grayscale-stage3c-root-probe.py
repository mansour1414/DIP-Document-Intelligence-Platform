#!/usr/bin/env python3
"""Regression tests for the Stage 3C read-only-root sandbox probe."""

from __future__ import annotations

import errno
import importlib.util
import pathlib
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROBE_PATH = ROOT / "scripts" / "experiments" / "structural-grayscale-stage3c-sandbox-probe.py"

# The guard is pure stdlib, but its owning probe imports runtime-only packages.
# Minimal import stubs let this unit test exercise the exact production function
# without adding those experimental packages to the host development environment.
sys.modules.setdefault("pikepdf", types.ModuleType("pikepdf"))
sys.modules.setdefault("resource", types.ModuleType("resource"))
pil = sys.modules.setdefault("PIL", types.ModuleType("PIL"))
pil.Image = object()
pil.features = object()

spec = importlib.util.spec_from_file_location("stage3c_sandbox_probe", PROBE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load Stage 3C sandbox probe")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakePath:
    def __init__(self, write_error: BaseException | None = None) -> None:
        self.write_error = write_error
        self.unlink_calls = 0

    def write_text(self, _value: str, *, encoding: str) -> int:
        if self.write_error is not None:
            raise self.write_error
        return 9

    def unlink(self) -> None:
        self.unlink_calls += 1


class ReadOnlyRootProbeTests(unittest.TestCase):
    def test_expected_rejection_does_not_attempt_cleanup(self) -> None:
        for error_number in (errno.EROFS, errno.EACCES):
            with self.subTest(error_number=error_number):
                path = FakePath(OSError(error_number, "expected rejection"))
                self.assertTrue(probe.verify_read_only_root(path))
                self.assertEqual(path.unlink_calls, 0)

    def test_unexpected_write_success_fails_after_cleanup(self) -> None:
        path = FakePath()
        with self.assertRaisesRegex(AssertionError, "root filesystem is writable"):
            probe.verify_read_only_root(path)
        self.assertEqual(path.unlink_calls, 1)

    def test_unexpected_exceptions_fail_closed_without_cleanup(self) -> None:
        for unexpected in (OSError(errno.ENOSPC, "disk full"), RuntimeError("unexpected")):
            with self.subTest(exception=type(unexpected).__name__):
                path = FakePath(unexpected)
                with self.assertRaises(type(unexpected)):
                    probe.verify_read_only_root(path)
                self.assertEqual(path.unlink_calls, 0)


if __name__ == "__main__":
    unittest.main()
