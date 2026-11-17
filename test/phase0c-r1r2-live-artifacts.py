#!/usr/bin/env python3
"""Offline regression tests for the separately gated Phase 0C live adapter."""
from __future__ import annotations

import contextlib
import io
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "experiments"))
import phase0c_r1r2_live_evidence as live  # noqa: E402
import phase0c_r1r2_poc as poc  # noqa: E402


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def mock_connection(reply: bytes | None, *, hold_open: bool = False):
    client, peer = socket.socketpair()
    observed: dict[str, object] = {"payload": bytearray(), "closed": False}

    def serve() -> None:
        try:
            command = bytearray()
            while not command.endswith(b"\x00"):
                part = peer.recv(1)
                if not part:
                    return
                command.extend(part)
            observed["command"] = bytes(command)
            while True:
                header = recv_exact(peer, 4)
                if len(header) != 4:
                    break
                count = int.from_bytes(header, "big")
                if count == 0:
                    break
                payload = recv_exact(peer, count)
                if len(payload) != count:
                    break
                observed["payload"].extend(payload)  # type: ignore[union-attr]
            if reply is not None:
                peer.sendall(reply)
            if hold_open:
                try:
                    peer.recv(1)
                except OSError:
                    pass
        except OSError:
            pass
        finally:
            observed["closed"] = True
            peer.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return client, thread, observed


def budget() -> poc.ResourceBudget:
    return poc.ResourceBudget(poc.DEFAULT_RESOURCE_LIMITS)


class LiveAdapterTests(unittest.TestCase):
    def test_complete_instream_frames_chunks_and_accepts_clean(self) -> None:
        client, thread, observed = mock_connection(b"stream: OK\x00")
        scanner = live.ClamdInstreamScanner("mock", 3310, live.Deadline(2),
                                            connector=lambda _address, timeout: client)
        scanner.feed(b"benign", budget())
        result = scanner.finish()
        thread.join(1)
        self.assertEqual(observed["command"], b"zINSTREAM\x00")
        self.assertEqual(observed["payload"], b"benign")
        self.assertEqual(result["scanner_verdict"], "CLEAN")
        self.assertEqual(result["bytes_sent"], 6)

    def test_independent_zip_reader_accepts_descriptor_interop_controls(self) -> None:
        cases = {spec.case_id: spec for spec in poc.build_case_suite()}
        for case_id, eicar_expected in (("R2-15", True), ("R2-24", True),
                                        ("R2-25", True), ("R2-38", False), ("R2-39", False)):
            with self.subTest(case_id=case_id):
                checked = live._verify_zip_independently(cases[case_id].builder(),
                                                         eicar_expected=eicar_expected)
                self.assertEqual(checked["status"], "PASS")

    def test_eicar_positive_and_benign_negative_classification(self) -> None:
        spec = poc.CaseSpec("CTRL", "CONTROL", "control", poc.INSPECTED, "zip", lambda: b"x")
        base = {"verdict_match": True, "observed_verdict": poc.INSPECTED,
                "objects": [{"scanner_reason": "CLAMD_INSTREAM_COMPLETE",
                             "scanner_verdict": "INFECTED",
                             "offline_control_signature": "Win.Test.EICAR"}]}
        self.assertEqual(live._case_result(spec, base, {"scanner_verdict": "CLEAN"},
                                           eicar_required=True), "PASS")
        benign = {"verdict_match": True, "observed_verdict": poc.INSPECTED,
                  "objects": [{"scanner_reason": "CLAMD_INSTREAM_COMPLETE",
                               "scanner_verdict": "CLEAN"}]}
        self.assertEqual(live._case_result(spec, benign, {"scanner_verdict": "CLEAN"},
                                           eicar_required=False), "PASS")
        self.assertEqual(live._case_result(spec, benign, {"scanner_verdict": "INFECTED"},
                                           eicar_required=False), "FAIL")

    def test_malformed_missing_error_and_trailing_replies_fail_closed(self) -> None:
        bad_replies = [b"", b"stream: OK", b"stream: OK\x00garbage", b"unexpected\x00",
                       b"stream: test ERROR\x00"]
        for reply in bad_replies:
            with self.subTest(reply=reply):
                client, thread, _ = mock_connection(reply)
                scanner = live.ClamdInstreamScanner("mock", 3310, live.Deadline(1),
                                                    connector=lambda _address, timeout: client)
                scanner.feed(b"x", budget())
                with self.assertRaises(live.LiveScanError):
                    scanner.finish()
                thread.join(1)

    def test_shared_deadline_times_out_and_closes_incomplete_connection(self) -> None:
        client, thread, observed = mock_connection(None, hold_open=True)
        scanner = live.ClamdInstreamScanner("mock", 3310, live.Deadline(0.05),
                                            connector=lambda _address, timeout: client)
        scanner.feed(b"partial", budget())
        with self.assertRaises(live.LiveScanError):
            scanner.finish()
        scanner.abort()
        thread.join(1)
        self.assertTrue(observed["closed"])

    def test_explicit_abort_cancels_incomplete_instream(self) -> None:
        client, thread, observed = mock_connection(None, hold_open=True)
        scanner = live.ClamdInstreamScanner("mock", 3310, live.Deadline(1),
                                            connector=lambda _address, timeout: client)
        scanner.feed(b"incomplete", budget())
        scanner.abort()
        thread.join(1)
        self.assertTrue(observed["closed"])
        self.assertEqual(observed["payload"], b"incomplete")

    def test_default_offline_suite_has_no_network_or_subprocess_path(self) -> None:
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError("network used")), \
             mock.patch.object(live, "ClamdInstreamScanner", side_effect=AssertionError("live scanner used")), \
             mock.patch.object(live, "_command", side_effect=AssertionError("live command used")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess used")), \
             mock.patch("subprocess.run", side_effect=AssertionError("subprocess used")):
            report = poc.run_offline_suite(start_tracemalloc=False)
        self.assertFalse(report["live_clamav_executed"])
        self.assertEqual(report["network_calls"], 0)
        self.assertEqual(report["subprocess_calls"], 0)
        self.assertFalse(report["summary"]["complete_safe_scan_claimed"])

    def test_live_mode_requires_explicit_opt_in(self) -> None:
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError("network used")), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                live.main([])

    def test_input_expansion_member_depth_entry_and_memory_limits_fail_closed_offline(self) -> None:
        cases = {spec.case_id: spec for spec in poc.build_case_suite()}
        for case_id in ("R2-05", "R2-11", "R2-12", "R2-18", "R1-13"):
            with self.subTest(case_id=case_id):
                observed = poc.run_case(cases[case_id])
                self.assertEqual(observed["observed_verdict"], poc.REJECTED)
                self.assertTrue(observed["budget"]["resource_limits_hit"] or
                                observed["observed_verdict"] == poc.REJECTED)
        limits = poc.replace(poc.DEFAULT_RESOURCE_LIMITS, max_input_bytes=8, max_memory_bytes=8,
                             max_materialized_object_bytes=8)
        budget_instance = poc.ResourceBudget(limits)
        with self.assertRaises(poc.BudgetExceeded):
            budget_instance.charge_input(9)
        with self.assertRaises(poc.BudgetExceeded):
            budget_instance.reserve_memory(9)

    def test_live_timeout_adjustments_and_resource_boundaries_are_explicit(self) -> None:
        self.assertEqual(live.CASE_DEADLINE_SECONDS, 90)
        self.assertEqual(live.TOTAL_DEADLINE_SECONDS, 20 * 60)
        self.assertEqual(live.LIVE_CPU_ACCOUNTING_SECONDS, 15)

        now = [10.0]
        deadline = live.Deadline(1.0, clock=lambda: now[0])
        self.assertEqual(deadline.remaining(), 1.0)
        now[0] = 11.1
        with self.assertRaisesRegex(live.LiveScanError, "END_TO_END_DEADLINE_EXCEEDED"):
            deadline.remaining()

    def test_coverage_statuses_remain_distinct_from_test_case_result(self) -> None:
        unsupported = poc.CaseSpec("UNSUPPORTED", "R1", "gap", poc.UNSUPPORTED, "pdf", lambda: b"")
        structural = {"verdict_match": True, "observed_verdict": poc.UNSUPPORTED, "objects": []}
        self.assertEqual(live._case_result(unsupported, structural,
                                           {"scanner_verdict": "CLEAN"}, eicar_required=False), "PASS")
        self.assertEqual(structural["observed_verdict"], "UNSUPPORTED")
        self.assertNotEqual("PASS", structural["observed_verdict"])

    def test_evidence_finalizer_records_cleanup_and_rejects_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "ledger.json"
            cleanup = root / "cleanup.json"
            report.write_text(json.dumps({"case_results": []}), encoding="utf-8")
            cleanup.write_text(json.dumps({"status": "PASS", "scratch_absent": True}), encoding="utf-8")
            merged = live.finalize_evidence(report, cleanup)
            self.assertEqual(merged["cleanup"]["status"], "PASS")
            report.write_text(json.dumps({"oversize": "x" * live.MAX_EVIDENCE_BYTES}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "EVIDENCE_SIZE_LIMIT"):
                live.finalize_evidence(report, cleanup)

    def test_cleanup_failure_is_preserved_as_nonpass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "ledger.json"
            cleanup = Path(tmp) / "cleanup.json"
            report.write_text(json.dumps({"case_results": []}), encoding="utf-8")
            cleanup.write_text(json.dumps({"status": "FAIL", "scratch_absent": False}), encoding="utf-8")
            merged = live.finalize_evidence(report, cleanup)
            self.assertEqual(merged["cleanup"]["status"], "FAIL")
            self.assertFalse(merged["cleanup"]["scratch_absent"])
            self.assertEqual(live.main(["--mode", "finalize", "--output", str(report),
                                       "--cleanup-status", str(cleanup)]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
