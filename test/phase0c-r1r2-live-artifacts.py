#!/usr/bin/env python3
"""Offline regression tests for the separately gated Phase 0C live adapter."""
from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SAFE_CLEANUP = ROOT / "scripts" / "experiments" / "phase0c_safe_scratch_cleanup.sh"
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
    def _run_safe_cleanup(self, runner_temp: Path, expected_work: Path, fakebin: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
        return subprocess.run(["bash", str(SAFE_CLEANUP), str(runner_temp), str(expected_work)],
                              cwd=ROOT, env=env, text=True, capture_output=True, timeout=5)

    def test_safe_cleanup_uses_sudo_only_for_fixed_canonical_scratch_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fakebin = root / "bin"
            fakebin.mkdir()
            sudo = fakebin / "sudo"
            sudo.write_text("#!/bin/sh\nprintf '%s\n' \"$*\" >> \"$SUDO_LOG\"\nexec \"$@\"\n", encoding="utf-8")
            sudo.chmod(0o755)
            runner_temp = root / "runner" / "work" / "_temp"
            runner_temp.mkdir(parents=True)
            scratch = runner_temp / "clamav-phase0c-work"
            (scratch / "db").mkdir(parents=True)
            protected_file = scratch / "db" / "owned-by-scanner"
            protected_file.write_text("signature database", encoding="utf-8")
            protected_file.chmod(0)
            env = os.environ.copy()
            env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
            log = root / "sudo.log"
            env["SUDO_LOG"] = str(log)
            result = subprocess.run(["bash", str(SAFE_CLEANUP), str(runner_temp), str(scratch)],
                                    cwd=ROOT, env=env, text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(scratch.exists())
            self.assertRegex(log.read_text(encoding="utf-8"), r"^rm -rf -- .*/clamav-phase0c-work\n$")

            protected = root / "outside-scratch"
            protected.mkdir()
            (protected / "do-not-delete").write_text("kept", encoding="utf-8")
            scratch.symlink_to(protected, target_is_directory=True)
            rejected = self._run_safe_cleanup(runner_temp, scratch, fakebin)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertTrue((protected / "do-not-delete").exists())
            scratch.unlink()
            scratch.mkdir()
            mismatch = self._run_safe_cleanup(runner_temp, root / "wrong-work-dir", fakebin)
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertTrue(scratch.exists())

            traversal = str(runner_temp.parent / "../_temp")
            rejected_traversal = self._run_safe_cleanup(Path(traversal), scratch, fakebin)
            self.assertNotEqual(rejected_traversal.returncode, 0)
            self.assertTrue(scratch.exists())

            scratch.rmdir()
            linked_temp = runner_temp.parent / "_temp-link-target"
            linked_temp.mkdir()
            symlink_temp = runner_temp.parent / "_temp"
            symlink_temp.rmdir()
            symlink_temp.symlink_to(linked_temp, target_is_directory=True)
            rejected_symlink = self._run_safe_cleanup(symlink_temp, linked_temp / "clamav-phase0c-work", fakebin)
            self.assertNotEqual(rejected_symlink.returncode, 0)

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
        for case_id, eicar_expected in (("R2-01", True), ("R2-02", True),
                                        ("R2-03", True), ("R2-04", True),
                                        ("R2-15", True), ("R2-24", True),
                                        ("R2-25", True), ("R2-38", False),
                                        ("R2-39", False), ("CTRL-NEG-01", False),
                                        ("CTRL-NEG-02", False)):
            with self.subTest(case_id=case_id):
                checked = live._verify_zip_independently(cases[case_id].builder(),
                                                         eicar_expected=eicar_expected)
                self.assertEqual(checked["status"], "PASS")

    def test_independent_zip_reader_enforces_expansion_entry_depth_and_memory_budgets(self) -> None:
        cases = {spec.case_id: spec for spec in poc.build_case_suite()}
        data = cases["R2-01"].builder()
        verified = live._verify_zip_independently(data, eicar_expected=True)
        self.assertGreater(verified["expanded_bytes"], 0)
        self.assertGreater(verified["largest_member_bytes"], 0)
        self.assertGreater(verified["entry_count"], 1)
        self.assertGreater(verified["max_depth_seen"], 0)
        for kwargs, failure in (
            ({"max_member_bytes": verified["largest_member_bytes"] - 1}, "member_limit"),
            ({"max_expanded_bytes": verified["expanded_bytes"] - 1}, "expansion_limit"),
            ({"max_entries": verified["entry_count"] - 1}, "entry_limit"),
            ({"max_depth": verified["max_depth_seen"] - 1}, "depth_limit"),
            ({"max_memory_bytes": verified["peak_memory_bytes"] - 1}, "memory_limit"),
        ):
            with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, failure):
                live._verify_zip_independently(data, eicar_expected=True, **kwargs)
        exact = live._verify_zip_independently(
            data, eicar_expected=True, max_member_bytes=verified["largest_member_bytes"],
            max_expanded_bytes=verified["expanded_bytes"], max_entries=verified["entry_count"],
            max_depth=verified["max_depth_seen"], max_memory_bytes=verified["peak_memory_bytes"])
        self.assertEqual(exact["status"], "PASS")

    def test_independent_zip_reader_rejects_expansion_and_entry_abuse(self) -> None:
        cases = {spec.case_id: spec for spec in poc.build_case_suite()}
        for case_id, kwargs, message in (
            ("R2-11", {"max_expanded_bytes": 1024}, "expansion_limit"),
            ("R2-12", {"max_entries": 5}, "entry_limit"),
        ):
            with self.subTest(case_id=case_id), self.assertRaisesRegex(ValueError, message):
                live._verify_zip_independently(cases[case_id].builder(), eicar_expected=False, **kwargs)

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

    def _passing_aggregate_report(self) -> dict[str, object]:
        provenance = {
            "architecture": "linux/arm64", "clamav_local_image_id": "sha256:" + "a" * 64,
            "client_local_image_id": "sha256:" + "b" * 64, "clamav_config_sha256": "c" * 64,
            "clamav_package_version": "1.5.4+dfsg-0ubuntu0.22.04.1+dipphase0b1",
            "network_mode": "internal_no_egress",
        }
        runtime = live._validate_runtime_provenance(provenance)
        cases = []
        for case_id, coverage in live.REQUIRED_CASE_EXPECTATIONS.items():
            direct = case_id == "CTRL-EICAR-RAW"
            positive = case_id in live.REQUIRED_EICAR_CASE_IDS
            original = {"classification": "OBSERVATIONAL_ONLY", "scanner_verdict": "CLEAN",
                        "scanner_reason": "CLAMD_INSTREAM_COMPLETE",
                        "response_framing": "ONE_NUL_TERMINATED_REPLY"}
            if direct:
                original.update({"classification": "DIRECT_POSITIVE_CONTROL", "scanner_verdict": "INFECTED",
                                 "signature": "Win.Test.EICAR"})
            payloads = []
            if coverage == poc.INSPECTED and not direct:
                payloads = [{"scanner_result": {
                    "scanner_verdict": "INFECTED" if positive else "CLEAN",
                    "reason": "CLAMD_INSTREAM_COMPLETE",
                    "signature": "Win.Test.EICAR" if positive else None,
                    "response_framing": "ONE_NUL_TERMINATED_REPLY",
                }}]
            kind = "direct_eicar" if direct else (
                "pdf" if case_id.startswith("R1-") or case_id in
                {"BENIGN-PDF-EN-AR", "ENCRYPTED-PDF-UNLOCK-REQUIRED"} else "zip")
            cases.append({
                "case_id": case_id, "input_kind": kind,
                "independent_verification": {"status": "PASS"},
                "TEST_CASE_RESULT": "PASS",
                "SECURITY_COVERAGE_STATUS": coverage,
                "expected_structural_status": coverage,
                "ORIGINAL_CONTAINER_SCAN_RESULT": original,
                "EXTRACTED_PAYLOAD_SCAN_RESULT": payloads,
            })
        report = {
            "schema_version": "phase0c-live-evidence-v1",
            "clamd": {"zPING": "PONG", "engine_version": "1.5.4",
                      "signature_database_version": "123456", "signature_database_date": "Tue Nov 17 2026"},
            "runtime_provenance": provenance, "runtime_verification": runtime,
            "independent_fixture_verification_overall": "PASS",
            "required_fixture_verification": [
                {"id": fixture_id, "sha256": "d" * 64, "tool_verification_status": "PASS"}
                for fixture_id in live.REQUIRED_FIXTURE_IDS
            ],
            "case_results": cases,
            "coverage_gaps": ["arbitrary_pdf_streams"],
            "expected_coverage_gaps": [
                {"case_id": case_id, "coverage_status": status}
                for case_id, status in live.REQUIRED_CASE_EXPECTATIONS.items() if status != poc.INSPECTED
            ],
            "COMPLETE_SAFE_SCAN": False,
            "cleanup": {"status": "PASS", "runtime_verification_passed": True,
                        "clamd_container_absent": True,
                        "client_container_absent": True, "internal_network_absent": True,
                        "candidate_image_absent": True, "client_image_absent": True,
                        "scratch_absent": True},
        }
        return report

    def test_aggregate_pass_keeps_expected_coverage_gaps_incomplete(self) -> None:
        pending = live._derive_aggregate(self._passing_aggregate_report(), require_cleanup=False)
        self.assertEqual(pending["OVERALL_RESULT"], "PENDING_CLEANUP")
        self.assertEqual(pending["required_evidence"]["status"], "PENDING")
        report = live._derive_aggregate(pending, require_cleanup=True)
        self.assertEqual(report["OVERALL_RESULT"], "PASS")
        self.assertEqual(report["COMPLETE_SAFE_SCAN"], False)
        self.assertEqual(report["expected_coverage_gaps"][0]["coverage_status"], poc.NOT_VERIFIED)
        gap = next(case for case in report["case_results"] if case["case_id"] == "R1-06")
        self.assertEqual(gap["TEST_CASE_RESULT"], "PASS")
        self.assertEqual(gap["SECURITY_COVERAGE_STATUS"], poc.NOT_VERIFIED)

    def test_mandatory_not_verified_fixture_scanner_runtime_or_cleanup_cannot_pass(self) -> None:
        report = self._passing_aggregate_report()
        mandatory = next(case for case in report["case_results"] if case["case_id"] == "R2-01")
        mandatory["TEST_CASE_RESULT"] = "NOT_VERIFIED"
        self.assertEqual(live._derive_aggregate(report, require_cleanup=True)["OVERALL_RESULT"], "FAIL")

        for mutation in (
            lambda doc: doc.update(independent_fixture_verification_overall="NOT_VERIFIED"),
            lambda doc: doc["required_fixture_verification"].pop(),
            lambda doc: doc["clamd"].update(signature_database_version=""),
            lambda doc: doc.update(runtime_verification={"status": "NOT_VERIFIED", "checks": {}}),
            lambda doc: next(case for case in doc["case_results"] if case["case_id"] == "R2-01")["ORIGINAL_CONTAINER_SCAN_RESULT"].update(response_framing=""),
            lambda doc: next(case for case in doc["case_results"] if case["case_id"] == "R2-01")["EXTRACTED_PAYLOAD_SCAN_RESULT"].clear(),
            lambda doc: doc["cleanup"].update(scratch_absent=False),
            lambda doc: doc["cleanup"].update(runtime_verification_passed=False),
            lambda doc: doc.pop("cleanup"),
        ):
            broken = self._passing_aggregate_report()
            mutation(broken)
            self.assertEqual(live._derive_aggregate(broken, require_cleanup=True)["OVERALL_RESULT"], "FAIL")

    def test_finalizer_nonpass_returns_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            cleanup_path = Path(tmp) / "cleanup.json"
            report = self._passing_aggregate_report()
            report["case_results"][0]["TEST_CASE_RESULT"] = "NOT_VERIFIED"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            cleanup_path.write_text(json.dumps(report["cleanup"]), encoding="utf-8")
            finalized = live.finalize_evidence(report_path, cleanup_path)
            self.assertEqual(finalized["OVERALL_RESULT"], "FAIL")
            self.assertNotEqual(live.main(["--mode", "finalize", "--output", str(report_path),
                                           "--cleanup-status", str(cleanup_path)]), 0)

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
