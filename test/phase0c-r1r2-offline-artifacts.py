#!/usr/bin/env python3
"""DIP Phase 0C -- offline regression suite for the R1/R2 isolated PoC.

EXPERIMENTAL / ISOLATED. Run explicitly (npm test does NOT run .py files):

    python3 test/phase0c-r1r2-offline-artifacts.py

No network, no subprocesses, no live scanner, no disk writes: the PoC under test
performs zero filesystem extraction, and this suite asserts that property.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POC_PATH = ROOT / "scripts" / "experiments" / "phase0c_r1r2_poc.py"
FIXTURES_PATH = ROOT / "scripts" / "experiments" / "phase0c_r1r2_fixtures.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


P = _load("phase0c_r1r2_poc", POC_PATH)
F = _load("phase0c_r1r2_fixtures", FIXTURES_PATH)

EICAR = F.EICAR_BYTES
BENIGN = F.BENIGN_BYTES


class FixtureIntegrityTests(unittest.TestCase):
    def test_eicar_signature_and_sha256(self) -> None:
        self.assertEqual(F.sha256_hex(EICAR), F.EICAR_EXPECTED_SHA256)
        # The full signature must NOT appear as a source literal (split halves only).
        source = FIXTURES_PATH.read_text()
        self.assertNotIn(EICAR.decode("ascii"), source)
        # Each half alone is harmless: neither contains the full signature.
        self.assertNotIn(EICAR, F.EICAR_PART_1)
        self.assertNotIn(EICAR, F.EICAR_PART_2)

    def test_zip_builders_are_deterministic_and_minimal(self) -> None:
        z32a = F.zip32(BENIGN)
        z32b = F.zip32(BENIGN)
        self.assertEqual(z32a, z32b)
        self.assertLess(len(z32a), 1024)
        # No ZIP64 structures in the ZIP32 builder.
        self.assertNotIn(b"PK\x06\x06", z32a)
        self.assertNotIn(b"PK\x06\x07", z32a)
        # ZIP64 builder: EOCD + locator + sentinels present.
        z64 = F.zip64(EICAR)
        self.assertIn(b"PK\x06\x06", z64)
        self.assertIn(b"PK\x06\x07", z64)
        self.assertIn(b"\xff\xff\xff\xff", z64)
        self.assertNotEqual(z64, F.zip32(EICAR))

    def test_nested_zip_chain_depth(self) -> None:
        chain = F.nested_zip_chain(3, BENIGN)
        # The PoC parser must be able to walk the chain: 3 containers, depth 3.
        budget = P.ResourceBudget()
        ledger = P.CoverageLedger("chain", budget)
        structural = P.inspect_zip_container(
            budget, ledger, object_path="root", data=chain, depth=0,
            scanner_factory=P.OfflineEicarControlProbe,
        )
        self.assertEqual(structural, "WELL_FORMED_ZIP32")
        self.assertEqual(budget.max_depth_seen, 3)
        # EICAR absent: negative control stays absent at every depth.
        for record in ledger.objects:
            self.assertEqual(record.offline_control_signature, "EICAR_SIGNATURE_ABSENT")

    def test_pdf_fixture_structure(self) -> None:
        data = F.build_pdf(F.PdfSpec(attachment=F.zip32(BENIGN)))
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertEqual(data.count(b"%%EOF"), 1)
        for marker in (b"startxref", b"trailer", b"xref\n", b"/Catalog"):
            self.assertIn(marker, data)
        # xref table is exact: the startxref offset points at "xref\n".
        tail = data[data.rfind(b"startxref") + len(b"startxref"):].lstrip(b"\r\n")
        startxref = int(tail.split(b"\n")[0])
        self.assertTrue(data.startswith(b"xref\n", startxref),
                        f"startxref offset {startxref} does not point at the xref table")
        # Name tree -> filespec -> /EF wiring exists.
        self.assertIn(b"/EmbeddedFiles", data)
        self.assertIn(b"/Type /Filespec", data)
        self.assertIn(b"/EF << /F", data)
        self.assertIn(b"/Type /EmbeddedFile", data)

    def test_pdf_modes_wire_expected_references(self) -> None:
        self.assertIn(b"/Names [", F.build_pdf(F.PdfSpec(attachment=BENIGN, mode="names_tree")))
        self.assertIn(b"/UF 8 0 R", F.build_pdf(F.PdfSpec(attachment=BENIGN, mode="filespec_ef")))
        self.assertIn(b"/Subtype /FileAttachment", F.build_pdf(F.PdfSpec(attachment=BENIGN, mode="annotation")))
        self.assertIn(b"/AF [", F.build_pdf(F.PdfSpec(attachment=BENIGN, mode="af")))
        # "unreferenced" mode: the /Filespec + /EF stream exist in the file, but no
        # catalog-level reference (/Names /EmbeddedFiles, /AF, /Annots) reaches them.
        unreferenced = F.build_pdf(F.PdfSpec(attachment=BENIGN, mode="unreferenced"))
        self.assertIn(b"/Type /Filespec", unreferenced)
        self.assertIn(b"/Type /EmbeddedFile", unreferenced)
        self.assertNotIn(b"/EmbeddedFiles", unreferenced)
        self.assertNotIn(b"/AF [", unreferenced)
        self.assertNotIn(b"/Subtype /FileAttachment", unreferenced)

    def test_synthetic_markers_are_labelled(self) -> None:
        data = F.build_pdf(F.PdfSpec(attachment=BENIGN, synthetic_encrypt_marker=True))
        self.assertIn(b"/Encrypt 12 0 R", data)
        revised = F.build_pdf(F.PdfSpec(attachment=BENIGN, incremental_revision=True))
        self.assertEqual(revised.count(b"%%EOF"), 2)
        malformed = F.build_pdf(F.PdfSpec(attachment=BENIGN, malformed=True))
        self.assertNotIn(b"startxref", malformed)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.cpu = 0.0

    def monotonic(self) -> float:
        return self.now

    def process_time(self) -> float:
        return self.cpu


def make_budget(**overrides: object) -> P.ResourceBudget:
    limits = P.DEFAULT_RESOURCE_LIMITS
    if overrides:
        limits = P.replace(limits, **overrides)  # type: ignore[arg-type]
    return P.ResourceBudget(limits)


class ResourceBudgetTests(unittest.TestCase):
    def test_input_byte_limit(self) -> None:
        budget = make_budget(max_input_bytes=10)
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.charge_input(11)
        self.assertEqual(ctx.exception.code, "INPUT_BYTE_LIMIT")
        self.assertIn("INPUT_BYTE_LIMIT", budget.limits_hit)

    def test_expanded_and_member_limits(self) -> None:
        budget = make_budget(max_expanded_bytes=100, max_member_bytes=50)
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.charge_expanded(200)
        self.assertEqual(ctx.exception.code, "EXPANDED_BYTE_LIMIT")
        # New Finding-2 contract: member_bytes is the RUNNING TOTAL including
        # the current chunk. Exactly at the ceiling is allowed; one over is not.
        budget2 = make_budget(max_expanded_bytes=100, max_member_bytes=50)
        budget2.charge_expanded(30, member_bytes=30)
        budget2.charge_expanded(20, member_bytes=50)  # exactly at ceiling: allowed
        self.assertEqual(budget2.limits_hit, [])
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget2.charge_expanded(1, member_bytes=51)  # one byte over: rejected
        self.assertEqual(ctx.exception.code, "MEMBER_BYTE_LIMIT")

    def test_entry_count_and_depth_limits(self) -> None:
        budget = make_budget(max_entries=2)
        budget.count_entry()
        budget.count_entry()
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.count_entry()
        self.assertEqual(ctx.exception.code, "ENTRY_COUNT_LIMIT")
        budget_depth = make_budget(max_depth=2)
        budget_depth.check_depth(2)
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget_depth.check_depth(3)
        self.assertEqual(ctx.exception.code, "RECURSION_DEPTH_LIMIT")

    def test_memory_and_temp_disk_limits(self) -> None:
        budget = make_budget(max_memory_bytes=100, max_temp_disk_bytes=10,
                             max_materialized_object_bytes=100)
        budget.reserve_memory(100)
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.reserve_memory(1)
        self.assertEqual(ctx.exception.code, "MEMORY_LIMIT")
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.account_temp_disk(11)
        self.assertEqual(ctx.exception.code, "TEMP_DISK_LIMIT")
        budget_large = make_budget(max_memory_bytes=1000, max_materialized_object_bytes=10)
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget_large.reserve_memory(100)
        self.assertEqual(ctx.exception.code, "MATERIALIZED_OBJECT_LIMIT")

    def test_scanner_feed_shares_the_same_end_to_end_budget(self) -> None:
        clock = FakeClock()
        budget = P.ResourceBudget(
            P.DEFAULT_RESOURCE_LIMITS, monotonic=clock.monotonic,
            process_time=clock.process_time,
        )
        probe = P.OfflineEicarControlProbe()
        probe.feed(b"x" * 1024, budget)
        self.assertEqual(budget.scanned_bytes, 1024)
        clock.now = 10.0  # beyond the 5 s wall-clock ceiling
        with self.assertRaises(P.BudgetExceeded) as ctx:
            probe.feed(b"y" * 16, budget)
        self.assertEqual(ctx.exception.code, "WALL_CLOCK_LIMIT")

    def test_cpu_time_limit_with_fake_clock(self) -> None:
        clock = FakeClock()
        budget = P.ResourceBudget(
            P.DEFAULT_RESOURCE_LIMITS, monotonic=clock.monotonic,
            process_time=clock.process_time,
        )
        clock.cpu = 4.0  # beyond the 3 s CPU ceiling
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.check_time()
        self.assertEqual(ctx.exception.code, "CPU_TIME_LIMIT")

    def test_limit_codes_are_recorded_once(self) -> None:
        budget = make_budget(max_input_bytes=1)
        for _ in range(3):
            try:
                budget.charge_input(2)
            except P.BudgetExceeded:
                pass
        self.assertEqual(budget.limits_hit.count("INPUT_BYTE_LIMIT"), 1)


class SafeMemberPathTests(unittest.TestCase):
    def test_accepts_safe_relative_names(self) -> None:
        self.assertEqual(P.safe_member_path("a/b.txt"), "a/b.txt")
        self.assertEqual(P.safe_member_path("notes.txt"), "notes.txt")

    def test_rejects_traversal_and_absolute_paths(self) -> None:
        for name in (
            "../../evil.txt",
            "a/../../evil.txt",
            "/absolute/path.txt",
            "~/.config/evil.txt",
            "C:\\windows\\evil.txt",
            "a\\b.txt",
            "a/./b.txt",
            "file..txt",
            "a\x00b.txt",
            "a\nb.txt",
            "",
        ):
            with self.assertRaises(P.RejectionError, msg=name):
                P.safe_member_path(name)


class ScannerAdapterAndConclusionTests(unittest.TestCase):
    def test_eicar_probe_detects_signature_across_chunk_boundaries(self) -> None:
        budget = P.ResourceBudget(P.DEFAULT_RESOURCE_LIMITS)
        probe = P.OfflineEicarControlProbe()
        # Feed in 3 chunks so the signature straddles chunk boundaries.
        probe.feed(EICAR[:10], budget)
        probe.feed(EICAR[10:40], budget)
        probe.feed(EICAR[40:], budget)
        result = probe.finish()
        self.assertEqual(result["signature"], "EICAR_SIGNATURE_PRESENT")
        self.assertEqual(result["scanner_verdict"], P.NOT_VERIFIED)
        self.assertFalse(result["is_clamav_scanner"])

    def test_eicar_probe_negative_control(self) -> None:
        budget = P.ResourceBudget(P.DEFAULT_RESOURCE_LIMITS)
        probe = P.OfflineEicarControlProbe()
        probe.feed(BENIGN, budget)
        self.assertEqual(probe.finish()["signature"], "EICAR_SIGNATURE_ABSENT")

    def test_clean_with_incomplete_coverage_is_never_complete_safe_scan(self) -> None:
        coverage = {
            "completeness": "INCOMPLETE",
            "end_to_end_coverage": "INCOMPLETE",
            "skipped_objects": [{"object_path": "input::/Stream#4", "reason": "x"}],
            "uninspected_stream_gaps": ["ARBITRARY_PDF_STREAMS_NOT_INSPECTED"],
            "rejected": 0, "unsupported": 0, "not_verified": 0,
        }
        conclusion = P.derive_conclusion(coverage, clamav_verified=True, scanner_all_clean=True)
        self.assertEqual(conclusion["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)
        self.assertIn("COVERAGE_INCOMPLETE", conclusion["blockers"])
        self.assertIn("SKIPPED_OBJECTS_PRESENT", conclusion["blockers"])

    def test_complete_safe_scan_contract_requires_everything(self) -> None:
        coverage = {
            "completeness": "COMPLETE",
            "end_to_end_coverage": "COMPLETE",
            "skipped_objects": [],
            "uninspected_stream_gaps": [],
            "rejected": 0, "unsupported": 0, "not_verified": 0,
        }
        conclusion = P.derive_conclusion(coverage, clamav_verified=True, scanner_all_clean=True)
        self.assertEqual(conclusion["overall_conclusion"], P.COMPLETE_SAFE_SCAN)
        # And the moment any input is missing, the conclusion flips.
        coverage_bad = dict(coverage, completeness="INCOMPLETE")
        conclusion_bad = P.derive_conclusion(coverage_bad, clamav_verified=True,
                                             scanner_all_clean=True)
        self.assertEqual(conclusion_bad["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)

    def test_fake_clean_stub_is_invariant_only(self) -> None:
        budget = P.ResourceBudget(P.DEFAULT_RESOURCE_LIMITS)
        stub = P.FakeAlwaysCleanScanner()
        stub.feed(b"x" * 16, budget)
        self.assertEqual(stub.finish()["scanner_verdict"], "CLEAN")


FORBIDDEN_MODULES = {
    "subprocess", "socket", "urllib", "http", "requests", "pty",
    "signal", "ctypes", "multiprocessing",
}
FORBIDDEN_CALLS = {"eval", "exec", "__import__"}


class PoCModuleSafetyTests(unittest.TestCase):
    def test_no_forbidden_capabilities_in_sources(self) -> None:
        """AST-level guard: the PoC modules must not IMPORT or CALL dangerous
        capabilities (network, process spawning, code execution, filesystem I/O
        primitives are all out of scope for an isolated zero-disk PoC).
        """
        import ast

        for path in (POC_PATH, FIXTURES_PATH):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(
                            alias.name.split(".")[0], FORBIDDEN_MODULES,
                            f"forbidden import {alias.name!r} in {path.name}",
                        )
                elif isinstance(node, ast.ImportFrom):
                    root_module = (node.module or "").split(".")[0]
                    self.assertNotIn(
                        root_module, FORBIDDEN_MODULES,
                        f"forbidden from-import {node.module!r} in {path.name}",
                    )
                elif isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name):
                        self.assertNotIn(
                            func.id, FORBIDDEN_CALLS,
                            f"forbidden call {func.id!r} in {path.name}",
                        )
                    elif isinstance(func, ast.Attribute):
                        self.assertNotIn(
                            func.attr, FORBIDDEN_CALLS | {"system"},
                            f"forbidden call .{func.attr} in {path.name}",
                        )

    def test_no_filesystem_write_primitives(self) -> None:
        import ast

        write_attrs = {"write", "write_text", "write_bytes", "open"}
        for path in (POC_PATH, FIXTURES_PATH):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(
                        node.attr, write_attrs,
                        f"filesystem write primitive {node.attr!r} in {path.name}",
                    )

    def test_fixtures_split_the_signature_across_two_literals(self) -> None:
        # The standard EICAR test signature must never appear as one contiguous
        # source literal in the fixture module (it is built by concatenation).
        source = FIXTURES_PATH.read_text()
        full_single_backslash = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
                                 "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        full_double_backslash = ("X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$"
                                 "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        self.assertNotIn(full_single_backslash, source)
        self.assertNotIn(full_double_backslash, source)
        # Runtime concatenation reproduces exactly the standard signature.
        self.assertEqual(F.EICAR_PART_1 + F.EICAR_PART_2, EICAR)


class OfflineSuiteTests(unittest.TestCase):
    """Run the full offline suite once (class-level) and assert every invariant."""

    report: dict[str, object]

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = P.run_offline_suite()

    def test_all_verdicts_match(self) -> None:
        summary = self.report["summary"]
        self.assertEqual(summary["cases_total"], 53)
        self.assertEqual(summary["r2_cases"], 37)
        self.assertTrue(summary["all_verdicts_match"])
        for case in self.report["cases"]:
            self.assertEqual(case["observed_verdict"], case["expected_verdict"],
                             case["case_id"])

    def test_no_live_scan_no_network_no_writes(self) -> None:
        self.assertFalse(self.report["live_clamav_executed"])
        self.assertEqual(self.report["network_calls"], 0)
        self.assertEqual(self.report["subprocess_calls"], 0)
        self.assertEqual(self.report["filesystem_extraction_writes"], 0)
        for case in self.report["cases"]:
            self.assertEqual(case["budget"]["filesystem_writes"], 0)
            self.assertEqual(case["budget"]["temp_disk_bytes_used"], 0)
            self.assertFalse(case["budget"]["full_extraction_materialized"])

    def test_complete_safe_scan_never_claimed(self) -> None:
        summary = self.report["summary"]
        self.assertFalse(summary["complete_safe_scan_claimed"])
        self.assertEqual(summary["conclusions_observed"], [P.NOT_COMPLETE_SAFE_SCAN])
        self.assertEqual(self.report["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)
        for case in self.report["cases"]:
            self.assertEqual(case["conclusion"]["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)

    def test_governance_preserved_verbatim(self) -> None:
        gov = self.report["governance"]
        for key in ("CLAMAV-CR-P01", "CLAMAV-CR-P02", "CLAMAV-CR-P03",
                    "CLAMAV-CR-R1", "CLAMAV-CR-R2"):
            self.assertEqual(gov[key], "PROPOSED — NOT APPROVED", key)
        self.assertEqual(gov["Security_Gate"], "OPEN")
        self.assertEqual(gov["Licensing_Gate"], "OPEN")
        self.assertEqual(gov["Stage_7"], "NOT ACCEPTED")
        self.assertEqual(gov["CI"], "NOT CHECKED")
        self.assertEqual(gov["R1"], "OPEN")
        self.assertEqual(gov["R2"], "OPEN")
        self.assertEqual(gov["production_source_or_dependency_changes"], "NONE")
        self.assertFalse(gov["live_execution_workflow_created"])

    def test_security_boundary_stated(self) -> None:
        boundary = self.report["security_boundary"]
        self.assertEqual(boundary["approved_sequence"],
                         "validateUpload -> requireCleanUpload -> storage.put")
        self.assertFalse(boundary["post_storage_worker_scan_satisfies_pre_storage"])

    def test_tool_capabilities_not_verified_offline(self) -> None:
        caps = self.report["tool_capabilities"]
        for key in ("qpdf_json_stream_inspection", "pdfjs_stream_inspection",
                    "pdfdetach_attachment_parity", "genuine_encrypted_pdf_fixture",
                    "clamav_live_scan"):
            self.assertEqual(caps[key]["verdict"], P.NOT_VERIFIED, key)

    def test_controls_fire_independently(self) -> None:
        by_id = {case["case_id"]: case for case in self.report["cases"]}
        positive = by_id["CTRL-POS-01"]
        self.assertIn("EICAR_SIGNATURE_PRESENT",
                      [str(o["offline_control_signature"]) for o in positive["objects"]])
        negative = by_id["CTRL-NEG-01"]
        for obj in negative["objects"]:
            self.assertEqual(obj["offline_control_signature"], "EICAR_SIGNATURE_ABSENT")
        clean_nested = by_id["CTRL-NEG-02"]
        for obj in clean_nested["objects"]:
            if not obj["skipped"]:
                self.assertEqual(obj["verdict"], P.INSPECTED)
        self.assertEqual(clean_nested["conclusion"]["overall_conclusion"],
                         P.NOT_COMPLETE_SAFE_SCAN)

    def test_r1_coverage_gaps_are_explicit(self) -> None:
        by_id = {case["case_id"]: case for case in self.report["cases"]}
        r1 = self.report["r1"]
        self.assertFalse(r1["complete_r1_remediation_claimed"])
        self.assertIn("arbitrary PDF streams (including unreferenced /EmbeddedFile streams)",
                      r1["coverage_not_verified"])
        self.assertIn("genuine encrypted PDFs and post-unlock output scanning",
                      r1["coverage_not_verified"])
        r1_06 = by_id["R1-06"]
        self.assertTrue(r1_06["coverage"]["skipped_objects"])
        self.assertIn(P.NOT_VERIFIED, [c["observed_verdict"] for c in self.report["cases"]])
        r1_07 = by_id["R1-07"]
        self.assertEqual(r1_07["observed_verdict"], P.UNSUPPORTED)
        self.assertTrue(
            any("NOT_VERIFIED offline" in note or "genuine" in note
                for obj in r1_07["objects"] for note in obj["notes"]),
            "encrypted-PDF record must state that genuine fixtures are NOT_VERIFIED",
        )
        r1_10 = by_id["R1-10"]
        self.assertEqual(r1_10["error_code"], "MALFORMED_PDF")
        r1_13 = by_id["R1-13"]
        self.assertIn("MATERIALIZED_OBJECT_LIMIT", r1_13["budget"]["resource_limits_hit"])

    def test_r2_streaming_and_fail_closed_evidence(self) -> None:
        by_id = {case["case_id"]: case for case in self.report["cases"]}
        r2 = self.report["r2"]
        self.assertFalse(r2["complete_r2_remediation_claimed"])
        r2_02 = by_id["R2-02"]
        self.assertTrue(any(
            obj["structural_verdict"].startswith("ZIP64") for obj in r2_02["objects"]))
        r2_05 = by_id["R2-05"]
        self.assertEqual(r2_05["error_code"], "RECURSION_DEPTH_LIMIT")
        self.assertEqual(r2_05["budget"]["max_depth_seen"], 4)
        r2_09 = by_id["R2-09"]
        self.assertEqual(r2_09["error_code"], "UNSAFE_MEMBER_PATH")
        r2_10 = by_id["R2-10"]
        self.assertEqual(r2_10["error_code"], "DECLARED_SIZE_MISMATCH")
        self.assertTrue(any("declared size was NOT trusted" in note
                            for obj in r2_10["objects"] for note in obj["notes"]))
        r2_03 = by_id["R2-03"]
        self.assertGreater(r2_03["budget"]["expanded_bytes"], 0)
        self.assertFalse(r2_03["budget"]["full_extraction_materialized"])

    def test_resource_budget_is_single_and_shared(self) -> None:
        budget_block = self.report["resource_budget"]
        self.assertTrue(budget_block["single_end_to_end_budget"])
        self.assertIn("scanner_feed", budget_block["shared_by"])
        streaming = budget_block["streaming_proof"]
        self.assertEqual(streaming["extraction_to_filesystem"], False)
        self.assertEqual(streaming["temp_disk_bytes_written"], 0)

    def test_security_requirements_tracked(self) -> None:
        reqs = {r["id"]: r for r in self.report["security_requirements"]}
        self.assertEqual(reqs["SEC-REQ-02"]["status"], "NOT_VERIFIED")
        self.assertEqual(reqs["SEC-REQ-03"]["status"], "NOT_VERIFIED")
        self.assertEqual(reqs["SEC-REQ-05"]["status"], "ENFORCED_IN_OFFLINE_POC")
        self.assertEqual(reqs["SEC-REQ-06"]["status"], "ENFORCED_IN_OFFLINE_POC")

    def test_report_is_json_serializable(self) -> None:
        # Guards against non-serializable objects in the coverage ledger.
        json.dumps(self.report, ensure_ascii=False)


class TruncatedDeflateRegressionTests(unittest.TestCase):
    """Finding 1: DEFLATE terminal strictness, trailing data, data descriptors."""

    def _run_zip(self, data: bytes, **limits: object) -> dict[str, object]:
        spec = P.CaseSpec("t", "R2", "probe", P.REJECTED, "zip",
                          lambda: data, limits=P.replace(P.DEFAULT_RESOURCE_LIMITS, **limits))  # type: ignore[arg-type]
        return P.run_case(spec)

    def test_inflate_bounded_requires_eof_and_bounded_chunks(self) -> None:
        truncated = F.deflate_truncated(BENIGN)
        chunks, result = P._inflate_bounded(memoryview(truncated), 64)
        total = sum(len(chunk) for chunk in chunks)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 64)
        self.assertEqual(total, len(BENIGN))
        self.assertFalse(result.eof, "truncated stream must NOT report eof")
        self.assertEqual(result.trailing_bytes, 0)

        full = F.deflate_two_block(BENIGN)
        chunks, result = P._inflate_bounded(memoryview(full), 64)
        self.assertEqual(b"".join(chunks), BENIGN)
        self.assertTrue(result.eof)
        self.assertEqual(result.trailing_bytes, 0)

        with_trailing = full + b"\x01\x02\x03"
        chunks, result = P._inflate_bounded(memoryview(with_trailing), 64)
        self.assertEqual(b"".join(chunks), BENIGN)
        self.assertTrue(result.eof)
        self.assertEqual(result.trailing_bytes, 3)

    def test_truncated_stream_with_matching_crc_and_size_is_rejected(self) -> None:
        payload = EICAR
        member = F.Member("trunc.bin", payload, method=8,
                          raw_compressed=F.deflate_truncated(payload))
        data = F.build_zip([member])
        # Prove the "otherwise matching" property: declared CRC and usize in the
        # central directory DO match the actual decompressed bytes.
        import zlib as _zlib

        budget = P.ResourceBudget()
        entries, _flags = P._parse_central_directory(data, budget)
        self.assertEqual(entries[0].crc, _zlib.crc32(payload) & 0xFFFFFFFF)
        self.assertEqual(entries[0].usize, len(payload))
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "TRUNCATED_DEFLATE_STREAM")

    def test_trailing_garbage_after_end_marker_is_rejected(self) -> None:
        payload = EICAR
        member = F.Member("trail.bin", payload, method=8,
                          raw_compressed=F.deflate_two_block(payload) + b"\x00\xffz")
        result = self._run_zip(F.build_zip([member]))
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "UNEXPECTED_TRAILING_COMPRESSED_DATA")

    def test_valid_16_byte_data_descriptor_is_accepted(self) -> None:
        """Standards placement: descriptor AFTER the data, CDH csize excludes it."""
        import zlib as _zlib

        payload = EICAR
        dd = F.zip_data_descriptor_16(_zlib.crc32(payload) & 0xFFFFFFFF,
                                      len(payload), len(payload))
        member = F.Member("dd.bin", payload, method=0, flags=0x0008,
                          raw_compressed=payload, raw_data_descriptor=dd)
        result = self._run_zip(F.build_zip([member]))
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])

    def test_valid_24_byte_zip64_data_descriptor_is_accepted(self) -> None:
        """Signed ZIP64 descriptor: sig+crc+csize64+usize64, NO offset field."""
        result = self._run_zip(F.zip64_with_descriptor(EICAR, method=0))
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])

    def test_corrupt_data_descriptor_fields_are_rejected(self) -> None:
        import zlib as _zlib

        payload = EICAR
        good_crc = _zlib.crc32(payload) & 0xFFFFFFFF
        bad_dd = F.DATA_DESCRIPTOR_SIG + (good_crc - 1).to_bytes(4, "little") \
            + len(payload).to_bytes(4, "little") + len(payload).to_bytes(4, "little")
        member = F.Member("badd.bin", payload, method=0, flags=0x0008,
                          raw_compressed=payload, raw_data_descriptor=bad_dd)
        result = self._run_zip(F.build_zip([member]))
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")

    def test_descriptor_flag_without_descriptor_is_rejected(self) -> None:
        result = self._run_zip(F.build_zip(
            [F.Member("nod.bin", EICAR, method=0, flags=0x0008)]))
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")


class MemberAccountingTests(unittest.TestCase):
    """Finding 2: per-member boundary is exact; cumulative ceiling independent."""

    def test_charge_expanded_contract(self) -> None:
        limits = P.replace(P.DEFAULT_RESOURCE_LIMITS, max_member_bytes=100,
                           max_expanded_bytes=1000)
        budget = P.ResourceBudget(limits)
        # Exactly at the per-member ceiling (running total including chunk): allowed.
        budget.charge_expanded(60, member_bytes=60)
        budget.charge_expanded(40, member_bytes=100)
        self.assertEqual(budget.expanded_bytes, 100)
        self.assertEqual(budget.limits_hit, [])
        # One byte over: rejected.
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.charge_expanded(1, member_bytes=101)
        self.assertEqual(ctx.exception.code, "MEMBER_BYTE_LIMIT")

    def test_cumulative_ceiling_is_independent_of_member_ceiling(self) -> None:
        limits = P.replace(P.DEFAULT_RESOURCE_LIMITS, max_member_bytes=100,
                           max_expanded_bytes=250)
        budget = P.ResourceBudget(limits)
        # Three members of 90 bytes: each under the member ceiling...
        for _ in range(2):
            budget.charge_expanded(90, member_bytes=90)
        # ...but the third crosses the cumulative ceiling.
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget.charge_expanded(90, member_bytes=90)
        self.assertEqual(ctx.exception.code, "EXPANDED_BYTE_LIMIT")

    def test_member_exactly_at_ceiling_multi_chunk_inspected(self) -> None:
        limits = P.replace(P.DEFAULT_RESOURCE_LIMITS, max_member_bytes=256,
                           chunk_bytes=64)
        data = F.build_zip([F.Member("exact.bin", b"A" * 256)])
        spec = P.CaseSpec("a", "R2", "exact", P.INSPECTED, "zip",
                          lambda: data, limits=limits)
        result = P.run_case(spec)
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertEqual(result["budget"]["expanded_bytes"], 256)

    def test_member_one_byte_over_multi_chunk_rejected(self) -> None:
        limits = P.replace(P.DEFAULT_RESOURCE_LIMITS, max_member_bytes=256,
                           chunk_bytes=64)
        data = F.build_zip([F.Member("over.bin", b"A" * 257)])
        spec = P.CaseSpec("b", "R2", "over", P.REJECTED, "zip",
                          lambda: data, limits=limits)
        result = P.run_case(spec)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "MEMBER_BYTE_LIMIT")

    def test_nested_members_share_the_cumulative_budget(self) -> None:
        payload = b"A" * 500
        inner = F.zip32(payload)
        outer = F.build_zip([F.Member("inner.zip", inner, method=0)])
        limits = P.replace(P.DEFAULT_RESOURCE_LIMITS,
                           max_expanded_bytes=len(inner) + len(payload) - 1)
        budget = P.ResourceBudget(limits)
        ledger = P.CoverageLedger("nested", budget)
        with self.assertRaises(P.BudgetExceeded) as ctx:
            P.inspect_zip_container(budget, ledger, object_path="root", data=outer,
                                    depth=0, scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(ctx.exception.code, "EXPANDED_BYTE_LIMIT")
        # The failing charge is NOT recorded: the budget stays at the outer
        # member's contribution (fail before adding keeps the ceiling intact).
        self.assertEqual(budget.expanded_bytes, len(inner))


class UnexpectedExceptionTests(unittest.TestCase):
    """Finding 3: unexpected exceptions yield bounded structured fail-closed reports."""

    def test_scanner_feed_raising_is_fail_closed(self) -> None:
        class BrokenFeed:
            name = "BROKEN"

            def feed(self, chunk: bytes, budget: P.ResourceBudget) -> None:
                raise RuntimeError("scanner blew up")

            def finish(self) -> dict[str, object]:
                return {"scanner_verdict": "NOT_SCANNED"}

        data = F.zip32(EICAR)
        spec = P.CaseSpec("x1", "R2", "broken scanner", P.REJECTED, "zip",
                          lambda: data, scanner_factory=BrokenFeed)
        result = P.run_case(spec)  # must not raise
        self.assertNotEqual(result["observed_verdict"], P.INSPECTED)
        self.assertEqual(result["error_code"], "UNEXPECTED_PARSER_ERROR")
        self.assertEqual(result["conclusion"]["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)
        notes = [note for obj in result["objects"] for note in obj["notes"]]
        self.assertTrue(any("RuntimeError" in note for note in notes))

    def test_scanner_finish_raising_is_fail_closed(self) -> None:
        class BrokenFinish:
            name = "BROKEN"

            def feed(self, chunk: bytes, budget: P.ResourceBudget) -> None:
                budget.charge_scanned(len(chunk))

            def finish(self) -> dict[str, object]:
                raise KeyError("no verdict key")

        data = F.zip32(EICAR)
        spec = P.CaseSpec("x2", "R2", "broken finish", P.REJECTED, "zip",
                          lambda: data, scanner_factory=BrokenFinish)
        result = P.run_case(spec)
        self.assertNotEqual(result["observed_verdict"], P.INSPECTED)
        self.assertEqual(result["error_code"], "UNEXPECTED_PARSER_ERROR")
        self.assertEqual(result["conclusion"]["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)

    def test_parser_raising_exception_without_code_attribute(self) -> None:
        import unittest.mock as mock

        data = F.zip32(EICAR)
        spec = P.CaseSpec("x3", "R2", "broken parser", P.REJECTED, "zip",
                          lambda: data)
        with mock.patch.object(P, "inspect_zip_container", side_effect=KeyError("boom")):
            result = P.run_case(spec)  # KeyError has no .code: must not crash
        self.assertNotEqual(result["observed_verdict"], P.INSPECTED)
        self.assertEqual(result["error_code"], "UNEXPECTED_PARSER_ERROR")
        self.assertEqual(result["conclusion"]["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)

    def test_builder_failing_produces_structured_case_not_crash(self) -> None:
        def bad_builder() -> bytes:
            raise ValueError("fixture build boom")

        spec = P.CaseSpec("x4", "R2", "broken builder", P.REJECTED, "zip", bad_builder)
        result = P.run_case(spec)  # must not raise
        self.assertNotEqual(result["observed_verdict"], P.INSPECTED)
        self.assertTrue(isinstance(result["error_code"], str) and result["error_code"])
        self.assertEqual(result["conclusion"]["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)
        self.assertEqual(result["input_bytes"], 0)
        self.assertTrue(any("ValueError" in note
                            for obj in result["objects"] for note in obj["notes"]))

    def test_bounded_message_is_length_capped(self) -> None:
        class Loud(Exception):
            pass

        message = P._bounded_message(Loud("x" * 10000), limit=200)
        self.assertLessEqual(len(message), 200)
        self.assertTrue(message.startswith("Loud:"))


class ZipStructureRegressionTests(unittest.TestCase):
    """Focused validation: LFH/CDH, ZIP64 extra fields, truncation, ambiguity.

    Malformed / ambiguous structures must never be classified as fully INSPECTED.
    """

    def test_lfh_cdh_method_mismatch_rejected(self) -> None:
        data = F.build_zip([F.Member("mm.bin", BENIGN, lfh_method_override=8)])
        budget = P.ResourceBudget()
        ledger = P.CoverageLedger("mm", budget)
        with self.assertRaises(P.RejectionError) as ctx:
            P.inspect_zip_container(budget, ledger, object_path="root", data=data,
                                    depth=0, scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(ctx.exception.code, "MALFORMED_LFH_CDH_MISMATCH")
        self.assertEqual(ledger.case_verdict(), P.REJECTED)

    def test_malformed_cdh_extra_field_rejected(self) -> None:
        # 0x0001 tag claiming 100 bytes of body but only 4 present: TLV overflow.
        bad_extra = b"\x01\x00" + (100).to_bytes(2, "little") + b"\x00" * 4
        data = F.build_zip([F.Member("bad.bin", BENIGN, cdh_extra_raw=bad_extra)])
        budget = P.ResourceBudget()
        ledger = P.CoverageLedger("bad", budget)
        with self.assertRaises(P.RejectionError) as ctx:
            P.inspect_zip_container(budget, ledger, object_path="root", data=data,
                                    depth=0, scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(ctx.exception.code, "MALFORMED_ZIP_EXTRA_FIELD")
        self.assertEqual(ledger.case_verdict(), P.REJECTED)

    def test_truncated_container_never_inspected(self) -> None:
        for cut in (1, 12, 21):
            data = F.zip32(BENIGN)[:-cut]
            budget = P.ResourceBudget()
            ledger = P.CoverageLedger("trunc", budget)
            with self.assertRaises(P.RejectionError):
                P.inspect_zip_container(budget, ledger, object_path="root", data=data,
                                        depth=0, scanner_factory=P.OfflineEicarControlProbe)
            self.assertNotEqual(ledger.case_verdict(), P.INSPECTED)

    def test_multi_disk_flag_rejected(self) -> None:
        data = bytearray(F.zip32(BENIGN))
        # "number of this disk" is at EOCD offset +4 => absolute len-18.
        data[-18:-16] = (1).to_bytes(2, "little")
        budget = P.ResourceBudget()
        ledger = P.CoverageLedger("md", budget)
        with self.assertRaises(P.RejectionError) as ctx:
            P.inspect_zip_container(budget, ledger, object_path="root",
                                    data=bytes(data), depth=0,
                                    scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(ctx.exception.code, "MULTI_DISK_ZIP_UNSUPPORTED")

    def test_zip64_positional_locator_rejects_magic_in_content(self) -> None:
        # A classic-EOCD zip whose member CONTENT contains ZIP64 magic bytes
        # must still parse as a plain ZIP32 (no false ZIP64 flag), and a
        # sentinel EOCD WITHOUT a positional locator must be rejected.
        inner = F.zip64(EICAR)
        outer = F.build_zip([F.Member("content.bin", inner)])
        budget = P.ResourceBudget()
        ledger = P.CoverageLedger("z64c", budget)
        structural = P.inspect_zip_container(budget, ledger, object_path="root",
                                             data=outer, depth=0,
                                             scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(structural, "WELL_FORMED_ZIP32")
        # Sentinel EOCD without the locator directly before it: reject.
        no_locator = F.zip64(EICAR)
        eocd = no_locator.rfind(b"PK\x05\x06")
        corrupted = no_locator[:eocd - 20] + b"\x00" * 20 + no_locator[eocd:]
        budget2 = P.ResourceBudget()
        ledger2 = P.CoverageLedger("z64n", budget2)
        with self.assertRaises(P.RejectionError) as ctx:
            P.inspect_zip_container(budget2, ledger2, object_path="root",
                                    data=corrupted, depth=0,
                                    scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(ctx.exception.code, "ZIP64_SENTINEL_WITHOUT_LOCATOR")


class DataDescriptorComplianceTests(unittest.TestCase):
    """Data descriptor STANDARDS-COMPLIANCE regression matrix (REVISION-4).

    Placement: descriptor AFTER the compressed data at data_start + csize; the
    CDH compressed-size field excludes the descriptor. Width selection from
    verified metadata; unsigned legacy form UNSUPPORTED; narrow ZIP64 EOCD
    locator 32-bit disk-field validation. Every negative case fails closed.
    """

    def _run_zip(self, data: bytes) -> dict[str, object]:
        spec = P.CaseSpec("t", "R2", "probe", P.REJECTED, "zip",
                          lambda: data, limits=P.DEFAULT_RESOURCE_LIMITS)  # type: ignore[arg-type]
        return P.run_case(spec)

    # --- mandatory positive controls (independent + own builder) -------------
    def test_valid_zip32_stored_with_16_byte_descriptor(self) -> None:
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("a.bin", EICAR, method=0, flags=0x0008,
                                     raw_compressed=EICAR,
                                     raw_data_descriptor=F.zip_data_descriptor_16(crc, len(EICAR), len(EICAR)))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])

    def test_valid_zip32_deflate_with_16_byte_descriptor(self) -> None:
        import zlib as _zlib

        compressed = F.deflate_two_block(EICAR)
        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("b.bin", EICAR, method=8, flags=0x0008,
                                     raw_compressed=compressed,
                                     raw_data_descriptor=F.zip_data_descriptor_16(
                                         crc, len(compressed), len(EICAR)))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])

    def test_valid_zip64_with_24_byte_descriptor(self) -> None:
        data = F.zip64_with_descriptor(EICAR, method=0)
        # Sanity: the on-disk descriptor is 24 bytes and has NO offset field.
        cdh = data.rfind(b"PK\x01\x02")
        self.assertLess(data.index(F.DATA_DESCRIPTOR_SIG), cdh,
                        "descriptor must sit between the member data and the CD")
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])

    def test_cpython_zipfile_nonseekable_streaming_output(self) -> None:
        """Independent writer: CPython zipfile over a non-seekable stream.

        The archive is produced by stdlib zipfile streaming mode (bit 3 set,
        zeroed LFH sizes, signed 16-byte descriptors after the data); the PoC
        reader must accept EXACTLY what the independent writer emitted.
        """
        data = F.zipfile_nonseekable_archive(
            [("stored.bin", EICAR, 0), ("deflated.txt", F.BENIGN_BYTES, 8)])
        self.assertTrue(data.startswith(b"PK\x03\x04"))
        # LFH CRC/size fields must be zeroed (streaming mode marker).
        self.assertEqual(data[14:26], b"\x00" * 12)
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])
        verdicts = [o["verdict"] for o in result["objects"] if not o["skipped"]]
        self.assertEqual(verdicts.count(P.INSPECTED), 3)  # container + 2 members

    def test_multi_entry_zip_with_descriptors_and_correct_boundaries(self) -> None:
        import zlib as _zlib

        crc_a = _zlib.crc32(EICAR) & 0xFFFFFFFF
        crc_b = _zlib.crc32(F.BENIGN_BYTES) & 0xFFFFFFFF
        compressed_b = F.deflate_two_block(F.BENIGN_BYTES)
        data = F.build_zip([
            F.Member("a.bin", EICAR, method=0, flags=0x0008, raw_compressed=EICAR,
                     raw_data_descriptor=F.zip_data_descriptor_16(crc_a, len(EICAR), len(EICAR))),
            F.Member("b.txt", F.BENIGN_BYTES, method=8, flags=0x0008,
                     raw_compressed=compressed_b,
                     raw_data_descriptor=F.zip_data_descriptor_16(
                         crc_b, len(compressed_b), len(F.BENIGN_BYTES))),
        ])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])

    # --- mandatory negative cases (all fail closed) --------------------------
    def test_bit3_set_without_descriptor_is_rejected(self) -> None:
        data = F.build_zip([F.Member("nod.bin", EICAR, method=0, flags=0x0008)])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")

    def test_truncated_descriptor_is_rejected(self) -> None:
        """Unit: the 16-byte descriptor extends past the end of the buffer."""
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        dd = F.zip_data_descriptor_16(crc, 64, 64)
        buffer = b"\x00" * 64 + dd[:8]  # only 8 of the 16 descriptor bytes exist
        with self.assertRaises(P.RejectionError) as ctx:
            P._validate_data_descriptor(data=buffer, data_start=0, compressed_size=64,
                                        flags=0x0008, zip64_sizes=False,
                                        actual=64, crc=crc)
        self.assertEqual(ctx.exception.code, "TRUNCATED_DATA_DESCRIPTOR")

    def test_descriptor_crc_mismatch_is_rejected(self) -> None:
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("c.bin", EICAR, method=0, flags=0x0008,
                                     raw_compressed=EICAR,
                                     raw_data_descriptor=F.zip_data_descriptor_16(
                                         crc ^ 1, len(EICAR), len(EICAR)))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")

    def test_descriptor_compressed_size_mismatch_is_rejected(self) -> None:
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("c.bin", EICAR, method=0, flags=0x0008,
                                     raw_compressed=EICAR,
                                     raw_data_descriptor=F.zip_data_descriptor_16(
                                         crc, len(EICAR) + 1, len(EICAR)))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")

    def test_descriptor_uncompressed_size_mismatch_is_rejected(self) -> None:
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("c.bin", EICAR, method=0, flags=0x0008,
                                     raw_compressed=EICAR,
                                     raw_data_descriptor=F.zip_data_descriptor_16(
                                         crc, len(EICAR), len(EICAR) + 1))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")

    def test_wrong_width_zip32_member_with_zip64_descriptor(self) -> None:
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("w.bin", EICAR, method=0, flags=0x0008,
                                     raw_compressed=EICAR,
                                     raw_data_descriptor=F.zip_data_descriptor_24(
                                         crc, len(EICAR), len(EICAR)))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")

    def test_wrong_width_zip64_member_with_zip32_descriptor(self) -> None:
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip(
            [F.Member("w64.bin", EICAR, method=0, version_needed=45, flags=0x0008,
                      lfh_zip64=True, cdh_zip64=True, raw_compressed=EICAR,
                      raw_data_descriptor=F.zip_data_descriptor_16(crc, len(EICAR), len(EICAR)))],
            zip64_eocd=True)
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "INVALID_DATA_DESCRIPTOR")

    def test_descriptor_falsely_embedded_in_compressed_window(self) -> None:
        """Legacy in-window layout (descriptor bytes inside the declared csize)."""
        import zlib as _zlib

        compressed = F.deflate_two_block(EICAR)
        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        dd = F.zip_data_descriptor_16(crc, len(compressed), len(EICAR))
        data = F.build_zip([F.Member("e.bin", EICAR, method=8, flags=0x0008,
                                     raw_compressed=compressed + dd)])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "UNEXPECTED_TRAILING_COMPRESSED_DATA")

    def test_unexpected_trailing_compressed_bytes(self) -> None:
        data = F.build_zip([F.Member("t.bin", EICAR, method=8,
                                     raw_compressed=F.deflate_two_block(EICAR) + b"\x00\xffz")])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "UNEXPECTED_TRAILING_COMPRESSED_DATA")

    def test_no_record_after_descriptor_is_rejected(self) -> None:
        """Unit: garbage instead of the following LFH/CDH record."""
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        dd = F.zip_data_descriptor_16(crc, 64, 64)
        buffer = b"\x00" * 64 + dd + b"\xde\xad\xbe\xef"
        with self.assertRaises(P.RejectionError) as ctx:
            P._validate_data_descriptor(data=buffer, data_start=0, compressed_size=64,
                                        flags=0x0008, zip64_sizes=False,
                                        actual=64, crc=crc)
        self.assertEqual(ctx.exception.code, "INVALID_DATA_DESCRIPTOR")

    def test_undeclared_descriptor_signature_rejected(self) -> None:
        """Bit 3 NOT set but a descriptor signature follows the data."""
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("u.bin", EICAR, method=0, flags=0,
                                     raw_compressed=EICAR,
                                     raw_data_descriptor=F.zip_data_descriptor_16(crc, len(EICAR), len(EICAR)))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.REJECTED)
        self.assertEqual(result["error_code"], "UNDECLARED_DATA_DESCRIPTOR")

    def test_unsigned_legacy_descriptor_classified_unsupported(self) -> None:
        import zlib as _zlib

        crc = _zlib.crc32(EICAR) & 0xFFFFFFFF
        data = F.build_zip([F.Member("s.bin", EICAR, method=0, flags=0x0008,
                                     raw_compressed=EICAR,
                                     raw_data_descriptor=F.zip_data_descriptor_unsigned_12(
                                         crc, len(EICAR), len(EICAR)))])
        result = self._run_zip(data)
        self.assertEqual(result["observed_verdict"], P.UNSUPPORTED)
        self.assertEqual(result["error_code"], "UNSIGNED_DATA_DESCRIPTOR_UNSUPPORTED")
        # Fail closed: never INSPECTED, never COMPLETE_SAFE_SCAN.
        self.assertEqual(result["conclusion"]["overall_conclusion"], P.NOT_COMPLETE_SAFE_SCAN)

    # --- narrow ZIP64 EOCD-locator 32-bit disk-field checks ------------------
    def test_zip64_locator_disk_number_field_is_32_bit(self) -> None:
        data = bytearray(F.zip64(EICAR))
        eocd = bytes(data).rfind(b"PK\x05\x06")
        data[eocd - 16] = 1  # 32-bit disk number (first byte)
        budget = P.ResourceBudget()
        ledger = P.CoverageLedger("z64d", budget)
        with self.assertRaises(P.RejectionError) as ctx:
            P.inspect_zip_container(budget, ledger, object_path="root",
                                    data=bytes(data), depth=0,
                                    scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(ctx.exception.code, "MULTI_DISK_ZIP_UNSUPPORTED")

    def test_zip64_locator_total_disk_count_field_is_32_bit(self) -> None:
        data = bytearray(F.zip64(EICAR))
        eocd = bytes(data).rfind(b"PK\x05\x06")
        data[eocd - 4] = 2  # 32-bit total disk count (first byte; was 1)
        budget = P.ResourceBudget()
        ledger = P.CoverageLedger("z64t", budget)
        with self.assertRaises(P.RejectionError) as ctx:
            P.inspect_zip_container(budget, ledger, object_path="root",
                                    data=bytes(data), depth=0,
                                    scanner_factory=P.OfflineEicarControlProbe)
        self.assertEqual(ctx.exception.code, "MULTI_DISK_ZIP_UNSUPPORTED")

    def test_genuine_zip64_locator_still_accepted(self) -> None:
        # The unmodified genuine ZIP64 fixture must remain INSPECTED: the
        # 32-bit validation must not produce false positives.
        result = self._run_zip(F.zip64(EICAR))
        self.assertEqual(result["observed_verdict"], P.INSPECTED)
        self.assertIsNone(result["error_code"])


class ReportRevisionTests(unittest.TestCase):
    def test_report_records_revisions_and_accounting_scope(self) -> None:
        report = P.run_offline_suite()
        self.assertEqual(len(report["revisions"]), 4)
        self.assertIn("REVISION-4", report["revisions"][3])
        self.assertIn("data descriptor", report["revisions"][3])
        scope = report["resource_budget"]["accounting_scope"]
        self.assertEqual(scope["level"], "APPLICATION_LEVEL_POC_ACCOUNTING")
        self.assertTrue(scope["os_enforcement_required_in_production"])
        # The new regression cases are part of the shipped matrix.
        ids = {case["case_id"] for case in report["cases"]}
        for expected in (
            "R2-13", "R2-14", "R2-15", "R2-16", "R2-17", "R2-18",
            "R2-19", "R2-20", "R2-21", "R2-22", "R2-23", "R2-24", "R2-25",
            "R2-26", "R2-27", "R2-28", "R2-29", "R2-30", "R2-31", "R2-32",
            "R2-33", "R2-34", "R2-35", "R2-36", "R2-37",
        ):
            self.assertIn(expected, ids)
        # All malformed/ambiguous structures rejected or unsupported, never INSPECTED.
        by_id = {case["case_id"]: case for case in report["cases"]}
        for case_id in ("R2-13", "R2-14", "R2-16", "R2-19", "R2-20",
                        "R2-26", "R2-27", "R2-28", "R2-29", "R2-30", "R2-31",
                        "R2-33", "R2-34", "R2-35", "R2-37"):
            self.assertIn(by_id[case_id]["observed_verdict"],
                          (P.REJECTED, P.UNSUPPORTED, P.NOT_VERIFIED))
        # Descriptor standards-compliance matrix codes (REVISION-4).
        for case_id, code in (
            ("R2-24", None), ("R2-25", None), ("R2-32", None),
            ("R2-26", "INVALID_DATA_DESCRIPTOR"),
            ("R2-29", "INVALID_DATA_DESCRIPTOR"),
            ("R2-30", "INVALID_DATA_DESCRIPTOR"),
            ("R2-31", "UNEXPECTED_TRAILING_COMPRESSED_DATA"),
            ("R2-34", "MULTI_DISK_ZIP_UNSUPPORTED"),
            ("R2-35", "MULTI_DISK_ZIP_UNSUPPORTED"),
            ("R2-36", "UNSIGNED_DATA_DESCRIPTOR_UNSUPPORTED"),
            ("R2-37", "UNDECLARED_DATA_DESCRIPTOR"),
        ):
            self.assertEqual(by_id[case_id]["error_code"], code, case_id)
        self.assertEqual(by_id["R2-24"]["observed_verdict"], P.INSPECTED)
        self.assertEqual(by_id["R2-25"]["observed_verdict"], P.INSPECTED)
        self.assertEqual(by_id["R2-32"]["observed_verdict"], P.INSPECTED)
        self.assertEqual(by_id["R2-36"]["observed_verdict"], P.UNSUPPORTED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
