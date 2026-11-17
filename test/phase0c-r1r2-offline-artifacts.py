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
        budget2 = make_budget(max_expanded_bytes=100, max_member_bytes=50)
        with self.assertRaises(P.BudgetExceeded) as ctx:
            budget2.charge_expanded(40, member_bytes=20)
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
        self.assertEqual(summary["cases_total"], 28)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
