#!/usr/bin/env python3
"""Regression tests for Stage 3C evidence sanitization."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "experiments" / "structural_grayscale_evidence.py"
SPEC = importlib.util.spec_from_file_location("structural_grayscale_evidence_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Stage 3C evidence sanitizer")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceSanitizationTests(unittest.TestCase):
    def test_document_content_paths_and_credentials_are_redacted(self) -> None:
        evidence = {
            "readers": [
                {"text": "محتوى مستند خام"},
                {"output_text": "raw English document text"},
            ],
            "nested": [{"snapshot": {"field_values": {"note": "private value"}}}],
            "appearance": [{"value": "edited form value"}],
            "diagnostic": "failed at /tmp/dip/customer.pdf password=never-publish",
            "note": "rejected /tmp/dip/other.pdf token=also-private",
        }
        sanitized = MODULE.sanitize_evidence(evidence)
        MODULE.assert_sanitized_evidence(sanitized)
        serialized = json.dumps(sanitized, ensure_ascii=False)
        self.assertNotIn("محتوى", serialized)
        self.assertNotIn("private value", serialized)
        self.assertNotIn("raw English document text", serialized)
        self.assertNotIn("edited form value", serialized)
        self.assertNotIn("/tmp/dip/customer.pdf", serialized)
        self.assertNotIn("never-publish", serialized)
        self.assertIn("[REDACTED_DIAGNOSTIC]", serialized)
        self.assertIn("[PDF_PATH]", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_cyclonedx_property_values_are_metadata_not_document_content(self) -> None:
        evidence = {
            "metadata": {"properties": [{"name": "component:scope", "value": "qa-only"}]},
            "components": [{"properties": [{"name": "native:library", "value": "libqpdf"}]}],
        }
        sanitized = MODULE.sanitize_evidence(evidence)
        MODULE.assert_sanitized_evidence(sanitized)
        self.assertEqual(sanitized, evidence)

    def test_log_summary_is_sanitized_and_bounded(self) -> None:
        output = io.StringIO()
        MODULE.print_sanitized_summary(
            {"status": "failed", "text": "private text", "diagnostic": "private failure"},
            stream=output,
        )
        logged = output.getvalue()
        self.assertNotIn("private text", logged)
        self.assertNotIn("private failure", logged)
        self.assertLessEqual(len(logged.encode("utf-8")), MODULE.MAX_LOG_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "string exceeds the length limit"):
            MODULE.print_sanitized_summary({"note": "x" * (MODULE.MAX_STRING_LENGTH + 1)})

    def test_artifact_directory_accepts_only_valid_sanitized_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.write_sanitized_json(root / "metrics.json", {"text": "document"})
            self.assertEqual(MODULE.audit_artifact_directory(root), {"validated_json_files": 1})

    def test_environment_dump_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "environment dumps are forbidden"):
            MODULE.sanitize_evidence({"environment": {"GROQ_API_KEY": "not-for-artifacts"}})

    def test_invalid_json_and_pdf_artifacts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "invalid.json").write_text("{not-json}", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                MODULE.audit_artifact_directory(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.write_sanitized_json(root / "valid.json", {"passed": True})
            (root / "forbidden.pdf").write_bytes(b"%PDF-1.4")
            with self.assertRaisesRegex(ValueError, "PDF outputs are forbidden"):
                MODULE.audit_artifact_directory(root)


if __name__ == "__main__":
    unittest.main()
