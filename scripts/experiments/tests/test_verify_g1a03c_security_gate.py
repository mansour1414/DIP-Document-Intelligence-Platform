import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "verify-g1a03c-security-gate.py"


def finding(evidence_id, severity, disposition="UNRESOLVED"):
    return {
        "evidence_id": evidence_id,
        "severity": severity,
        "security_disposition": disposition,
        "raw_match_count": 1,
    }


def report(gate, findings):
    counts = {}
    for item in findings:
        severity = item["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "security_gate": gate,
        "findings": findings,
        "deduplicated_finding_count": len(findings),
        "raw_match_count": len(findings),
        "deduplicated_severity_counts": counts,
    }


class SecurityGateTests(unittest.TestCase):
    def run_gate(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "triage.json"
            path.write_text(text, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), "--triage", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def assert_rejected(self, triage, reason):
        result = self.run_gate(json.dumps(triage))
        self.assertEqual(result.returncode, 1)
        self.assertIn(reason, result.stderr)

    def test_explicit_fail_is_preserved_even_after_a_disposition(self):
        self.assert_rejected(
            report("FAIL", [finding("sample", "High", "REMEDIATED")]),
            "0 unresolved Critical/High findings",
        )

    def test_open_high_and_critical_override_claimed_pass(self):
        self.assert_rejected(
            report("PASS", [finding("sample-1", "Critical"), finding("sample-2", "High")]),
            "2 unresolved Critical/High findings",
        )

    def test_valid_reviewed_dispositions_can_satisfy_record_check(self):
        records = [
            finding("sample-1", "Critical", "REMEDIATED"),
            finding("sample-2", "High", "OWNER_ACCEPTED_EXCEPTION"),
            finding("sample-3", "Medium"),
        ]
        self.assertEqual(self.run_gate(json.dumps(report("PASS", records))).returncode, 0)

    def test_complete_zero_finding_record_is_valid(self):
        self.assertEqual(self.run_gate(json.dumps(report("PASS", []))).returncode, 0)

    def test_missing_or_inconsistent_totals_fail_closed(self):
        self.assert_rejected({"security_gate": "PASS"}, "gate status or findings")
        for key, reason in (
            ("deduplicated_finding_count", "finding count does not match"),
            ("raw_match_count", "raw match count does not match"),
            ("deduplicated_severity_counts", "severity counts do not match"),
        ):
            triage = report("PASS", [finding("sample", "Low")])
            triage[key] = 0
            with self.subTest(key=key):
                self.assert_rejected(triage, reason)

    def test_duplicate_keys_or_evidence_ids_are_rejected(self):
        duplicate_key = self.run_gate('{"security_gate":"FAIL","security_gate":"PASS"}')
        self.assertEqual(duplicate_key.returncode, 1)
        self.assertIn("unambiguous triage JSON", duplicate_key.stderr)
        self.assert_rejected(
            report("PASS", [finding("sample", "Low"), finding("sample", "Low")]),
            "duplicate evidence ID",
        )

    def test_unknown_spellings_do_not_hide_findings(self):
        self.assert_rejected(report("PASS", [finding("sample", "high")]), "invalid finding severity")
        self.assert_rejected(
            report("PASS", [finding("sample", "High", "IGNORED")]),
            "invalid finding disposition",
        )


if __name__ == "__main__":
    unittest.main()
