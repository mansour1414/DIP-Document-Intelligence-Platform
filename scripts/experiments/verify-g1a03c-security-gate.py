#!/usr/bin/env python3
"""Check the recorded G1-A/03C Security Gate offline."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys


SEVERITIES = frozenset({"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
BLOCKING_SEVERITIES = frozenset({"Critical", "High"})
RESOLVED = frozenset({"REMEDIATED", "OWNER_ACCEPTED_EXCEPTION"})
DISPOSITIONS = RESOLVED | {"UNRESOLVED"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_triage(report):
    if not isinstance(report, dict):
        raise ValueError("triage must be a JSON object")
    findings = report.get("findings")
    gate = report.get("security_gate")
    if gate not in ("FAIL", "PASS") or not isinstance(findings, list):
        raise ValueError("missing or invalid gate status or findings")
    expected_count = report.get("deduplicated_finding_count")
    if type(expected_count) is not int or expected_count != len(findings):
        raise ValueError("finding count does not match the findings array")

    evidence_ids = set()
    severity_counts = Counter()
    raw_matches = 0
    blocking = 0
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("each finding must be a JSON object")
        evidence_id = finding.get("evidence_id")
        severity = finding.get("severity")
        disposition = finding.get("security_disposition")
        count = finding.get("raw_match_count")
        if not isinstance(evidence_id, str) or not evidence_id.strip() or evidence_id in evidence_ids:
            raise ValueError("missing or duplicate evidence ID")
        if not isinstance(severity, str) or severity not in SEVERITIES:
            raise ValueError("invalid finding severity")
        if not isinstance(disposition, str) or disposition not in DISPOSITIONS:
            raise ValueError("invalid finding disposition")
        if type(count) is not int or count < 1:
            raise ValueError("invalid finding raw match count")

        evidence_ids.add(evidence_id)
        severity_counts[severity] += 1
        raw_matches += count
        if severity in BLOCKING_SEVERITIES and disposition not in RESOLVED:
            blocking += 1

    expected_raw = report.get("raw_match_count")
    if type(expected_raw) is not int or expected_raw != raw_matches:
        raise ValueError("raw match count does not match the findings")
    expected_severities = report.get("deduplicated_severity_counts")
    if (
        not isinstance(expected_severities, dict)
        or any(type(count) is not int for count in expected_severities.values())
        or expected_severities != dict(severity_counts)
    ):
        raise ValueError("severity counts do not match the findings")
    return gate, blocking


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triage", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.triage.open(encoding="utf-8") as source:
            report = json.load(source, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, ValueError):
        print("G1-A/03C Security Gate FAIL: unable to read a valid, unambiguous triage JSON", file=sys.stderr)
        return 1

    try:
        gate, blocking = validate_triage(report)
    except ValueError as error:
        print(f"G1-A/03C Security Gate FAIL: {error}", file=sys.stderr)
        return 1
    if gate != "PASS" or blocking:
        print(f"G1-A/03C Security Gate FAIL: {blocking} unresolved Critical/High findings", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
