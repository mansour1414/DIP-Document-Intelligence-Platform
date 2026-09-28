#!/usr/bin/env python3
"""Fail-closed reconciliation for the isolated G1-A/03B candidate evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    expected = json.loads(args.expected.read_text(encoding="utf-8"))
    actual_python = json.loads((args.evidence / "inventory/python-packages.json").read_text(encoding="utf-8"))
    expected_python = {item["name"].lower(): item["version"] for item in expected["python_wheels"]}
    actual_versions = {item["name"].lower(): item["version"] for item in actual_python}
    mismatches = [
        {"name": name, "expected": version, "actual": actual_versions.get(name, "MISSING")}
        for name, version in sorted(expected_python.items())
        if actual_versions.get(name) != version
    ]

    required = [
        "candidate-image.spdx.json",
        "candidate-image.cdx.json",
        "vulnerability-scan.grype.json",
        "inventory/debian-packages.tsv",
        "inventory/node-packages.json",
        "inventory/python-native-sha256.txt",
        "inventory/debian-notices-sha256.txt",
        "debian-notices.tar.gz",
        "local-image-id.json",
        "registry-repo-digests.json",
    ]
    missing = [name for name in required if not (args.evidence / name).is_file() or (args.evidence / name).stat().st_size == 0]
    repo_digests = json.loads((args.evidence / "registry-repo-digests.json").read_text(encoding="utf-8"))
    record = {
        "schema": "dip-g1a03b-reconciliation-v1",
        "candidate_contains_grayscale_engine": False,
        "production_evidence": False,
        "expected_python_versions": expected_python,
        "python_version_mismatches": mismatches,
        "missing_required_evidence": missing,
        "local_image_id_status": "VERIFIED LOCALLY",
        "registry_oci_digest_status": "NOT VERIFIED",
        "registry_repo_digests_observed": repo_digests,
        "interpretation": "A local image ID and local archive hash are not an immutable registry digest. No registry push or independent pull occurs in this workflow.",
        "result": "PASS" if not mismatches and not missing and repo_digests in (None, []) else "FAIL",
    }
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if record["result"] != "PASS":
        raise SystemExit("candidate evidence reconciliation failed closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
