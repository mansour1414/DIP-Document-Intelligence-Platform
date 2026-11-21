# G1-A/03C candidate security gate record

**Security Gate FAIL. Licensing Gate OPEN. Production acceptance remains pending.** This record preserves the result for the historical G1-A candidate reviewed after commit `ad68d55cc73a6246c21ae2e5f3d4cb647b699ddf`. It describes the candidate examined in that run. Stage 3C Grayscale and ClamAV Stage 7 have separate evidence and acceptance gates.

| Recorded evidence | Value |
|---|---|
| Candidate registry OCI digest | Unverified in the original record |
| Findings | 999 raw matches and 987 deduplicated findings, including 28 Critical and 213 High |
| Disposition of the 241 Critical or High findings | All unresolved in the preserved record |
| G1-A/03D remediation routes | 75 proposed fixes and 166 unresolved paths. No accepted exception or approved change |

The totals and verdict come from preserved local records. Artifact identifiers, checksum evidence, scanner output and remediation worksheets remain in local custody. Reassessment requires scanner and SBOM evidence tied to the immutable candidate, a reviewed disposition for each unresolved finding, and independent licensing review. Changes to the Node base, pypdf, runtime toolchain or native library packaging require owner approval.

Run the offline check against a normalized record in approved custody:

```text
python scripts/experiments/verify-g1a03c-security-gate.py --triage PATH_TO_NORMALIZED_TRIAGE
python -B -m unittest discover -s scripts/experiments/tests -p test_verify_g1a03c_security_gate.py
```

The helper checks the recorded verdict, finding counts and dispositions. A successful process exit reports a consistent record with no unresolved Critical or High finding. Verify report provenance and signed-off exception authority separately. The helper has no workflow or runtime entry point.
