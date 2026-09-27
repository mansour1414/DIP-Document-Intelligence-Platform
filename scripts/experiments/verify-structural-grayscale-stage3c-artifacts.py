#!/usr/bin/env python3
"""Fail-closed validator for sanitized Stage 3C CI artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from structural_grayscale_evidence import audit_artifact_directory


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    args = parser.parse_args()
    result = audit_artifact_directory(args.artifact_root.resolve())
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
