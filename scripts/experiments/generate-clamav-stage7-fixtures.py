#!/usr/bin/env python3
"""Generate deterministic ClamAV limit-regression fixtures for Stage 7."""

from __future__ import annotations

import argparse
import io
import zipfile
from pathlib import Path

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def member(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def max_files_fixture(path: Path) -> None:
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        for index in range(10_005):
            archive.writestr(member(f"benign/{index:05d}.txt"), b"DIP benign fixture\n")
        archive.writestr(member("eicar-after-max-files.txt"), EICAR)


def nested_fixture(path: Path) -> None:
    payload = EICAR
    filename = "eicar.txt"
    for depth in range(20, 0, -1):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
            archive.writestr(member(filename), payload)
        payload = output.getvalue()
        filename = f"layer-{depth:02d}.zip"
    path.write_bytes(payload)


def bomb_fixture(path: Path) -> None:
    """Regression fixture: single 420 MiB decompressed member, forced ZIP64.

    Preserved unchanged as the Stage 7 regression case (the failing fixture
    from run 43937894854 step 20).
    """
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        with archive.open(member("420-mib-zero-payload.bin"), "w", force_zip64=True) as target:
            for _ in range(420):
                target.write(chunk)


def bomb_fixture_zip32(path: Path) -> None:
    """Diagnostic fixture: same 420 MiB member but ZIP32 (no ZIP64 forcing).

    Used to distinguish whether the silent-CLEAN result depends on the ZIP64
    parser path (CLAM-3102 covers stored/DEFLATE/DEFLATE64/BZIP2/IMPLODE
    truncation alerts; ZIP64 local-header handling is a separate concern,
    see clamav issue #1888).
    """
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(path, "w") as archive:  # no force_zip64 -> ZIP32 when possible
        with archive.open(member("420-mib-zero-payload.bin"), "w") as target:
            for _ in range(420):
                target.write(chunk)


def maxfilesize_member_fixture(path: Path, member_mib: int = 115) -> None:
    """Diagnostic fixture: a single member just over MaxFileSize (110M).

    Each member is member_mib MiB of zeros. Default 115 MiB > 110M MaxFileSize,
    so a single member exceeds the per-file limit while remaining far below
    MaxScanSize. Exercises the MaxFileSize truncation path that CLAM-3102
    makes alert via Heuristics.Limits.Exceeded.MaxFileSize.
    """
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        with archive.open(member("oversized-member.bin"), "w", force_zip64=True) as target:
            for _ in range(member_mib):
                target.write(chunk)


def aggregate_scansize_fixture(path: Path, member_count: int = 5, member_mib: int = 90) -> None:
    """Diagnostic fixture: N members each under MaxFileSize but aggregate > MaxScanSize.

    Default: 5 members x 90 MiB = 450 MiB aggregate decompressed.
      - each member 90 MiB < 110M MaxFileSize  (individual members pass)
      - aggregate 450 MiB > 400M MaxScanSize  (aggregate exceeds)
    Exercises the MaxScanSize truncation path without any single member
    violating MaxFileSize. Compresses to a small on-disk size.
    """
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        for index in range(member_count):
            name = f"member-{index:03d}.bin"
            with archive.open(member(name), "w", force_zip64=True) as target:
                for _ in range(member_mib):
                    target.write(chunk)


def small_maxfilesize_fixture(path: Path, member_kb: int = 15) -> None:
    """Small bounded fixture for fast local verification.

    Single member of member_kb KiB of 'A' bytes. Intended for local runs with
    a custom clamscan --max-filesize=1K configuration (isolated test config,
    not the DIP candidate config). Compresses poorly, stays tiny on disk, and
    exercises the MaxFileSize truncation alert path without large memory use.
    """
    data = b"A" * (member_kb * 1024)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member("oversized.txt"), data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    max_files_fixture(args.output_dir / "bypass_maxfiles.zip")
    nested_fixture(args.output_dir / "bypass_nested.zip")
    bomb_fixture(args.output_dir / "bomb.zip")                      # regression (ZIP64, 420 MiB)
    bomb_fixture_zip32(args.output_dir / "bomb-zip32.zip")          # diagnostic (ZIP32, 420 MiB)
    maxfilesize_member_fixture(args.output_dir / "oversized-member.zip")  # MaxFileSize > 110M
    aggregate_scansize_fixture(args.output_dir / "aggregate-scansize.zip")  # MaxScanSize > 400M
    small_maxfilesize_fixture(args.output_dir / "small-maxfilesize.zip")    # bounded local check
    for path in sorted(args.output_dir.iterdir()):
        print(f"{path.name}\t{path.stat().st_size}")


if __name__ == "__main__":
    main()
