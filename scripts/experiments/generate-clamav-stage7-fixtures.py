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
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        with archive.open(member("420-mib-zero-payload.bin"), "w", force_zip64=True) as target:
            for _ in range(420):
                target.write(chunk)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    max_files_fixture(args.output_dir / "bypass_maxfiles.zip")
    nested_fixture(args.output_dir / "bypass_nested.zip")
    bomb_fixture(args.output_dir / "bomb.zip")
    for path in sorted(args.output_dir.iterdir()):
        print(f"{path.name}\t{path.stat().st_size}")


if __name__ == "__main__":
    main()
