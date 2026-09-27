#!/usr/bin/env python3
"""Provision the reviewed Stage 3C CMYK ICC fixture from locked pdfjs-dist.

This is CI/PoC infrastructure only. Processing remains network-disabled; the
source package is installed by the existing lockfile-backed ``npm ci`` step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = Path(__file__).with_name("structural-grayscale-stage3c-icc-fixture.json")
DEFAULT_PACKAGE_ROOT = ROOT / "node_modules" / "pdfjs-dist"
DEFAULT_OUTPUT_ROOT = ROOT / ".stage3c-fixtures"


class FixtureProvisioningError(RuntimeError):
    """The reviewed fixture cannot be proven and must not be provisioned."""


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_reviewed_file(path: Path, expected_size: int, expected_sha256: str, label: str) -> bytes:
    try:
        data = path.read_bytes()
    except FileNotFoundError as error:
        raise FixtureProvisioningError(f"reviewed {label} is missing: {path}") from error
    if len(data) != expected_size:
        raise FixtureProvisioningError(
            f"reviewed {label} size mismatch: expected {expected_size}, got {len(data)}"
        )
    actual_sha256 = sha256(data)
    if actual_sha256 != expected_sha256:
        raise FixtureProvisioningError(
            f"reviewed {label} checksum mismatch: expected {expected_sha256}, got {actual_sha256}"
        )
    return data


def validate_cmyk_icc(data: bytes, manifest: dict[str, object]) -> None:
    profile = manifest["profile"]
    assert isinstance(profile, dict)
    if len(data) < 132:
        raise FixtureProvisioningError("reviewed CMYK ICC profile is truncated")
    declared_size = struct.unpack(">I", data[0:4])[0]
    if declared_size != len(data):
        raise FixtureProvisioningError("reviewed CMYK ICC declared size is invalid")
    if data[36:40] != b"acsp":
        raise FixtureProvisioningError("reviewed CMYK ICC signature is invalid")
    checks = (
        (data[12:16].decode("ascii", "strict"), profile["deviceClass"], "device class"),
        (data[16:20].decode("ascii", "strict"), profile["colorSpace"], "color space"),
        (data[20:24].decode("ascii", "strict"), profile["connectionSpace"], "connection space"),
    )
    for actual, expected, label in checks:
        if actual != expected:
            raise FixtureProvisioningError(
                f"reviewed CMYK ICC {label} mismatch: expected {expected!r}, got {actual!r}"
            )
    major, minor = data[8], data[9] >> 4
    if f"{major}.{minor}" != profile["iccVersion"]:
        raise FixtureProvisioningError("reviewed CMYK ICC version is incompatible")
    tag_count = struct.unpack(">I", data[128:132])[0]
    table_end = 132 + tag_count * 12
    if tag_count == 0 or table_end > len(data):
        raise FixtureProvisioningError("reviewed CMYK ICC tag table is invalid")
    for offset in range(132, table_end, 12):
        tag_offset, tag_size = struct.unpack(">II", data[offset + 4 : offset + 12])
        if tag_size == 0 or tag_offset < table_end or tag_offset + tag_size > len(data):
            raise FixtureProvisioningError("reviewed CMYK ICC tag bounds are invalid")


def provision(package_root: Path, output_root: Path) -> dict[str, object]:
    manifest = load_manifest()
    source_package = manifest["sourcePackage"]
    profile = manifest["profile"]
    license_file = manifest["licenseFile"]
    assert isinstance(source_package, dict)
    assert isinstance(profile, dict)
    assert isinstance(license_file, dict)

    package_json_path = package_root / "package.json"
    try:
        package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise FixtureProvisioningError(f"locked pdfjs-dist package is missing: {package_root}") from error
    if package_json.get("name") != source_package["name"] or package_json.get("version") != source_package["version"]:
        raise FixtureProvisioningError("pdfjs-dist package identity/version does not match reviewed fixture source")

    profile_data = require_reviewed_file(
        package_root / str(source_package["path"]),
        int(profile["size"]),
        str(profile["sha256"]),
        "CMYK ICC profile",
    )
    validate_cmyk_icc(profile_data, manifest)
    license_data = require_reviewed_file(
        package_root / str(license_file["path"]),
        int(license_file["size"]),
        str(license_file["sha256"]),
        "CMYK ICC license",
    )

    output_root.mkdir(parents=True, exist_ok=True)
    profile_output = output_root / str(manifest["fixture"])
    license_output = output_root / "CGATS001Compat-v2-micro.LICENSE.txt"
    profile_output.write_bytes(profile_data)
    license_output.write_bytes(license_data)

    # Re-read the staged files so a failed or truncated copy cannot enter the image.
    staged_profile = require_reviewed_file(
        profile_output, int(profile["size"]), str(profile["sha256"]), "staged CMYK ICC profile"
    )
    validate_cmyk_icc(staged_profile, manifest)
    require_reviewed_file(
        license_output,
        int(license_file["size"]),
        str(license_file["sha256"]),
        "staged CMYK ICC license",
    )
    provenance_output = output_root / "CGATS001Compat-v2-micro.provenance.json"
    shutil.copyfile(MANIFEST_PATH, provenance_output)
    return {
        "fixture": profile_output.name,
        "sha256": profile["sha256"],
        "size": profile["size"],
        "license": manifest["license"],
        "source_package": f"{source_package['name']}@{source_package['version']}",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", type=Path, default=DEFAULT_PACKAGE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    evidence = provision(args.package_root.resolve(), args.output_root.resolve())
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
