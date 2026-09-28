#!/usr/bin/env python3
"""Create a deterministic candidate notices bundle from reviewed wheels and Node packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


NOTICE_NAMES = ("license", "licence", "copying", "notice")
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def add(entries: list[dict], payloads: dict[str, bytes], path: str, data: bytes, source: str) -> None:
    if path in payloads:
        return
    payloads[path] = data
    entries.append({"path": path, "source": source, "sha256": sha256(data), "bytes": len(data)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--package-lock", type=Path, required=True)
    parser.add_argument("--node-modules", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    entries: list[dict] = []
    payloads: dict[str, bytes] = {}

    for wheel in sorted(args.wheel_dir.glob("*.whl")):
        with zipfile.ZipFile(wheel) as archive:
            for member in sorted(archive.namelist()):
                if member.endswith("/") or not any(token in member.lower() for token in NOTICE_NAMES):
                    continue
                add(entries, payloads, f"python/{wheel.name}/{member}", archive.read(member), wheel.name)

    lock = json.loads(args.package_lock.read_text(encoding="utf-8"))
    missing_node_notices = []
    for lock_path, package in sorted(lock["packages"].items()):
        if not lock_path.startswith("node_modules/") or package.get("dev") is True:
            continue
        package_name = lock_path.removeprefix("node_modules/")
        package_dir = args.node_modules / package_name
        found = False
        if package_dir.is_dir():
            for candidate in sorted(package_dir.iterdir()):
                if candidate.is_file() and any(candidate.name.lower().startswith(token) for token in NOTICE_NAMES):
                    add(entries, payloads, f"node/{package_name}/{candidate.name}", candidate.read_bytes(), package_name)
                    found = True
        if not found:
            missing_node_notices.append({"name": package_name, "version": package.get("version", "NOT VERIFIED")})

    boundary = {
        "scope": "G1-A/03 candidate notices; not final image compliance approval",
        "debian_notices": "NOT VERIFIED until extracted from the built candidate image",
        "node_packages_without_top_level_notice_file": missing_node_notices,
        "node_missing_notice_classification": "EVIDENCE_GAP_NOT_CONFIRMED_LICENSE_VIOLATION",
        "node_missing_notice_count": len(missing_node_notices),
        "interpretation": "A missing top-level notice file is not proof that the package is unlicensed or non-compliant; review package metadata, bundled files, source distribution, and license obligations.",
        "production_approval": False,
    }
    add(entries, payloads, "BOUNDARY.json", json.dumps(boundary, indent=2, sort_keys=True).encode() + b"\n", "collector")
    manifest = {"schema": "dip-g1a03-notices-v1", "entries": entries, "boundary": boundary}
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    add(entries, payloads, "MANIFEST.json", manifest_bytes, "collector")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output_dir / "g1a03-notices-manifest.json"
    bundle_path = args.output_dir / "g1a03-notices-bundle.zip"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(payloads):
            info = zipfile.ZipInfo(path, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, payloads[path])
    print(json.dumps({
        "bundle": str(bundle_path), "bundle_sha256": sha256(bundle_path.read_bytes()),
        "entries": len(entries), "missing_node_top_level_notices": len(missing_node_notices),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
