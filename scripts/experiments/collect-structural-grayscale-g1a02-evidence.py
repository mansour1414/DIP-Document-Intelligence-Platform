#!/usr/bin/env python3
"""Build the G1-A/02 candidate inventory and unified SBOM without installing wheels.

This collector is experiment-only. It reads exact wheel archives, package-lock.json,
and the frozen G0 Debian summary. It never modifies the production worker image.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import zipfile
from email.parser import Parser
from pathlib import Path
from typing import Any


EXPECTED_WHEELS = {
    "charset-normalizer": ("3.5.1", "c7b742bf31c88566b4bb6335a7f393bb322e580b6bb98df7bd0c25e6e3519ce8"),
    "lxml": ("6.1.3", "527195c188d7d0af748cd48d220ab8cdc5cb99be3d49ac4d9be7324d8abf9bc0"),
    "packaging": ("26.3", "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"),
    "pikepdf": ("10.13.0.post1", "365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8"),
    "pillow": ("12.3.0", "23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd"),
    "pypdf": ("6.10.0", "90005e959e1596c6e6c84c8b0ad383285b3e17011751cedd17f2ce8fcdfc86de"),
    "pypdfium2": ("5.13.0", "81df25c1ab4c13ff773102d3cbea1967511d079123b067fc077bd0c4d57d91d8"),
    "reportlab": ("4.4.9", "68e2d103ae8041a37714e8896ec9b79a1c1e911d68c3bd2ea17546568cf17bfd"),
    "uharfbuzz": ("0.56.2", "f058d70848312366e82068ebef54ead53269bdf34e893c25a3174ea1f5c6d2d3"),
}

PYTHON_ROLES = {
    "pikepdf": "candidate-direct-transformer",
    "pillow": "candidate-direct-image-icc",
    "lxml": "pikepdf-transitive",
    "packaging": "pikepdf-transitive",
    "charset-normalizer": "reportlab-transitive",
    "pypdf": "experimental-validator",
    "pypdfium2": "experimental-reference-reader-existing-ocr-pin",
    "reportlab": "fixture-only",
    "uharfbuzz": "fixture-only",
}

DEBIAN_G0_COMPONENTS = [
    ("qpdf", "11.3.0-1+deb12u1", "Apache-2.0"),
    ("libqpdf29", "11.3.0-1+deb12u1", "Apache-2.0"),
    ("libreoffice-core", "4:7.4.7-1+deb12u14", "NOASSERTION"),
    ("tesseract-ocr", "5.3.0-2", "NOASSERTION"),
    ("tesseract-ocr-ara", "1:4.1.0-2", "NOASSERTION"),
    ("tesseract-ocr-eng", "1:4.1.0-2", "NOASSERTION"),
    ("python3", "3.11.2-1+b1", "NOASSERTION"),
    ("libjpeg62-turbo", "1:2.1.5-2", "NOASSERTION"),
    ("liblcms2-2", "2.14-2+deb12u1", "NOASSERTION"),
    ("libopenjp2-7", "2.5.0-2+deb12u3", "NOASSERTION"),
    ("libpoppler126", "22.12.0-2+deb12u3", "NOASSERTION"),
]

NATIVE_LICENSES = {
    "libqpdf": ("12.3.2", "Apache-2.0"),
    "libjpeg-e87d2658": ("1.5.3-14.el8_10", "IJG AND BSD-3-Clause AND Zlib"),
    "libjpeg-31e2ca52": ("3.1.4.1", "IJG AND BSD-3-Clause"),
    "liblcms2": ("2.19.1", "MIT"),
    "libopenjp2": ("2.5.4", "BSD-2-Clause"),
    "libtiff": ("4.7.1", "libtiff"),
    "libwebp": ("1.6.0", "BSD-3-Clause"),
    "libwebpdemux": ("1.6.0", "BSD-3-Clause"),
    "libwebpmux": ("1.6.0", "BSD-3-Clause"),
    "libsharpyuv": ("1.6.0", "BSD-3-Clause"),
    "libxcb": ("1.17.0", "X11"),
    "libXau": ("1.0.9-3.el8", "X11"),
    "libavif": ("1.4.2", "BSD-2-Clause"),
    "libfreetype": ("2.14.3", "FTL"),
    "libharfbuzz": ("14.2.1", "MIT"),
    "libpng": ("1.6.58", "libpng-2.0"),
    "libzstd": ("1.5.7", "BSD-3-Clause"),
    "liblzma": ("5.8.3", "0BSD"),
    "libbrotlicommon": ("1.2.0", "MIT"),
    "libbrotlidec": ("1.2.0", "MIT"),
    "libpdfium": ("5.13.0-wheel-binary", "BSD-3-Clause AND third-party-notices"),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def metadata_for(archive: zipfile.ZipFile) -> Any:
    names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    if len(names) != 1:
        raise ValueError(f"expected one METADATA file, found {names}")
    return Parser().parsestr(archive.read(names[0]).decode("utf-8", "replace"))


def source_url(metadata: Any) -> str:
    urls = metadata.get_all("Project-URL", [])
    for preferred in ("source", "repository", "code", "homepage"):
        for item in urls:
            label, _, url = item.partition(",")
            if label.strip().lower() == preferred:
                return url.strip()
    return (metadata.get("Home-page") or "NOT VERIFIED").strip()


def license_expression(metadata: Any) -> str:
    return (metadata.get("License-Expression") or metadata.get("License") or "NOASSERTION").strip()


def license_files(archive: zipfile.ZipFile) -> list[dict[str, Any]]:
    result = []
    for name in sorted(archive.namelist()):
        lowered = name.lower()
        if name.endswith("/") or not any(token in lowered for token in ("license", "copying", "notice")):
            continue
        data = archive.read(name)
        result.append({"path": name, "sha256": sha256_bytes(data), "bytes": len(data)})
    return result


def native_identity(member: str, wheel_name: str, wheel_license: str, wheel_version: str) -> tuple[str, str, str]:
    filename = Path(member).name
    for prefix, (version, license_name) in NATIVE_LICENSES.items():
        if filename.startswith(prefix):
            return prefix, version, license_name
    return filename.split(".cpython", 1)[0].split(".abi3", 1)[0], wheel_version, wheel_license


def inspect_wheels(wheel_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    packages: list[dict[str, Any]] = []
    natives: list[dict[str, Any]] = []
    seen: set[str] = set()
    for wheel in sorted(wheel_dir.glob("*.whl")):
        digest = sha256_file(wheel)
        with zipfile.ZipFile(wheel) as archive:
            metadata = metadata_for(archive)
            name = normalize_name(metadata["Name"])
            version = metadata["Version"]
            expected = EXPECTED_WHEELS.get(name)
            if expected is None:
                raise RuntimeError(f"unexpected wheel: {name}")
            if expected != (version, digest):
                raise RuntimeError(f"wheel evidence mismatch for {name}: {(version, digest)}")
            seen.add(name)
            dependencies = [value for value in metadata.get_all("Requires-Dist", []) if "extra ==" not in value]
            package = {
                "name": name,
                "version": version,
                "filename": wheel.name,
                "bytes": wheel.stat().st_size,
                "sha256": digest,
                "license": license_expression(metadata),
                "source": source_url(metadata),
                "role": PYTHON_ROLES[name],
                "requires_dist": dependencies,
                "license_files": license_files(archive),
                "approval": "NOT APPROVED",
            }
            packages.append(package)
            for member in sorted(name for name in archive.namelist() if ".so" in Path(name).name):
                data = archive.read(member)
                native_name, native_version, native_license = native_identity(
                    member, name, package["license"], version
                )
                natives.append({
                    "name": native_name,
                    "version": native_version,
                    "member": member,
                    "source_wheel": wheel.name,
                    "source_wheel_sha256": digest,
                    "sha256": sha256_bytes(data),
                    "bytes": len(data),
                    "license": native_license,
                    "approval": "NOT APPROVED",
                })
    missing = sorted(set(EXPECTED_WHEELS) - seen)
    if missing:
        raise RuntimeError(f"missing reviewed wheels: {missing}")
    return packages, natives


def npm_components(lock_path: Path) -> list[dict[str, Any]]:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    components = []
    for path, package in sorted(lock["packages"].items()):
        if not path.startswith("node_modules/") or package.get("dev") is True:
            continue
        name = path.removeprefix("node_modules/")
        item = {
            "name": name,
            "version": package.get("version", "NOT VERIFIED"),
            "license": package.get("license", "NOASSERTION"),
            "source": package.get("resolved", "NOT VERIFIED"),
            "integrity": package.get("integrity", "NOT VERIFIED"),
            "sha256": "NOT VERIFIED",
            "approval": "PRODUCTION-LOCK CANDIDATE; ACTUAL IMAGE PRESENCE NOT VERIFIED",
        }
        components.append(item)
    return components


def bom_component(item: dict[str, Any], ecosystem: str) -> dict[str, Any]:
    name = item["name"]
    version = item["version"]
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"{ecosystem}:{name}@{version}:{hashlib.sha256(str(item).encode()).hexdigest()[:12]}",
        "name": name,
        "version": version,
        "licenses": [{"license": {"name": item.get("license", "NOASSERTION")}}],
        "properties": [
            {"name": "dip:layer", "value": ecosystem},
            {"name": "dip:approval", "value": item.get("approval", "NOT APPROVED")},
            {"name": "dip:source", "value": item.get("source", item.get("source_wheel", "NOT VERIFIED"))},
        ],
    }
    digest = item.get("sha256")
    if digest and digest != "NOT VERIFIED":
        component["hashes"] = [{"alg": "SHA-256", "content": digest}]
    else:
        component["properties"].append({"name": "dip:sha256", "value": "NOT VERIFIED"})
    if item.get("integrity", "").startswith("sha512-"):
        raw = base64.b64decode(item["integrity"].removeprefix("sha512-"))
        component.setdefault("hashes", []).append({"alg": "SHA-512", "content": raw.hex()})
    return component


def build_sbom(python: list[dict[str, Any]], native: list[dict[str, Any]], node: list[dict[str, Any]]) -> dict[str, Any]:
    debian = [
        {"name": name, "version": version, "license": license_name, "source": "G0 qpdf-worker SPDX artifact summary", "sha256": "NOT VERIFIED", "approval": "EXISTING BASE IMAGE; G0 LICENSE FIELD MAY BE NOASSERTION"}
        for name, version, license_name in DEBIAN_G0_COMPONENTS
    ]
    components = (
        [bom_component(item, "python-wheel") for item in python]
        + [bom_component(item, "native-wheel-member") for item in native]
        + [bom_component(item, "node-production-lock-candidate") for item in node]
        + [bom_component(item, "debian-g0-selected") for item in debian]
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:5dc805b4-acde-4df4-9150-9a94d7d5ef02",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "DIP Structural Grayscale G1-A/02 Candidate", "version": "evidence-only"},
            "properties": [
                {"name": "dip:scope", "value": "experimental-candidate-no-production-integration"},
                {"name": "dip:approval", "value": "NOT APPROVED"},
                {"name": "dip:registry-image-digest", "value": "NOT VERIFIED"},
                {"name": "dip:local-image-id", "value": "NOT VERIFIED in available local evidence"},
                {"name": "dip:stage3c-artifact-zip-sha256", "value": "96db802a0afa3fec8866a8dfe106fdc3fd75bc7e5561ed1b6005e4d7f1d3af6e"},
                {"name": "dip:debian-spdx-artifact-zip-sha256", "value": "f5fa8b1326956309a0bb829fd2da4a0e300a1d75c54b3fd7fb707fc9f046a3a2"},
                {"name": "dip:debian-spdx-total-packages", "value": "301"},
                {"name": "dip:debian-components-materialized-here", "value": str(len(debian))},
                {"name": "dip:debian-full-artifact-locally-available", "value": "false"},
            ],
        },
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--package-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    python, native = inspect_wheels(args.wheel_dir)
    node = npm_components(args.package_lock)
    inventory = {
        "schema": "dip-g1a02-licensing-evidence-v1",
        "scope": "experimental-candidate-no-production-integration",
        "approval": "NOT APPROVED",
        "registry_image_digest": "NOT VERIFIED",
        "local_image_id": "NOT VERIFIED in available local evidence",
        "python_wheels": python,
        "native_members": native,
        "node_production_lock_candidates": node,
        "debian_g0_summary": {
            "artifact_zip_sha256": "f5fa8b1326956309a0bb829fd2da4a0e300a1d75c54b3fd7fb707fc9f046a3a2",
            "reported_total_packages": 301,
            "materialized_selected_components": [
                {"name": name, "version": version, "license": license_name, "sha256": "NOT VERIFIED"}
                for name, version, license_name in DEBIAN_G0_COMPONENTS
            ],
            "full_spdx_locally_available": False,
        },
        "key_findings": {
            "libqpdf": "bundled in pikepdf wheel and separately hashed; distinct from Debian qpdf CLI",
            "littlecms": "bundled in Pillow wheel and separately hashed",
            "libjpeg": "distinct bundled builds exist in pikepdf and Pillow and are separately hashed",
            "libimagequant": "listed optional in Pillow source SBOM but absent as a wheel member; no approval waiver for another build",
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    inventory_path = args.output_dir / "g1a02-python-native-inventory.json"
    sbom_path = args.output_dir / "g1a02-unified-candidate-sbom.cdx.json"
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    sbom_path.write_text(json.dumps(build_sbom(python, native, node), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "inventory": str(inventory_path),
        "sbom": str(sbom_path),
        "python_wheels": len(python),
        "native_members": len(native),
        "node_production_lock_candidates": len(node),
        "debian_selected_components": len(DEBIAN_G0_COMPONENTS),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
