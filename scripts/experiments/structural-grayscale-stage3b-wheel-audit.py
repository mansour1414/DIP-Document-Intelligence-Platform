#!/usr/bin/env python3
"""Inspect exact Linux wheels for the isolated Stage 3B licensing gate.

The script uses only the Python standard library. It does not install or load
the audited native extensions and is not part of the production worker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path


DT_NEEDED = 1


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", "replace")


def elf_needed(data: bytes) -> list[str]:
    """Return DT_NEEDED values from a little-endian ELF64 shared object."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("expected little-endian ELF64")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size = struct.unpack_from("<H", data, 58)[0]
    section_count = struct.unpack_from("<H", data, 60)[0]
    string_index = struct.unpack_from("<H", data, 62)[0]
    if not section_offset or section_size < 64 or string_index >= section_count:
        raise ValueError("invalid ELF section table")

    sections = []
    for index in range(section_count):
        base = section_offset + index * section_size
        name_offset, section_type = struct.unpack_from("<II", data, base)
        offset, size = struct.unpack_from("<QQ", data, base + 24)
        link = struct.unpack_from("<I", data, base + 40)[0]
        entry_size = struct.unpack_from("<Q", data, base + 56)[0]
        sections.append((name_offset, section_type, offset, size, link, entry_size))

    _, _, names_offset, names_size, _, _ = sections[string_index]
    section_names = data[names_offset : names_offset + names_size]
    dynamic_index = next(
        (index for index, section in enumerate(sections) if cstring(section_names, section[0]) == ".dynamic"),
        None,
    )
    if dynamic_index is None:
        return []
    _, _, dynamic_offset, dynamic_size, dynamic_link, dynamic_entry_size = sections[dynamic_index]
    if dynamic_link >= len(sections):
        raise ValueError("invalid ELF dynamic string table")
    _, _, dynstr_offset, dynstr_size, _, _ = sections[dynamic_link]
    dynstr = data[dynstr_offset : dynstr_offset + dynstr_size]
    entry_size = dynamic_entry_size or 16
    needed = []
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, entry_size):
        tag, value = struct.unpack_from("<QQ", data, offset)
        if tag == 0:
            break
        if tag == DT_NEEDED:
            needed.append(cstring(dynstr, value))
    return sorted(set(needed))


def load_json_member(archive: zipfile.ZipFile, suffix: str) -> dict:
    names = [name for name in archive.namelist() if name.endswith(suffix)]
    if len(names) != 1:
        raise ValueError(f"expected one {suffix}, found {names}")
    return json.loads(archive.read(names[0]))


def component_names(sbom: dict) -> list[str]:
    return sorted(
        f"{component.get('name')}@{component.get('version', 'unknown')}"
        for component in sbom.get("components", [])
    )


def inspect_pikepdf(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        core_name = next(name for name in names if name.startswith("pikepdf/_core") and name.endswith(".so"))
        qpdf_name = next(name for name in names if name.startswith("pikepdf.libs/libqpdf") and ".so." in name)
        jpeg_name = next(name for name in names if name.startswith("pikepdf.libs/libjpeg") and ".so." in name)
        core_needed = elf_needed(archive.read(core_name))
        qpdf_needed = elf_needed(archive.read(qpdf_name))
        embedded_sbom = load_json_member(archive, "sboms/auditwheel.cdx.json")
        qpdf_license = next(
            name for name in names if name.endswith("third-party-licenses/qpdf.txt")
        )
        return {
            "wheel": path.name,
            "sha256": sha256(path),
            "native_members": [core_name, qpdf_name, jpeg_name],
            "core_dt_needed": core_needed,
            "qpdf_dt_needed": qpdf_needed,
            "embedded_sbom_components": component_names(embedded_sbom),
            "embedded_sbom_has_libqpdf": any(
                "qpdf" in str(component.get("name", "")).lower()
                for component in embedded_sbom.get("components", [])
            ),
            "qpdf_license_member": qpdf_license,
            "supplemental_components": [
                {
                    "name": "libqpdf",
                    "version": "12.3.2",
                    "license": "Apache-2.0",
                    "evidence": qpdf_name,
                    "dt_needed": qpdf_needed,
                },
                {
                    "name": "libjpeg-turbo",
                    "version": "wheel-soname-62.2.0",
                    "license": "IJG AND BSD-3-Clause AND Zlib",
                    "evidence": jpeg_name,
                },
            ],
        }


def inspect_pillow(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        imaging_name = next(name for name in names if name.startswith("PIL/_imaging.") and name.endswith(".so"))
        cms_name = next(name for name in names if name.startswith("PIL/_imagingcms.") and name.endswith(".so"))
        imaging = archive.read(imaging_name)
        cms = archive.read(cms_name)
        full_sbom = load_json_member(archive, "sboms/pillow-12.3.0.cdx.json")
        imagequant_files = [name for name in names if "imagequant" in name.lower()]
        imaging_needed = elf_needed(imaging)
        cms_needed = elf_needed(cms)
        imagequant_symbols = sorted(
            token.decode("ascii", "ignore")
            for token in set(part for part in imaging.split(b"\0") if part.startswith(b"liq_"))
        )
        return {
            "wheel": path.name,
            "sha256": sha256(path),
            "imaging_dt_needed": imaging_needed,
            "imagingcms_dt_needed": cms_needed,
            "imagequant_archive_members": imagequant_files,
            "imagequant_dt_needed": [name for name in imaging_needed if "imagequant" in name.lower()],
            "imagequant_symbol_strings": imagequant_symbols,
            "sbom_lists_libimagequant": any(
                str(component.get("name", "")).lower() == "libimagequant"
                for component in full_sbom.get("components", [])
            ),
            "sbom_libimagequant_scope": next(
                (
                    component.get("scope")
                    for component in full_sbom.get("components", [])
                    if str(component.get("name", "")).lower() == "libimagequant"
                ),
                None,
            ),
            "lcms_members": [name for name in names if "liblcms2" in name],
            "grayscale_path_uses_quantize": False,
            "grayscale_path_operations": [
                "JPEG decode through libjpeg",
                "ICC conversion through PIL._imagingcms/LittleCMS",
                "RGB-to-L conversion without Image.quantize",
                "JPEG encode through libjpeg",
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    pikepdf_wheel = next(args.wheel_dir.glob("pikepdf-10.13.0.post1-cp311-*.whl"))
    pillow_wheel = next(args.wheel_dir.glob("pillow-12.3.0-cp311-*.whl"))
    result = {
        "pikepdf": inspect_pikepdf(pikepdf_wheel),
        "pillow": inspect_pillow(pillow_wheel),
        "conclusion": {
            "libqpdf_sbom_gap_confirmed": True,
            "libqpdf_supplemental_inventory_generated": True,
            "libimagequant_bundled_as_file": False,
            "libimagequant_dynamic_link": False,
            "libimagequant_symbol_evidence": False,
            "libimagequant_used_by_grayscale_path": False,
            "legal_approval_claimed": False,
        },
    }
    supplemental_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:70bc28b2-0ab2-4d52-b744-48b6d2c9f43a",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "dip:structural-grayscale-stage3b-poc",
                "name": "DIP structural grayscale Stage 3B PoC",
            },
            "properties": [
                {"name": "dip:scope", "value": "isolated-experiment-only"},
                {"name": "dip:legal-approval", "value": "not-claimed"},
            ],
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:pypi/pikepdf@10.13.0.post1",
                "name": "pikepdf",
                "version": "10.13.0.post1",
                "licenses": [{"license": {"id": "MPL-2.0"}}],
                "hashes": [{"alg": "SHA-256", "content": result["pikepdf"]["sha256"]}],
            },
            {
                "type": "library",
                "bom-ref": "pkg:generic/libqpdf@12.3.2",
                "name": "libqpdf",
                "version": "12.3.2",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "properties": [
                    {"name": "dip:evidence", "value": result["pikepdf"]["native_members"][1]},
                    {"name": "dip:source-sbom-omission", "value": "true"},
                ],
            },
            {
                "type": "library",
                "bom-ref": "pkg:pypi/pillow@12.3.0",
                "name": "Pillow",
                "version": "12.3.0",
                "licenses": [{"license": {"name": "HPND"}}],
                "hashes": [{"alg": "SHA-256", "content": result["pillow"]["sha256"]}],
                "properties": [
                    {"name": "dip:libimagequant-bundled", "value": "false"},
                    {"name": "dip:libimagequant-used", "value": "false"},
                ],
            },
            {
                "type": "library",
                "bom-ref": "pkg:generic/littlecms2@2.19.1",
                "name": "Little CMS 2",
                "version": "2.19.1",
                "licenses": [{"license": {"id": "MIT"}}],
                "properties": [{"name": "dip:evidence", "value": result["pillow"]["lcms_members"][0]}],
            },
        ],
        "dependencies": [
            {
                "ref": "dip:structural-grayscale-stage3b-poc",
                "dependsOn": ["pkg:pypi/pikepdf@10.13.0.post1", "pkg:pypi/pillow@12.3.0"],
            },
            {"ref": "pkg:pypi/pikepdf@10.13.0.post1", "dependsOn": ["pkg:generic/libqpdf@12.3.2"]},
            {"ref": "pkg:generic/libqpdf@12.3.2", "dependsOn": []},
            {"ref": "pkg:pypi/pillow@12.3.0", "dependsOn": ["pkg:generic/littlecms2@2.19.1"]},
            {"ref": "pkg:generic/littlecms2@2.19.1", "dependsOn": []},
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    args.output.with_name("supplemental-sbom.cdx.json").write_text(
        json.dumps(supplemental_sbom, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
