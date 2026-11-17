#!/usr/bin/env python3
"""
Phase 0B Isolated Security Remediation PoC — Fixture Generator, Preflight Runner,
Live clamd Harness, and Fail-Closed Evidence Assembler.

ISOLATED EXPERIMENT ONLY — NOT INTEGRATED INTO PRODUCTION.
Provisional governance references (PROPOSED — NOT APPROVED):
  - CLAMAV-CR-P01 (Part A: ClamAV 1.5.4 + upstream CLAM-3102 ARM64 candidate)
  - CLAMAV-CR-P02 (Part B: Bounded ZIP/OOXML structural preflight prototype)
  - CLAMAV-CR-P03 (Phase 0B live test matrix & GPLv2/SBOM governance)

Safety & forensic invariants:
  1. EICAR test string is constructed via concatenation of two benign halves so the
     script itself never triggers static AV scanners.
  2. Wire verdicts are judged strictly on anchored, NUL-terminated raw clamd replies.
     Truncated, missing-NUL, concatenated, or malformed wire output ALWAYS fails closed.
  3. Exact-boundary (== MaxFileSize) and forged-size ZIP32 controls are verified at the
     binary header AND inflation levels during offline --self-test.
  4. PDF-embedded ZIP64 residual risk (upstream ClamAV issue #1888) is explicitly modeled
     as an informational residual-risk probe and never falsely reported as remediated.
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import io
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Split to avoid triggering static scanners on the test harness source itself.
EICAR_PART_1 = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
EICAR_PART_2 = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_BYTES = EICAR_PART_1 + EICAR_PART_2

# Default isolated experiment limit for Part A MaxFileSize testing (matches Phase 0A)
DEFAULT_EXPERIMENT_MAX_FILE_SIZE = 16384  # 16K

# Anchored raw wire verdict regexes (NUL-terminated single stanza only)
RE_OK = re.compile(rb"^stream: OK\x00$")
RE_FOUND = re.compile(rb"^stream: ([^\x00\r\n]+) FOUND\x00$")
RE_ERROR = re.compile(rb"^(?:stream: )?([^\x00\r\n]+) ERROR\x00$")


@dataclass(frozen=True)
class FixtureSpec:
    id: str
    part: str  # "PART_A" | "PART_B" | "RESIDUAL_RISK"
    filename: str
    declared_kind: str  # docx | xlsx | pptx | ooxml | zip | pdf
    description: str
    sha256: str
    size_bytes: int
    header_summary: dict[str, Any]
    expected_preflight_action: str  # ALLOW | ALLOW_WITH_RESIDUAL_RISK_WARNING | REJECT
    expected_preflight_code: str | None
    live_scan_target: str | None  # "yes" | "no" | "both" | None
    expected_clamd_yes: str | None  # CLEAN | EICAR_FOUND | MAXFILESIZE_FOUND | RECORD_ONLY
    expected_clamd_no: str | None  # CLEAN | RECORD_ONLY | None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_ooxml_zip(
    entries: list[tuple[str, bytes]],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
    version_needed: int | None = None,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in entries:
            zi = zipfile.ZipInfo(name, date_time=(2026, 11, 16, 0, 0, 0))
            zi.compress_type = compression
            zf.writestr(zi, data)
    raw = bytearray(buf.getvalue())
    if version_needed is not None:
        raw = _rewrite_zip_version_needed(raw, version_needed)
    return bytes(raw)


def _rewrite_zip_version_needed(raw: bytearray, version_needed: int) -> bytearray:
    """Safely rewrite version_needed in every LFH and CDH without introducing ZIP64 fields."""
    eocd_pos = raw.rfind(b"PK\x05\x06")
    if eocd_pos < 0:
        raise ValueError("EOCD missing while rewriting version_needed")
    total_entries, cd_size, cd_offset = struct.unpack_from("<HII", raw, eocd_pos + 10)
    cursor = cd_offset
    for _ in range(total_entries):
        if raw[cursor : cursor + 4] != b"PK\x01\x02":
            raise ValueError("Invalid CDH while rewriting version_needed")
        struct.pack_into("<H", raw, cursor + 6, version_needed)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", raw, cursor + 28)
        lfh_offset = struct.unpack_from("<I", raw, cursor + 42)[0]
        if raw[lfh_offset : lfh_offset + 4] != b"PK\x03\x04":
            raise ValueError("Invalid LFH while rewriting version_needed")
        struct.pack_into("<H", raw, lfh_offset + 4, version_needed)
        cursor += 46 + name_len + extra_len + comment_len
    return raw


def _build_raw_zip(
    entries: list[dict[str, Any]],
    *,
    append_zip64_eocd: bool = False,
) -> bytes:
    """Low-level deterministic ZIP assembler for exact binary test vectors."""
    local_parts: list[bytes] = []
    cd_parts: list[bytes] = []
    offset = 0

    for entry in entries:
        name_b: bytes = entry["name"].encode("ascii")
        compressed: bytes = entry["compressed"]
        crc: int = entry["crc32"]
        csize: int = entry.get("csize", len(compressed))
        usize: int = entry.get("usize", len(compressed))
        method: int = entry.get("method", 0)
        lfh_method: int = entry.get("lfh_method", method)
        flags: int = entry.get("flags", 0)
        version_needed: int = entry.get("version_needed", 20)
        lfh_extra: bytes = entry.get("lfh_extra", b"")
        cdh_extra: bytes = entry.get("cdh_extra", b"")
        dd_mode: str = entry.get("dd_mode", "none")  # none | dd32 | dd64
        force_lfh_sentinel: bool = entry.get("force_lfh_sentinel", False)
        force_cdh_sentinel: bool = entry.get("force_cdh_sentinel", False)

        if dd_mode != "none":
            flags |= 0x0008

        lfh_crc = 0 if dd_mode != "none" else crc
        lfh_csize = 0xFFFFFFFF if force_lfh_sentinel else (0 if dd_mode != "none" else csize)
        lfh_usize = 0xFFFFFFFF if force_lfh_sentinel else (0 if dd_mode != "none" else usize)

        lfh = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            version_needed,
            flags,
            lfh_method,
            0,
            0,
            lfh_crc,
            lfh_csize,
            lfh_usize,
            len(name_b),
            len(lfh_extra),
        )
        lfh_offset = offset
        local_parts.extend([lfh, name_b, lfh_extra, compressed])
        offset += len(lfh) + len(name_b) + len(lfh_extra) + len(compressed)

        if dd_mode == "dd32":
            dd = struct.pack("<IIII", 0x08074B50, crc, csize, usize)
            local_parts.append(dd)
            offset += len(dd)
        elif dd_mode == "dd64":
            dd = struct.pack("<IIQQ", 0x08074B50, crc, csize, usize)
            local_parts.append(dd)
            offset += len(dd)

        cdh_csize = 0xFFFFFFFF if force_cdh_sentinel else csize
        cdh_usize = 0xFFFFFFFF if force_cdh_sentinel else usize

        cdh = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            version_needed,
            version_needed,
            flags,
            method,
            0,
            0,
            crc,
            cdh_csize,
            cdh_usize,
            len(name_b),
            len(cdh_extra),
            0,
            0,
            0,
            0,
            lfh_offset,
        )
        cd_parts.extend([cdh, name_b, cdh_extra])

    cd_offset = offset
    cd_bytes = b"".join(cd_parts)
    out_parts = [*local_parts, cd_bytes]

    if append_zip64_eocd:
        z64_eocd_offset = cd_offset + len(cd_bytes)
        z64_eocd = struct.pack(
            "<IQHHIIQQQQ",
            0x06064B50,
            44,
            45,
            45,
            0,
            0,
            len(entries),
            len(entries),
            len(cd_bytes),
            cd_offset,
        )
        z64_loc = struct.pack("<IIQI", 0x07064B50, 0, z64_eocd_offset, 1)
        out_parts.extend([z64_eocd, z64_loc])

    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        0xFFFF if append_zip64_eocd else len(entries),
        0xFFFF if append_zip64_eocd else len(entries),
        0xFFFFFFFF if append_zip64_eocd else len(cd_bytes),
        0xFFFFFFFF if append_zip64_eocd else cd_offset,
        0,
    )
    out_parts.append(eocd)
    return b"".join(out_parts)


def _deflate_raw(data: bytes) -> bytes:
    comp = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-zlib.MAX_WBITS)
    return comp.compress(data) + comp.flush()


def _build_minimal_pdf(body_comment: bytes, *, encrypted: bool = False, extra_stream: bytes | None = None) -> bytes:
    """Build a valid minimal single-page PDF 1.4 fixture with exact xref offsets."""
    objects: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
    ]
    encrypt_ref = b""
    if encrypted:
        objects.append(
            b"5 0 obj\n<< /Filter /Standard /V 1 /R 2 /O (0123456789abcdef0123456789abcdef) "
            b"/U (fedcba9876543210fedcba9876543210) /P -4 >>\nendobj\n"
        )
        encrypt_ref = b" /Encrypt 5 0 R"
    if extra_stream is not None:
        obj_num = len(objects) + 1
        objects.append(
            f"{obj_num} 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fzip /Length {len(extra_stream)} >>\nstream\n".encode("ascii")
            + extra_stream
            + b"\nendstream\nendobj\n"
        )

    out = bytearray(b"%PDF-1.4\n% " + body_comment + b"\n")
    offsets: list[int] = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R".encode("ascii")
        + encrypt_ref
        + f" >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


def inspect_binary_header(data: bytes) -> dict[str, Any]:
    """Quick structural summary of generated fixtures for audit provenance."""
    if data.startswith(b"%PDF-"):
        return {
            "container": "PDF",
            "has_encrypt_dict": b"/Encrypt" in data,
            "contains_pk0304": b"PK\x03\x04" in data,
            "contains_zip64_extra_0x0001_sentinel": b"\xff\xff\xff\xff\xff\xff\xff\xff" in data,
        }
    if not data.startswith(b"PK\x03\x04"):
        return {"container": "RAW", "magic_hex": data[:8].hex()}

    eocd_pos = data.rfind(b"PK\x05\x06")
    info: dict[str, Any] = {
        "container": "ZIP",
        "has_eocd": eocd_pos >= 0,
        "has_zip64_eocd_sig": b"PK\x06\x06" in data,
        "has_zip64_locator_sig": b"PK\x06\x07" in data,
    }
    if len(data) >= 30:
        ver, flags, method, _, _, _, csize, usize, nlen, elen = struct.unpack_from("<HHHHHIIIHH", data, 4)
        info["first_lfh"] = {
            "version_needed": ver,
            "flags_hex": f"0x{flags:04x}",
            "method": method,
            "csize": csize,
            "usize": usize,
            "name_len": nlen,
            "extra_len": elen,
        }
    return info


def generate_fixtures(out_dir: Path, max_file_size: int = DEFAULT_EXPERIMENT_MAX_FILE_SIZE) -> list[FixtureSpec]:
    out_dir.mkdir(parents=True, exist_ok=True)
    content_types = b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
    specs: list[FixtureSpec] = []

    def add_fixture(
        *,
        fid: str,
        part: str,
        filename: str,
        declared_kind: str,
        description: str,
        payload: bytes,
        expected_preflight_action: str,
        expected_preflight_code: str | None,
        live_scan_target: str | None,
        expected_clamd_yes: str | None,
        expected_clamd_no: str | None = None,
    ) -> None:
        path = out_dir / filename
        path.write_bytes(payload)
        specs.append(
            FixtureSpec(
                id=fid,
                part=part,
                filename=filename,
                declared_kind=declared_kind,
                description=description,
                sha256=sha256_bytes(payload),
                size_bytes=len(payload),
                header_summary=inspect_binary_header(payload),
                expected_preflight_action=expected_preflight_action,
                expected_preflight_code=expected_preflight_code,
                live_scan_target=live_scan_target,
                expected_clamd_yes=expected_clamd_yes,
                expected_clamd_no=expected_clamd_no,
            )
        )

    # ------------------------------------------------------------------
    # PART A: CLAM-3102 (MaxFileSize ZIP member truncation alerting)
    # ------------------------------------------------------------------

    # A1: EICAR inside normal ZIP32 control
    a1_data = _make_ooxml_zip([("eicar.txt", EICAR_BYTES)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A1_eicar_zip32_control",
        part="PART_A",
        filename="A1_eicar_zip32_control.zip",
        declared_kind="zip",
        description="Positive control: EICAR inside standard ZIP32 (<= MaxFileSize).",
        payload=a1_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="EICAR_FOUND",
    )

    # A2: Exact boundary (uncompressed == MaxFileSize = 16384B) -> MUST be CLEAN (no false alert)
    exact_payload = b"A" * max_file_size
    a2_data = _make_ooxml_zip([("exact_boundary.bin", exact_payload)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A2_exact_boundary_zip32_eq_maxfilesize",
        part="PART_A",
        filename="A2_exact_boundary_zip32_eq_maxfilesize.zip",
        declared_kind="zip",
        description=f"Exact-boundary control: DEFLATE ZIP32 expanding to exactly {max_file_size} bytes (== MaxFileSize).",
        payload=a2_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="CLEAN",
    )

    # A3: One byte over boundary (MaxFileSize + 1 = 16385B) DEFLATE
    over1_payload = b"B" * (max_file_size + 1)
    a3_data = _make_ooxml_zip([("over_by_one.bin", over1_payload)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A3_over_boundary_plus1_zip32_deflate",
        part="PART_A",
        filename="A3_over_boundary_plus1_zip32_deflate.zip",
        declared_kind="zip",
        description=f"CLAM-3102 boundary probe: DEFLATE ZIP32 expanding to {max_file_size + 1} bytes (MaxFileSize + 1).",
        payload=a3_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="MAXFILESIZE_FOUND",
    )

    # A4: Phase 0A E1 reproduction (65536B DEFLATE ZIP32) tested on BOTH yes and no daemons
    over64k_payload = b"Z" * 65536
    a4_data = _make_ooxml_zip([("payload_64k.bin", over64k_payload)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A4_phase0a_e1_repro_zip32_64k_deflate",
        part="PART_A",
        filename="A4_phase0a_e1_repro_zip32_64k_deflate.zip",
        declared_kind="zip",
        description="Direct reproduction of Phase 0A E1_yes failure: 65536B DEFLATE ZIP32 under MaxFileSize=16K.",
        payload=a4_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="both",
        expected_clamd_yes="MAXFILESIZE_FOUND",
        expected_clamd_no="CLEAN",
    )

    # A5: STORED (method 0) member > MaxFileSize (20480B) -> exercises unz() STORED branch (line 166)
    stored_payload = b"S" * (max_file_size + 4096)
    a5_data = _make_ooxml_zip([("stored_over.bin", stored_payload)], compression=zipfile.ZIP_STORED)
    add_fixture(
        fid="A5_over_boundary_zip32_stored",
        part="PART_A",
        filename="A5_over_boundary_zip32_stored.zip",
        declared_kind="zip",
        description=f"CLAM-3102 STORED branch probe: method 0 member of {len(stored_payload)} bytes (> MaxFileSize).",
        payload=a5_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="MAXFILESIZE_FOUND",
    )

    # A6: BZIP2 (method 12) member > MaxFileSize (32768B) -> exercises unz() BZIP2 branch (line 274)
    bzip2_raw = b"Q" * (max_file_size * 2)
    bzip2_comp = bz2.compress(bzip2_raw)
    a6_data = _build_raw_zip(
        [
            {
                "name": "bzip2_over.bin",
                "compressed": bzip2_comp,
                "crc32": zlib.crc32(bzip2_raw) & 0xFFFFFFFF,
                "csize": len(bzip2_comp),
                "usize": len(bzip2_raw),
                "method": 12,
                "version_needed": 46,
            }
        ]
    )
    add_fixture(
        fid="A6_over_boundary_zip32_bzip2",
        part="PART_A",
        filename="A6_over_boundary_zip32_bzip2.zip",
        declared_kind="zip",
        description=f"CLAM-3102 BZIP2 branch probe: method 12 member expanding to {len(bzip2_raw)} bytes (> MaxFileSize).",
        payload=a6_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="MAXFILESIZE_FOUND",
    )

    # A7: FORGED-SIZE CONTROL — DEFLATE stream expands to 65536B, but LFH and CDH lie and declare usize=100!
    # Proves: (1) header-only preflight intentionally does not decompress (returns ALLOW),
    #         (2) patched clamd (CLAM-3102) MUST STILL catch actual inflated > MaxFileSize!
    forged_real_payload = b"F" * 65536
    forged_comp = _deflate_raw(forged_real_payload)
    a7_data = _build_raw_zip(
        [
            {
                "name": "forged_usize_100_real_64k.bin",
                "compressed": forged_comp,
                "crc32": zlib.crc32(forged_real_payload) & 0xFFFFFFFF,
                "csize": len(forged_comp),
                "usize": 100,  # FORGED declared uncompressed size!
                "method": 8,
                "version_needed": 20,
            }
        ]
    )
    add_fixture(
        fid="A7_forged_size_header_zip32_maxfilesize",
        part="PART_A",
        filename="A7_forged_size_header_zip32_maxfilesize.zip",
        declared_kind="zip",
        description=(
            "Forged-size control: LFH/CDH declare uncompressed_size=100 while DEFLATE stream "
            "expands to 65536 bytes (> MaxFileSize=16K). Header-only preflight passes; patched clamd MUST alert."
        ),
        payload=a7_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="both",
        expected_clamd_yes="MAXFILESIZE_FOUND",
        expected_clamd_no="CLEAN",
    )

    # A8: EICAR hidden past MaxFileSize offset inside DEFLATE ZIP32
    hidden_eicar_payload = (b"X" * (max_file_size + 4096)) + EICAR_BYTES
    a8_data = _make_ooxml_zip([("eicar_past_limit.txt", hidden_eicar_payload)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A8_eicar_hidden_past_maxfilesize_zip32",
        part="PART_A",
        filename="A8_eicar_hidden_past_maxfilesize_zip32.zip",
        declared_kind="zip",
        description="Security regression: EICAR appended beyond MaxFileSize inside DEFLATE ZIP32 must trigger MaxFileSize alert.",
        payload=a8_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="MAXFILESIZE_FOUND",
    )

    # A9: Raw non-ZIP 65536B control (proves non-ZIP MaxFileSize still alerts cleanly)
    a9_data = b"R" * 65536
    add_fixture(
        fid="A9_raw_non_zip_64k_maxfilesize_control",
        part="PART_A",
        filename="A9_raw_non_zip_64k_maxfilesize_control.bin",
        declared_kind="zip",
        description="Baseline non-ZIP control: raw 65536B payload under MaxFileSize=16K, AlertExceedsMax=yes.",
        payload=a9_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="MALFORMED_NOT_ZIP_MAGIC",
        live_scan_target="yes",
        expected_clamd_yes="MAXFILESIZE_FOUND",
    )

    # ------------------------------------------------------------------
    # PART B: Bounded ZIP / OOXML Preflight & Controls
    # ------------------------------------------------------------------

    # B1: Deterministic reproduction of Phase 0A D_eicar_zip64 (ZIP64_LFH_PYTHON312):
    # LFH carries 0xFFFFFFFF sentinels + 0x0001 ZIP64 extra field; CDH/EOCD stay 32-bit.
    # Built explicitly (rather than via stdlib zipfile.open) so output bytes are identical
    # across Python 3.11 and Python 3.12+ runners.
    eicar_comp = _deflate_raw(EICAR_BYTES)
    z64_extra = struct.pack("<HHQQ", 0x0001, 16, len(EICAR_BYTES), len(eicar_comp))
    b1_data = _build_raw_zip(
        [
            {
                "name": "eicar.txt",
                "compressed": eicar_comp,
                "crc32": zlib.crc32(EICAR_BYTES) & 0xFFFFFFFF,
                "csize": len(eicar_comp),
                "usize": len(EICAR_BYTES),
                "method": 8,
                "version_needed": 45,
                "lfh_extra": z64_extra,
                "force_lfh_sentinel": True,
                "force_cdh_sentinel": False,
            }
        ],
        append_zip64_eocd=False,
    )
    add_fixture(
        fid="B1_zip64_eicar_lfh_python312",
        part="PART_B",
        filename="B1_zip64_eicar_lfh_python312.zip",
        declared_kind="zip",
        description="Deterministic reproduction of Phase 0A D_eicar_zip64 (LFH 0xFFFFFFFF sentinels + 0x0001 extra field, 32-bit CDH/EOCD).",
        payload=b1_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_LFH_SENTINEL",
        live_scan_target="yes",
        expected_clamd_yes="RECORD_ONLY",  # PR #1845 intentionally excluded from Part A
    )

    # B1b: ZIP64 0x0001 extra field WITHOUT 0xFFFFFFFF sentinels (streaming writer / Python 3.11 pattern)
    b1b_data = _build_raw_zip(
        [
            {
                "name": "eicar.txt",
                "compressed": eicar_comp,
                "crc32": zlib.crc32(EICAR_BYTES) & 0xFFFFFFFF,
                "csize": len(eicar_comp),
                "usize": len(EICAR_BYTES),
                "method": 8,
                "version_needed": 20,
                "lfh_extra": z64_extra,
                "force_lfh_sentinel": False,
                "force_cdh_sentinel": False,
            }
        ],
        append_zip64_eocd=False,
    )
    add_fixture(
        fid="B1b_zip64_extra_field_without_sentinels",
        part="PART_B",
        filename="B1b_zip64_extra_field_without_sentinels.zip",
        declared_kind="zip",
        description="ZIP64 0x0001 extra field present without 0xFFFFFFFF sentinels (streaming-writer variant).",
        payload=b1b_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_EXTRA_FIELD_PRESENT",
        live_scan_target=None,
        expected_clamd_yes=None,
    )

    # B2: Full ZIP64 EOCD + Locator + CDH sentinel carrying EICAR
    b2_data = _build_raw_zip(
        [
            {
                "name": "eicar.txt",
                "compressed": eicar_comp,
                "crc32": zlib.crc32(EICAR_BYTES) & 0xFFFFFFFF,
                "csize": len(eicar_comp),
                "usize": len(EICAR_BYTES),
                "method": 8,
                "version_needed": 45,
                "lfh_extra": z64_extra,
                "cdh_extra": z64_extra,
                "force_lfh_sentinel": True,
                "force_cdh_sentinel": True,
            }
        ],
        append_zip64_eocd=True,
    )
    add_fixture(
        fid="B2_zip64_eicar_full_eocd_cdh",
        part="PART_B",
        filename="B2_zip64_eicar_full_eocd_cdh.zip",
        declared_kind="zip",
        description="Full ZIP64 archive (ZIP64 EOCD + Locator + CDH/LFH sentinels + 0x0001 extra) containing EICAR.",
        payload=b2_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_EOCD_LOCATOR_PRESENT",
        live_scan_target="yes",
        expected_clamd_yes="RECORD_ONLY",
    )

    # B3: Subtle ZIP64 24-byte Data Descriptor (version_needed=45, bit 0x0008, NO 0xFFFFFFFF sentinels)
    b3_data = _build_raw_zip(
        [
            {
                "name": "[Content_Types].xml",
                "compressed": content_types,
                "crc32": zlib.crc32(content_types) & 0xFFFFFFFF,
                "csize": len(content_types),
                "usize": len(content_types),
                "method": 0,
                "version_needed": 45,
                "dd_mode": "dd64",
            },
            {
                "name": "word/document.xml",
                "compressed": EICAR_BYTES,
                "crc32": zlib.crc32(EICAR_BYTES) & 0xFFFFFFFF,
                "csize": len(EICAR_BYTES),
                "usize": len(EICAR_BYTES),
                "method": 0,
                "version_needed": 45,
                "dd_mode": "dd64",
            },
        ]
    )
    add_fixture(
        fid="B3_zip64_data_descriptor_no_sentinels",
        part="PART_B",
        filename="B3_zip64_data_descriptor_no_sentinels.docx",
        declared_kind="docx",
        description="Subtle ZIP64 OOXML using 24-byte 64-bit Data Descriptors without 0xFFFFFFFF sentinels or 0x0001 extra fields.",
        payload=b3_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_DATA_DESCRIPTOR_DETECTED",
        live_scan_target="yes",
        expected_clamd_yes="RECORD_ONLY",
    )

    # B4: Unsupported compression method LZMA (14)
    b4_data = _build_raw_zip(
        [
            {
                "name": "payload_lzma.bin",
                "compressed": b"\x09\x14\x05\x00\x5d\x00\x00\x80\x00",
                "crc32": 0x12345678,
                "csize": 9,
                "usize": 68,
                "method": 14,
                "version_needed": 63,
            }
        ]
    )
    add_fixture(
        fid="B4_unsupported_method_lzma_14",
        part="PART_B",
        filename="B4_unsupported_method_lzma_14.zip",
        declared_kind="zip",
        description="Unsupported ZIP compression method 14 (LZMA), which ClamAV 1.5.4 skips.",
        payload=b4_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="UNSUPPORTED_COMPRESSION_METHOD",
        live_scan_target=None,
        expected_clamd_yes=None,
    )

    # B5: Unsupported compression method PPMd (98)
    b5_data = _build_raw_zip(
        [
            {
                "name": "payload_ppmd.bin",
                "compressed": b"\x00\x01\x02\x03\x04\x05",
                "crc32": 0x87654321,
                "csize": 6,
                "usize": 68,
                "method": 98,
                "version_needed": 63,
            }
        ]
    )
    add_fixture(
        fid="B5_unsupported_method_ppmd_98",
        part="PART_B",
        filename="B5_unsupported_method_ppmd_98.zip",
        declared_kind="zip",
        description="Unsupported ZIP compression method 98 (PPMd), which ClamAV 1.5.4 skips.",
        payload=b5_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="UNSUPPORTED_COMPRESSION_METHOD",
        live_scan_target=None,
        expected_clamd_yes=None,
    )

    # B6: Encrypted OOXML (traditional PKWARE flag 0x0001)
    b6_data = _build_raw_zip(
        [
            {
                "name": "[Content_Types].xml",
                "compressed": b"encrypted-bytes",
                "crc32": 0xAABBCCDD,
                "csize": 15,
                "usize": 15,
                "method": 0,
                "flags": 0x0001,
                "version_needed": 20,
            }
        ]
    )
    add_fixture(
        fid="B6_encrypted_ooxml_traditional",
        part="PART_B",
        filename="B6_encrypted_ooxml_traditional.docx",
        declared_kind="docx",
        description="Encrypted OOXML member (traditional PKWARE flag 0x0001) must be rejected by preflight.",
        payload=b6_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="ENCRYPTED_MEMBER_TRADITIONAL",
        live_scan_target=None,
        expected_clamd_yes=None,
    )

    # B7: Encrypted OOXML (WinZip AES method 99 + 0x9901 extra)
    aes_extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", 3, 0)
    b7_data = _build_raw_zip(
        [
            {
                "name": "[Content_Types].xml",
                "compressed": b"aes-ciphertext-bytes",
                "crc32": 0,
                "csize": 20,
                "usize": 20,
                "method": 99,
                "flags": 0x0001,
                "version_needed": 51,
                "lfh_extra": aes_extra,
                "cdh_extra": aes_extra,
            }
        ]
    )
    add_fixture(
        fid="B7_encrypted_ooxml_winzip_aes",
        part="PART_B",
        filename="B7_encrypted_ooxml_winzip_aes.xlsx",
        declared_kind="xlsx",
        description="Encrypted OOXML member (WinZip AES method 99 / 0x9901) must be rejected by preflight.",
        payload=b7_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="ENCRYPTED_MEMBER_AES",
        live_scan_target=None,
        expected_clamd_yes=None,
    )

    # B8: Malformed header mismatch (LFH method != CDH method)
    b8_data = _build_raw_zip(
        [
            {
                "name": "[Content_Types].xml",
                "compressed": content_types,
                "crc32": zlib.crc32(content_types) & 0xFFFFFFFF,
                "csize": len(content_types),
                "usize": len(content_types),
                "method": 0,
                "lfh_method": 8,
                "version_needed": 20,
            }
        ]
    )
    add_fixture(
        fid="B8_malformed_lfh_cdh_mismatch",
        part="PART_B",
        filename="B8_malformed_lfh_cdh_mismatch.docx",
        declared_kind="docx",
        description="Malformed OOXML with LFH/CDH compression method mismatch (parser differential evasion).",
        payload=b8_data,
        expected_preflight_action="REJECT",
        expected_preflight_code="MALFORMED_LFH_CDH_MISMATCH",
        live_scan_target=None,
        expected_clamd_yes=None,
    )

    # B9: Benign version_needed=45 DOCX with NO ZIP64 structures -> MUST ALLOW (not blind reject!)
    b9_data = _make_ooxml_zip(
        [
            ("[Content_Types].xml", content_types),
            ("word/document.xml", b"<w:document><w:body><w:p>Benign v45 DOCX</w:p></w:body></w:document>"),
        ],
        compression=zipfile.ZIP_DEFLATED,
        version_needed=45,
    )
    add_fixture(
        fid="B9_benign_version_needed_45_docx",
        part="PART_B",
        filename="B9_benign_version_needed_45_docx.docx",
        declared_kind="docx",
        description="Nuanced-policy control: valid DOCX with version_needed=45 and standard 32-bit structures (no ZIP64).",
        payload=b9_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code="BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES",
        live_scan_target="yes",
        expected_clamd_yes="CLEAN",
    )

    # B10: Valid DOCX control
    b10_data = _make_ooxml_zip(
        [
            ("[Content_Types].xml", content_types),
            ("word/document.xml", b"<w:document><w:body><w:p>DIP valid DOCX control</w:p></w:body></w:document>"),
        ]
    )
    add_fixture(
        fid="B10_valid_docx_control",
        part="PART_B",
        filename="B10_valid_docx_control.docx",
        declared_kind="docx",
        description="Clean valid DOCX control.",
        payload=b10_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="CLEAN",
    )

    # B11: Valid XLSX control
    b11_data = _make_ooxml_zip(
        [
            ("[Content_Types].xml", content_types),
            ("xl/workbook.xml", b"<workbook><sheets><sheet name='Sheet1'/></sheets></workbook>"),
        ]
    )
    add_fixture(
        fid="B11_valid_xlsx_control",
        part="PART_B",
        filename="B11_valid_xlsx_control.xlsx",
        declared_kind="xlsx",
        description="Clean valid XLSX control.",
        payload=b11_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="CLEAN",
    )

    # B12: Valid PPTX control
    b12_data = _make_ooxml_zip(
        [
            ("[Content_Types].xml", content_types),
            ("ppt/presentation.xml", b"<p:presentation><p:sldIdLst/></p:presentation>"),
        ]
    )
    add_fixture(
        fid="B12_valid_pptx_control",
        part="PART_B",
        filename="B12_valid_pptx_control.pptx",
        declared_kind="pptx",
        description="Clean valid PPTX control.",
        payload=b12_data,
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        live_scan_target="yes",
        expected_clamd_yes="CLEAN",
    )

    # B13: Valid clean PDF control
    b13_data = _build_minimal_pdf(b"DIP Phase 0B valid PDF control")
    add_fixture(
        fid="B13_valid_pdf_control",
        part="PART_B",
        filename="B13_valid_pdf_control.pdf",
        declared_kind="pdf",
        description="Clean valid PDF control (passes OOXML preflight with explicit PDF residual-risk warning).",
        payload=b13_data,
        expected_preflight_action="ALLOW_WITH_RESIDUAL_RISK_WARNING",
        expected_preflight_code="OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64",
        live_scan_target="yes",
        expected_clamd_yes="CLEAN",
    )

    # B14: Encrypted PDF control (unlock-pdf compatibility check)
    b14_data = _build_minimal_pdf(b"DIP Phase 0B unlock-pdf encrypted PDF control", encrypted=True)
    add_fixture(
        fid="B14_encrypted_pdf_unlock_pdf_control",
        part="PART_B",
        filename="B14_encrypted_pdf_unlock_pdf_control.pdf",
        declared_kind="pdf",
        description="Password-protected PDF control confirming AlertEncrypted=no and OOXML preflight preserve unlock-pdf.",
        payload=b14_data,
        expected_preflight_action="ALLOW_WITH_RESIDUAL_RISK_WARNING",
        expected_preflight_code="OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64",
        live_scan_target="yes",
        expected_clamd_yes="CLEAN",
    )

    # ------------------------------------------------------------------
    # RESIDUAL RISK PROBE: PDF-embedded ZIP64 (upstream ClamAV #1888)
    # ------------------------------------------------------------------
    r1_data = _build_minimal_pdf(b"DIP Phase 0B PDF-embedded ZIP64 residual-risk probe", extra_stream=b1_data)
    add_fixture(
        fid="R1_pdf_embedded_zip64_residual_risk",
        part="RESIDUAL_RISK",
        filename="R1_pdf_embedded_zip64_residual_risk.pdf",
        declared_kind="pdf",
        description=(
            "Explicit residual-risk probe (upstream ClamAV #1888): PDF containing embedded ZIP64 EICAR. "
            "Demonstrates that OOXML-only preflight does NOT solve PDF-embedded ZIP64."
        ),
        payload=r1_data,
        expected_preflight_action="ALLOW_WITH_RESIDUAL_RISK_WARNING",
        expected_preflight_code="OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64",
        live_scan_target="yes",
        expected_clamd_yes="RECORD_ONLY",
    )

    manifest = {
        "schema_version": "phase0b-fixtures-v1",
        "experiment_max_file_size": max_file_size,
        "fixture_count": len(specs),
        "fixtures": [asdict(s) for s in specs],
    }
    (out_dir / "fixtures-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return specs


# ============================================================================
# Fail-Closed Raw clamd Wire Client & Parser
# ============================================================================

def classify_raw_clamd_reply(raw: bytes) -> dict[str, Any]:
    """
    Strictly classify a raw clamd TCP reply.
    ONLY a single, anchored, NUL-terminated stanza yields CLEAN / FOUND / ERROR.
    Anything else is MALFORMED_OR_INCOMPLETE and fails closed.
    """
    if not raw:
        return {"kind": "MALFORMED_OR_INCOMPLETE", "signature": None, "raw_repr": repr(raw)}
    if raw.count(b"\x00") != 1 or not raw.endswith(b"\x00"):
        return {"kind": "MALFORMED_OR_INCOMPLETE", "signature": None, "raw_repr": repr(raw)}

    if RE_OK.match(raw):
        return {"kind": "CLEAN", "signature": None, "raw_repr": repr(raw)}

    m_found = RE_FOUND.match(raw)
    if m_found:
        sig = m_found.group(1).decode("utf-8", errors="replace")
        return {"kind": "FOUND", "signature": sig, "raw_repr": repr(raw)}

    m_err = RE_ERROR.match(raw)
    if m_err:
        err = m_err.group(1).decode("utf-8", errors="replace")
        return {"kind": "ERROR", "signature": err, "raw_repr": repr(raw)}

    return {"kind": "MALFORMED_OR_INCOMPLETE", "signature": None, "raw_repr": repr(raw)}


def evaluate_clamd_expectation(expected: str, parsed: dict[str, Any]) -> bool:
    kind = parsed["kind"]
    sig = parsed.get("signature") or ""
    if expected == "RECORD_ONLY":
        return kind in ("CLEAN", "FOUND", "ERROR")
    if expected == "CLEAN":
        return kind == "CLEAN"
    if expected == "EICAR_FOUND":
        return kind == "FOUND" and "eicar" in sig.lower()
    if expected == "MAXFILESIZE_FOUND":
        return kind == "FOUND" and sig == "Heuristics.Limits.Exceeded.MaxFileSize"
    return False


def clamd_instream_scan(host: str, port: int, payload: bytes, timeout_sec: float = 30.0) -> dict[str, Any]:
    t0 = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout_sec) as sock:
        sock.settimeout(timeout_sec)
        sock.sendall(b"zINSTREAM\x00")
        chunk_size = 65536
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            sock.sendall(struct.pack("!I", len(chunk)))
            sock.sendall(chunk)
        sock.sendall(struct.pack("!I", 0))
        chunks: list[bytes] = []
        while True:
            buf = sock.recv(4096)
            if not buf:
                break
            chunks.append(buf)
            if b"\x00" in buf:
                break
    elapsed_ms = round((time.monotonic() - t0) * 1000.0, 2)
    raw = b"".join(chunks)
    parsed = classify_raw_clamd_reply(raw)
    parsed["elapsed_ms"] = elapsed_ms
    return parsed


# ============================================================================
# Preflight Cross-Runner (invokes isolated TypeScript prototype via Node)
# ============================================================================

def run_preflight_suite(manifest_path: Path, preflight_script: Path, out_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixtures_dir = manifest_path.parent
    results: list[dict[str, Any]] = []
    passed = 0
    failed = 0

    for fx in manifest["fixtures"]:
        fx_path = fixtures_dir / fx["filename"]
        cmd = [
            "node",
            str(preflight_script),
            "--inspect",
            str(fx_path),
            "--kind",
            fx["declared_kind"],
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            failed += 1
            results.append(
                {
                    "id": fx["id"],
                    "part": fx["part"],
                    "status": "FAIL",
                    "error": f"node exited {proc.returncode}: {proc.stderr.strip()}",
                }
            )
            continue

        report = json.loads(proc.stdout)
        actual_action = report["action"]
        all_codes = [*report["rejectCodes"], *report["warningCodes"], *report["infoCodes"]]
        action_ok = actual_action == fx["expected_preflight_action"]
        code_ok = fx["expected_preflight_code"] is None or fx["expected_preflight_code"] in all_codes
        no_decomp_ok = report.get("decompressionPerformed") is False
        ok = action_ok and code_ok and no_decomp_ok
        if ok:
            passed += 1
        else:
            failed += 1

        results.append(
            {
                "id": fx["id"],
                "part": fx["part"],
                "filename": fx["filename"],
                "status": "PASS" if ok else "FAIL",
                "expected_action": fx["expected_preflight_action"],
                "actual_action": actual_action,
                "expected_code": fx["expected_preflight_code"],
                "reject_codes": report["rejectCodes"],
                "warning_codes": report["warningCodes"],
                "info_codes": report["infoCodes"],
                "decompression_performed": report.get("decompressionPerformed"),
            }
        )

    payload = {
        "schema_version": "phase0b-preflight-results-v1",
        "preflight_script": str(preflight_script),
        "passed": passed,
        "failed": failed,
        "total": len(results),
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def run_live_scans(
    manifest_path: Path,
    *,
    host_yes: str,
    port_yes: int,
    host_no: str,
    port_no: int,
    out_path: Path,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixtures_dir = manifest_path.parent
    results: list[dict[str, Any]] = []
    passed = 0
    failed = 0

    for fx in manifest["fixtures"]:
        target = fx["live_scan_target"]
        if not target:
            continue
        data = (fixtures_dir / fx["filename"]).read_bytes()
        entry: dict[str, Any] = {
            "id": fx["id"],
            "part": fx["part"],
            "filename": fx["filename"],
            "sha256": fx["sha256"],
        }
        case_ok = True

        if target in ("yes", "both"):
            res_yes = clamd_instream_scan(host_yes, port_yes, data)
            exp_yes = fx["expected_clamd_yes"]
            ok_yes = evaluate_clamd_expectation(exp_yes, res_yes)
            entry["alert_exceeds_max_yes"] = {
                "expected": exp_yes,
                "observed": res_yes,
                "pass": ok_yes,
            }
            case_ok = case_ok and ok_yes

        if target in ("no", "both") and fx.get("expected_clamd_no"):
            res_no = clamd_instream_scan(host_no, port_no, data)
            exp_no = fx["expected_clamd_no"]
            ok_no = evaluate_clamd_expectation(exp_no, res_no)
            entry["alert_exceeds_max_no"] = {
                "expected": exp_no,
                "observed": res_no,
                "pass": ok_no,
            }
            case_ok = case_ok and ok_no

        entry["status"] = "PASS" if case_ok else "FAIL"
        if case_ok:
            passed += 1
        else:
            failed += 1
        results.append(entry)

    payload = {
        "schema_version": "phase0b-live-scan-results-v1",
        "passed": passed,
        "failed": failed,
        "total": len(results),
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def assemble_report(
    *,
    manifest_path: Path,
    preflight_results_path: Path,
    live_results_path: Path,
    provenance_path: Path,
    out_md_path: Path,
    out_json_path: Path,
) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    preflight = json.loads(preflight_results_path.read_text(encoding="utf-8"))
    live = json.loads(live_results_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))

    overall_pass = preflight["failed"] == 0 and live["failed"] == 0

    combined = {
        "schema_version": "phase0b-evidence-report-v1",
        "overall_experiment_verdict": "PASS" if overall_pass else "FAIL",
        "gates": {
            "security_gate": "OPEN_PENDING_HUMAN_REVIEW_AND_PROD_INTEGRATION",
            "licensing_gate": "OPEN_PENDING_LEGAL_SBOM_AND_GPLV2_SIGNOFF",
            "stage_7_status": "NOT_ACCEPTED",
            "production_change_made": False,
            "ghcr_published": False,
        },
        "provenance": provenance,
        "fixtures_count": manifest["fixture_count"],
        "preflight": preflight,
        "live_clamd": live,
    }
    out_json_path.write_text(json.dumps(combined, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# DIP Phase 0B Isolated Security Remediation — Evidence Summary",
        "",
        f"- **Overall Experiment Verdict**: `{'PASS' if overall_pass else 'FAIL'}`",
        "- **Security Gate**: `OPEN` (human review + approved CR + production integration still required)",
        "- **Licensing Gate**: `OPEN` (GPLv2 Corresponding Source, SBOM, and legal review still required)",
        "- **Stage 7**: `NOT ACCEPTED`",
        "- **GHCR Publishing**: `DISABLED (not published)`",
        "",
        "## Provenance",
        "",
        "```json",
        json.dumps(provenance, indent=2),
        "```",
        "",
        f"## Part B — Preflight Prototype Results (`{preflight['passed']}/{preflight['total']}` PASS)",
        "",
        "| ID | Part | Status | Expected | Actual | Codes |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in preflight["results"]:
        codes = ", ".join([*r.get("reject_codes", []), *r.get("warning_codes", []), *r.get("info_codes", [])]) or "-"
        lines.append(
            f"| `{r['id']}` | `{r['part']}` | **{r['status']}** | `{r.get('expected_action')}` | `{r.get('actual_action')}` | `{codes}` |"
        )

    lines.extend(
        [
            "",
            f"## Part A & Controls — Live Patched clamd Results (`{live['passed']}/{live['total']}` PASS)",
            "",
            "| ID | Part | Status | AlertExceedsMax=yes | AlertExceedsMax=no |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for r in live["results"]:
        yes_col = "-"
        if "alert_exceeds_max_yes" in r:
            y = r["alert_exceeds_max_yes"]
            yes_col = f"`{y['observed']['kind']}` (`{y['observed'].get('signature')}`) vs `{y['expected']}`"
        no_col = "-"
        if "alert_exceeds_max_no" in r:
            n = r["alert_exceeds_max_no"]
            no_col = f"`{n['observed']['kind']}` (`{n['observed'].get('signature')}`) vs `{n['expected']}`"
        lines.append(f"| `{r['id']}` | `{r['part']}` | **{r['status']}** | {yes_col} | {no_col} |")

    lines.extend(
        [
            "",
            "## Explicit Residual Risk",
            "",
            "- `R1_pdf_embedded_zip64_residual_risk`: OOXML-only ZIP preflight does **NOT** inspect ZIP64 archives embedded inside PDF object streams (upstream ClamAV issue `#1888`).",
            "- Unreviewed upstream ZIP64 PR `#1845` is **intentionally excluded** from the Part A ClamAV build.",
        ]
    )

    out_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if overall_pass else 1


# ============================================================================
# Offline Self-Test (no Docker, no clamd, no network required)
# ============================================================================

def run_self_test(preflight_script: Path) -> int:
    # 1. Wire parser unit checks (fail-closed)
    assert classify_raw_clamd_reply(b"stream: OK\x00")["kind"] == "CLEAN"
    assert classify_raw_clamd_reply(b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00") == {
        "kind": "FOUND",
        "signature": "Heuristics.Limits.Exceeded.MaxFileSize",
        "raw_repr": repr(b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00"),
    }
    assert classify_raw_clamd_reply(b"stream: OK")["kind"] == "MALFORMED_OR_INCOMPLETE"
    assert classify_raw_clamd_reply(b"stream: OK\x00trailing")["kind"] == "MALFORMED_OR_INCOMPLETE"
    assert classify_raw_clamd_reply(b"stream: OK\x00stream: OK\x00")["kind"] == "MALFORMED_OR_INCOMPLETE"
    assert evaluate_clamd_expectation(
        "MAXFILESIZE_FOUND",
        classify_raw_clamd_reply(b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00"),
    )
    assert not evaluate_clamd_expectation(
        "MAXFILESIZE_FOUND",
        classify_raw_clamd_reply(b"stream: OK\x00"),
    )
    assert not evaluate_clamd_expectation(
        "MAXFILESIZE_FOUND",
        classify_raw_clamd_reply(b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\x00"),
    )

    # 2. Fixture generation & binary integrity verification
    with tempfile.TemporaryDirectory(prefix="dip-phase0b-selftest-") as tmp:
        tmp_dir = Path(tmp)
        specs = generate_fixtures(tmp_dir, max_file_size=DEFAULT_EXPERIMENT_MAX_FILE_SIZE)
        assert len(specs) == 25, f"Expected 25 fixtures, got {len(specs)}"

        # Verify A2 exact boundary inflates to exactly 16384B and A3 to 16385B
        with zipfile.ZipFile(tmp_dir / "A2_exact_boundary_zip32_eq_maxfilesize.zip") as zf:
            assert len(zf.read("exact_boundary.bin")) == 16384
        with zipfile.ZipFile(tmp_dir / "A3_over_boundary_plus1_zip32_deflate.zip") as zf:
            assert len(zf.read("over_by_one.bin")) == 16385

        # Verify A7 forged-size header declares usize=100 while raw DEFLATE inflates to 65536B!
        a7_raw = (tmp_dir / "A7_forged_size_header_zip32_maxfilesize.zip").read_bytes()
        lfh_csize, lfh_usize, lfh_nlen, lfh_elen = struct.unpack_from("<IIHH", a7_raw, 18)
        assert lfh_usize == 100, f"Expected forged LFH usize=100, got {lfh_usize}"
        comp_start = 30 + lfh_nlen + lfh_elen
        inflated = zlib.decompress(a7_raw[comp_start : comp_start + lfh_csize], -zlib.MAX_WBITS)
        assert len(inflated) == 65536, f"Expected inflated size 65536, got {len(inflated)}"

        # 3. Cross-validate every generated fixture against the TypeScript preflight prototype
        pf_out = tmp_dir / "preflight-results.json"
        pf_summary = run_preflight_suite(tmp_dir / "fixtures-manifest.json", preflight_script, pf_out)
        print(
            json.dumps(
                {
                    "suite": "phase0b-evidence-python-self-test",
                    "wire_parser_checks": "PASS",
                    "fixtures_generated": len(specs),
                    "forged_size_verified": {"declared_usize": lfh_usize, "inflated_bytes": len(inflated)},
                    "preflight_cross_check": {
                        "passed": pf_summary["passed"],
                        "failed": pf_summary["failed"],
                        "total": pf_summary["total"],
                    },
                },
                indent=2,
            )
        )
        if pf_summary["failed"] != 0:
            for r in pf_summary["results"]:
                if r["status"] != "PASS":
                    print(f"FAILED: {json.dumps(r)}", file=sys.stderr)
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="DIP Phase 0B Isolated Remediation Evidence Tool")
    sub = parser.add_subparsers(dest="cmd")

    p_gen = sub.add_parser("generate", help="Generate deterministic Phase 0B fixtures")
    p_gen.add_argument("--out-dir", required=True, type=Path)
    p_gen.add_argument("--max-file-size", type=int, default=DEFAULT_EXPERIMENT_MAX_FILE_SIZE)

    p_pf = sub.add_parser("run-preflight", help="Run isolated TS preflight prototype against fixtures")
    p_pf.add_argument("--manifest", required=True, type=Path)
    p_pf.add_argument("--preflight-script", required=True, type=Path)
    p_pf.add_argument("--out", required=True, type=Path)

    p_live = sub.add_parser("scan-live", help="Run raw INSTREAM scans against live patched clamd")
    p_live.add_argument("--manifest", required=True, type=Path)
    p_live.add_argument("--host", default="127.0.0.1")
    p_live.add_argument("--host-yes", default=None)
    p_live.add_argument("--host-no", default=None)
    p_live.add_argument("--port-yes", required=True, type=int)
    p_live.add_argument("--port-no", required=True, type=int)
    p_live.add_argument("--out", required=True, type=Path)

    p_rep = sub.add_parser("assemble-report", help="Assemble fail-closed Phase 0B Markdown + JSON report")
    p_rep.add_argument("--manifest", required=True, type=Path)
    p_rep.add_argument("--preflight-results", required=True, type=Path)
    p_rep.add_argument("--live-results", required=True, type=Path)
    p_rep.add_argument("--provenance", required=True, type=Path)
    p_rep.add_argument("--out-md", required=True, type=Path)
    p_rep.add_argument("--out-json", required=True, type=Path)

    p_st = sub.add_parser("self-test", help="Run offline self-test + cross-validation with TS preflight")
    p_st.add_argument(
        "--preflight-script",
        type=Path,
        default=Path("docs/operations/experimental/clamav-phase0b-zip-preflight.mts"),
    )

    parser.add_argument("--self-test", action="store_true", help="Alias for subcommand self-test")

    args = parser.parse_args()

    if args.self_test or args.cmd == "self-test":
        pf_script = getattr(args, "preflight_script", Path("docs/operations/experimental/clamav-phase0b-zip-preflight.mts"))
        return run_self_test(pf_script)

    if args.cmd == "generate":
        specs = generate_fixtures(args.out_dir, max_file_size=args.max_file_size)
        print(f"Generated {len(specs)} Phase 0B fixtures in {args.out_dir}")
        return 0

    if args.cmd == "run-preflight":
        summary = run_preflight_suite(args.manifest, args.preflight_script, args.out)
        print(f"Preflight suite: {summary['passed']}/{summary['total']} PASS ({summary['failed']} FAIL)")
        return 0 if summary["failed"] == 0 else 1

    if args.cmd == "scan-live":
        summary = run_live_scans(
            args.manifest,
            host_yes=args.host_yes or args.host,
            port_yes=args.port_yes,
            host_no=args.host_no or args.host,
            port_no=args.port_no,
            out_path=args.out,
        )
        print(f"Live clamd suite: {summary['passed']}/{summary['total']} PASS ({summary['failed']} FAIL)")
        return 0 if summary["failed"] == 0 else 1

    if args.cmd == "assemble-report":
        return assemble_report(
            manifest_path=args.manifest,
            preflight_results_path=args.preflight_results,
            live_results_path=args.live_results,
            provenance_path=args.provenance,
            out_md_path=args.out_md,
            out_json_path=args.out_json,
        )

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
