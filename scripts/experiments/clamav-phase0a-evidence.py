#!/usr/bin/env python3
"""Phase 0A isolated ClamAV 1.5.4 evidence generator, scanner probe, and report assembler.

Experimental verification harness only. Does not modify production code,
Dockerfiles, scanner configurations, or active services.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import resource
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Strict resource and safety bounds (never generate/decompress 420 MiB bombs)
# ---------------------------------------------------------------------------
MAX_FIXTURE_ARCHIVE_BYTES = 16 * 1024       # 16 KiB max on-disk fixture size
MAX_FIXTURE_UNCOMPRESSED_BYTES = 64 * 1024  # 64 KiB max decompressed payload
MAX_ZIP_MEMBERS = 1                         # Generated ZIP fixtures have 1 member
MAX_INSPECT_ZIP_ENTRIES = 16                # Hard cap for binary ZIP parser
MAX_SCAN_INPUT_BYTES = 64 * 1024            # 64 KiB max bytes sent over zINSTREAM
MAX_CLAMD_RESPONSE_BYTES = 4096             # 4 KiB max clamd reply buffer
DEFAULT_SOCKET_TIMEOUT_SECONDS = 30.0
MAX_SOCKET_TIMEOUT_SECONDS = 60.0
REPLY_SETTLE_SECONDS = 0.05                 # Drain trailing bytes after NUL
PROCESS_FSIZE_LIMIT_BYTES = 16 * 1024 * 1024  # 16 MiB max file write ceiling
PROCESS_CPU_LIMIT_SECONDS = 120

# Reduced isolated test limits for Experiment E (small ZIP32 MaxFileSize)
REDUCED_MAX_FILE_SIZE_BYTES = 16 * 1024     # 16K
REDUCED_MAX_SCAN_SIZE_BYTES = 512 * 1024    # 512K
REDUCED_STREAM_MAX_LENGTH_BYTES = 1024 * 1024  # 1M
SMALL_MAXFILESIZE_MEMBER_BYTES = 64 * 1024  # 64 KiB > 16K MaxFileSize, < 512K MaxScanSize

# Standard non-sensitive fixtures
CLEAN_PAYLOAD = b"DIP Phase 0A clean control fixture\n"
EICAR_PAYLOAD = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_EXPECTED_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
ZIP_FIXED_TIME = (2026, 1, 1, 0, 0, 0)

# ZIP binary signatures (PKWARE APPNOTE 6.3.x)
SIG_LFH = 0x04034B50
SIG_CDH = 0x02014B50
SIG_EOCD = 0x06054B50
SIG_ZIP64_EOCD = 0x06064B50
SIG_ZIP64_LOCATOR = 0x07064B50
SIG_DATA_DESCRIPTOR = 0x08074B50
EXTRA_ID_ZIP64 = 0x0001
SENTINEL_U32 = 0xFFFFFFFF
SENTINEL_U16 = 0xFFFF
ZIP64_MIN_VERSION = 45

# Required verdict taxonomy (Section 7)
VERDICT_CLEAN = "CLEAN"
VERDICT_INFECTED = "INFECTED"
VERDICT_LIMIT_ALERT = "LIMIT ALERT"
VERDICT_SCAN_ERROR = "SCAN ERROR"
VERDICT_TIMEOUT = "TIMEOUT"
VERDICT_UNAVAILABLE = "UNAVAILABLE"
VERDICT_MALFORMED = "MALFORMED RESPONSE"

ALL_VERDICTS = frozenset({
    VERDICT_CLEAN,
    VERDICT_INFECTED,
    VERDICT_LIMIT_ALERT,
    VERDICT_SCAN_ERROR,
    VERDICT_TIMEOUT,
    VERDICT_UNAVAILABLE,
    VERDICT_MALFORMED,
})

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_NOT_VERIFIED = "NOT VERIFIED"

EXPECTED_MAX_FILE_SIZE_ALERT = "Heuristics.Limits.Exceeded.MaxFileSize"
INSTREAM_LIMIT_REFUSAL = "INSTREAM size limit exceeded. ERROR"

LIMIT_ALERT_PREFIX = "Heuristics.Limits.Exceeded."
STANZA_RE = re.compile(r"^(?:stream|instream):[ \t]*(\S(?:[^\r\n]*\S)?)$", re.IGNORECASE)
FOUND_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.+-]*) FOUND$")
ERROR_RE = re.compile(r"^\S.*[ \t]ERROR$")
ZVERSION_RE = re.compile(r"^ClamAV\s+([^/\s]+)/(\d+)/(.+)$")
EICAR_SIG_RE = re.compile(r"eicar", re.IGNORECASE)

EFFECTIVE_LIMIT_KEYS = (
    "StreamMaxLength",
    "MaxFileSize",
    "MaxScanSize",
    "MaxScanTime",
    "ReadTimeout",
    "MaxThreads",
    "MaxRecursion",
    "MaxFiles",
    "AlertExceedsMax",
    "AlertEncrypted",
    "ConcurrentDatabaseReload",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def peak_rss_kb() -> int:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # Linux reports ru_maxrss in KiB; macOS reports bytes.
    if sys.platform == "darwin":
        return int(usage.ru_maxrss // 1024)
    return int(usage.ru_maxrss)


def apply_process_limits() -> dict[str, Any]:
    """Enforce bounded file write and CPU limits for the Python process."""
    applied: dict[str, Any] = {}
    for name, limit_const, target in (
        ("RLIMIT_FSIZE", getattr(resource, "RLIMIT_FSIZE", None), PROCESS_FSIZE_LIMIT_BYTES),
        ("RLIMIT_CPU", getattr(resource, "RLIMIT_CPU", None), PROCESS_CPU_LIMIT_SECONDS),
    ):
        if limit_const is None:
            applied[name] = "unsupported"
            continue
        try:
            soft, hard = resource.getrlimit(limit_const)
            new_soft = target if soft == resource.RLIM_INFINITY or soft > target else soft
            if hard != resource.RLIM_INFINITY and new_soft > hard:
                new_soft = hard
            resource.setrlimit(limit_const, (new_soft, hard))
            applied[name] = {"soft": new_soft, "hard": hard}
        except (OSError, ValueError) as exc:
            applied[name] = f"not_applied:{type(exc).__name__}"
    return applied


# ---------------------------------------------------------------------------
# Binary ZIP32 / ZIP64 structure inspection (PKWARE APPNOTE.TXT)
# ---------------------------------------------------------------------------
def _parse_extra_fields(extra: bytes, *, compressed_size_32: int, uncompressed_size_32: int, local_header_offset_32: int | None) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    pos = 0
    total = len(extra)
    while pos < total:
        if pos + 4 > total:
            fields.append({
                "malformed_trailing_bytes": total - pos,
                "raw_hex": extra[pos:].hex(),
            })
            break
        header_id, data_size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + data_size > total:
            fields.append({
                "header_id": header_id,
                "header_id_hex": f"0x{header_id:04x}",
                "declared_data_size": data_size,
                "truncated_available_bytes": total - pos,
                "raw_hex": extra[pos:].hex(),
            })
            break
        payload = extra[pos:pos + data_size]
        pos += data_size
        item: dict[str, Any] = {
            "header_id": header_id,
            "header_id_hex": f"0x{header_id:04x}",
            "data_size": data_size,
            "raw_hex": payload.hex(),
        }
        if header_id == EXTRA_ID_ZIP64:
            item["name"] = "ZIP64_EXTENDED_INFORMATION"
            decoded: dict[str, Any] = {}
            q_offset = 0
            # Per APPNOTE 4.5.3, LFH includes both 64-bit sizes when ZIP64 extra
            # is present; CDH includes fields corresponding to 0xFFFFFFFF sentinels.
            is_lfh = local_header_offset_32 is None
            if is_lfh:
                if q_offset + 8 <= len(payload):
                    decoded["uncompressed_size_64"] = struct.unpack_from("<Q", payload, q_offset)[0]
                    q_offset += 8
                if q_offset + 8 <= len(payload):
                    decoded["compressed_size_64"] = struct.unpack_from("<Q", payload, q_offset)[0]
                    q_offset += 8
            else:
                if uncompressed_size_32 == SENTINEL_U32 and q_offset + 8 <= len(payload):
                    decoded["uncompressed_size_64"] = struct.unpack_from("<Q", payload, q_offset)[0]
                    q_offset += 8
                if compressed_size_32 == SENTINEL_U32 and q_offset + 8 <= len(payload):
                    decoded["compressed_size_64"] = struct.unpack_from("<Q", payload, q_offset)[0]
                    q_offset += 8
                if local_header_offset_32 == SENTINEL_U32 and q_offset + 8 <= len(payload):
                    decoded["local_header_offset_64"] = struct.unpack_from("<Q", payload, q_offset)[0]
                    q_offset += 8
                if q_offset == 0 and len(payload) >= 16:
                    # Non-sentinel extra block still holding 64-bit sizes
                    decoded["raw_u64_values"] = list(struct.unpack_from("<" + "Q" * (len(payload) // 8), payload, 0))
            item["decoded"] = decoded
        fields.append(item)
    return fields


def _find_eocd_offset(data: bytes) -> int:
    min_eocd_size = 22
    if len(data) < min_eocd_size:
        raise ValueError("ZIP data shorter than 22-byte EOCD minimum")
    search_start = max(0, len(data) - min_eocd_size - 65535)
    sig_bytes = struct.pack("<I", SIG_EOCD)
    pos = data.rfind(sig_bytes, search_start)
    while pos != -1:
        comment_len = struct.unpack_from("<H", data, pos + 20)[0]
        if pos + 22 + comment_len == len(data):
            return pos
        pos = data.rfind(sig_bytes, search_start, pos)
    raise ValueError("ZIP End of Central Directory (PK\\x05\\x06) not found")


def inspect_zip_binary(data: bytes) -> dict[str, Any]:
    """Parse raw ZIP EOCD, ZIP64 EOCD/Locator, Central Directory, and Local File Headers."""
    if len(data) > MAX_FIXTURE_ARCHIVE_BYTES:
        raise ValueError(f"Refusing to inspect ZIP larger than {MAX_FIXTURE_ARCHIVE_BYTES} bytes: {len(data)}")

    eocd_offset = _find_eocd_offset(data)
    (
        eocd_sig,
        disk_num,
        cd_start_disk,
        entries_on_disk,
        total_entries,
        cd_size,
        cd_offset,
        comment_len,
    ) = struct.unpack_from("<IHHHHIIH", data, eocd_offset)
    if eocd_sig != SIG_EOCD:
        raise ValueError(f"Unexpected EOCD signature: 0x{eocd_sig:08x}")

    eocd_info: dict[str, Any] = {
        "offset": eocd_offset,
        "signature_hex": f"0x{eocd_sig:08x}",
        "disk_number": disk_num,
        "cd_start_disk": cd_start_disk,
        "entries_on_disk": entries_on_disk,
        "total_entries": total_entries,
        "cd_size": cd_size,
        "cd_offset": cd_offset,
        "comment_length": comment_len,
        "has_zip64_sentinels": (
            entries_on_disk == SENTINEL_U16
            or total_entries == SENTINEL_U16
            or cd_size == SENTINEL_U32
            or cd_offset == SENTINEL_U32
        ),
    }

    # Inspect optional ZIP64 EOCD Locator (20 bytes immediately preceding EOCD)
    zip64_locator: dict[str, Any] | None = None
    zip64_eocd: dict[str, Any] | None = None
    effective_cd_offset = cd_offset
    effective_total_entries = total_entries
    if eocd_offset >= 20:
        loc_offset = eocd_offset - 20
        loc_sig, z64_disk, z64_eocd_rel_offset, total_disks = struct.unpack_from("<IIQI", data, loc_offset)
        if loc_sig == SIG_ZIP64_LOCATOR:
            zip64_locator = {
                "offset": loc_offset,
                "signature_hex": f"0x{loc_sig:08x}",
                "zip64_eocd_disk": z64_disk,
                "zip64_eocd_offset": z64_eocd_rel_offset,
                "total_disks": total_disks,
            }
            if z64_eocd_rel_offset + 56 <= len(data):
                (
                    z64_sig,
                    z64_rec_size,
                    z64_vmade,
                    z64_vneed,
                    z64_disk_num,
                    z64_cd_disk,
                    z64_entries_disk,
                    z64_entries_total,
                    z64_cd_size,
                    z64_cd_offset,
                ) = struct.unpack_from("<IQHHIIQQQQ", data, z64_eocd_rel_offset)
                if z64_sig == SIG_ZIP64_EOCD:
                    zip64_eocd = {
                        "offset": z64_eocd_rel_offset,
                        "signature_hex": f"0x{z64_sig:08x}",
                        "record_size": z64_rec_size,
                        "version_made_by": z64_vmade,
                        "version_needed": z64_vneed,
                        "disk_number": z64_disk_num,
                        "cd_start_disk": z64_cd_disk,
                        "entries_on_disk": z64_entries_disk,
                        "total_entries": z64_entries_total,
                        "cd_size": z64_cd_size,
                        "cd_offset": z64_cd_offset,
                    }
                    if cd_offset == SENTINEL_U32:
                        effective_cd_offset = z64_cd_offset
                    if total_entries == SENTINEL_U16:
                        effective_total_entries = z64_entries_total

    if effective_total_entries > MAX_INSPECT_ZIP_ENTRIES:
        raise ValueError(f"ZIP entry count exceeds inspection cap ({MAX_INSPECT_ZIP_ENTRIES}): {effective_total_entries}")

    central_directory_headers: list[dict[str, Any]] = []
    local_file_headers: list[dict[str, Any]] = []

    cursor = effective_cd_offset
    for index in range(effective_total_entries):
        if cursor + 46 > len(data):
            raise ValueError(f"Truncated Central Directory Header at entry {index}, offset {cursor}")
        (
            csig,
            vmade,
            vneed,
            cflags,
            cmethod,
            cmtime,
            cmdate,
            ccrc,
            ccsize,
            cusize,
            cfnlen,
            cexlen,
            ccomlen,
            cdisk,
            ciattr,
            ceattr,
            clhoff,
        ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, cursor)
        if csig != SIG_CDH:
            raise ValueError(f"Invalid CDH signature at offset {cursor}: 0x{csig:08x}")
        var_end = cursor + 46 + cfnlen + cexlen + ccomlen
        if var_end > len(data):
            raise ValueError(f"CDH variable fields exceed archive bounds at entry {index}")
        cfname_bytes = data[cursor + 46:cursor + 46 + cfnlen]
        cextra_bytes = data[cursor + 46 + cfnlen:cursor + 46 + cfnlen + cexlen]
        cextra_fields = _parse_extra_fields(
            cextra_bytes,
            compressed_size_32=ccsize,
            uncompressed_size_32=cusize,
            local_header_offset_32=clhoff,
        )
        cdh_zip64_extras = [f for f in cextra_fields if f.get("header_id") == EXTRA_ID_ZIP64]
        cdh_zip64_sentinels = (
            ccsize == SENTINEL_U32
            or cusize == SENTINEL_U32
            or clhoff == SENTINEL_U32
        )

        # Resolve true LFH offset if sentinel used in CDH
        resolved_lfh_offset = clhoff
        if clhoff == SENTINEL_U32 and cdh_zip64_extras:
            decoded_off = cdh_zip64_extras[0].get("decoded", {}).get("local_header_offset_64")
            if isinstance(decoded_off, int):
                resolved_lfh_offset = decoded_off

        cdh_record: dict[str, Any] = {
            "index": index,
            "offset": cursor,
            "signature_hex": f"0x{csig:08x}",
            "version_made_by": vmade,
            "version_needed": vneed,
            "flags": cflags,
            "flags_hex": f"0x{cflags:04x}",
            "uses_data_descriptor": bool(cflags & 0x0008),
            "compression_method": cmethod,
            "crc32_hex": f"0x{ccrc:08x}",
            "compressed_size_field": ccsize,
            "compressed_size_field_hex": f"0x{ccsize:08x}",
            "uncompressed_size_field": cusize,
            "uncompressed_size_field_hex": f"0x{cusize:08x}",
            "local_header_offset_field": clhoff,
            "local_header_offset_field_hex": f"0x{clhoff:08x}",
            "filename": cfname_bytes.decode("utf-8", errors="replace"),
            "extra_length": cexlen,
            "comment_length": ccomlen,
            "disk_number_start": cdisk,
            "internal_attr": ciattr,
            "external_attr_hex": f"0x{ceattr:08x}",
            "extra_fields": cextra_fields,
            "has_zip64_extra_field": bool(cdh_zip64_extras),
            "has_zip64_size_or_offset_sentinels": cdh_zip64_sentinels,
            "version_is_zip64": vneed >= ZIP64_MIN_VERSION,
        }
        central_directory_headers.append(cdh_record)
        cursor = var_end

        # Parse matching Local File Header (LFH)
        if resolved_lfh_offset + 30 > len(data):
            raise ValueError(f"LFH offset out of bounds for entry {index}: {resolved_lfh_offset}")
        (
            lsig,
            lvneed,
            lflags,
            lmethod,
            lmtime,
            lmdate,
            lcrc,
            lcsize,
            lusize,
            lfnlen,
            lexlen,
        ) = struct.unpack_from("<IHHHHHIIIHH", data, resolved_lfh_offset)
        if lsig != SIG_LFH:
            raise ValueError(f"Invalid LFH signature at offset {resolved_lfh_offset}: 0x{lsig:08x}")
        l_var_end = resolved_lfh_offset + 30 + lfnlen + lexlen
        if l_var_end > len(data):
            raise ValueError(f"LFH variable fields exceed archive bounds at entry {index}")
        lfname_bytes = data[resolved_lfh_offset + 30:resolved_lfh_offset + 30 + lfnlen]
        lextra_bytes = data[resolved_lfh_offset + 30 + lfnlen:l_var_end]
        lextra_fields = _parse_extra_fields(
            lextra_bytes,
            compressed_size_32=lcsize,
            uncompressed_size_32=lusize,
            local_header_offset_32=None,
        )
        lfh_zip64_extras = [f for f in lextra_fields if f.get("header_id") == EXTRA_ID_ZIP64]
        lfh_zip64_sentinels = (lcsize == SENTINEL_U32 and lusize == SENTINEL_U32)

        # Optional data descriptor inspection if flag bit 3 is set
        dd_info: dict[str, Any] | None = None
        if lflags & 0x0008:
            # Resolve compressed data size from CDH (32-bit or 64-bit)
            true_csize = ccsize
            if ccsize == SENTINEL_U32 and cdh_zip64_extras:
                true_csize = cdh_zip64_extras[0].get("decoded", {}).get("compressed_size_64", 0)
            dd_pos = l_var_end + true_csize
            if dd_pos + 4 <= len(data) and struct.unpack_from("<I", data, dd_pos)[0] == SIG_DATA_DESCRIPTOR:
                if (lvneed >= ZIP64_MIN_VERSION or lfh_zip64_extras) and dd_pos + 24 <= len(data):
                    dsig, dcrc, dcsize64, dusize64 = struct.unpack_from("<IIQQ", data, dd_pos)
                    dd_info = {
                        "offset": dd_pos,
                        "signature_hex": f"0x{dsig:08x}",
                        "format": "ZIP64_24_BYTE",
                        "crc32_hex": f"0x{dcrc:08x}",
                        "compressed_size": dcsize64,
                        "uncompressed_size": dusize64,
                    }
                elif dd_pos + 16 <= len(data):
                    dsig, dcrc, dcsize32, dusize32 = struct.unpack_from("<IIII", data, dd_pos)
                    dd_info = {
                        "offset": dd_pos,
                        "signature_hex": f"0x{dsig:08x}",
                        "format": "ZIP32_16_BYTE",
                        "crc32_hex": f"0x{dcrc:08x}",
                        "compressed_size": dcsize32,
                        "uncompressed_size": dusize32,
                    }

        lfh_record: dict[str, Any] = {
            "index": index,
            "offset": resolved_lfh_offset,
            "signature_hex": f"0x{lsig:08x}",
            "version_needed": lvneed,
            "flags": lflags,
            "flags_hex": f"0x{lflags:04x}",
            "uses_data_descriptor": bool(lflags & 0x0008),
            "compression_method": lmethod,
            "crc32_hex": f"0x{lcrc:08x}",
            "compressed_size_field": lcsize,
            "compressed_size_field_hex": f"0x{lcsize:08x}",
            "uncompressed_size_field": lusize,
            "uncompressed_size_field_hex": f"0x{lusize:08x}",
            "filename": lfname_bytes.decode("utf-8", errors="replace"),
            "extra_length": lexlen,
            "extra_fields": lextra_fields,
            "has_zip64_extra_field": bool(lfh_zip64_extras),
            "has_zip64_size_sentinels": lfh_zip64_sentinels,
            "version_is_zip64": lvneed >= ZIP64_MIN_VERSION,
            "data_descriptor": dd_info,
        }
        local_file_headers.append(lfh_record)

    lfh_has_z64_extra = any(h["has_zip64_extra_field"] for h in local_file_headers)
    lfh_has_z64_sentinels = any(h["has_zip64_size_sentinels"] for h in local_file_headers)
    lfh_ver_z64 = any(h["version_is_zip64"] for h in local_file_headers)
    cdh_has_z64_extra = any(h["has_zip64_extra_field"] for h in central_directory_headers)
    cdh_has_z64_sentinels = any(h["has_zip64_size_or_offset_sentinels"] for h in central_directory_headers)
    cdh_ver_z64 = any(h["version_is_zip64"] for h in central_directory_headers)
    has_z64_eocd = zip64_eocd is not None
    has_z64_locator = zip64_locator is not None

    lfh_cdh_asymmetry = (
        lfh_has_z64_extra
        and lfh_has_z64_sentinels
        and not cdh_has_z64_extra
        and not cdh_has_z64_sentinels
    )

    if lfh_has_z64_extra and lfh_has_z64_sentinels and lfh_ver_z64:
        if cdh_has_z64_extra or has_z64_eocd or has_z64_locator:
            format_classification = "ZIP64_FULL"
        else:
            format_classification = "ZIP64_LFH_PYTHON312"
        has_zip64_characteristics = True
    elif has_z64_eocd or has_z64_locator or (cdh_has_z64_extra and cdh_has_z64_sentinels):
        format_classification = "ZIP64_FULL"
        has_zip64_characteristics = True
    elif lfh_has_z64_extra or cdh_has_z64_extra or lfh_ver_z64 or cdh_ver_z64:
        format_classification = "ZIP64_PARTIAL_NON_SENTINEL"
        has_zip64_characteristics = False
    else:
        format_classification = "ZIP32"
        has_zip64_characteristics = False

    return {
        "archive_size_bytes": len(data),
        "entry_count": len(central_directory_headers),
        "eocd": eocd_info,
        "zip64_eocd_locator": zip64_locator,
        "zip64_eocd_record": zip64_eocd,
        "local_file_headers": local_file_headers,
        "central_directory_headers": central_directory_headers,
        "summary": {
            "lfh_has_zip64_extra_field": lfh_has_z64_extra,
            "lfh_has_zip64_size_sentinels": lfh_has_z64_sentinels,
            "lfh_version_is_zip64": lfh_ver_z64,
            "cdh_has_zip64_extra_field": cdh_has_z64_extra,
            "cdh_has_zip64_size_or_offset_sentinels": cdh_has_z64_sentinels,
            "cdh_version_is_zip64": cdh_ver_z64,
            "has_zip64_eocd_record": has_z64_eocd,
            "has_zip64_eocd_locator": has_z64_locator,
            "lfh_cdh_zip64_asymmetry": lfh_cdh_asymmetry,
            "has_zip64_characteristics": has_zip64_characteristics,
            "format_classification": format_classification,
        },
    }


def assert_strict_zip32(inspection: dict[str, Any], *, expected_member_name: str, expected_uncompressed_size: int) -> None:
    summary = inspection["summary"]
    if summary["format_classification"] != "ZIP32":
        raise ValueError(f"Expected strict ZIP32, got {summary['format_classification']}")
    if summary["has_zip64_characteristics"]:
        raise ValueError("ZIP32 fixture unexpectedly has ZIP64 characteristics")
    if inspection["entry_count"] != 1:
        raise ValueError(f"Expected 1 ZIP32 member, got {inspection['entry_count']}")
    lfh = inspection["local_file_headers"][0]
    cdh = inspection["central_directory_headers"][0]
    if lfh["filename"] != expected_member_name or cdh["filename"] != expected_member_name:
        raise ValueError("ZIP32 member filename mismatch")
    if lfh["uncompressed_size_field"] != expected_uncompressed_size or cdh["uncompressed_size_field"] != expected_uncompressed_size:
        raise ValueError("ZIP32 uncompressed size mismatch in binary headers")
    if lfh["has_zip64_extra_field"] or cdh["has_zip64_extra_field"]:
        raise ValueError("ZIP32 fixture must not contain 0x0001 ZIP64 extra field")
    if lfh["has_zip64_size_sentinels"] or cdh["has_zip64_size_or_offset_sentinels"]:
        raise ValueError("ZIP32 fixture must not contain 0xFFFFFFFF ZIP64 sentinels")


def assert_python312_zip64(inspection: dict[str, Any], *, expected_member_name: str, expected_uncompressed_size: int) -> None:
    """Confirm actual binary ZIP64 LFH/CDH characteristics (not filename or metadata)."""
    summary = inspection["summary"]
    if not summary["has_zip64_characteristics"]:
        raise ValueError(
            f"Archive lacks confirmed binary ZIP64 characteristics "
            f"(classification={summary['format_classification']})"
        )
    if summary["format_classification"] not in ("ZIP64_LFH_PYTHON312", "ZIP64_FULL"):
        raise ValueError(f"Unexpected ZIP64 classification: {summary['format_classification']}")
    if inspection["entry_count"] != 1:
        raise ValueError(f"Expected 1 ZIP64 member, got {inspection['entry_count']}")
    lfh = inspection["local_file_headers"][0]
    cdh = inspection["central_directory_headers"][0]
    if lfh["filename"] != expected_member_name or cdh["filename"] != expected_member_name:
        raise ValueError("ZIP64 member filename mismatch")
    if not lfh["version_is_zip64"]:
        raise ValueError(f"LFH version_needed must be >= {ZIP64_MIN_VERSION}, got {lfh['version_needed']}")
    if not lfh["has_zip64_size_sentinels"]:
        raise ValueError(
            f"LFH must use 0xFFFFFFFF ZIP64 size sentinels, got "
            f"csize={lfh['compressed_size_field_hex']} usize={lfh['uncompressed_size_field_hex']}"
        )
    if not lfh["has_zip64_extra_field"]:
        raise ValueError("LFH missing 0x0001 ZIP64 Extended Information Extra Field")
    z64_extra = next(f for f in lfh["extra_fields"] if f.get("header_id") == EXTRA_ID_ZIP64)
    decoded = z64_extra.get("decoded", {})
    if decoded.get("uncompressed_size_64") != expected_uncompressed_size:
        raise ValueError(
            f"LFH ZIP64 extra uncompressed_size_64={decoded.get('uncompressed_size_64')} "
            f"!= expected {expected_uncompressed_size}"
        )
    if not isinstance(decoded.get("compressed_size_64"), int) or decoded["compressed_size_64"] <= 0:
        raise ValueError(f"LFH ZIP64 extra compressed_size_64 invalid: {decoded.get('compressed_size_64')}")


# ---------------------------------------------------------------------------
# Deterministic small fixture generation (Section 6)
# ---------------------------------------------------------------------------
def _zip_member(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    return info


def _verify_zip_roundtrip(path: Path, expected_member: str, expected_bytes: bytes) -> None:
    with zipfile.ZipFile(path, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise ValueError(f"Corrupt ZIP fixture {path.name}: bad CRC on member {bad}")
        names = zf.namelist()
        if names != [expected_member]:
            raise ValueError(f"Unexpected ZIP members in {path.name}: {names}")
        extracted = zf.read(expected_member)
        if len(extracted) > MAX_FIXTURE_UNCOMPRESSED_BYTES:
            raise ValueError(f"Extracted payload exceeds safety cap in {path.name}")
        if extracted != expected_bytes:
            raise ValueError(f"Round-trip extraction mismatch in {path.name}")


def generate_fixtures(output_dir: Path, *, require_python_312: bool = True) -> dict[str, Any]:
    if require_python_312 and sys.version_info < (3, 12):
        raise RuntimeError(
            f"Python 3.12+ is required for native force_zip64=True LFH ZIP64 generation "
            f"(running Python {platform.python_version()}; Python <3.12 omits 0xFFFFFFFF "
            f"LFH sentinels and version_needed=45 on small members)."
        )

    if sha256_bytes(EICAR_PAYLOAD) != EICAR_EXPECTED_SHA256:
        raise RuntimeError("Embedded EICAR payload SHA-256 mismatch")

    output_dir.mkdir(parents=True, exist_ok=True)
    fixtures: dict[str, Any] = {}

    # A: clean.txt
    clean_path = output_dir / "clean.txt"
    clean_path.write_bytes(CLEAN_PAYLOAD)
    fixtures["clean"] = {
        "fixture_id": "clean",
        "filename": clean_path.name,
        "kind": "raw_clean",
        "size_bytes": len(CLEAN_PAYLOAD),
        "sha256": sha256_bytes(CLEAN_PAYLOAD),
        "uncompressed_size_bytes": len(CLEAN_PAYLOAD),
        "uncompressed_sha256": sha256_bytes(CLEAN_PAYLOAD),
        "member_count": 0,
        "zip_inspection": None,
    }

    # B: eicar.txt
    eicar_path = output_dir / "eicar.txt"
    eicar_path.write_bytes(EICAR_PAYLOAD)
    fixtures["eicar_direct"] = {
        "fixture_id": "eicar_direct",
        "filename": eicar_path.name,
        "kind": "raw_eicar",
        "size_bytes": len(EICAR_PAYLOAD),
        "sha256": sha256_bytes(EICAR_PAYLOAD),
        "uncompressed_size_bytes": len(EICAR_PAYLOAD),
        "uncompressed_sha256": sha256_bytes(EICAR_PAYLOAD),
        "member_count": 0,
        "zip_inspection": None,
    }

    # C: eicar-zip32.zip
    zip32_path = output_dir / "eicar-zip32.zip"
    with zipfile.ZipFile(zip32_path, "w", allowZip64=False) as archive:
        archive.writestr(_zip_member("eicar.txt"), EICAR_PAYLOAD)
    zip32_bytes = zip32_path.read_bytes()
    if len(zip32_bytes) > MAX_FIXTURE_ARCHIVE_BYTES:
        raise ValueError(f"eicar-zip32.zip exceeds archive byte cap: {len(zip32_bytes)}")
    zip32_inspection = inspect_zip_binary(zip32_bytes)
    assert_strict_zip32(zip32_inspection, expected_member_name="eicar.txt", expected_uncompressed_size=len(EICAR_PAYLOAD))
    _verify_zip_roundtrip(zip32_path, "eicar.txt", EICAR_PAYLOAD)
    fixtures["eicar_zip32"] = {
        "fixture_id": "eicar_zip32",
        "filename": zip32_path.name,
        "kind": "zip32_eicar",
        "size_bytes": len(zip32_bytes),
        "sha256": sha256_bytes(zip32_bytes),
        "uncompressed_size_bytes": len(EICAR_PAYLOAD),
        "uncompressed_sha256": sha256_bytes(EICAR_PAYLOAD),
        "member_count": 1,
        "zip_inspection": zip32_inspection,
    }

    # D: eicar-zip64.zip (Python 3.12+ force_zip64=True)
    zip64_path = output_dir / "eicar-zip64.zip"
    with zipfile.ZipFile(zip64_path, "w", allowZip64=True) as archive:
        with archive.open(_zip_member("eicar.txt"), "w", force_zip64=True) as target:
            target.write(EICAR_PAYLOAD)
    zip64_bytes = zip64_path.read_bytes()
    if len(zip64_bytes) > MAX_FIXTURE_ARCHIVE_BYTES:
        raise ValueError(f"eicar-zip64.zip exceeds archive byte cap: {len(zip64_bytes)}")
    zip64_inspection = inspect_zip_binary(zip64_bytes)
    assert_python312_zip64(zip64_inspection, expected_member_name="eicar.txt", expected_uncompressed_size=len(EICAR_PAYLOAD))
    _verify_zip_roundtrip(zip64_path, "eicar.txt", EICAR_PAYLOAD)
    fixtures["eicar_zip64"] = {
        "fixture_id": "eicar_zip64",
        "filename": zip64_path.name,
        "kind": "zip64_eicar_python312",
        "size_bytes": len(zip64_bytes),
        "sha256": sha256_bytes(zip64_bytes),
        "uncompressed_size_bytes": len(EICAR_PAYLOAD),
        "uncompressed_sha256": sha256_bytes(EICAR_PAYLOAD),
        "member_count": 1,
        "zip_inspection": zip64_inspection,
    }

    # E: small-zip32-maxfilesize.zip (64 KiB benign 'A' inside strict ZIP32, < 16 KiB on disk)
    maxfs_payload = b"A" * SMALL_MAXFILESIZE_MEMBER_BYTES
    if len(maxfs_payload) > MAX_FIXTURE_UNCOMPRESSED_BYTES:
        raise ValueError("MaxFileSize fixture payload exceeds uncompressed safety cap")
    maxfs_path = output_dir / "small-zip32-maxfilesize.zip"
    with zipfile.ZipFile(maxfs_path, "w", allowZip64=False) as archive:
        archive.writestr(_zip_member("oversized-member.txt"), maxfs_payload)
    maxfs_bytes = maxfs_path.read_bytes()
    if len(maxfs_bytes) >= REDUCED_MAX_FILE_SIZE_BYTES or len(maxfs_bytes) > MAX_FIXTURE_ARCHIVE_BYTES:
        raise ValueError(
            f"small-zip32-maxfilesize.zip compressed size ({len(maxfs_bytes)}) must be "
            f"strictly below reduced MaxFileSize ({REDUCED_MAX_FILE_SIZE_BYTES})"
        )
    maxfs_inspection = inspect_zip_binary(maxfs_bytes)
    assert_strict_zip32(
        maxfs_inspection,
        expected_member_name="oversized-member.txt",
        expected_uncompressed_size=SMALL_MAXFILESIZE_MEMBER_BYTES,
    )
    _verify_zip_roundtrip(maxfs_path, "oversized-member.txt", maxfs_payload)
    fixtures["small_zip32_maxfilesize"] = {
        "fixture_id": "small_zip32_maxfilesize",
        "filename": maxfs_path.name,
        "kind": "zip32_maxfilesize_small",
        "size_bytes": len(maxfs_bytes),
        "sha256": sha256_bytes(maxfs_bytes),
        "uncompressed_size_bytes": len(maxfs_payload),
        "uncompressed_sha256": sha256_bytes(maxfs_payload),
        "member_count": 1,
        "reduced_limit_design": {
            "compressed_bytes": len(maxfs_bytes),
            "uncompressed_bytes": len(maxfs_payload),
            "target_reduced_max_file_size_bytes": REDUCED_MAX_FILE_SIZE_BYTES,
            "target_reduced_max_scan_size_bytes": REDUCED_MAX_SCAN_SIZE_BYTES,
            "compressed_below_max_file_size": len(maxfs_bytes) < REDUCED_MAX_FILE_SIZE_BYTES,
            "uncompressed_above_max_file_size": len(maxfs_payload) > REDUCED_MAX_FILE_SIZE_BYTES,
            "uncompressed_below_max_scan_size": len(maxfs_payload) < REDUCED_MAX_SCAN_SIZE_BYTES,
        },
        "zip_inspection": maxfs_inspection,
    }

    return {
        "generated_at_utc": utc_now_iso(),
        "python_version": platform.python_version(),
        "python_version_full": sys.version,
        "python_implementation": platform.python_implementation(),
        "bounds": {
            "max_fixture_archive_bytes": MAX_FIXTURE_ARCHIVE_BYTES,
            "max_fixture_uncompressed_bytes": MAX_FIXTURE_UNCOMPRESSED_BYTES,
            "max_zip_members": MAX_ZIP_MEMBERS,
            "bomb_420mib_generated": False,
        },
        "fixtures": fixtures,
    }


# ---------------------------------------------------------------------------
# Strict anchored clamd wire response classifier (Section 7)
# ---------------------------------------------------------------------------
def format_raw_response(raw_bytes: bytes) -> str:
    """Lossless printable representation preserving NUL and control characters."""
    out: list[str] = []
    for byte in raw_bytes:
        if byte == 0:
            out.append("\\0")
        elif byte == 0x0A:
            out.append("\\n")
        elif byte == 0x0D:
            out.append("\\r")
        elif byte == 0x09:
            out.append("\\t")
        elif byte == 0x5C:
            out.append("\\\\")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def classify_clamd_response(raw_bytes: bytes, *, overflowed: bool = False) -> dict[str, Any]:
    """Classify verbatim clamd wire bytes into the required 7-class taxonomy."""
    base: dict[str, Any] = {
        "raw_bytes_hex": raw_bytes.hex(),
        "raw_response_repr": format_raw_response(raw_bytes),
        "raw_byte_length": len(raw_bytes),
        "nul_count": raw_bytes.count(b"\x00"),
        "nul_terminated": False,
        "normalized_response": None,
        "verdict": VERDICT_MALFORMED,
        "signature": None,
        "detail": "",
    }

    if overflowed:
        base["detail"] = f"response exceeded {MAX_CLAMD_RESPONSE_BYTES} bytes"
        return base
    if not raw_bytes:
        base["detail"] = "empty response (no NUL terminator)"
        return base

    nul_count = raw_bytes.count(b"\x00")
    if nul_count == 0:
        base["detail"] = "missing NUL terminator"
        return base
    if nul_count > 1:
        base["detail"] = f"multiple/embedded NUL terminators ({nul_count})"
        return base

    nul_index = raw_bytes.index(b"\x00")
    if nul_index != len(raw_bytes) - 1:
        trailing = raw_bytes[nul_index + 1:]
        base["detail"] = f"trailing bytes after NUL terminator: {format_raw_response(trailing[:40])}"
        return base

    base["nul_terminated"] = True
    body_bytes = raw_bytes[:nul_index]
    try:
        body_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        base["detail"] = "non-UTF-8 bytes before NUL terminator"
        return base

    # Strip optional trailing CR/LF immediately before NUL; reject internal newlines.
    trimmed = body_text.rstrip("\r\n")
    if not trimmed.strip():
        base["detail"] = "empty reply body before NUL terminator"
        return base
    if "\r" in trimmed or "\n" in trimmed:
        base["detail"] = "multiple lines / concatenated stanzas in reply"
        return base
    if trimmed != trimmed.strip():
        base["detail"] = "unexpected leading or trailing horizontal whitespace"
        return base

    base["normalized_response"] = trimmed

    if trimmed == INSTREAM_LIMIT_REFUSAL:
        base["verdict"] = VERDICT_SCAN_ERROR
        base["detail"] = INSTREAM_LIMIT_REFUSAL
        return base

    stanza = STANZA_RE.match(trimmed)
    if not stanza:
        base["detail"] = f"not a valid clamd stream stanza: {trimmed[:80]}"
        return base

    payload = stanza.group(1)
    if payload.upper() == "OK":
        base["verdict"] = VERDICT_CLEAN
        base["detail"] = "stream: OK"
        return base

    found = FOUND_RE.match(payload)
    if found:
        sig = found.group(1)
        base["signature"] = sig
        if sig.startswith(LIMIT_ALERT_PREFIX):
            base["verdict"] = VERDICT_LIMIT_ALERT
            base["detail"] = f"limit alert: {sig}"
        else:
            base["verdict"] = VERDICT_INFECTED
            base["detail"] = f"malware signature: {sig}"
        return base

    if ERROR_RE.match(payload):
        base["verdict"] = VERDICT_SCAN_ERROR
        base["detail"] = payload
        return base

    base["detail"] = f"unrecognized stanza payload: {payload[:80]}"
    return base


# ---------------------------------------------------------------------------
# Socket helpers (zPING, zVERSION, zINSTREAM)
# ---------------------------------------------------------------------------
def _recv_clamd_reply(sock: socket.socket, timeout_seconds: float) -> tuple[bytes, bool]:
    chunks = bytearray()
    overflowed = False
    deadline = time.monotonic() + timeout_seconds
    saw_nul = False
    settle_deadline: float | None = None

    while True:
        now = time.monotonic()
        remaining = deadline - now
        if settle_deadline is not None:
            remaining = min(remaining, settle_deadline - now)
        if remaining <= 0:
            if saw_nul:
                break
            raise TimeoutError(f"clamd reply timeout after {timeout_seconds:.2f}s")

        sock.settimeout(remaining)
        try:
            chunk = sock.recv(1024)
        except socket.timeout:
            if saw_nul:
                break
            raise TimeoutError(f"clamd socket timeout after {timeout_seconds:.2f}s") from None

        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > MAX_CLAMD_RESPONSE_BYTES:
            overflowed = True
            del chunks[MAX_CLAMD_RESPONSE_BYTES:]
            break
        if not saw_nul and b"\x00" in chunk:
            saw_nul = True
            settle_deadline = time.monotonic() + REPLY_SETTLE_SECONDS

    return bytes(chunks), overflowed


def clamd_simple_command(host: str, port: int, command: str, timeout_seconds: float = 15.0) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            sock.sendall(command.encode("ascii") + b"\x00")
            raw_bytes, overflowed = _recv_clamd_reply(sock, timeout_seconds)
    except TimeoutError as exc:
        return {
            "ok": False,
            "verdict": VERDICT_TIMEOUT,
            "detail": str(exc),
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 2),
        }
    except OSError as exc:
        return {
            "ok": False,
            "verdict": VERDICT_UNAVAILABLE,
            "detail": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 2),
        }

    elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
    nul_count = raw_bytes.count(b"\x00")
    nul_terminated = (not overflowed) and nul_count == 1 and raw_bytes.endswith(b"\x00")
    text = raw_bytes[:-1].decode("utf-8", errors="replace").strip() if nul_terminated else None
    return {
        "ok": nul_terminated,
        "verdict": "OK" if nul_terminated else VERDICT_MALFORMED,
        "raw_bytes_hex": raw_bytes.hex(),
        "raw_response_repr": format_raw_response(raw_bytes),
        "nul_terminated": nul_terminated,
        "nul_count": nul_count,
        "text": text,
        "elapsed_ms": elapsed_ms,
    }


def clamd_instream_scan(host: str, port: int, payload: bytes, timeout_seconds: float = DEFAULT_SOCKET_TIMEOUT_SECONDS) -> dict[str, Any]:
    if len(payload) == 0 or len(payload) > MAX_SCAN_INPUT_BYTES:
        raise ValueError(f"Refusing to scan payload of {len(payload)} bytes (allowed: 1..{MAX_SCAN_INPUT_BYTES})")
    if timeout_seconds <= 0 or timeout_seconds > MAX_SOCKET_TIMEOUT_SECONDS:
        raise ValueError(f"Timeout out of bounds: {timeout_seconds}")

    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            sock.sendall(b"zINSTREAM\x00")
            chunk_size = 16 * 1024
            for offset in range(0, len(payload), chunk_size):
                chunk = payload[offset:offset + chunk_size]
                sock.sendall(struct.pack(">I", len(chunk)) + chunk)
            sock.sendall(b"\x00\x00\x00\x00")
            raw_bytes, overflowed = _recv_clamd_reply(sock, timeout_seconds)
    except TimeoutError as exc:
        return {
            "raw_bytes_hex": "",
            "raw_response_repr": "",
            "raw_byte_length": 0,
            "nul_count": 0,
            "nul_terminated": False,
            "normalized_response": None,
            "verdict": VERDICT_TIMEOUT,
            "signature": None,
            "detail": str(exc),
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 2),
            "peak_rss_kb": peak_rss_kb(),
        }
    except OSError as exc:
        return {
            "raw_bytes_hex": "",
            "raw_response_repr": "",
            "raw_byte_length": 0,
            "nul_count": 0,
            "nul_terminated": False,
            "normalized_response": None,
            "verdict": VERDICT_UNAVAILABLE,
            "signature": None,
            "detail": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000.0, 2),
            "peak_rss_kb": peak_rss_kb(),
        }

    classified = classify_clamd_response(raw_bytes, overflowed=overflowed)
    classified["elapsed_ms"] = round((time.monotonic() - started) * 1000.0, 2)
    classified["peak_rss_kb"] = peak_rss_kb()
    return classified


def parse_zversion(text: str | None) -> dict[str, str] | None:
    if not text:
        return None
    match = ZVERSION_RE.match(text.strip())
    if not match:
        return None
    return {
        "engine_version": match.group(1),
        "signature_db_version": match.group(2),
        "signature_db_timestamp": match.group(3).strip(),
        "raw": text.strip(),
    }


# ---------------------------------------------------------------------------
# clamconf effective configuration parser (ClamAV 1.5.4 clamconf.c syntax)
# ---------------------------------------------------------------------------
def parse_clamconf_clamd_section(clamconf_text: str) -> dict[str, Any]:
    """Parse effective clamd.conf directives from `clamconf --config-dir=...`."""
    in_clamd_section = False
    found_clamd_section = False
    settings: dict[str, str] = {}

    for raw_line in clamconf_text.splitlines():
        line = raw_line.strip()
        section_match = re.match(r"^Config file:\s+(.+)$", line)
        if section_match:
            section_name = section_match.group(1).strip()
            in_clamd_section = section_name == "clamd.conf"
            if in_clamd_section:
                found_clamd_section = True
            continue
        if not in_clamd_section or not line or line.startswith("-"):
            continue
        kv_match = re.match(r'^([A-Za-z0-9]+)\s*=\s*"([^"]*)"$', line)
        if kv_match:
            settings[kv_match.group(1)] = kv_match.group(2)
            continue
        disabled_match = re.match(r"^([A-Za-z0-9]+)\s+disabled$", line)
        if disabled_match:
            settings[disabled_match.group(1)] = "disabled"

    if not found_clamd_section:
        raise ValueError("clamconf output did not contain a 'Config file: clamd.conf' section")

    effective_subset = {key: settings.get(key) for key in EFFECTIVE_LIMIT_KEYS}
    raw_alert = settings.get("AlertExceedsMax")
    if raw_alert is None:
        alert_normalized = "unknown"
    elif raw_alert.lower() in ("yes", "true", "1"):
        alert_normalized = "yes"
    elif raw_alert.lower() in ("no", "false", "0", "disabled"):
        alert_normalized = "no"
    else:
        alert_normalized = f"unexpected:{raw_alert}"

    return {
        "clamd_section_found": True,
        "alert_exceeds_max_raw": raw_alert,
        "alert_exceeds_max_effective": alert_normalized,
        "effective_limits": effective_subset,
        "total_parsed_keys": len(settings),
    }


# ---------------------------------------------------------------------------
# Case evaluation rules (Section 2, Section 7, Section 8)
# ---------------------------------------------------------------------------
def evaluate_case(case_id: str, expectation: str, scan_result: dict[str, Any]) -> dict[str, Any]:
    verdict = scan_result["verdict"]
    sig = scan_result.get("signature")
    nul_ok = bool(scan_result.get("nul_terminated"))

    status = STATUS_FAIL
    security_failure = False
    control_only = False
    diagnosis = ""

    if expectation == "CLEAN":
        if verdict == VERDICT_CLEAN and nul_ok:
            status = STATUS_PASS
            diagnosis = "Clean control returned NUL-terminated CLEAN (stream: OK)."
        else:
            status = STATUS_FAIL
            diagnosis = f"Expected CLEAN for clean control, observed {verdict} ({scan_result.get('detail')})."

    elif expectation == "INFECTED_EICAR":
        if verdict == VERDICT_INFECTED and nul_ok and sig and EICAR_SIG_RE.search(sig):
            status = STATUS_PASS
            diagnosis = f"EICAR detected with signature {sig}."
        elif verdict == VERDICT_CLEAN:
            status = STATUS_FAIL
            security_failure = True
            diagnosis = "SECURITY FAILURE: unexpected CLEAN verdict for EICAR input."
        else:
            status = STATUS_FAIL
            diagnosis = f"Expected EICAR INFECTED, observed {verdict} (signature={sig}, detail={scan_result.get('detail')})."

    elif expectation == "LIMIT_ALERT_MAX_FILE_SIZE":
        if verdict == VERDICT_LIMIT_ALERT and nul_ok and sig == EXPECTED_MAX_FILE_SIZE_ALERT:
            status = STATUS_PASS
            diagnosis = f"Observed exact required limit alert {EXPECTED_MAX_FILE_SIZE_ALERT}."
        elif verdict == VERDICT_CLEAN:
            status = STATUS_FAIL
            security_failure = True
            diagnosis = (
                "SECURITY FAILURE: unexpected CLEAN verdict for ZIP32 input exceeding MaxFileSize "
                "while AlertExceedsMax=yes (silent truncation)."
            )
        elif verdict == VERDICT_LIMIT_ALERT:
            status = STATUS_FAIL
            diagnosis = f"Different limit alert fired ({sig}); does not prove {EXPECTED_MAX_FILE_SIZE_ALERT}."
        else:
            status = STATUS_FAIL
            diagnosis = (
                f"Expected {EXPECTED_MAX_FILE_SIZE_ALERT}, observed {verdict} "
                f"(signature={sig}, detail={scan_result.get('detail')})."
            )

    elif expectation == "CONTROL_ALERT_EXCEEDS_MAX_NO":
        control_only = True
        if verdict == VERDICT_CLEAN and nul_ok:
            status = STATUS_PASS
            diagnosis = (
                "Observational comparison control only (NOT a security pass): with AlertExceedsMax=no, "
                "clamd returned NUL-terminated CLEAN on the reduced MaxFileSize ZIP32 fixture."
            )
        elif verdict in (VERDICT_LIMIT_ALERT, VERDICT_INFECTED, VERDICT_SCAN_ERROR) and nul_ok:
            status = STATUS_PASS
            diagnosis = (
                f"Observational comparison control only: with AlertExceedsMax=no, clamd returned "
                f"decisive non-CLEAN verdict {verdict} ({sig or scan_result.get('detail')})."
            )
        else:
            status = STATUS_FAIL
            diagnosis = (
                f"Comparison control failed to obtain a valid NUL-terminated clamd verdict: "
                f"{verdict} ({scan_result.get('detail')})."
            )
    else:
        raise ValueError(f"Unknown expectation: {expectation}")

    return {
        "case_id": case_id,
        "expectation": expectation,
        "status": status,
        "security_failure": security_failure,
        "control_only": control_only,
        "diagnosis": diagnosis,
        "scan": scan_result,
    }


PROFILE_PLANS: dict[str, list[tuple[str, str, str, str]]] = {
    "candidate": [
        ("A_clean", "clean", "CLEAN", "A. Clean file detection (unmodified candidate config)"),
        ("B_eicar_direct", "eicar_direct", "INFECTED_EICAR", "B. Direct EICAR detection (unmodified candidate config)"),
        ("C_eicar_zip32", "eicar_zip32", "INFECTED_EICAR", "C. EICAR inside ZIP32 (unmodified candidate config)"),
        ("D_eicar_zip64", "eicar_zip64", "INFECTED_EICAR", "D. EICAR inside Python-generated ZIP64 (unmodified candidate config)"),
    ],
    "reduced_alert_yes": [
        ("E0_yes_eicar_zip32_control", "eicar_zip32", "INFECTED_EICAR", "E0a. Control: EICAR inside ZIP32 under reduced limits (AlertExceedsMax=yes)"),
        ("E1_yes_small_zip32_maxfilesize", "small_zip32_maxfilesize", "LIMIT_ALERT_MAX_FILE_SIZE", "E1. Small ZIP32 MaxFileSize truncation (isolated reduced limits, AlertExceedsMax=yes)"),
    ],
    "reduced_alert_no": [
        ("E0_no_eicar_zip32_control", "eicar_zip32", "INFECTED_EICAR", "E0b. Control: EICAR inside ZIP32 under reduced limits (AlertExceedsMax=no)"),
        ("E2_no_small_zip32_maxfilesize", "small_zip32_maxfilesize", "CONTROL_ALERT_EXCEEDS_MAX_NO", "E2. Comparison control: Small ZIP32 MaxFileSize truncation (isolated reduced limits, AlertExceedsMax=no)"),
    ],
}


def run_scan_profile(
    *,
    profile: str,
    host: str,
    port: int,
    fixtures_dir: Path,
    manifest: dict[str, Any],
    expected_engine: str,
    clamconf_text: str,
    expected_alert_exceeds_max: str,
    timeout_seconds: float,
    container_stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if profile not in PROFILE_PLANS:
        raise ValueError(f"Unsupported profile: {profile}")

    # 1. Fail-closed effective config verification via clamconf
    parsed_conf = parse_clamconf_clamd_section(clamconf_text)
    if parsed_conf["alert_exceeds_max_effective"] != expected_alert_exceeds_max:
        raise RuntimeError(
            f"Profile {profile}: effective AlertExceedsMax={parsed_conf['alert_exceeds_max_effective']} "
            f"(raw={parsed_conf['alert_exceeds_max_raw']}) != expected {expected_alert_exceeds_max}"
        )
    if profile in ("reduced_alert_yes", "reduced_alert_no"):
        eff = parsed_conf["effective_limits"]
        expected_numeric = {
            "MaxFileSize": str(REDUCED_MAX_FILE_SIZE_BYTES),
            "MaxScanSize": str(REDUCED_MAX_SCAN_SIZE_BYTES),
            "StreamMaxLength": str(REDUCED_STREAM_MAX_LENGTH_BYTES),
        }
        for key, expected_val in expected_numeric.items():
            if eff.get(key) != expected_val:
                raise RuntimeError(
                    f"Profile {profile}: effective {key}={eff.get(key)!r} != expected {expected_val!r}"
                )

    # 2. Fail-closed scanner readiness & ClamAV version verification (zPING + zVERSION)
    ping = clamd_simple_command(host, port, "zPING", timeout_seconds=min(timeout_seconds, 15.0))
    if not ping["ok"] or ping.get("text") != "PONG":
        raise RuntimeError(f"Profile {profile}: clamd zPING failed: {ping}")

    version_probe = clamd_simple_command(host, port, "zVERSION", timeout_seconds=min(timeout_seconds, 15.0))
    version_parsed = parse_zversion(version_probe.get("text")) if version_probe["ok"] else None
    if version_parsed is None:
        raise RuntimeError(f"Profile {profile}: clamd zVERSION failed or malformed: {version_probe}")
    if version_parsed["engine_version"] != expected_engine:
        raise RuntimeError(
            f"Profile {profile}: unexpected ClamAV engine version "
            f"{version_parsed['engine_version']!r} != expected {expected_engine!r}"
        )

    # 3. Execute bounded fixture scans for this profile
    fixtures_meta = manifest["fixtures"]
    results: list[dict[str, Any]] = []
    profile_started = time.monotonic()

    for case_id, fixture_id, expectation, description in PROFILE_PLANS[profile]:
        meta = fixtures_meta[fixture_id]
        fixture_path = fixtures_dir / meta["filename"]
        if not fixture_path.is_file():
            raise FileNotFoundError(f"Missing fixture file: {fixture_path}")
        payload = fixture_path.read_bytes()
        observed_sha256 = sha256_bytes(payload)
        if observed_sha256 != meta["sha256"]:
            raise RuntimeError(f"Fixture SHA-256 drift for {fixture_id}: {observed_sha256} != {meta['sha256']}")

        scan_outcome = clamd_instream_scan(host, port, payload, timeout_seconds=timeout_seconds)
        evaluated = evaluate_case(case_id, expectation, scan_outcome)
        evaluated["description"] = description
        evaluated["fixture_id"] = fixture_id
        evaluated["fixture_filename"] = meta["filename"]
        evaluated["fixture_size_bytes"] = len(payload)
        evaluated["fixture_sha256"] = observed_sha256
        results.append(evaluated)

    return {
        "profile": profile,
        "collected_at_utc": utc_now_iso(),
        "elapsed_ms_total": round((time.monotonic() - profile_started) * 1000.0, 2),
        "scanner": {
            "port": port,
            "zping": {
                "ok": ping["ok"],
                "raw_response_repr": ping["raw_response_repr"],
                "nul_terminated": ping["nul_terminated"],
                "elapsed_ms": ping["elapsed_ms"],
            },
            "zversion": {
                "ok": version_probe["ok"],
                "raw_response_repr": version_probe["raw_response_repr"],
                "nul_terminated": version_probe["nul_terminated"],
                "elapsed_ms": version_probe["elapsed_ms"],
                "parsed": version_parsed,
            },
            "effective_config": parsed_conf,
            "container_stats": container_stats,
        },
        "cases": results,
    }


# ---------------------------------------------------------------------------
# Evidence report assembly (Section 8)
# ---------------------------------------------------------------------------
def _load_optional_json(path: Path) -> Any:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def assemble_report(
    *,
    evidence_dir: Path,
    run_id: str,
    run_attempt: str,
    commit_sha: str,
    repository: str,
    ref: str,
    image_ref: str,
    expected_engine: str,
    expected_package_version: str,
) -> dict[str, Any]:
    provenance = _load_optional_json(evidence_dir / "candidate-provenance.json")
    image_verification = _load_optional_json(evidence_dir / "image-verification.json")
    signature_db = _load_optional_json(evidence_dir / "signature-db-metadata.json")
    fixtures_manifest = _load_optional_json(evidence_dir / "fixtures-manifest.json")
    resource_observations = _load_optional_json(evidence_dir / "resource-observations.json")
    profiles: dict[str, Any] = {
        "candidate": _load_optional_json(evidence_dir / "profile-candidate.json"),
        "reduced_alert_yes": _load_optional_json(evidence_dir / "profile-reduced-alert-yes.json"),
        "reduced_alert_no": _load_optional_json(evidence_dir / "profile-reduced-alert-no.json"),
    }

    # Build complete ordered case list — never omit missing profiles; mark NOT VERIFIED
    all_cases: list[dict[str, Any]] = []
    for profile_name, plan in PROFILE_PLANS.items():
        profile_data = profiles.get(profile_name)
        by_id = {c["case_id"]: c for c in (profile_data.get("cases", []) if profile_data else [])}
        for case_id, fixture_id, expectation, description in plan:
            if case_id in by_id:
                entry = dict(by_id[case_id])
                entry["profile"] = profile_name
                all_cases.append(entry)
            else:
                all_cases.append({
                    "case_id": case_id,
                    "profile": profile_name,
                    "fixture_id": fixture_id,
                    "expectation": expectation,
                    "description": description,
                    "status": STATUS_NOT_VERIFIED,
                    "security_failure": False,
                    "control_only": expectation == "CONTROL_ALERT_EXCEEDS_MAX_NO",
                    "diagnosis": f"Profile '{profile_name}' did not produce scan results (prerequisite failure or incomplete run).",
                    "scan": None,
                })

    by_case_id = {c["case_id"]: c for c in all_cases}
    e1 = by_case_id["E1_yes_small_zip32_maxfilesize"]
    e2 = by_case_id["E2_no_small_zip32_maxfilesize"]
    e1_verdict = e1["scan"]["verdict"] if e1.get("scan") else None
    e2_verdict = e2["scan"]["verdict"] if e2.get("scan") else None
    alert_comparison = {
        "fixture_id": "small_zip32_maxfilesize",
        "reduced_limits": {
            "MaxFileSize": REDUCED_MAX_FILE_SIZE_BYTES,
            "MaxScanSize": REDUCED_MAX_SCAN_SIZE_BYTES,
            "StreamMaxLength": REDUCED_STREAM_MAX_LENGTH_BYTES,
        },
        "alert_exceeds_max_yes": {
            "status": e1["status"],
            "verdict": e1_verdict,
            "signature": e1["scan"].get("signature") if e1.get("scan") else None,
            "raw_response_repr": e1["scan"].get("raw_response_repr") if e1.get("scan") else None,
            "security_failure": e1["security_failure"],
        },
        "alert_exceeds_max_no": {
            "status": e2["status"],
            "verdict": e2_verdict,
            "signature": e2["scan"].get("signature") if e2.get("scan") else None,
            "raw_response_repr": e2["scan"].get("raw_response_repr") if e2.get("scan") else None,
            "control_only": True,
        },
        "both_profiles_verified": (e1_verdict is not None and e2_verdict is not None),
        "alert_exceeds_max_changed_verdict": (
            (e1_verdict != e2_verdict or (
                e1.get("scan", {}).get("raw_response_repr") != e2.get("scan", {}).get("raw_response_repr")
            ))
            if (e1_verdict is not None and e2_verdict is not None)
            else None
        ),
        "silent_truncation_observed_with_alert_yes": (e1_verdict == VERDICT_CLEAN),
    }

    security_failures = [c["case_id"] for c in all_cases if c.get("security_failure")]
    failed_cases = [c["case_id"] for c in all_cases if c["status"] == STATUS_FAIL]
    not_verified_cases = [c["case_id"] for c in all_cases if c["status"] == STATUS_NOT_VERIFIED]
    passed_cases = [c["case_id"] for c in all_cases if c["status"] == STATUS_PASS]

    overall_status = (
        STATUS_PASS
        if (not failed_cases and not not_verified_cases and not security_failures)
        else STATUS_FAIL
    )

    # Extract observed engine and signature versions from live profiles (if available)
    observed_zversions = {
        name: p["scanner"]["zversion"]["parsed"]
        for name, p in profiles.items()
        if p and p.get("scanner", {}).get("zversion", {}).get("parsed")
    }
    observed_limits = {
        name: p["scanner"]["effective_config"]
        for name, p in profiles.items()
        if p and p.get("scanner", {}).get("effective_config")
    }

    report: dict[str, Any] = {
        "schema_version": "dip.clamav.phase0a.evidence.v1",
        "generated_at_utc": utc_now_iso(),
        "workflow": {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "commit_sha": commit_sha,
            "repository": repository,
            "ref": ref,
        },
        "gates_context": {
            "security_gate": "OPEN",
            "licensing_gate": "OPEN",
            "clamav_stage7_acceptance": "NOT ACCEPTED",
            "production_authorization": "NONE (isolated Phase 0A evidence only)",
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "fixture_generator_version": fixtures_manifest.get("python_version") if fixtures_manifest else None,
        },
        "candidate_image": {
            "pinned_reference": image_ref,
            "expected_engine_version": expected_engine,
            "expected_package_version": expected_package_version,
            "provenance": provenance,
            "runtime_verification": image_verification,
        },
        "signature_database": {
            "metadata": signature_db,
            "zversion_observations": observed_zversions,
        },
        "effective_scanner_limits": observed_limits,
        "resource_observations": resource_observations,
        "fixtures": fixtures_manifest,
        "profiles": profiles,
        "alert_exceeds_max_comparison": alert_comparison,
        "classifications": {
            "passed": passed_cases,
            "failed": failed_cases,
            "not_verified": not_verified_cases,
            "security_failures": security_failures,
            "counts": {
                "total": len(all_cases),
                "pass": len(passed_cases),
                "fail": len(failed_cases),
                "not_verified": len(not_verified_cases),
                "security_failures": len(security_failures),
            },
        },
        "cases": all_cases,
        "overall_status": overall_status,
    }

    evidence_dir.mkdir(parents=True, exist_ok=True)
    json_path = evidence_dir / "phase0a-evidence.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    md_path = evidence_dir / "phase0a-evidence-summary.md"
    md_path.write_text(render_markdown_summary(report), encoding="utf-8")

    # Compute SHA-256 manifest for all evidence files except the manifest itself
    manifest_lines: list[str] = []
    for entry in sorted(evidence_dir.iterdir()):
        if entry.is_file() and entry.name != "artifact-files.sha256":
            manifest_lines.append(f"{sha256_file(entry)}  {entry.name}")
    (evidence_dir / "artifact-files.sha256").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

    return report


def render_markdown_summary(report: dict[str, Any]) -> str:
    wf = report["workflow"]
    cls = report["classifications"]
    cmp_e = report["alert_exceeds_max_comparison"]
    lines = [
        "# DIP — ClamAV 1.5.4 Phase 0A Isolated Evidence Summary",
        "",
        f"- **Overall Experiment Status**: `{report['overall_status']}`",
        f"- **Security Failures**: `{cls['counts']['security_failures']}`",
        f"- **Counts**: PASS={cls['counts']['pass']}, FAIL={cls['counts']['fail']}, NOT VERIFIED={cls['counts']['not_verified']} (total={cls['counts']['total']})",
        f"- **Workflow Run**: `{wf['run_id']}` (attempt `{wf['run_attempt']}`)",
        f"- **Repository / Ref / Commit**: `{wf['repository']}` / `{wf['ref']}` / `{wf['commit_sha']}`",
        f"- **Pinned Candidate Image**: `{report['candidate_image']['pinned_reference']}`",
        f"- **Python Version**: `{report['python']['version']}` ({report['python']['implementation']})",
        "- **Gates**: Security Gate `OPEN`, Licensing Gate `OPEN`, ClamAV Stage 7 `NOT ACCEPTED`",
        "",
        "## Case Verdicts",
        "",
        "| Case | Profile | Status | Security Failure | Verdict | Raw Reply | NUL | Elapsed (ms) |",
        "| --- | --- | --- | --- | --- | --- | --- | ---: |",
    ]
    for case in report["cases"]:
        scan = case.get("scan") or {}
        verdict = scan.get("verdict", "N/A")
        raw_repr = scan.get("raw_response_repr", "N/A").replace("|", "\\|")
        nul = str(scan.get("nul_terminated", "N/A"))
        elapsed = str(scan.get("elapsed_ms", "N/A"))
        lines.append(
            f"| `{case['case_id']}` | `{case['profile']}` | **{case['status']}** | "
            f"`{case['security_failure']}` | `{verdict}` | `{raw_repr}` | `{nul}` | {elapsed} |"
        )

    lines.extend([
        "",
        "## Experiment E — AlertExceedsMax Comparison (Isolated Reduced Limits)",
        "",
        f"- Limits: `MaxFileSize={cmp_e['reduced_limits']['MaxFileSize']}`, "
        f"`MaxScanSize={cmp_e['reduced_limits']['MaxScanSize']}`, "
        f"`StreamMaxLength={cmp_e['reduced_limits']['StreamMaxLength']}`",
        f"- `AlertExceedsMax yes`: status=`{cmp_e['alert_exceeds_max_yes']['status']}`, "
        f"verdict=`{cmp_e['alert_exceeds_max_yes']['verdict']}`, "
        f"raw=`{cmp_e['alert_exceeds_max_yes']['raw_response_repr']}`, "
        f"security_failure=`{cmp_e['alert_exceeds_max_yes']['security_failure']}`",
        f"- `AlertExceedsMax no` (control): status=`{cmp_e['alert_exceeds_max_no']['status']}`, "
        f"verdict=`{cmp_e['alert_exceeds_max_no']['verdict']}`, "
        f"raw=`{cmp_e['alert_exceeds_max_no']['raw_response_repr']}`",
        f"- `alert_exceeds_max_changed_verdict`: `{cmp_e['alert_exceeds_max_changed_verdict']}`",
        f"- `silent_truncation_observed_with_alert_yes`: `{cmp_e['silent_truncation_observed_with_alert_yes']}`",
        "",
    ])

    fixtures_manifest = report.get("fixtures") or {}
    fixtures = fixtures_manifest.get("fixtures") or {}
    if fixtures:
        lines.extend([
            "## Fixtures & Binary ZIP Verification",
            "",
            "| Fixture | File | Bytes | Uncompressed | SHA-256 | Binary Format |",
            "| --- | --- | ---: | ---: | --- | --- |",
        ])
        for fid, meta in fixtures.items():
            zip_insp = meta.get("zip_inspection")
            fmt = zip_insp["summary"]["format_classification"] if zip_insp else "RAW"
            lines.append(
                f"| `{fid}` | `{meta['filename']}` | {meta['size_bytes']} | "
                f"{meta['uncompressed_size_bytes']} | `{meta['sha256']}` | `{fmt}` |"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Synthetic exact Python 3.12 ZIP64 test vector builder (for offline self-test)
# ---------------------------------------------------------------------------
def _build_python312_zip64_reference_bytes(member_name: str, payload: bytes) -> bytes:
    """Build exact byte-equivalent of CPython 3.12 zipfile force_zip64=True output.

    Used strictly in --self-test to verify the binary LFH/CDH parser even when
    local validation runs on Python 3.11 (where stdlib zipfile omits LFH
    0xFFFFFFFF sentinels and version_needed=45 for small payloads).
    """
    import zlib

    crc = zlib.crc32(payload) & 0xFFFFFFFF
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
    compressed = compressor.compress(payload) + compressor.flush()
    fname = member_name.encode("utf-8")
    dos_time = (ZIP_FIXED_TIME[3] << 11) | (ZIP_FIXED_TIME[4] << 5) | (ZIP_FIXED_TIME[5] // 2)
    dos_date = ((ZIP_FIXED_TIME[0] - 1980) << 9) | (ZIP_FIXED_TIME[1] << 5) | ZIP_FIXED_TIME[2]

    # Python 3.12 ZipInfo.FileHeader(zip64=True):
    # writes 0x0001 extra (uncompressed_size, compressed_size), sets LFH sizes to 0xFFFFFFFF and version_needed to 45
    lfh_extra = struct.pack("<HHQQ", EXTRA_ID_ZIP64, 16, len(payload), len(compressed))
    lfh = struct.pack(
        "<IHHHHHIIIHH",
        SIG_LFH,
        ZIP64_MIN_VERSION,
        0,
        zipfile.ZIP_DEFLATED,
        dos_time,
        dos_date,
        crc,
        SENTINEL_U32,
        SENTINEL_U32,
        len(fname),
        len(lfh_extra),
    ) + fname + lfh_extra

    cd_offset = len(lfh) + len(compressed)
    # Python 3.12 _write_end_record(): preserves extract_version=45, writes 32-bit sizes when <= ZIP64_LIMIT
    cdh = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        SIG_CDH,
        (3 << 8) | ZIP64_MIN_VERSION,
        ZIP64_MIN_VERSION,
        0,
        zipfile.ZIP_DEFLATED,
        dos_time,
        dos_date,
        crc,
        len(compressed),
        len(payload),
        len(fname),
        0,
        0,
        0,
        0,
        0o100644 << 16,
        0,
    ) + fname
    eocd = struct.pack("<IHHHHIIH", SIG_EOCD, 0, 0, 1, 1, len(cdh), cd_offset, 0)
    return lfh + compressed + cdh + eocd


def _build_full_zip64_reference_bytes(member_name: str, payload: bytes) -> bytes:
    """Build full ZIP64 archive (LFH + CDH 0x0001 + ZIP64 EOCD + Locator) for parser self-test."""
    import zlib

    crc = zlib.crc32(payload) & 0xFFFFFFFF
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
    compressed = compressor.compress(payload) + compressor.flush()
    fname = member_name.encode("utf-8")
    dos_time = 0
    dos_date = ((ZIP_FIXED_TIME[0] - 1980) << 9) | (ZIP_FIXED_TIME[1] << 5) | ZIP_FIXED_TIME[2]

    lfh_extra = struct.pack("<HHQQ", EXTRA_ID_ZIP64, 16, len(payload), len(compressed))
    lfh = struct.pack(
        "<IHHHHHIIIHH",
        SIG_LFH, ZIP64_MIN_VERSION, 0, zipfile.ZIP_DEFLATED, dos_time, dos_date,
        crc, SENTINEL_U32, SENTINEL_U32, len(fname), len(lfh_extra),
    ) + fname + lfh_extra

    cd_offset = len(lfh) + len(compressed)
    cdh_extra = struct.pack("<HHQQ", EXTRA_ID_ZIP64, 16, len(payload), len(compressed))
    cdh = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        SIG_CDH, (3 << 8) | ZIP64_MIN_VERSION, ZIP64_MIN_VERSION, 0, zipfile.ZIP_DEFLATED,
        dos_time, dos_date, crc, SENTINEL_U32, SENTINEL_U32,
        len(fname), len(cdh_extra), 0, 0, 0, 0o100644 << 16, 0,
    ) + fname + cdh_extra

    z64_eocd_offset = cd_offset + len(cdh)
    z64_eocd = struct.pack(
        "<IQHHIIQQQQ",
        SIG_ZIP64_EOCD, 44, (3 << 8) | ZIP64_MIN_VERSION, ZIP64_MIN_VERSION,
        0, 0, 1, 1, len(cdh), cd_offset,
    )
    z64_loc = struct.pack("<IIQI", SIG_ZIP64_LOCATOR, 0, z64_eocd_offset, 1)
    eocd = struct.pack(
        "<IHHHHIIH",
        SIG_EOCD, 0, 0, SENTINEL_U16, SENTINEL_U16, SENTINEL_U32, SENTINEL_U32, 0,
    )
    return lfh + compressed + cdh + z64_eocd + z64_loc + eocd


# ---------------------------------------------------------------------------
# Offline bounded self-test (no Docker / no live ClamAV required)
# ---------------------------------------------------------------------------
def run_self_test() -> int:
    passed = 0
    failed = 0
    not_verified: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"PASS | selftest | {name} | {detail}")
        else:
            failed += 1
            print(f"FAIL | selftest | {name} | {detail}")

    # 1. Standard EICAR SHA-256 verification
    check(
        "EICAR standard SHA-256",
        len(EICAR_PAYLOAD) == 68 and sha256_bytes(EICAR_PAYLOAD) == EICAR_EXPECTED_SHA256,
        f"len={len(EICAR_PAYLOAD)} sha256={sha256_bytes(EICAR_PAYLOAD)}",
    )

    # 2. Wire protocol response classifier covering all 7 verdict classes & malformed negatives
    wire_cases: list[tuple[str, bytes, str, bool, str | None]] = [
        ("valid CLEAN", b"stream: OK\x00", VERDICT_CLEAN, True, None),
        ("valid CLEAN with CRLF before NUL", b"stream: OK\r\n\x00", VERDICT_CLEAN, True, None),
        ("valid EICAR INFECTED", b"stream: Win.Test.EICAR_HDB-1 FOUND\x00", VERDICT_INFECTED, True, "Win.Test.EICAR_HDB-1"),
        ("valid MaxFileSize LIMIT ALERT", b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00", VERDICT_LIMIT_ALERT, True, EXPECTED_MAX_FILE_SIZE_ALERT),
        ("valid MaxScanSize LIMIT ALERT", b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\x00", VERDICT_LIMIT_ALERT, True, "Heuristics.Limits.Exceeded.MaxScanSize"),
        ("valid prefixless INSTREAM SCAN ERROR", b"INSTREAM size limit exceeded. ERROR\x00", VERDICT_SCAN_ERROR, True, None),
        ("valid prefixed SCAN ERROR", b"stream: Size limit reached ERROR\x00", VERDICT_SCAN_ERROR, True, None),
        ("missing NUL on CLEAN -> MALFORMED", b"stream: OK", VERDICT_MALFORMED, False, None),
        ("missing NUL on LIMIT ALERT -> MALFORMED", b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND", VERDICT_MALFORMED, False, None),
        ("trailing space after NUL -> MALFORMED", b"stream: OK\x00 ", VERDICT_MALFORMED, False, None),
        ("concatenated stanzas -> MALFORMED", b"stream: OK\x00stream: OK\x00", VERDICT_MALFORMED, False, None),
        ("trailing garbage after FOUND -> MALFORMED", b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND extra\x00", VERDICT_MALFORMED, True, None),
        ("leading garbage before FOUND -> MALFORMED", b"stream: junk Win.Test.EICAR_HDB-1 FOUND\x00", VERDICT_MALFORMED, True, None),
        ("multiline body -> MALFORMED", b"stream: OK\nstream: OK\x00", VERDICT_MALFORMED, True, None),
        ("empty reply -> MALFORMED", b"", VERDICT_MALFORMED, False, None),
        ("empty body before NUL -> MALFORMED", b"\x00", VERDICT_MALFORMED, True, None),
        ("invalid UTF-8 -> MALFORMED", b"\xff\xfe\x00", VERDICT_MALFORMED, True, None),
    ]
    for label, raw, expected_verdict, expected_nul, expected_sig in wire_cases:
        res = classify_clamd_response(raw)
        ok = (
            res["verdict"] == expected_verdict
            and res["nul_terminated"] == expected_nul
            and res["signature"] == expected_sig
        )
        check(f"wire:{label}", ok, f"got={res['verdict']} nul={res['nul_terminated']} sig={res['signature']}")

    # 3. Security failure rules: unexpected CLEAN is ALWAYS security_failure=True, never PASS
    eicar_clean_eval = evaluate_case("B", "INFECTED_EICAR", classify_clamd_response(b"stream: OK\x00"))
    check(
        "unexpected CLEAN on EICAR is SECURITY FAILURE",
        eicar_clean_eval["status"] == STATUS_FAIL and eicar_clean_eval["security_failure"] is True,
        eicar_clean_eval["diagnosis"],
    )
    limit_clean_eval = evaluate_case("E1", "LIMIT_ALERT_MAX_FILE_SIZE", classify_clamd_response(b"stream: OK\x00"))
    check(
        "unexpected CLEAN on MaxFileSize (AlertExceedsMax=yes) is SECURITY FAILURE",
        limit_clean_eval["status"] == STATUS_FAIL and limit_clean_eval["security_failure"] is True,
        limit_clean_eval["diagnosis"],
    )
    limit_wrong_alert_eval = evaluate_case(
        "E1",
        "LIMIT_ALERT_MAX_FILE_SIZE",
        classify_clamd_response(b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\x00"),
    )
    check(
        "wrong limit alert does not pass MaxFileSize assertion",
        limit_wrong_alert_eval["status"] == STATUS_FAIL and limit_wrong_alert_eval["security_failure"] is False,
        limit_wrong_alert_eval["diagnosis"],
    )
    limit_exact_eval = evaluate_case(
        "E1",
        "LIMIT_ALERT_MAX_FILE_SIZE",
        classify_clamd_response(b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00"),
    )
    check(
        "exact MaxFileSize limit alert passes",
        limit_exact_eval["status"] == STATUS_PASS and limit_exact_eval["security_failure"] is False,
        limit_exact_eval["diagnosis"],
    )
    ctrl_no_eval = evaluate_case("E2", "CONTROL_ALERT_EXCEEDS_MAX_NO", classify_clamd_response(b"stream: OK\x00"))
    check(
        "AlertExceedsMax=no control marked control_only",
        ctrl_no_eval["status"] == STATUS_PASS and ctrl_no_eval["control_only"] is True and ctrl_no_eval["security_failure"] is False,
        ctrl_no_eval["diagnosis"],
    )

    # 4. clamconf parser (both AlertExceedsMax = "yes" and AlertExceedsMax disabled)
    sample_conf_yes = (
        "Checking configuration files in /etc/clamav-phase0a\n\n"
        "Config file: clamd.conf\n"
        "-----------------------\n"
        'StreamMaxLength = "1048576"\n'
        'MaxFileSize = "16384"\n'
        'MaxScanSize = "524288"\n'
        'AlertExceedsMax = "yes"\n\n'
        "Config file: freshclam.conf\n"
        "---------------------------\n"
    )
    parsed_yes = parse_clamconf_clamd_section(sample_conf_yes)
    check(
        "clamconf parses AlertExceedsMax=yes and reduced limits",
        parsed_yes["alert_exceeds_max_effective"] == "yes"
        and parsed_yes["effective_limits"]["MaxFileSize"] == "16384"
        and parsed_yes["effective_limits"]["MaxScanSize"] == "524288",
        str(parsed_yes["effective_limits"]),
    )
    sample_conf_no = sample_conf_yes.replace('AlertExceedsMax = "yes"', "AlertExceedsMax disabled")
    parsed_no = parse_clamconf_clamd_section(sample_conf_no)
    check(
        "clamconf parses AlertExceedsMax disabled as effective no",
        parsed_no["alert_exceeds_max_effective"] == "no" and parsed_no["alert_exceeds_max_raw"] == "disabled",
        f"raw={parsed_no['alert_exceeds_max_raw']} effective={parsed_no['alert_exceeds_max_effective']}",
    )

    # 5. Binary ZIP32 & ZIP64 inspection tests
    with tempfile.TemporaryDirectory(prefix="dip-phase0a-selftest-") as tmp:
        tmp_path = Path(tmp)

        # Build ZIP32 and small MaxFileSize fixtures directly (works on Python 3.11+)
        zip32_path = tmp_path / "eicar-zip32.zip"
        with zipfile.ZipFile(zip32_path, "w", allowZip64=False) as zf:
            zf.writestr(_zip_member("eicar.txt"), EICAR_PAYLOAD)
        zip32_insp = inspect_zip_binary(zip32_path.read_bytes())
        assert_strict_zip32(zip32_insp, expected_member_name="eicar.txt", expected_uncompressed_size=len(EICAR_PAYLOAD))
        _verify_zip_roundtrip(zip32_path, "eicar.txt", EICAR_PAYLOAD)
        check(
            "binary inspector confirms strict ZIP32",
            zip32_insp["summary"]["format_classification"] == "ZIP32",
            f"bytes={zip32_insp['archive_size_bytes']} sha256={sha256_file(zip32_path)[:16]}...",
        )

        # Confirm ZIP32 is REJECTED by ZIP64 verifier
        zip32_rejected = False
        try:
            assert_python312_zip64(zip32_insp, expected_member_name="eicar.txt", expected_uncompressed_size=len(EICAR_PAYLOAD))
        except ValueError:
            zip32_rejected = True
        check("ZIP64 verifier rejects ZIP32 archive", zip32_rejected, "fail-closed")

        # Small MaxFileSize ZIP32 fixture verification
        maxfs_path = tmp_path / "small-zip32-maxfilesize.zip"
        maxfs_payload = b"A" * SMALL_MAXFILESIZE_MEMBER_BYTES
        with zipfile.ZipFile(maxfs_path, "w", allowZip64=False) as zf:
            zf.writestr(_zip_member("oversized-member.txt"), maxfs_payload)
        maxfs_bytes = maxfs_path.read_bytes()
        maxfs_insp = inspect_zip_binary(maxfs_bytes)
        assert_strict_zip32(maxfs_insp, expected_member_name="oversized-member.txt", expected_uncompressed_size=SMALL_MAXFILESIZE_MEMBER_BYTES)
        check(
            "small ZIP32 MaxFileSize fixture fits reduced limit envelope",
            len(maxfs_bytes) < REDUCED_MAX_FILE_SIZE_BYTES < len(maxfs_payload) < REDUCED_MAX_SCAN_SIZE_BYTES,
            f"compressed={len(maxfs_bytes)}B < MaxFileSize={REDUCED_MAX_FILE_SIZE_BYTES}B < uncompressed={len(maxfs_payload)}B < MaxScanSize={REDUCED_MAX_SCAN_SIZE_BYTES}B",
        )

        # Python 3.12 exact ZIP64 byte reference vector verification
        py312_ref_bytes = _build_python312_zip64_reference_bytes("eicar.txt", EICAR_PAYLOAD)
        py312_ref_path = tmp_path / "eicar-zip64-py312-ref.zip"
        py312_ref_path.write_bytes(py312_ref_bytes)
        _verify_zip_roundtrip(py312_ref_path, "eicar.txt", EICAR_PAYLOAD)
        py312_insp = inspect_zip_binary(py312_ref_bytes)
        assert_python312_zip64(py312_insp, expected_member_name="eicar.txt", expected_uncompressed_size=len(EICAR_PAYLOAD))
        check(
            "binary inspector confirms Python 3.12 ZIP64 LFH/CDH structure & asymmetry",
            py312_insp["summary"]["format_classification"] == "ZIP64_LFH_PYTHON312"
            and py312_insp["summary"]["lfh_cdh_zip64_asymmetry"] is True
            and py312_insp["local_file_headers"][0]["version_needed"] == 45
            and py312_insp["central_directory_headers"][0]["version_needed"] == 45,
            f"classification={py312_insp['summary']['format_classification']} asymmetry={py312_insp['summary']['lfh_cdh_zip64_asymmetry']}",
        )

        # Full ZIP64 archive (with CDH 0x0001 + ZIP64 EOCD + Locator) verification
        full_z64_bytes = _build_full_zip64_reference_bytes("eicar.txt", EICAR_PAYLOAD)
        full_z64_insp = inspect_zip_binary(full_z64_bytes)
        assert_python312_zip64(full_z64_insp, expected_member_name="eicar.txt", expected_uncompressed_size=len(EICAR_PAYLOAD))
        check(
            "binary inspector confirms full ZIP64 (LFH + CDH + ZIP64 EOCD/Locator)",
            full_z64_insp["summary"]["format_classification"] == "ZIP64_FULL"
            and full_z64_insp["summary"]["has_zip64_eocd_record"] is True
            and full_z64_insp["summary"]["has_zip64_eocd_locator"] is True,
            f"classification={full_z64_insp['summary']['format_classification']}",
        )

        # Native generate_fixtures check (Python 3.12+ vs fail-closed on Python < 3.12)
        if sys.version_info >= (3, 12):
            manifest = generate_fixtures(tmp_path / "native-fixtures", require_python_312=True)
            check(
                "native Python 3.12+ generate_fixtures succeeds and verifies ZIP64",
                manifest["fixtures"]["eicar_zip64"]["zip_inspection"]["summary"]["format_classification"] == "ZIP64_LFH_PYTHON312",
                f"python={platform.python_version()}",
            )
        else:
            # Verify Python <3.12 fail-closed guard AND verify Python 3.11 non-sentinel LFH is rejected
            guard_rejected = False
            try:
                generate_fixtures(tmp_path / "native-fixtures", require_python_312=True)
            except RuntimeError:
                guard_rejected = True
            check(
                "Python <3.12 fail-closed guard rejects native ZIP64 generation",
                guard_rejected,
                f"local_python={platform.python_version()} requires>=3.12",
            )
            py311_z64_path = tmp_path / "py311-force-zip64.zip"
            with zipfile.ZipFile(py311_z64_path, "w", allowZip64=True) as zf:
                with zf.open(_zip_member("eicar.txt"), "w", force_zip64=True) as target:
                    target.write(EICAR_PAYLOAD)
            py311_insp = inspect_zip_binary(py311_z64_path.read_bytes())
            py311_rejected = False
            try:
                assert_python312_zip64(py311_insp, expected_member_name="eicar.txt", expected_uncompressed_size=len(EICAR_PAYLOAD))
            except ValueError:
                py311_rejected = True
            check(
                "binary ZIP64 verifier catches Python 3.11 non-sentinel LFH",
                py311_rejected and py311_insp["summary"]["format_classification"] == "ZIP64_PARTIAL_NON_SENTINEL",
                f"classification={py311_insp['summary']['format_classification']}",
            )
            not_verified.append(
                f"native_python312_zip64_generation (local Python is {platform.python_version()}; workflow pins Python 3.12)"
            )

        # 6. Loopback mock TCP protocol framing self-test (NOT live ClamAV!)
        class MockClamdHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                req = bytearray()
                while b"\x00" not in req and len(req) < 64:
                    part = self.request.recv(64)
                    if not part:
                        return
                    req.extend(part)
                nul_pos = req.index(b"\x00")
                cmd = bytes(req[:nul_pos])
                remainder = bytes(req[nul_pos + 1:])
                if cmd == b"zPING":
                    self.request.sendall(b"PONG\x00")
                    return
                if cmd == b"zVERSION":
                    self.request.sendall(b"ClamAV 1.5.4/27890/Mon Nov 16 09:00:00 2026\x00")
                    return
                if cmd == b"zINSTREAM":
                    buf = bytearray(remainder)
                    stream_data = bytearray()
                    while True:
                        while len(buf) < 4:
                            part = self.request.recv(4096)
                            if not part:
                                return
                            buf.extend(part)
                        chunk_len = struct.unpack(">I", bytes(buf[:4]))[0]
                        del buf[:4]
                        if chunk_len == 0:
                            break
                        while len(buf) < chunk_len:
                            part = self.request.recv(4096)
                            if not part:
                                return
                            buf.extend(part)
                        stream_data.extend(buf[:chunk_len])
                        del buf[:chunk_len]
                    raw_payload = bytes(stream_data)
                    if raw_payload == b"SLEEP_TIMEOUT":
                        time.sleep(0.4)
                        return
                    if raw_payload == CLEAN_PAYLOAD:
                        self.request.sendall(b"stream: OK\x00")
                    elif EICAR_PAYLOAD in raw_payload:
                        self.request.sendall(b"stream: Win.Test.EICAR_HDB-1 FOUND\x00")
                    else:
                        self.request.sendall(b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00")

        class ReusableTCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        with ReusableTCPServer(("127.0.0.1", 0), MockClamdHandler) as server:
            host, port = server.server_address
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                p = clamd_simple_command(host, port, "zPING", timeout_seconds=5.0)
                check("mock TCP zPING framing", p["ok"] and p["text"] == "PONG", str(p["raw_response_repr"]))
                v = clamd_simple_command(host, port, "zVERSION", timeout_seconds=5.0)
                vp = parse_zversion(v.get("text"))
                check(
                    "mock TCP zVERSION parsing",
                    vp is not None and vp["engine_version"] == "1.5.4" and vp["signature_db_version"] == "27890",
                    str(vp),
                )
                r_clean = clamd_instream_scan(host, port, CLEAN_PAYLOAD, timeout_seconds=5.0)
                check("mock TCP zINSTREAM CLEAN", r_clean["verdict"] == VERDICT_CLEAN and r_clean["nul_terminated"], r_clean["raw_response_repr"])
                r_eicar = clamd_instream_scan(host, port, EICAR_PAYLOAD, timeout_seconds=5.0)
                check("mock TCP zINSTREAM INFECTED", r_eicar["verdict"] == VERDICT_INFECTED and r_eicar["signature"] == "Win.Test.EICAR_HDB-1", r_eicar["raw_response_repr"])
                r_limit = clamd_instream_scan(host, port, maxfs_bytes, timeout_seconds=5.0)
                check("mock TCP zINSTREAM LIMIT ALERT", r_limit["verdict"] == VERDICT_LIMIT_ALERT and r_limit["signature"] == EXPECTED_MAX_FILE_SIZE_ALERT, r_limit["raw_response_repr"])
                r_timeout = clamd_instream_scan(host, port, b"SLEEP_TIMEOUT", timeout_seconds=0.1)
                check("mock TCP zINSTREAM TIMEOUT", r_timeout["verdict"] == VERDICT_TIMEOUT, r_timeout["detail"])
            finally:
                server.shutdown()

        # Closed port -> UNAVAILABLE
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unused_sock:
            unused_sock.bind(("127.0.0.1", 0))
            closed_port = unused_sock.getsockname()[1]
        r_unavail = clamd_instream_scan("127.0.0.1", closed_port, CLEAN_PAYLOAD, timeout_seconds=2.0)
        check("closed port -> UNAVAILABLE", r_unavail["verdict"] == VERDICT_UNAVAILABLE, r_unavail["detail"])

        # 7. Report assembly with incomplete profiles -> marks missing as NOT VERIFIED and overall FAIL
        ev_dir = tmp_path / "evidence"
        partial_report = assemble_report(
            evidence_dir=ev_dir,
            run_id="selftest-0",
            run_attempt="1",
            commit_sha="0" * 40,
            repository="mansour1414/DIP-Document-Intelligence-Platform",
            ref="refs/heads/main",
            image_ref="ghcr.io/mansour1414/dip-clamav@sha256:" + "0" * 64,
            expected_engine="1.5.4",
            expected_package_version="1.5.4+dfsg-0ubuntu0.22.04.1",
        )
        check(
            "assemble-report marks absent profiles NOT VERIFIED and overall FAIL",
            partial_report["overall_status"] == STATUS_FAIL
            and partial_report["classifications"]["counts"]["not_verified"] == 8
            and (ev_dir / "phase0a-evidence.json").is_file()
            and (ev_dir / "phase0a-evidence-summary.md").is_file()
            and (ev_dir / "artifact-files.sha256").is_file(),
            f"overall={partial_report['overall_status']} not_verified={partial_report['classifications']['counts']['not_verified']}",
        )

        # 8. End-to-end synthetic profile + report assembly comparison (PASS vs E1 silent truncation vs D ZIP64 bypass)
        def _synthetic_profile(profile_name: str, responses: dict[str, bytes], conf_text: str) -> dict[str, Any]:
            cases = []
            for case_id, fid, expectation, desc in PROFILE_PLANS[profile_name]:
                ev = evaluate_case(case_id, expectation, classify_clamd_response(responses[case_id]))
                ev["description"] = desc
                ev["fixture_id"] = fid
                cases.append(ev)
            return {
                "profile": profile_name,
                "collected_at_utc": utc_now_iso(),
                "elapsed_ms_total": 1.0,
                "scanner": {
                    "port": 3310,
                    "zping": {"ok": True, "raw_response_repr": "PONG\\0", "nul_terminated": True, "elapsed_ms": 0.2},
                    "zversion": {
                        "ok": True,
                        "raw_response_repr": "ClamAV 1.5.4/27890/Mon Nov 16 09:00:00 2026\\0",
                        "nul_terminated": True,
                        "elapsed_ms": 0.2,
                        "parsed": parse_zversion("ClamAV 1.5.4/27890/Mon Nov 16 09:00:00 2026"),
                    },
                    "effective_config": parse_clamconf_clamd_section(conf_text),
                    "container_stats": None,
                },
                "cases": cases,
            }

        cand_conf = sample_conf_yes.replace('"16384"', '"115343360"').replace('"524288"', '"419430400"').replace('"1048576"', '"115343360"')
        for scenario_name, e1_raw, d_raw, exp_overall, exp_sec_fail, exp_changed, exp_silent in (
            (
                "all-pass",
                b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00",
                b"stream: Win.Test.EICAR_HDB-1 FOUND\x00",
                STATUS_PASS,
                0,
                True,
                False,
            ),
            (
                "e1-silent-truncation",
                b"stream: OK\x00",
                b"stream: Win.Test.EICAR_HDB-1 FOUND\x00",
                STATUS_FAIL,
                1,
                False,
                True,
            ),
            (
                "d-zip64-silent-clean",
                b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00",
                b"stream: OK\x00",
                STATUS_FAIL,
                1,
                True,
                False,
            ),
        ):
            s_dir = tmp_path / f"ev-{scenario_name}"
            s_dir.mkdir(parents=True, exist_ok=True)
            (s_dir / "profile-candidate.json").write_text(json.dumps(_synthetic_profile(
                "candidate",
                {
                    "A_clean": b"stream: OK\x00",
                    "B_eicar_direct": b"stream: Win.Test.EICAR_HDB-1 FOUND\x00",
                    "C_eicar_zip32": b"stream: Win.Test.EICAR_HDB-1 FOUND\x00",
                    "D_eicar_zip64": d_raw,
                },
                cand_conf,
            )), encoding="utf-8")
            (s_dir / "profile-reduced-alert-yes.json").write_text(json.dumps(_synthetic_profile(
                "reduced_alert_yes",
                {
                    "E0_yes_eicar_zip32_control": b"stream: Win.Test.EICAR_HDB-1 FOUND\x00",
                    "E1_yes_small_zip32_maxfilesize": e1_raw,
                },
                sample_conf_yes,
            )), encoding="utf-8")
            (s_dir / "profile-reduced-alert-no.json").write_text(json.dumps(_synthetic_profile(
                "reduced_alert_no",
                {
                    "E0_no_eicar_zip32_control": b"stream: Win.Test.EICAR_HDB-1 FOUND\x00",
                    "E2_no_small_zip32_maxfilesize": b"stream: OK\x00",
                },
                sample_conf_no,
            )), encoding="utf-8")
            rep = assemble_report(
                evidence_dir=s_dir,
                run_id="selftest-0",
                run_attempt="1",
                commit_sha="0" * 40,
                repository="mansour1414/DIP-Document-Intelligence-Platform",
                ref="refs/heads/main",
                image_ref="ghcr.io/mansour1414/dip-clamav@sha256:" + "0" * 64,
                expected_engine="1.5.4",
                expected_package_version="1.5.4+dfsg-0ubuntu0.22.04.1",
            )
            cmp_r = rep["alert_exceeds_max_comparison"]
            check(
                f"report scenario:{scenario_name}",
                rep["overall_status"] == exp_overall
                and rep["classifications"]["counts"]["security_failures"] == exp_sec_fail
                and cmp_r["alert_exceeds_max_changed_verdict"] is exp_changed
                and cmp_r["silent_truncation_observed_with_alert_yes"] is exp_silent,
                f"overall={rep['overall_status']} sec_fail={rep['classifications']['counts']['security_failures']} changed={cmp_r['alert_exceeds_max_changed_verdict']} silent={cmp_r['silent_truncation_observed_with_alert_yes']}",
            )

    print(f"### SELFTEST_PASS={passed} SELFTEST_FAIL={failed} SELFTEST_NOT_VERIFIED={len(not_verified)}")
    for item in not_verified:
        print(f"NOT_VERIFIED | {item}")
    return 0 if failed == 0 else 1


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DIP Phase 0A isolated ClamAV 1.5.4 evidence tool.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline bounded self-tests (no Docker/ClamAV required).",
    )
    sub = parser.add_subparsers(dest="command")

    p_gen = sub.add_parser("generate-fixtures", help="Generate bounded Phase 0A test fixtures.")
    p_gen.add_argument("--output-dir", required=True, type=Path)
    p_gen.add_argument("--manifest-out", required=True, type=Path)
    p_gen.add_argument("--require-python-312", action="store_true", default=True)

    p_scan = sub.add_parser("scan-profile", help="Run scans for one isolated scanner profile.")
    p_scan.add_argument("--profile", required=True, choices=tuple(PROFILE_PLANS.keys()))
    p_scan.add_argument("--host", required=True)
    p_scan.add_argument("--port", type=int, default=3310)
    p_scan.add_argument("--fixtures-dir", required=True, type=Path)
    p_scan.add_argument("--manifest", required=True, type=Path)
    p_scan.add_argument("--expected-engine", required=True)
    p_scan.add_argument("--clamconf-file", required=True, type=Path)
    p_scan.add_argument("--expected-alert-exceeds-max", required=True, choices=("yes", "no"))
    p_scan.add_argument("--timeout-seconds", type=float, default=DEFAULT_SOCKET_TIMEOUT_SECONDS)
    p_scan.add_argument("--container-stats-file", type=Path, default=None)
    p_scan.add_argument("--output", required=True, type=Path)

    p_rep = sub.add_parser("assemble-report", help="Assemble bounded Phase 0A JSON/Markdown evidence.")
    p_rep.add_argument("--evidence-dir", required=True, type=Path)
    p_rep.add_argument("--run-id", required=True)
    p_rep.add_argument("--run-attempt", required=True)
    p_rep.add_argument("--commit-sha", required=True)
    p_rep.add_argument("--repository", required=True)
    p_rep.add_argument("--ref", required=True)
    p_rep.add_argument("--image-ref", required=True)
    p_rep.add_argument("--expected-engine", required=True)
    p_rep.add_argument("--expected-package-version", required=True)
    p_rep.add_argument("--fail-on-non-pass", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    apply_process_limits()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if args.command == "generate-fixtures":
        manifest = generate_fixtures(args.output_dir, require_python_312=args.require_python_312)
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"PHASE0A_FIXTURES_PASS count={len(manifest['fixtures'])} python={manifest['python_version']}")
        for fid, meta in manifest["fixtures"].items():
            zip_insp = meta.get("zip_inspection")
            fmt = zip_insp["summary"]["format_classification"] if zip_insp else "RAW"
            print(f"FIXTURE | {fid} | {meta['filename']} | bytes={meta['size_bytes']} | uncomp={meta['uncompressed_size_bytes']} | fmt={fmt} | sha256={meta['sha256']}")
        return 0

    if args.command == "scan-profile":
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        clamconf_text = args.clamconf_file.read_text(encoding="utf-8")
        container_stats = None
        if args.container_stats_file and args.container_stats_file.is_file():
            raw_stats = args.container_stats_file.read_text(encoding="utf-8").strip()
            if raw_stats:
                try:
                    container_stats = json.loads(raw_stats)
                except json.JSONDecodeError:
                    container_stats = {"raw": raw_stats[:512]}
        result = run_scan_profile(
            profile=args.profile,
            host=args.host,
            port=args.port,
            fixtures_dir=args.fixtures_dir,
            manifest=manifest,
            expected_engine=args.expected_engine,
            clamconf_text=clamconf_text,
            expected_alert_exceeds_max=args.expected_alert_exceeds_max,
            timeout_seconds=args.timeout_seconds,
            container_stats=container_stats,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        for case in result["cases"]:
            scan = case["scan"]
            print(
                f"{case['status']} | {case['case_id']} | verdict={scan['verdict']} | "
                f"security_failure={case['security_failure']} | nul={scan['nul_terminated']} | "
                f"raw={scan['raw_response_repr']} | elapsed_ms={scan['elapsed_ms']}"
            )
        return 0

    if args.command == "assemble-report":
        report = assemble_report(
            evidence_dir=args.evidence_dir,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            commit_sha=args.commit_sha,
            repository=args.repository,
            ref=args.ref,
            image_ref=args.image_ref,
            expected_engine=args.expected_engine,
            expected_package_version=args.expected_package_version,
        )
        counts = report["classifications"]["counts"]
        print(
            f"PHASE0A_REPORT | overall={report['overall_status']} | "
            f"pass={counts['pass']} fail={counts['fail']} not_verified={counts['not_verified']} "
            f"security_failures={counts['security_failures']}"
        )
        if args.fail_on_non_pass and report["overall_status"] != STATUS_PASS:
            return 1
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
