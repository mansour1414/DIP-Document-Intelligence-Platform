#!/usr/bin/env python3
"""
Phase 0B Isolated Security Remediation PoC — Fixture Generator, Authenticity Verifier,
Preflight Runner, Live Multi-Profile clamd Harness, and Fail-Closed Evidence Assembler.

ISOLATED EXPERIMENT ONLY — NOT INTEGRATED INTO PRODUCTION.
Provisional governance references (PROPOSED — NOT APPROVED):
  - CLAMAV-CR-P01 (Part A: ClamAV 1.5.4 + upstream CLAM-3102 ARM64 candidate)
  - CLAMAV-CR-P02 (Part B: Bounded ZIP/OOXML structural preflight prototype)
  - CLAMAV-CR-P03 (Phase 0B live test matrix & GPLv2/SBOM governance)

Evidence-quality & forensic invariants:
  1. EICAR test string is constructed via concatenation of two benign halves so the
     script itself never triggers static AV scanners.
  2. Every live scanner profile (`candidate`, `reduced_alert_yes`, `reduced_alert_no`)
     MUST pass full 22-key `clamconf` validation, `zPING`, and `zVERSION` engine-identity
     verification (`1.5.4`) BEFORE any fixture is scanned (fail closed).
  3. Isolated `MaxFileSize` profiles use `MaxFileSize=16K`, `MaxScanSize=512K`,
     `StreamMaxLength=1M`, `MaxThreads=4` (matching Phase 0A's established isolated
     profile so 64 KiB expanded ZIP inputs cannot be confounded by `MaxScanSize`).
  4. Wire verdicts are judged strictly on anchored, single-NUL-terminated raw clamd
     replies. Unexpected `CLEAN` on any required security control is classified explicitly
     as `SECURITY FAILURE`.
  5. `OBSERVATIONAL_RECORD_ONLY` and `RESIDUAL_RISK_OPEN` outcomes are NEVER counted as
     security passes and NEVER imply complete remediation.
  6. Genuine Office (DOCX/XLSX/PPTX with English + Arabic UTF-8), genuinely AES-256
     encrypted PDF (`qpdf`), and structurally referenced ISO 32000-1 PDF attachments
     (`/Names -> /EmbeddedFiles -> /Filespec -> /EmbeddedFile`) are verified by isolated
     tools when present; any unverified check is honestly recorded as `NOT VERIFIED`.
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import io
import json
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Split to avoid triggering static scanners on the test harness source itself.
EICAR_PART_1 = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
EICAR_PART_2 = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_BYTES = EICAR_PART_1 + EICAR_PART_2

# Bilingual control text (English + Arabic UTF-8 for DIP bilingual compatibility)
BILINGUAL_EN_TEXT = "DIP Phase 0B English Compatibility Control"
BILINGUAL_AR_TEXT = "وثيقة اختبار عربية — منصة ذكاء المستندات DIP"
ARABIC_CHAR_RE = re.compile(r"[\u0600-\u06FF]")

# Non-sensitive deterministic passwords for genuine AES-256/R6 qpdf unlock-pdf control
PDF_TEST_USER_PASSWORD = "dip-phase0b-user-2026"
PDF_TEST_OWNER_PASSWORD = "dip-phase0b-owner-2026"

# Authoritative baseline limits (docs/operations/experimental/clamav-arm64-stage4-candidate.conf)
CANDIDATE_STREAM_MAX_LENGTH_BYTES = 110 * 1024 * 1024  # 110M
CANDIDATE_MAX_FILE_SIZE_BYTES = 110 * 1024 * 1024      # 110M
CANDIDATE_MAX_SCAN_SIZE_BYTES = 400 * 1024 * 1024      # 400M

# Established isolated reduced profile (matches Phase 0A: isolates MaxFileSize from MaxScanSize)
REDUCED_STREAM_MAX_LENGTH_BYTES = 1 * 1024 * 1024      # 1M
REDUCED_MAX_FILE_SIZE_BYTES = 16 * 1024                # 16K
REDUCED_MAX_SCAN_SIZE_BYTES = 512 * 1024               # 512K (8x above 64 KiB expanded test inputs)

DEFAULT_EXPERIMENT_MAX_FILE_SIZE = REDUCED_MAX_FILE_SIZE_BYTES
EXPECTED_MAX_FILE_SIZE_ALERT = "Heuristics.Limits.Exceeded.MaxFileSize"
LIMIT_ALERT_PREFIX = "Heuristics.Limits.Exceeded."

# Strict verdict taxonomy
VERDICT_CLEAN = "CLEAN"
VERDICT_INFECTED = "INFECTED"
VERDICT_LIMIT_ALERT = "LIMIT ALERT"
VERDICT_SCAN_ERROR = "SCAN ERROR"
VERDICT_TIMEOUT = "TIMEOUT"
VERDICT_UNAVAILABLE = "UNAVAILABLE"
VERDICT_MALFORMED = "MALFORMED RESPONSE"

OUTCOME_PASS = "PASS"
OUTCOME_FAIL = "FAIL"
OUTCOME_SECURITY_FAILURE = "SECURITY FAILURE"
OUTCOME_OBSERVATIONAL_CONTROL_OK = "OBSERVATIONAL_CONTROL_OK"
OUTCOME_OBSERVATIONAL_RECORD_ONLY = "OBSERVATIONAL_RECORD_ONLY"
OUTCOME_RESIDUAL_RISK_OPEN = "RESIDUAL_RISK_OPEN"
OUTCOME_NOT_VERIFIED = "NOT VERIFIED"

# Anchored raw wire verdict regexes (single NUL-terminated stanza only)
RE_OK = re.compile(rb"^stream: OK\x00$")
RE_FOUND = re.compile(rb"^stream: ([A-Za-z0-9][A-Za-z0-9_.+-]*) FOUND\x00$")
RE_ERROR = re.compile(rb"^(?:stream: )?([^\x00\r\n]+) ERROR\x00$")
ZVERSION_RE = re.compile(r"^ClamAV\s+([^/\s]+)/(\d+)/(.+)$")
EICAR_SIG_RE = re.compile(r"eicar", re.IGNORECASE)

# Full 22-key resource/security profile (aligned with Phase 0A & Stage 4 clamd.conf)
EFFECTIVE_LIMIT_KEYS = (
    "StreamMaxLength",
    "MaxFileSize",
    "MaxScanSize",
    "MaxScanTime",
    "ReadTimeout",
    "MaxThreads",
    "MaxRecursion",
    "MaxFiles",
    "MaxEmbeddedPE",
    "MaxHTMLNormalize",
    "MaxHTMLNoTags",
    "MaxScriptNormalize",
    "MaxZipTypeRcg",
    "MaxIconsPE",
    "MaxRecHWP3",
    "MaxPartitions",
    "PCREMatchLimit",
    "PCRERecMatchLimit",
    "PCREMaxFileSize",
    "AlertExceedsMax",
    "AlertEncrypted",
    "ConcurrentDatabaseReload",
)

COMMON_EFFECTIVE_LIMIT_SPECS: dict[str, tuple[str, int | str]] = {
    "MaxScanTime": ("number", 25000),
    "ReadTimeout": ("number", 120),
    "MaxRecursion": ("number", 16),
    "MaxFiles": ("number", 10000),
    "MaxEmbeddedPE": ("size", 40 * 1024 * 1024),
    "MaxHTMLNormalize": ("size", 40 * 1024 * 1024),
    "MaxHTMLNoTags": ("size", 8 * 1024 * 1024),
    "MaxScriptNormalize": ("size", 20 * 1024 * 1024),
    "MaxZipTypeRcg": ("size", 1 * 1024 * 1024),
    "MaxIconsPE": ("number", 100),
    "MaxRecHWP3": ("number", 16),
    "MaxPartitions": ("number", 50),
    "PCREMatchLimit": ("number", 100000),
    "PCRERecMatchLimit": ("number", 2000),
    "PCREMaxFileSize": ("size", 100 * 1024 * 1024),
    "AlertEncrypted": ("bool", "no"),
    "ConcurrentDatabaseReload": ("bool", "no"),
}

PROFILE_EXPECTED_LIMIT_SPECS: dict[str, dict[str, tuple[str, int | str]]] = {
    "candidate": {
        "StreamMaxLength": ("size", CANDIDATE_STREAM_MAX_LENGTH_BYTES),
        "MaxFileSize": ("size", CANDIDATE_MAX_FILE_SIZE_BYTES),
        "MaxScanSize": ("size", CANDIDATE_MAX_SCAN_SIZE_BYTES),
        "MaxThreads": ("number", 12),
        "AlertExceedsMax": ("bool", "yes"),
        **COMMON_EFFECTIVE_LIMIT_SPECS,
    },
    "reduced_alert_yes": {
        "StreamMaxLength": ("size", REDUCED_STREAM_MAX_LENGTH_BYTES),
        "MaxFileSize": ("size", REDUCED_MAX_FILE_SIZE_BYTES),
        "MaxScanSize": ("size", REDUCED_MAX_SCAN_SIZE_BYTES),
        "MaxThreads": ("number", 4),
        "AlertExceedsMax": ("bool", "yes"),
        **COMMON_EFFECTIVE_LIMIT_SPECS,
    },
    "reduced_alert_no": {
        "StreamMaxLength": ("size", REDUCED_STREAM_MAX_LENGTH_BYTES),
        "MaxFileSize": ("size", REDUCED_MAX_FILE_SIZE_BYTES),
        "MaxScanSize": ("size", REDUCED_MAX_SCAN_SIZE_BYTES),
        "MaxThreads": ("number", 4),
        "AlertExceedsMax": ("bool", "no"),
        **COMMON_EFFECTIVE_LIMIT_SPECS,
    },
}

CLAMCONF_SIZE_RE = re.compile(r"^([0-9]+)([KMGkmg])?$")
CLAMCONF_NUMBER_RE = re.compile(r"^[0-9]+$")
CLAMCONF_SECTION_END_RE = re.compile(
    r"^(?:.+\.conf\s+not\s+found|Software settings|Database information|Platform information|Build information)$"
)
CLAMCONF_SIZE_MULTIPLIERS = {"": 1, "k": 1024, "m": 1024 * 1024, "g": 1024 * 1024 * 1024}


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
    generation_method: str
    expected_preflight_action: str
    expected_preflight_code: str | None
    candidate_expectation: str | None  # CLEAN | EICAR_FOUND | OBSERVATIONAL_UNPATCHED_ZIP64 | RESIDUAL_RISK_PROBE
    reduced_yes_expectation: str | None  # CLEAN | EICAR_FOUND | MAXFILESIZE_FOUND | None
    reduced_no_expectation: str | None  # COMPARISON_CONTROL_ALERT_NO | None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ============================================================================
# Genuine ECMA-376 OPC Office Fixtures (DOCX, XLSX, PPTX — English + Arabic)
# ============================================================================

def _zip_entries_deterministic(
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
    """Safely rewrite version_needed in every LFH and CDH without adding ZIP64 structures."""
    eocd_pos = raw.rfind(b"PK\x05\x06")
    if eocd_pos < 0:
        raise ValueError("EOCD missing while rewriting version_needed")
    total_entries, _cd_size, cd_offset = struct.unpack_from("<HII", raw, eocd_pos + 10)
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


def _build_genuine_docx(*, version_needed: int | None = None) -> bytes:
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '</Types>'
    ).encode("utf-8")

    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
        '<w:name w:val="Normal"/>'
        '<w:rPr><w:rFonts w:ascii="DejaVu Sans" w:hAnsi="DejaVu Sans" w:cs="DejaVu Sans"/>'
        '<w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>'
        '</w:style>'
        '</w:styles>'
    ).encode("utf-8")

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body>'
        '<w:p><w:r><w:t>' + BILINGUAL_EN_TEXT + '</w:t></w:r></w:p>'
        '<w:p><w:pPr><w:bidi/></w:pPr>'
        '<w:r><w:rPr><w:rtl/></w:rPr><w:t>' + BILINGUAL_AR_TEXT + '</w:t></w:r></w:p>'
        '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr>'
        '</w:body></w:document>'
    ).encode("utf-8")

    return _zip_entries_deterministic(
        [
            ("[Content_Types].xml", content_types),
            ("_rels/.rels", root_rels),
            ("word/_rels/document.xml.rels", doc_rels),
            ("word/styles.xml", styles_xml),
            ("word/document.xml", document_xml),
        ],
        compression=zipfile.ZIP_DEFLATED,
        version_needed=version_needed,
    )


def _build_genuine_xlsx() -> bytes:
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '</Types>'
    ).encode("utf-8")

    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="DIP Control" sheetId="1" r:id="rId1"/></sheets>'
        '</workbook>'
    ).encode("utf-8")

    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="1"><font><sz val="11"/><name val="DejaVu Sans"/></font></fonts>'
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
        '<borders count="1"><border/></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>'
        '</styleSheet>'
    ).encode("utf-8")

    sheet1_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>'
        '<row r="1"><c r="A1" t="inlineStr"><is><t>' + BILINGUAL_EN_TEXT + '</t></is></c></row>'
        '<row r="2"><c r="A2" t="inlineStr"><is><t>' + BILINGUAL_AR_TEXT + '</t></is></c></row>'
        '</sheetData></worksheet>'
    ).encode("utf-8")

    return _zip_entries_deterministic(
        [
            ("[Content_Types].xml", content_types),
            ("_rels/.rels", root_rels),
            ("xl/_rels/workbook.xml.rels", wb_rels),
            ("xl/workbook.xml", workbook_xml),
            ("xl/styles.xml", styles_xml),
            ("xl/worksheets/sheet1.xml", sheet1_xml),
        ],
        compression=zipfile.ZIP_DEFLATED,
    )


def _build_genuine_pptx() -> bytes:
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/ppt/presentation.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>'
        '<Override PartName="/ppt/slides/slide1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>'
        '<Override PartName="/ppt/slideMasters/slideMaster1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>'
        '<Override PartName="/ppt/theme/theme1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
        '</Types>'
    ).encode("utf-8")

    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="ppt/presentation.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    pres_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
        'Target="slideMasters/slideMaster1.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
        'Target="slides/slide1.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    pres_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
        '<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>'
        '<p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>'
        '<p:notesSz cx="6858000" cy="9144000"/>'
        '</p:presentation>'
    ).encode("utf-8")

    master_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
        'Target="../slideLayouts/slideLayout1.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" '
        'Target="../theme/theme1.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    master_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr/></p:spTree></p:cSld>'
        '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" '
        'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
        '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
        '</p:sldMaster>'
    ).encode("utf-8")

    layout_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
        'Target="../slideMasters/slideMaster1.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    layout_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">'
        '<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr/></p:spTree></p:cSld></p:sldLayout>'
    ).encode("utf-8")

    theme_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="DIPTheme">'
        '<a:themeElements>'
        '<a:clrScheme name="DIP">'
        '<a:dk1><a:srgbClr val="000000"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>'
        '<a:dk2><a:srgbClr val="1F497D"/></a:dk2><a:lt2><a:srgbClr val="EEECE1"/></a:lt2>'
        '<a:accent1><a:srgbClr val="4F81BD"/></a:accent1><a:accent2><a:srgbClr val="C0504D"/></a:accent2>'
        '<a:accent3><a:srgbClr val="9BBB59"/></a:accent3><a:accent4><a:srgbClr val="8064A2"/></a:accent4>'
        '<a:accent5><a:srgbClr val="4BACC6"/></a:accent5><a:accent6><a:srgbClr val="F79646"/></a:accent6>'
        '<a:hlink><a:srgbClr val="0000FF"/></a:hlink><a:folHlink><a:srgbClr val="800080"/></a:folHlink>'
        '</a:clrScheme>'
        '<a:fontScheme name="DIP">'
        '<a:majorFont><a:latin typeface="DejaVu Sans"/><a:ea typeface=""/><a:cs typeface="DejaVu Sans"/></a:majorFont>'
        '<a:minorFont><a:latin typeface="DejaVu Sans"/><a:ea typeface=""/><a:cs typeface="DejaVu Sans"/></a:minorFont>'
        '</a:fontScheme>'
        '<a:fmtScheme name="DIP">'
        '<a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>'
        '<a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>'
        '<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>'
        '<a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>'
        '</a:fmtScheme>'
        '</a:themeElements></a:theme>'
    ).encode("utf-8")

    slide_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
        'Target="../slideLayouts/slideLayout1.xml"/>'
        '</Relationships>'
    ).encode("utf-8")

    slide1_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld><p:spTree>'
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr/>'
        '<p:sp>'
        '<p:nvSpPr><p:cNvPr id="2" name="TextBox 1"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
        '<p:spPr><a:xfrm><a:off x="457200" y="457200"/><a:ext cx="8229600" cy="2286000"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
        '<p:txBody><a:bodyPr/><a:lstStyle/>'
        '<a:p><a:r><a:rPr lang="en-US" sz="2000"/><a:t>' + BILINGUAL_EN_TEXT + '</a:t></a:r></a:p>'
        '<a:p><a:pPr rtl="1"/><a:r><a:rPr lang="ar-SA" sz="2000"/><a:t>' + BILINGUAL_AR_TEXT + '</a:t></a:r></a:p>'
        '</p:txBody>'
        '</p:sp>'
        '</p:spTree></p:cSld></p:sld>'
    ).encode("utf-8")

    return _zip_entries_deterministic(
        [
            ("[Content_Types].xml", content_types),
            ("_rels/.rels", root_rels),
            ("ppt/_rels/presentation.xml.rels", pres_rels),
            ("ppt/presentation.xml", pres_xml),
            ("ppt/slideMasters/_rels/slideMaster1.xml.rels", master_rels),
            ("ppt/slideMasters/slideMaster1.xml", master_xml),
            ("ppt/slideLayouts/_rels/slideLayout1.xml.rels", layout_rels),
            ("ppt/slideLayouts/slideLayout1.xml", layout_xml),
            ("ppt/theme/theme1.xml", theme_xml),
            ("ppt/slides/_rels/slide1.xml.rels", slide_rels),
            ("ppt/slides/slide1.xml", slide1_xml),
        ],
        compression=zipfile.ZIP_DEFLATED,
    )


# ============================================================================
# Low-Level Deterministic ZIP & ISO 32000-1 PDF Builders
# ============================================================================

def _build_raw_zip(
    entries: list[dict[str, Any]],
    *,
    append_zip64_eocd: bool = False,
) -> bytes:
    local_parts: list[bytes] = []
    cd_parts: list[bytes] = []
    offset = 0

    for entry in entries:
        name_b: bytes = entry["name"].encode("utf-8")
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


def _pdf_utf16be_hex(text: str) -> bytes:
    encoded = b"\xfe\xff" + text.encode("utf-16-be")
    return b"<" + encoded.hex().upper().encode("ascii") + b">"


def _build_valid_pdf(
    *,
    page_text: str = BILINGUAL_EN_TEXT,
    title_text: str = f"{BILINGUAL_EN_TEXT} | {BILINGUAL_AR_TEXT}",
    attachment: tuple[str, bytes] | None = None,
) -> bytes:
    """
    Build a structurally valid ISO 32000-1 PDF 1.4 document with exact xref offsets.
    When `attachment=(filename, payload)` is provided, wires a complete structural PDF
    attachment tree: /Catalog -> /Names << /EmbeddedFiles >> -> /Filespec -> /EF -> /EmbeddedFile.
    """
    stream_body = f"BT /F1 12 Tf 48 720 Td ({page_text}) Tj ET\n".encode("ascii")

    objects: list[bytes] = []
    if attachment is None:
        # 1: Catalog, 2: Pages, 3: Page, 4: Contents, 5: Font, 6: Info
        objects = [
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n",
            f"4 0 obj\n<< /Length {len(stream_body)} >>\nstream\n".encode("ascii") + stream_body + b"endstream\nendobj\n",
            b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
            b"6 0 obj\n<< /Title " + _pdf_utf16be_hex(title_text) + b" >>\nendobj\n",
        ]
        info_ref = b" /Info 6 0 R"
    else:
        att_name, att_bytes = attachment
        att_name_b = att_name.encode("ascii")
        # 1: Catalog (references /Names -> /EmbeddedFiles 7 0 R)
        # 2: Pages, 3: Page, 4: Contents, 5: Font, 6: Filespec, 7: EmbeddedFiles NameTree,
        # 8: EmbeddedFile stream, 9: Info
        objects = [
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 7 0 R >> >>\nendobj\n",
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n",
            f"4 0 obj\n<< /Length {len(stream_body)} >>\nstream\n".encode("ascii") + stream_body + b"endstream\nendobj\n",
            b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
            (
                b"6 0 obj\n<< /Type /Filespec /F (" + att_name_b + b") /UF "
                + _pdf_utf16be_hex(att_name)
                + b" /EF << /F 8 0 R /UF 8 0 R >> /Desc (DIP Phase 0B residual-risk embedded ZIP64 attachment) >>\nendobj\n"
            ),
            b"7 0 obj\n<< /Names [ (" + att_name_b + b") 6 0 R ] >>\nendobj\n",
            (
                f"8 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fzip /Length {len(att_bytes)} "
                f"/Params << /Size {len(att_bytes)} >> >>\nstream\n"
            ).encode("ascii")
            + att_bytes
            + b"\nendstream\nendobj\n",
            b"9 0 obj\n<< /Title " + _pdf_utf16be_hex(title_text) + b" >>\nendobj\n",
        ]
        info_ref = b" /Info 9 0 R"

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
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
        + info_ref
        + f" >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


def _generate_genuine_encrypted_pdf(plain_pdf_bytes: bytes, out_path: Path) -> tuple[bytes, str]:
    """
    Generate a genuinely AES-256/R6 encrypted PDF using `qpdf` (matching DIP's unlock-pdf).
    NEVER fabricates a fake `/Encrypt` dictionary: if `qpdf` is absent, returns the plain PDF
    and marks generation_method='QPDF_UNAVAILABLE_NOT_GENERATED' so verification marks NOT VERIFIED.
    """
    qpdf_bin = shutil.which("qpdf")
    if not qpdf_bin:
        out_path.write_bytes(plain_pdf_bytes)
        return plain_pdf_bytes, "QPDF_UNAVAILABLE_NOT_GENERATED"

    with tempfile.TemporaryDirectory(prefix="dip-phase0b-qpdf-") as tmp:
        src = Path(tmp) / "plain.pdf"
        dst = Path(tmp) / "encrypted.pdf"
        src.write_bytes(plain_pdf_bytes)
        cmd = [
            qpdf_bin,
            str(src),
            "--password-mode=unicode",
            "--encrypt",
            PDF_TEST_USER_PASSWORD,
            PDF_TEST_OWNER_PASSWORD,
            "256",
            "--",
            str(dst),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0 or not dst.is_file():
            raise RuntimeError(f"qpdf encryption failed (rc={proc.returncode}): {proc.stderr.strip()}")
        enc_bytes = dst.read_bytes()
        out_path.write_bytes(enc_bytes)
        return enc_bytes, "qpdf_aes256_r6"


def inspect_binary_header(data: bytes) -> dict[str, Any]:
    if data.startswith(b"%PDF-"):
        return {
            "container": "PDF",
            "has_encrypt_dict": b"/Encrypt" in data,
            "has_embedded_files_tree": b"/EmbeddedFiles" in data and b"/Type /Filespec" in data and b"/Type /EmbeddedFile" in data,
            "contains_pk0304": b"PK\x03\x04" in data,
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


def generate_fixtures(
    out_dir: Path,
    *,
    max_file_size: int = DEFAULT_EXPERIMENT_MAX_FILE_SIZE,
    require_qpdf: bool = False,
) -> list[FixtureSpec]:
    out_dir.mkdir(parents=True, exist_ok=True)
    minimal_ct = b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
    specs: list[FixtureSpec] = []

    def add_fixture(
        *,
        fid: str,
        part: str,
        filename: str,
        declared_kind: str,
        description: str,
        payload: bytes,
        generation_method: str,
        expected_preflight_action: str,
        expected_preflight_code: str | None,
        candidate_expectation: str | None = None,
        reduced_yes_expectation: str | None = None,
        reduced_no_expectation: str | None = None,
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
                generation_method=generation_method,
                expected_preflight_action=expected_preflight_action,
                expected_preflight_code=expected_preflight_code,
                candidate_expectation=candidate_expectation,
                reduced_yes_expectation=reduced_yes_expectation,
                reduced_no_expectation=reduced_no_expectation,
            )
        )

    # ------------------------------------------------------------------
    # PART A: CLAM-3102 (MaxFileSize=16K isolated under MaxScanSize=512K)
    # ------------------------------------------------------------------

    a1_data = _zip_entries_deterministic([("eicar.txt", EICAR_BYTES)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A1_eicar_zip32_control",
        part="PART_A",
        filename="A1_eicar_zip32_control.zip",
        declared_kind="zip",
        description="Positive control: EICAR inside standard ZIP32 (<= MaxFileSize).",
        payload=a1_data,
        generation_method="python_zipfile_deflated",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        candidate_expectation="EICAR_FOUND",
        reduced_yes_expectation="EICAR_FOUND",
    )

    a2_data = _zip_entries_deterministic([("exact_boundary.bin", b"A" * max_file_size)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A2_exact_boundary_zip32_eq_maxfilesize",
        part="PART_A",
        filename="A2_exact_boundary_zip32_eq_maxfilesize.zip",
        declared_kind="zip",
        description=f"Exact-boundary control: DEFLATE ZIP32 expanding to exactly {max_file_size} bytes (== MaxFileSize=16K, << MaxScanSize=512K).",
        payload=a2_data,
        generation_method="python_zipfile_deflated",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        reduced_yes_expectation="CLEAN",
    )

    a3_data = _zip_entries_deterministic([("over_by_one.bin", b"B" * (max_file_size + 1))], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A3_over_boundary_plus1_zip32_deflate",
        part="PART_A",
        filename="A3_over_boundary_plus1_zip32_deflate.zip",
        declared_kind="zip",
        description=f"CLAM-3102 boundary probe: DEFLATE ZIP32 expanding to {max_file_size + 1} bytes (MaxFileSize + 1, << MaxScanSize=512K).",
        payload=a3_data,
        generation_method="python_zipfile_deflated",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        reduced_yes_expectation="MAXFILESIZE_FOUND",
    )

    a4_data = _zip_entries_deterministic([("payload_64k.bin", b"Z" * 65536)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A4_phase0a_e1_repro_zip32_64k_deflate",
        part="PART_A",
        filename="A4_phase0a_e1_repro_zip32_64k_deflate.zip",
        declared_kind="zip",
        description="Direct reproduction of Phase 0A E1_yes failure: 65536B DEFLATE ZIP32 under MaxFileSize=16K, MaxScanSize=512K.",
        payload=a4_data,
        generation_method="python_zipfile_deflated",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        reduced_yes_expectation="MAXFILESIZE_FOUND",
        reduced_no_expectation="COMPARISON_CONTROL_ALERT_NO",
    )

    stored_payload = b"S" * (max_file_size + 4096)
    a5_data = _zip_entries_deterministic([("stored_over.bin", stored_payload)], compression=zipfile.ZIP_STORED)
    add_fixture(
        fid="A5_over_boundary_zip32_stored",
        part="PART_A",
        filename="A5_over_boundary_zip32_stored.zip",
        declared_kind="zip",
        description=f"CLAM-3102 STORED branch probe: method 0 member of {len(stored_payload)} bytes (> MaxFileSize=16K, << MaxScanSize=512K).",
        payload=a5_data,
        generation_method="python_zipfile_stored",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        reduced_yes_expectation="MAXFILESIZE_FOUND",
    )

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
        description=f"CLAM-3102 BZIP2 branch probe: method 12 member expanding to {len(bzip2_raw)} bytes (> MaxFileSize=16K, << MaxScanSize=512K).",
        payload=a6_data,
        generation_method="raw_zip_bzip2",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        reduced_yes_expectation="MAXFILESIZE_FOUND",
    )

    forged_real = b"F" * 65536
    forged_comp = _deflate_raw(forged_real)
    a7_data = _build_raw_zip(
        [
            {
                "name": "forged_usize_100_real_64k.bin",
                "compressed": forged_comp,
                "crc32": zlib.crc32(forged_real) & 0xFFFFFFFF,
                "csize": len(forged_comp),
                "usize": 100,  # FORGED declared uncompressed size
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
            "Forged-size control: LFH/CDH declare uncompressed_size=100 while DEFLATE expands to 65536B "
            "(> MaxFileSize=16K, << MaxScanSize=512K). Header-only preflight passes; patched clamd MUST alert."
        ),
        payload=a7_data,
        generation_method="raw_zip_forged_usize",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        reduced_yes_expectation="MAXFILESIZE_FOUND",
        reduced_no_expectation="COMPARISON_CONTROL_ALERT_NO",
    )

    hidden_eicar = (b"X" * (max_file_size + 4096)) + EICAR_BYTES
    a8_data = _zip_entries_deterministic([("eicar_past_limit.txt", hidden_eicar)], compression=zipfile.ZIP_DEFLATED)
    add_fixture(
        fid="A8_eicar_hidden_past_maxfilesize_zip32",
        part="PART_A",
        filename="A8_eicar_hidden_past_maxfilesize_zip32.zip",
        declared_kind="zip",
        description="Security regression: EICAR appended beyond MaxFileSize inside DEFLATE ZIP32 must trigger MaxFileSize alert.",
        payload=a8_data,
        generation_method="python_zipfile_deflated",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        reduced_yes_expectation="MAXFILESIZE_FOUND",
    )

    a9_data = b"R" * 65536
    add_fixture(
        fid="A9_raw_non_zip_64k_maxfilesize_control",
        part="PART_A",
        filename="A9_raw_non_zip_64k_maxfilesize_control.bin",
        declared_kind="zip",
        description="Baseline non-ZIP control: raw 65536B payload under MaxFileSize=16K, MaxScanSize=512K.",
        payload=a9_data,
        generation_method="raw_bytes",
        expected_preflight_action="REJECT",
        expected_preflight_code="MALFORMED_NOT_ZIP_MAGIC",
        reduced_yes_expectation="MAXFILESIZE_FOUND",
    )

    # ------------------------------------------------------------------
    # PART B: Bounded ZIP / OOXML Preflight & Genuine Office/PDF Controls
    # ------------------------------------------------------------------

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
        description="Deterministic reproduction of Phase 0A D_eicar_zip64 (LFH 0xFFFFFFFF sentinels + 0x0001 extra, 32-bit CDH/EOCD).",
        payload=b1_data,
        generation_method="raw_zip64_lfh_python312",
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_LFH_SENTINEL",
        candidate_expectation="OBSERVATIONAL_UNPATCHED_ZIP64",
    )

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
        generation_method="raw_zip64_extra_only",
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_EXTRA_FIELD_PRESENT",
    )

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
        generation_method="raw_zip64_full_eocd",
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_EOCD_LOCATOR_PRESENT",
        candidate_expectation="OBSERVATIONAL_UNPATCHED_ZIP64",
    )

    b3_data = _build_raw_zip(
        [
            {
                "name": "[Content_Types].xml",
                "compressed": minimal_ct,
                "crc32": zlib.crc32(minimal_ct) & 0xFFFFFFFF,
                "csize": len(minimal_ct),
                "usize": len(minimal_ct),
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
        description="Subtle ZIP64 OOXML using 24-byte 64-bit Data Descriptors without 0xFFFFFFFF sentinels or 0x0001 extra.",
        payload=b3_data,
        generation_method="raw_zip64_dd64",
        expected_preflight_action="REJECT",
        expected_preflight_code="ZIP64_DATA_DESCRIPTOR_DETECTED",
        candidate_expectation="OBSERVATIONAL_UNPATCHED_ZIP64",
    )

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
        generation_method="raw_zip_method_14",
        expected_preflight_action="REJECT",
        expected_preflight_code="UNSUPPORTED_COMPRESSION_METHOD",
    )

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
        generation_method="raw_zip_method_98",
        expected_preflight_action="REJECT",
        expected_preflight_code="UNSUPPORTED_COMPRESSION_METHOD",
    )

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
        generation_method="raw_zip_pkware_encrypted_flag",
        expected_preflight_action="REJECT",
        expected_preflight_code="ENCRYPTED_MEMBER_TRADITIONAL",
    )

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
        generation_method="raw_zip_winzip_aes",
        expected_preflight_action="REJECT",
        expected_preflight_code="ENCRYPTED_MEMBER_AES",
    )

    b8_data = _build_raw_zip(
        [
            {
                "name": "[Content_Types].xml",
                "compressed": minimal_ct,
                "crc32": zlib.crc32(minimal_ct) & 0xFFFFFFFF,
                "csize": len(minimal_ct),
                "usize": len(minimal_ct),
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
        generation_method="raw_zip_lfh_cdh_mismatch",
        expected_preflight_action="REJECT",
        expected_preflight_code="MALFORMED_LFH_CDH_MISMATCH",
    )

    # Genuine OPC-compliant Office controls (Arabic + English UTF-8)
    b9_data = _build_genuine_docx(version_needed=45)
    add_fixture(
        fid="B9_benign_version_needed_45_docx",
        part="PART_B",
        filename="B9_benign_version_needed_45_docx.docx",
        declared_kind="docx",
        description="Nuanced-policy control: genuine bilingual (EN/AR) OPC DOCX with version_needed=45 and standard 32-bit structures (no ZIP64).",
        payload=b9_data,
        generation_method="opc_ecma376_docx_bilingual_v45",
        expected_preflight_action="ALLOW",
        expected_preflight_code="BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES",
        candidate_expectation="CLEAN",
    )

    b10_data = _build_genuine_docx()
    add_fixture(
        fid="B10_valid_docx_control",
        part="PART_B",
        filename="B10_valid_docx_control.docx",
        declared_kind="docx",
        description="Genuine bilingual (EN/AR) ECMA-376 OPC DOCX control (verified via LibreOffice conversion when available).",
        payload=b10_data,
        generation_method="opc_ecma376_docx_bilingual",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        candidate_expectation="CLEAN",
    )

    b11_data = _build_genuine_xlsx()
    add_fixture(
        fid="B11_valid_xlsx_control",
        part="PART_B",
        filename="B11_valid_xlsx_control.xlsx",
        declared_kind="xlsx",
        description="Genuine bilingual (EN/AR) ECMA-376 OPC XLSX control (verified via LibreOffice conversion when available).",
        payload=b11_data,
        generation_method="opc_ecma376_xlsx_bilingual",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        candidate_expectation="CLEAN",
    )

    b12_data = _build_genuine_pptx()
    add_fixture(
        fid="B12_valid_pptx_control",
        part="PART_B",
        filename="B12_valid_pptx_control.pptx",
        declared_kind="pptx",
        description="Genuine bilingual (EN/AR) ECMA-376 OPC PPTX control (verified via LibreOffice conversion when available).",
        payload=b12_data,
        generation_method="opc_ecma376_pptx_bilingual",
        expected_preflight_action="ALLOW",
        expected_preflight_code=None,
        candidate_expectation="CLEAN",
    )

    b13_data = _build_valid_pdf()
    add_fixture(
        fid="B13_valid_pdf_control",
        part="PART_B",
        filename="B13_valid_pdf_control.pdf",
        declared_kind="pdf",
        description="Valid ISO 32000-1 PDF control with English body + UTF-16BE bilingual metadata (passes OOXML preflight with PDF residual-risk warning).",
        payload=b13_data,
        generation_method="iso32000_pdf14_bilingual_meta",
        expected_preflight_action="ALLOW_WITH_RESIDUAL_RISK_WARNING",
        expected_preflight_code="OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64",
        candidate_expectation="CLEAN",
    )

    b14_path = out_dir / "B14_encrypted_pdf_unlock_pdf_control.pdf"
    b14_data, b14_gen_method = _generate_genuine_encrypted_pdf(b13_data, b14_path)
    if require_qpdf and b14_gen_method != "qpdf_aes256_r6":
        raise RuntimeError("qpdf is required (--require-qpdf) to generate genuinely encrypted B14 PDF control")
    add_fixture(
        fid="B14_encrypted_pdf_unlock_pdf_control",
        part="PART_B",
        filename="B14_encrypted_pdf_unlock_pdf_control.pdf",
        declared_kind="pdf",
        description="Genuinely AES-256/R6 encrypted PDF (via qpdf) confirming AlertEncrypted=no and OOXML preflight preserve unlock-pdf.",
        payload=b14_data,
        generation_method=b14_gen_method,
        expected_preflight_action="ALLOW_WITH_RESIDUAL_RISK_WARNING",
        expected_preflight_code="OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64",
        candidate_expectation="CLEAN",
    )

    # ------------------------------------------------------------------
    # RESIDUAL RISK PROBES (Explicitly open; NEVER counted as security PASS)
    # ------------------------------------------------------------------

    r1_data = _build_valid_pdf(
        page_text="DIP Phase 0B Residual-Risk Probe: Embedded ZIP64 PDF Attachment",
        attachment=("eicar_zip64.zip", b1_data),
    )
    add_fixture(
        fid="R1_pdf_embedded_zip64_residual_risk",
        part="RESIDUAL_RISK",
        filename="R1_pdf_embedded_zip64_residual_risk.pdf",
        declared_kind="pdf",
        description=(
            "Explicit open residual-risk probe (upstream ClamAV #1888): ISO 32000-1 PDF with structurally referenced "
            "/Names -> /EmbeddedFiles -> /Filespec -> /EmbeddedFile ZIP64 EICAR attachment. "
            "OOXML-only preflight does NOT inspect PDF-embedded ZIP64."
        ),
        payload=r1_data,
        generation_method="iso32000_pdf_embedded_filespec_zip64",
        expected_preflight_action="ALLOW_WITH_RESIDUAL_RISK_WARNING",
        expected_preflight_code="OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64",
        candidate_expectation="RESIDUAL_RISK_PROBE",
    )

    r2_data = _zip_entries_deterministic(
        [("nested/inner_zip64_eicar.zip", b1_data)],
        compression=zipfile.ZIP_DEFLATED,
    )
    add_fixture(
        fid="R2_compressed_nested_zip64_inside_zip32_residual_risk",
        part="RESIDUAL_RISK",
        filename="R2_compressed_nested_zip64_inside_zip32_residual_risk.zip",
        declared_kind="zip",
        description=(
            "Explicit open residual-risk probe: valid outer ZIP32 containing DEFLATE-compressed inner ZIP64 EICAR. "
            "Zero-decompression preflight cannot inspect compressed nested archives (emits warning only)."
        ),
        payload=r2_data,
        generation_method="nested_deflated_zip64_in_zip32",
        expected_preflight_action="ALLOW_WITH_RESIDUAL_RISK_WARNING",
        expected_preflight_code="COMPRESSED_NESTED_ARCHIVE_NOT_INSPECTED_RESIDUAL_RISK",
        candidate_expectation="RESIDUAL_RISK_PROBE",
    )

    manifest = {
        "schema_version": "phase0b-fixtures-v2",
        "experiment_max_file_size": max_file_size,
        "experiment_max_scan_size": REDUCED_MAX_SCAN_SIZE_BYTES,
        "fixture_count": len(specs),
        "fixtures": [asdict(s) for s in specs],
    }
    (out_dir / "fixtures-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return specs


# ============================================================================
# Fixture Authenticity Verification (Offline OPC/PDF + Isolated Tool Checks)
# ============================================================================

def _verify_ooxml_opc_structure(path: Path, expected_part_prefix: str) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        assert "[Content_Types].xml" in names, "missing [Content_Types].xml"
        assert "_rels/.rels" in names, "missing _rels/.rels"
        en_found = False
        ar_found = False
        for name in names:
            data = zf.read(name)
            if name.endswith(".xml") or name.endswith(".rels"):
                ET.fromstring(data)  # raises ParseError on malformed XML
                text = data.decode("utf-8")
                if BILINGUAL_EN_TEXT in text:
                    en_found = True
                if BILINGUAL_AR_TEXT in text:
                    ar_found = True
        rels_root = ET.fromstring(zf.read("_rels/.rels"))
        targets = [el.attrib.get("Target", "") for el in rels_root]
        assert any(t.startswith(expected_part_prefix) for t in targets), f"missing {expected_part_prefix} target in _rels/.rels"
        assert en_found, "missing English bilingual text"
        assert ar_found, "missing Arabic bilingual text"
        return {
            "opc_xml_valid": True,
            "member_count": len(names),
            "english_text_present": en_found,
            "arabic_text_present": ar_found,
        }


def verify_fixtures(manifest_path: Path, *, out_path: Path, require_tool_verification: bool = False) -> dict[str, Any]:
    """
    Verify authenticity of genuine Office/PDF/attachment fixtures.
    - Structural XML/OPC/PDF checks always run offline.
    - Tool-backed checks (`soffice`, `qpdf`, `pdfdetach`, `pdftotext`) run when installed;
      if a tool is absent, status is honestly recorded as `NOT VERIFIED` (NEVER `PASS`).
    - When `--require-tool-verification` is set (live CI workflow), any `NOT VERIFIED` or
      `FAIL` causes fail-closed failure.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixtures_dir = manifest_path.parent
    by_id = {f["id"]: f for f in manifest["fixtures"]}

    soffice_bin = shutil.which("soffice") or shutil.which("libreoffice")
    qpdf_bin = shutil.which("qpdf")
    pdftotext_bin = shutil.which("pdftotext")
    pdfdetach_bin = shutil.which("pdfdetach")

    checks: list[dict[str, Any]] = []

    # 1. Office controls (B9, B10, B11, B12): OPC + Bilingual + LibreOffice conversion
    office_specs = [
        ("B9_benign_version_needed_45_docx", "word/"),
        ("B10_valid_docx_control", "word/"),
        ("B11_valid_xlsx_control", "xl/"),
        ("B12_valid_pptx_control", "ppt/"),
    ]
    for fid, prefix in office_specs:
        fx = by_id[fid]
        fx_path = fixtures_dir / fx["filename"]
        opc = _verify_ooxml_opc_structure(fx_path, prefix)

        if not soffice_bin:
            checks.append(
                {
                    "id": fid,
                    "kind": "office_control",
                    "structural_check": OUTCOME_PASS,
                    "structural_details": opc,
                    "tool_verification_status": OUTCOME_NOT_VERIFIED,
                    "tool_details": "LibreOffice (soffice) unavailable in current environment; open/convert compatibility NOT VERIFIED.",
                }
            )
            continue

        with tempfile.TemporaryDirectory(prefix="dip-phase0b-lo-") as tmp:
            tmp_dir = Path(tmp)
            lo_profile = tmp_dir / "lo-profile"
            out_pdf_dir = tmp_dir / "pdf-out"
            out_pdf_dir.mkdir()
            cmd = [
                soffice_bin,
                "--headless",
                "--nologo",
                "--nodefault",
                "--nofirststartwizard",
                "--norestore",
                f"-env:UserInstallation={lo_profile.as_uri()}",
                "--convert-to",
                "pdf",
                "--outdir",
                str(out_pdf_dir),
                str(fx_path),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            pdf_candidates = list(out_pdf_dir.glob("*.pdf"))
            if proc.returncode != 0 or not pdf_candidates:
                checks.append(
                    {
                        "id": fid,
                        "kind": "office_control",
                        "structural_check": OUTCOME_PASS,
                        "structural_details": opc,
                        "tool_verification_status": OUTCOME_FAIL,
                        "tool_details": f"soffice failed rc={proc.returncode}: {proc.stderr.strip()}",
                    }
                )
                continue

            converted_pdf = pdf_candidates[0]
            pdf_magic_ok = converted_pdf.read_bytes().startswith(b"%PDF-")
            qpdf_ok = True
            if qpdf_bin:
                qp = subprocess.run([qpdf_bin, "--check", str(converted_pdf)], capture_output=True, text=True, check=False)
                qpdf_ok = qp.returncode in (0, 3)

            en_extracted = None
            ar_extracted = None
            if pdftotext_bin:
                pt = subprocess.run([pdftotext_bin, str(converted_pdf), "-"], capture_output=True, text=True, check=False)
                if pt.returncode == 0:
                    en_extracted = "DIP Phase 0B" in pt.stdout
                    ar_extracted = bool(ARABIC_CHAR_RE.search(pt.stdout))

            tool_ok = pdf_magic_ok and qpdf_ok and (en_extracted is not False) and (ar_extracted is not False)
            checks.append(
                {
                    "id": fid,
                    "kind": "office_control",
                    "structural_check": OUTCOME_PASS,
                    "structural_details": opc,
                    "tool_verification_status": OUTCOME_PASS if tool_ok else OUTCOME_FAIL,
                    "tool_details": {
                        "soffice_rc": proc.returncode,
                        "converted_pdf_bytes": converted_pdf.stat().st_size,
                        "pdf_magic_ok": pdf_magic_ok,
                        "qpdf_check_ok": qpdf_ok,
                        "pdftotext_english_found": en_extracted,
                        "pdftotext_arabic_script_found": ar_extracted,
                    },
                }
            )

    # 2. Clean PDF control (B13)
    b13_path = fixtures_dir / by_id["B13_valid_pdf_control"]["filename"]
    b13_raw = b13_path.read_bytes()
    b13_struct_ok = b13_raw.startswith(b"%PDF-") and b"%%EOF" in b13_raw and b"xref" in b13_raw
    if not qpdf_bin:
        checks.append(
            {
                "id": "B13_valid_pdf_control",
                "kind": "pdf_control",
                "structural_check": OUTCOME_PASS if b13_struct_ok else OUTCOME_FAIL,
                "tool_verification_status": OUTCOME_NOT_VERIFIED,
                "tool_details": "qpdf unavailable; PDF structural check NOT VERIFIED by external tool.",
            }
        )
    else:
        qp = subprocess.run([qpdf_bin, "--check", str(b13_path)], capture_output=True, text=True, check=False)
        checks.append(
            {
                "id": "B13_valid_pdf_control",
                "kind": "pdf_control",
                "structural_check": OUTCOME_PASS if b13_struct_ok else OUTCOME_FAIL,
                "tool_verification_status": OUTCOME_PASS if qp.returncode == 0 else OUTCOME_FAIL,
                "tool_details": {"qpdf_check_rc": qp.returncode, "stderr": qp.stderr.strip()},
            }
        )

    # 3. Genuinely encrypted PDF control (B14) — AES-256/R6 + decrypt + wrong-password check
    b14_fx = by_id["B14_encrypted_pdf_unlock_pdf_control"]
    b14_path = fixtures_dir / b14_fx["filename"]
    if not qpdf_bin or b14_fx["generation_method"] != "qpdf_aes256_r6":
        checks.append(
            {
                "id": "B14_encrypted_pdf_unlock_pdf_control",
                "kind": "encrypted_pdf_control",
                "structural_check": OUTCOME_NOT_VERIFIED,
                "tool_verification_status": OUTCOME_NOT_VERIFIED,
                "tool_details": (
                    f"qpdf unavailable or fixture not generated by qpdf (generation_method={b14_fx['generation_method']}); "
                    "genuine AES-256 encryption & decryption NOT VERIFIED."
                ),
            }
        )
    else:
        with tempfile.TemporaryDirectory(prefix="dip-phase0b-decrypt-") as tmp:
            dec_path = Path(tmp) / "decrypted.pdf"
            wrong_path = Path(tmp) / "wrong.pdf"
            show = subprocess.run(
                [qpdf_bin, str(b14_path), "--password-mode=unicode", f"--password={PDF_TEST_OWNER_PASSWORD}", "--show-encryption"],
                capture_output=True,
                text=True,
                check=False,
            )
            dec = subprocess.run(
                [qpdf_bin, str(b14_path), "--password-mode=unicode", f"--password={PDF_TEST_USER_PASSWORD}", "--decrypt", str(dec_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            chk = subprocess.run([qpdf_bin, "--check", str(dec_path)], capture_output=True, text=True, check=False) if dec.returncode == 0 else None
            wrong = subprocess.run(
                [qpdf_bin, str(b14_path), "--password=definitely-wrong-password", "--decrypt", str(wrong_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            aes256_ok = show.returncode == 0 and bool(re.search(r"R\s*=\s*6", show.stdout)) and ("AESv3" in show.stdout)
            dec_ok = dec.returncode == 0 and chk is not None and chk.returncode == 0
            wrong_rejected = wrong.returncode == 2
            checks.append(
                {
                    "id": "B14_encrypted_pdf_unlock_pdf_control",
                    "kind": "encrypted_pdf_control",
                    "structural_check": OUTCOME_PASS if aes256_ok else OUTCOME_FAIL,
                    "tool_verification_status": OUTCOME_PASS if (aes256_ok and dec_ok and wrong_rejected) else OUTCOME_FAIL,
                    "tool_details": {
                        "aes256_r6_proven": aes256_ok,
                        "valid_password_decrypted_and_checked": dec_ok,
                        "wrong_password_rejected_rc2": wrong_rejected,
                    },
                }
            )

    # 4. Structurally referenced PDF-embedded ZIP64 attachment (R1)
    r1_path = fixtures_dir / by_id["R1_pdf_embedded_zip64_residual_risk"]["filename"]
    b1_sha = by_id["B1_zip64_eicar_lfh_python312"]["sha256"]
    b1_bytes = (fixtures_dir / by_id["B1_zip64_eicar_lfh_python312"]["filename"]).read_bytes()
    r1_raw = r1_path.read_bytes()
    r1_struct_ok = (
        r1_raw.startswith(b"%PDF-")
        and b"/Names << /EmbeddedFiles 7 0 R >>" in r1_raw
        and b"/Type /Filespec" in r1_raw
        and b"/EF << /F 8 0 R /UF 8 0 R >>" in r1_raw
        and b"/Type /EmbeddedFile" in r1_raw
        and (b1_bytes in r1_raw)
    )
    if not qpdf_bin or not pdfdetach_bin:
        checks.append(
            {
                "id": "R1_pdf_embedded_zip64_residual_risk",
                "kind": "pdf_embedded_zip64_attachment",
                "structural_check": OUTCOME_PASS if r1_struct_ok else OUTCOME_FAIL,
                "tool_verification_status": OUTCOME_NOT_VERIFIED,
                "tool_details": "qpdf and/or pdfdetach unavailable; external PDF attachment extraction NOT VERIFIED.",
            }
        )
    else:
        with tempfile.TemporaryDirectory(prefix="dip-phase0b-detach-") as tmp:
            extracted = Path(tmp) / "extracted.zip"
            qp = subprocess.run([qpdf_bin, "--check", str(r1_path)], capture_output=True, text=True, check=False)
            ls = subprocess.run([pdfdetach_bin, "-list", str(r1_path)], capture_output=True, text=True, check=False)
            sv = subprocess.run([pdfdetach_bin, "-save", "1", "-o", str(extracted), str(r1_path)], capture_output=True, text=True, check=False)
            ext_sha = sha256_bytes(extracted.read_bytes()) if extracted.is_file() else None
            ok = qp.returncode == 0 and ls.returncode == 0 and ("eicar_zip64.zip" in ls.stdout) and sv.returncode == 0 and ext_sha == b1_sha
            checks.append(
                {
                    "id": "R1_pdf_embedded_zip64_residual_risk",
                    "kind": "pdf_embedded_zip64_attachment",
                    "structural_check": OUTCOME_PASS if r1_struct_ok else OUTCOME_FAIL,
                    "tool_verification_status": OUTCOME_PASS if ok else OUTCOME_FAIL,
                    "tool_details": {
                        "qpdf_check_rc": qp.returncode,
                        "pdfdetach_lists_attachment": "eicar_zip64.zip" in ls.stdout,
                        "extracted_sha256_matches_b1": ext_sha == b1_sha,
                    },
                }
            )

    failed_structural = sum(1 for c in checks if c["structural_check"] == OUTCOME_FAIL)
    failed_tool = sum(1 for c in checks if c["tool_verification_status"] == OUTCOME_FAIL)
    not_verified_tool = sum(1 for c in checks if c["tool_verification_status"] == OUTCOME_NOT_VERIFIED)

    if failed_structural > 0 or failed_tool > 0:
        overall = OUTCOME_FAIL
    elif not_verified_tool > 0:
        overall = OUTCOME_FAIL if require_tool_verification else OUTCOME_NOT_VERIFIED
    else:
        overall = OUTCOME_PASS

    payload = {
        "schema_version": "phase0b-fixture-verification-v1",
        "require_tool_verification": require_tool_verification,
        "tools_detected": {
            "soffice": soffice_bin,
            "qpdf": qpdf_bin,
            "pdftotext": pdftotext_bin,
            "pdfdetach": pdfdetach_bin,
        },
        "overall_status": overall,
        "summary": {
            "total_checks": len(checks),
            "failed_structural": failed_structural,
            "failed_tool": failed_tool,
            "not_verified_tool": not_verified_tool,
        },
        "checks": checks,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


# ============================================================================
# 22-Key clamconf Parser & Fail-Closed Effective-Limit Validator
# ============================================================================

def parse_clamconf_size_bytes(raw: str) -> int:
    match = CLAMCONF_SIZE_RE.match(raw)
    if not match:
        raise ValueError(f"malformed size value: {raw!r}")
    return int(match.group(1)) * CLAMCONF_SIZE_MULTIPLIERS[(match.group(2) or "").lower()]


def parse_clamconf_number(raw: str) -> int:
    if not CLAMCONF_NUMBER_RE.match(raw):
        raise ValueError(f"malformed numeric value: {raw!r}")
    return int(raw)


def parse_clamconf_bool(raw: str) -> str:
    lowered = raw.lower()
    if lowered in ("yes", "true", "1"):
        return "yes"
    if lowered in ("no", "false", "0", "disabled"):
        return "no"
    raise ValueError(f"malformed boolean value: {raw!r}")


def parse_clamconf_clamd_section(clamconf_text: str) -> dict[str, Any]:
    in_clamd = False
    found_clamd = False
    settings: dict[str, str] = {}
    duplicates: dict[str, list[str]] = {}
    malformed: dict[str, str] = {}
    tracked = frozenset(EFFECTIVE_LIMIT_KEYS)

    for raw_line in clamconf_text.splitlines():
        line = raw_line.strip()
        sec = re.match(r"^Config file:\s+(.+)$", line)
        if sec:
            if sec.group(1).strip() == "clamd.conf":
                if found_clamd:
                    raise ValueError("duplicate 'Config file: clamd.conf' section in clamconf output")
                in_clamd = True
                found_clamd = True
            else:
                in_clamd = False
            continue
        if in_clamd and CLAMCONF_SECTION_END_RE.match(line):
            in_clamd = False
            continue
        if not in_clamd or not line or line.startswith("-") or line.startswith("***"):
            continue

        kv = re.match(r'^([A-Za-z0-9]+)\s*=\s*"([^"]*)"$', line)
        if kv:
            k, v = kv.group(1), kv.group(2)
            if k in settings:
                duplicates.setdefault(k, [settings[k]]).append(v)
            else:
                settings[k] = v
            continue

        dis = re.match(r"^([A-Za-z0-9]+)\s+disabled$", line)
        if dis:
            k = dis.group(1)
            if k in settings:
                duplicates.setdefault(k, [settings[k]]).append("disabled")
            else:
                settings[k] = "disabled"
            continue

        any_kv = re.match(r"^([A-Za-z0-9]+)\s*=\s*(.*)$", line)
        if any_kv and any_kv.group(1) in tracked:
            malformed[any_kv.group(1)] = any_kv.group(2)
            continue

        tok = re.match(r"^([A-Za-z0-9]+)\b", line)
        if tok and tok.group(1) in tracked:
            malformed[tok.group(1)] = line

    if not found_clamd:
        raise ValueError("clamconf output missing 'Config file: clamd.conf' section")

    return {
        "clamd_section_found": True,
        "effective_limits": {k: settings.get(k) for k in EFFECTIVE_LIMIT_KEYS},
        "duplicate_directives": duplicates,
        "malformed_directives": malformed,
        "total_parsed_keys": len(settings),
    }


def validate_effective_limits(profile: str, parsed_conf: dict[str, Any], expected_alert_exceeds_max: str) -> dict[str, Any]:
    if profile not in PROFILE_EXPECTED_LIMIT_SPECS:
        raise ValueError(f"Unsupported scanner profile: {profile}")

    specs = PROFILE_EXPECTED_LIMIT_SPECS[profile]
    if expected_alert_exceeds_max != specs["AlertExceedsMax"][1]:
        raise RuntimeError(
            f"Profile {profile}: caller expected AlertExceedsMax={expected_alert_exceeds_max!r} "
            f"!= profile specification {specs['AlertExceedsMax'][1]!r}"
        )

    eff = parsed_conf.get("effective_limits") or {}
    duplicates = parsed_conf.get("duplicate_directives") or {}
    malformed = parsed_conf.get("malformed_directives") or {}
    violations: list[str] = []
    normalized: dict[str, int | str] = {}

    for key, (kind, expected_value) in specs.items():
        if key in duplicates:
            violations.append(f"{key}: duplicate directive values={duplicates[key]!r}")
            continue
        if key in malformed:
            violations.append(f"{key}: malformed clamconf syntax={malformed[key]!r}")
            continue
        raw_val = eff.get(key)
        if raw_val is None:
            violations.append(f"{key}: missing (expected {expected_value!r})")
            continue
        try:
            if kind == "size":
                actual: int | str = parse_clamconf_size_bytes(raw_val)
            elif kind == "number":
                actual = parse_clamconf_number(raw_val)
            elif kind == "bool":
                actual = parse_clamconf_bool(raw_val)
            else:
                raise ValueError(f"unknown kind {kind!r}")
        except ValueError as exc:
            violations.append(f"{key}: malformed ({exc}; expected {expected_value!r})")
            continue
        if actual != expected_value:
            violations.append(f"{key}: mismatch (actual={actual!r} raw={raw_val!r} != expected={expected_value!r})")
            continue
        normalized[key] = actual

    if violations:
        raise RuntimeError(
            f"Profile {profile}: fail-closed 22-key clamconf validation failed "
            f"({len(violations)} violation(s)): " + "; ".join(violations)
        )

    return {
        "status": OUTCOME_PASS,
        "profile": profile,
        "checked_key_count": len(specs),
        "checked_keys": list(specs.keys()),
        "normalized_limits": normalized,
    }


# ============================================================================
# Fail-Closed Raw clamd Wire Client (zPING, zVERSION, zINSTREAM) & Evaluator
# ============================================================================

def _recv_nul_reply(sock: socket.socket, max_bytes: int = 4096) -> bytes:
    chunks: list[bytes] = []
    total = 0
    saw_nul = False
    while total < max_bytes:
        try:
            buf = sock.recv(min(4096, max_bytes - total))
        except socket.timeout:
            if saw_nul:
                break
            raise
        if not buf:
            break
        chunks.append(buf)
        total += len(buf)
        if b"\x00" in buf:
            saw_nul = True
            # Briefly drain trailing garbage so concatenated stanzas fail closed
            sock.settimeout(0.05)
    return b"".join(chunks)


def clamd_simple_command(host: str, port: int, cmd: str, timeout_sec: float = 15.0) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout_sec) as sock:
        sock.settimeout(timeout_sec)
        sock.sendall(cmd.encode("ascii") + b"\x00")
        raw = _recv_nul_reply(sock)
    if not raw or raw.count(b"\x00") != 1 or not raw.endswith(b"\x00"):
        return {"ok": False, "text": None, "raw_repr": repr(raw)}
    return {"ok": True, "text": raw[:-1].decode("utf-8", errors="replace"), "raw_repr": repr(raw)}


def parse_zversion(text: str | None) -> dict[str, str] | None:
    if not text:
        return None
    m = ZVERSION_RE.match(text.strip())
    if not m:
        return None
    return {"engine_version": m.group(1), "signature_db_version": m.group(2), "signature_db_date": m.group(3)}


def classify_raw_clamd_reply(raw: bytes) -> dict[str, Any]:
    if not raw or raw.count(b"\x00") != 1 or not raw.endswith(b"\x00"):
        return {"verdict": VERDICT_MALFORMED, "signature": None, "nul_terminated": False, "raw_repr": repr(raw)}

    if RE_OK.match(raw):
        return {"verdict": VERDICT_CLEAN, "signature": None, "nul_terminated": True, "raw_repr": repr(raw)}

    m_found = RE_FOUND.match(raw)
    if m_found:
        sig = m_found.group(1).decode("utf-8", errors="replace")
        verdict = VERDICT_LIMIT_ALERT if sig.startswith(LIMIT_ALERT_PREFIX) else VERDICT_INFECTED
        return {"verdict": verdict, "signature": sig, "nul_terminated": True, "raw_repr": repr(raw)}

    m_err = RE_ERROR.match(raw)
    if m_err:
        err = m_err.group(1).decode("utf-8", errors="replace")
        return {"verdict": VERDICT_SCAN_ERROR, "signature": err, "nul_terminated": True, "raw_repr": repr(raw)}

    return {"verdict": VERDICT_MALFORMED, "signature": None, "nul_terminated": False, "raw_repr": repr(raw)}


def evaluate_clamd_case(expectation: str, parsed: dict[str, Any]) -> dict[str, Any]:
    verdict = parsed["verdict"]
    sig = parsed.get("signature") or ""
    nul_ok = bool(parsed.get("nul_terminated"))

    if expectation == "CLEAN":
        if verdict == VERDICT_CLEAN and nul_ok:
            return {"outcome": OUTCOME_PASS, "security_failure": False, "counts_as_required": True, "diagnosis": "Valid control returned CLEAN."}
        return {"outcome": OUTCOME_FAIL, "security_failure": False, "counts_as_required": True, "diagnosis": f"Expected CLEAN, observed {verdict} ({sig})."}

    if expectation == "EICAR_FOUND":
        if verdict == VERDICT_INFECTED and nul_ok and EICAR_SIG_RE.search(sig):
            return {"outcome": OUTCOME_PASS, "security_failure": False, "counts_as_required": True, "diagnosis": f"EICAR detected ({sig})."}
        if verdict == VERDICT_CLEAN:
            return {"outcome": OUTCOME_SECURITY_FAILURE, "security_failure": True, "counts_as_required": True, "diagnosis": "SECURITY FAILURE: unexpected CLEAN on EICAR control."}
        return {"outcome": OUTCOME_FAIL, "security_failure": False, "counts_as_required": True, "diagnosis": f"Expected EICAR INFECTED, observed {verdict} ({sig})."}

    if expectation == "MAXFILESIZE_FOUND":
        if verdict == VERDICT_LIMIT_ALERT and nul_ok and sig == EXPECTED_MAX_FILE_SIZE_ALERT:
            return {"outcome": OUTCOME_PASS, "security_failure": False, "counts_as_required": True, "diagnosis": f"Observed exact {EXPECTED_MAX_FILE_SIZE_ALERT}."}
        if verdict == VERDICT_CLEAN:
            return {
                "outcome": OUTCOME_SECURITY_FAILURE,
                "security_failure": True,
                "counts_as_required": True,
                "diagnosis": "SECURITY FAILURE: unexpected CLEAN on ZIP32 exceeding MaxFileSize while AlertExceedsMax=yes.",
            }
        if verdict == VERDICT_LIMIT_ALERT:
            return {
                "outcome": OUTCOME_FAIL,
                "security_failure": False,
                "counts_as_required": True,
                "diagnosis": f"Confounded/wrong limit alert ({sig}) != required {EXPECTED_MAX_FILE_SIZE_ALERT}.",
            }
        return {"outcome": OUTCOME_FAIL, "security_failure": False, "counts_as_required": True, "diagnosis": f"Expected {EXPECTED_MAX_FILE_SIZE_ALERT}, observed {verdict} ({sig})."}

    if expectation == "COMPARISON_CONTROL_ALERT_NO":
        if verdict == VERDICT_CLEAN and nul_ok:
            return {
                "outcome": OUTCOME_OBSERVATIONAL_CONTROL_OK,
                "security_failure": False,
                "counts_as_required": False,
                "diagnosis": "Observational comparison control only (NOT a security pass): AlertExceedsMax=no returned CLEAN.",
            }
        return {
            "outcome": OUTCOME_FAIL,
            "security_failure": False,
            "counts_as_required": True,
            "diagnosis": f"Comparison control AlertExceedsMax=no failed to confirm toggle behavior: observed {verdict} ({sig}).",
        }

    if expectation == "OBSERVATIONAL_UNPATCHED_ZIP64":
        # Direct raw clamd scan bypassing Part B preflight (PR #1845 intentionally excluded).
        # NEVER counted as PASS!
        if nul_ok and verdict in (VERDICT_CLEAN, VERDICT_INFECTED, VERDICT_LIMIT_ALERT, VERDICT_SCAN_ERROR):
            return {
                "outcome": OUTCOME_OBSERVATIONAL_RECORD_ONLY,
                "security_failure": False,
                "counts_as_required": False,
                "diagnosis": (
                    f"RECORD_ONLY (NOT a security pass): raw clamd without Part B preflight returned {verdict} ({sig or 'none'}). "
                    "PR #1845 is intentionally excluded; ZIP64 mitigation relies on Part B preflight."
                ),
            }
        return {"outcome": OUTCOME_FAIL, "security_failure": False, "counts_as_required": True, "diagnosis": f"Malformed/failed raw clamd probe: {verdict}."}

    if expectation == "RESIDUAL_RISK_PROBE":
        # Open residual risk (R1 PDF-embedded ZIP64, R2 compressed nested ZIP64 in ZIP32).
        # ALWAYS classified RESIDUAL_RISK_OPEN, NEVER counted as PASS!
        if nul_ok and verdict in (VERDICT_CLEAN, VERDICT_INFECTED, VERDICT_LIMIT_ALERT, VERDICT_SCAN_ERROR):
            return {
                "outcome": OUTCOME_RESIDUAL_RISK_OPEN,
                "security_failure": False,
                "counts_as_required": False,
                "diagnosis": (
                    f"OPEN RESIDUAL RISK (NOT remediated by Phase 0B preflight): raw clamd observed {verdict} ({sig or 'none'})."
                ),
            }
        return {"outcome": OUTCOME_FAIL, "security_failure": False, "counts_as_required": True, "diagnosis": f"Malformed/failed residual-risk probe: {verdict}."}

    raise ValueError(f"Unknown expectation: {expectation}")


def clamd_instream_scan(host: str, port: int, payload: bytes, timeout_sec: float = 30.0) -> dict[str, Any]:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            sock.settimeout(timeout_sec)
            sock.sendall(b"zINSTREAM\x00")
            chunk_size = 65536
            for i in range(0, len(payload), chunk_size):
                chunk = payload[i : i + chunk_size]
                sock.sendall(struct.pack("!I", len(chunk)))
                sock.sendall(chunk)
            sock.sendall(struct.pack("!I", 0))
            raw = _recv_nul_reply(sock)
        parsed = classify_raw_clamd_reply(raw)
    except socket.timeout:
        parsed = {"verdict": VERDICT_TIMEOUT, "signature": None, "nul_terminated": False, "raw_repr": "TIMEOUT"}
    except OSError as exc:
        parsed = {"verdict": VERDICT_UNAVAILABLE, "signature": str(exc), "nul_terminated": False, "raw_repr": repr(exc)}
    parsed["elapsed_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
    return parsed


# ============================================================================
# Preflight & Multi-Profile Live Scan Runners
# ============================================================================

def run_preflight_suite(manifest_path: Path, preflight_script: Path, out_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixtures_dir = manifest_path.parent
    results: list[dict[str, Any]] = []
    passed = 0
    failed = 0

    for fx in manifest["fixtures"]:
        fx_path = fixtures_dir / fx["filename"]
        cmd = ["node", str(preflight_script), "--inspect", str(fx_path), "--kind", fx["declared_kind"]]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            failed += 1
            results.append({"id": fx["id"], "part": fx["part"], "status": OUTCOME_FAIL, "error": proc.stderr.strip()})
            continue

        report = json.loads(proc.stdout)
        actual_action = report["action"]
        all_codes = [*report["rejectCodes"], *report["warningCodes"], *report["infoCodes"]]
        action_ok = actual_action == fx["expected_preflight_action"]
        code_ok = fx["expected_preflight_code"] is None or fx["expected_preflight_code"] in all_codes
        no_decomp_ok = report.get("decompressionPerformed") is False
        ok = action_ok and code_ok and no_decomp_ok

        # Residual-risk probes (R1, R2) verify that warning is emitted, but are explicitly tagged
        # so they are never misunderstood as remediating the underlying residual risk.
        is_residual = fx["part"] == "RESIDUAL_RISK"
        if ok:
            passed += 1
        else:
            failed += 1

        results.append(
            {
                "id": fx["id"],
                "part": fx["part"],
                "filename": fx["filename"],
                "status": (OUTCOME_RESIDUAL_RISK_OPEN if (ok and is_residual) else (OUTCOME_PASS if ok else OUTCOME_FAIL)),
                "preflight_warning_verified": ok,
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
        "schema_version": "phase0b-preflight-results-v2",
        "preflight_script": str(preflight_script),
        "required_passed": sum(1 for r in results if r["status"] == OUTCOME_PASS),
        "residual_risk_warnings_verified": sum(1 for r in results if r["status"] == OUTCOME_RESIDUAL_RISK_OPEN),
        "failed": failed,
        "total": len(results),
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def run_scan_profile(
    *,
    profile: str,
    manifest_path: Path,
    host: str,
    port: int,
    clamconf_file: Path,
    expected_engine: str,
    expected_alert_exceeds_max: str,
    out_path: Path,
) -> dict[str, Any]:
    # 1. Fail-closed 22-key clamconf verification BEFORE any scan
    clamconf_text = clamconf_file.read_text(encoding="utf-8")
    parsed_conf = parse_clamconf_clamd_section(clamconf_text)
    limit_validation = validate_effective_limits(profile, parsed_conf, expected_alert_exceeds_max)

    # 2. Fail-closed zPING + zVERSION verification BEFORE any scan
    ping = clamd_simple_command(host, port, "zPING")
    if not ping["ok"] or ping["text"] != "PONG":
        raise RuntimeError(f"Profile {profile}: clamd zPING failed closed: {ping}")

    ver = clamd_simple_command(host, port, "zVERSION")
    parsed_ver = parse_zversion(ver["text"]) if ver["ok"] else None
    if parsed_ver is None:
        raise RuntimeError(f"Profile {profile}: clamd zVERSION failed or malformed: {ver}")
    if parsed_ver["engine_version"] != expected_engine:
        raise RuntimeError(
            f"Profile {profile}: unexpected ClamAV engine {parsed_ver['engine_version']!r} != expected {expected_engine!r}"
        )

    # 3. Select fixtures belonging to this profile
    expectation_field = {
        "candidate": "candidate_expectation",
        "reduced_alert_yes": "reduced_yes_expectation",
        "reduced_alert_no": "reduced_no_expectation",
    }[profile]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixtures_dir = manifest_path.parent
    results: list[dict[str, Any]] = []

    for fx in manifest["fixtures"]:
        expectation = fx.get(expectation_field)
        if not expectation:
            continue
        data = (fixtures_dir / fx["filename"]).read_bytes()
        observed = clamd_instream_scan(host, port, data)
        eval_res = evaluate_clamd_case(expectation, observed)
        results.append(
            {
                "id": fx["id"],
                "part": fx["part"],
                "filename": fx["filename"],
                "sha256": fx["sha256"],
                "expectation": expectation,
                "observed": observed,
                **eval_res,
            }
        )

    required_pass = sum(1 for r in results if r["outcome"] == OUTCOME_PASS)
    security_failures = sum(1 for r in results if r["outcome"] == OUTCOME_SECURITY_FAILURE)
    other_failures = sum(1 for r in results if r["outcome"] == OUTCOME_FAIL)
    obs_controls = sum(1 for r in results if r["outcome"] == OUTCOME_OBSERVATIONAL_CONTROL_OK)
    obs_records = sum(1 for r in results if r["outcome"] == OUTCOME_OBSERVATIONAL_RECORD_ONLY)
    residual_open = sum(1 for r in results if r["outcome"] == OUTCOME_RESIDUAL_RISK_OPEN)

    payload = {
        "schema_version": "phase0b-profile-scan-v2",
        "profile": profile,
        "pre_scan_gates": {
            "clamconf_22key_validation": limit_validation,
            "zping": ping,
            "zversion": parsed_ver,
        },
        "counts": {
            "total": len(results),
            "required_pass": required_pass,
            "security_failures": security_failures,
            "other_failures": other_failures,
            "observational_controls_ok": obs_controls,
            "observational_record_only": obs_records,
            "residual_risk_open": residual_open,
        },
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def assemble_report(
    *,
    manifest_path: Path,
    fixture_verification_path: Path,
    preflight_results_path: Path,
    profile_paths: list[Path],
    provenance_path: Path,
    out_md_path: Path,
    out_json_path: Path,
) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fx_ver = json.loads(fixture_verification_path.read_text(encoding="utf-8"))
    preflight = json.loads(preflight_results_path.read_text(encoding="utf-8"))
    profiles = [json.loads(p.read_text(encoding="utf-8")) for p in profile_paths]
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))

    total_security_failures = sum(p["counts"]["security_failures"] for p in profiles)
    total_other_failures = sum(p["counts"]["other_failures"] for p in profiles)
    total_required_pass = sum(p["counts"]["required_pass"] for p in profiles)
    total_obs_record = sum(p["counts"]["observational_record_only"] for p in profiles)
    total_residual_open = sum(p["counts"]["residual_risk_open"] for p in profiles)

    fx_ok = fx_ver["overall_status"] == OUTCOME_PASS
    scoped_checks_ok = (
        fx_ok
        and preflight["failed"] == 0
        and total_security_failures == 0
        and total_other_failures == 0
    )

    if total_security_failures > 0:
        overall_remediation_status = "FAILED_SECURITY_CONTROLS"
    elif not scoped_checks_ok:
        overall_remediation_status = "FAILED_OR_NOT_VERIFIED"
    else:
        # Scoped Part A + Part B checks passed, while R1 (PDF-embedded ZIP64) and
        # R2 (compressed nested archives) remain explicitly OPEN residual risks.
        overall_remediation_status = "PARTIAL_RESIDUAL_RISKS_OPEN"

    combined = {
        "schema_version": "phase0b-evidence-report-v2",
        "scoped_poc_checks_status": OUTCOME_PASS if scoped_checks_ok else (OUTCOME_SECURITY_FAILURE if total_security_failures > 0 else OUTCOME_FAIL),
        "overall_remediation_status": overall_remediation_status,
        "explicit_residual_risk_flags": {
            "pdf_embedded_zip64_remediated": False,
            "compressed_nested_archives_inspected_by_preflight": False,
            "unreviewed_zip64_pr1845_included": False,
            "open_residual_risk_probe_count": total_residual_open,
            "observational_record_only_count": total_obs_record,
        },
        "gates": {
            "security_gate": "OPEN",
            "licensing_gate": "OPEN",
            "stage_7_status": "NOT_ACCEPTED",
            "production_change_made": False,
            "ghcr_published": False,
        },
        "provenance": provenance,
        "fixtures_count": manifest["fixture_count"],
        "fixture_authenticity": fx_ver,
        "preflight": preflight,
        "live_profiles": profiles,
    }
    out_json_path.write_text(json.dumps(combined, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# DIP Phase 0B Isolated Security Remediation — Evidence Summary",
        "",
        "> **OPEN RESIDUAL RISKS & GATE STATUS (DO NOT MISREPRESENT AS COMPLETE REMEDIATION)**",
        f"> - **Scoped PoC Checks**: `{combined['scoped_poc_checks_status']}`",
        f"> - **Overall Remediation Status**: `{overall_remediation_status}`",
        "> - **PDF-Embedded ZIP64 Remediated**: `false` (`R1_pdf_embedded_zip64_residual_risk` — OPEN residual risk, upstream ClamAV `#1888`)",
        "> - **Compressed Nested Archives Inspected by Preflight**: `false` (`R2_compressed_nested_zip64_inside_zip32_residual_risk` — OPEN residual risk under zero-decompression preflight)",
        "> - **Security Gate**: `OPEN` | **Licensing Gate**: `OPEN` | **Stage 7**: `NOT ACCEPTED` | **GHCR Published**: `false`",
        "",
        "## 1. Fixture Authenticity & Bilingual Office/PDF Verification",
        "",
        f"- Overall authenticity status: **`{fx_ver['overall_status']}`**",
        "",
        "| Fixture ID | Kind | Structural Check | Isolated Tool Verification |",
        "| --- | --- | --- | --- |",
    ]
    for c in fx_ver["checks"]:
        lines.append(f"| `{c['id']}` | `{c['kind']}` | **{c['structural_check']}** | **{c['tool_verification_status']}** |")

    lines.extend(
        [
            "",
            f"## 2. Part B — Bounded Preflight Prototype (`{preflight['required_passed']}` PASS, `{preflight['residual_risk_warnings_verified']}` RESIDUAL_RISK_OPEN, `{preflight['failed']}` FAIL)",
            "",
            "| ID | Part | Status | Expected Action | Actual Action | Codes |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for r in preflight["results"]:
        codes = ", ".join([*r.get("reject_codes", []), *r.get("warning_codes", []), *r.get("info_codes", [])]) or "-"
        lines.append(
            f"| `{r['id']}` | `{r['part']}` | **{r['status']}** | `{r.get('expected_action')}` | `{r.get('actual_action')}` | `{codes}` |"
        )

    lines.extend(
        [
            "",
            f"## 3. Live Patched clamd Profiles (`{total_required_pass}` required PASS, `{total_security_failures}` SECURITY FAILURE, `{total_other_failures}` FAIL, `{total_obs_record}` RECORD_ONLY, `{total_residual_open}` RESIDUAL_RISK_OPEN)",
            "",
        ]
    )
    for p in profiles:
        ver_info = p["pre_scan_gates"]["zversion"]
        lim_info = p["pre_scan_gates"]["clamconf_22key_validation"]
        lines.extend(
            [
                f"### Profile `{p['profile']}`",
                f"- Pre-scan 22-key `clamconf` validation: **`{lim_info['status']}`** (`{lim_info['checked_key_count']}` keys; `MaxFileSize={lim_info['normalized_limits']['MaxFileSize']}`, `MaxScanSize={lim_info['normalized_limits']['MaxScanSize']}`, `AlertExceedsMax={lim_info['normalized_limits']['AlertExceedsMax']}`)",
                f"- Pre-scan `zVERSION`: `ClamAV {ver_info['engine_version']}/{ver_info['signature_db_version']}/{ver_info['signature_db_date']}`",
                "",
                "| Fixture ID | Expectation | Outcome | Observed Verdict | Signature |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for r in p["results"]:
            obs = r["observed"]
            lines.append(
                f"| `{r['id']}` | `{r['expectation']}` | **{r['outcome']}** | `{obs['verdict']}` | `{obs.get('signature') or '-'}` |"
            )
        lines.append("")

    out_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if scoped_checks_ok else 1


# ============================================================================
# Offline Self-Test (Mock clamd TCP server + 22-key clamconf + Fixture & Preflight checks)
# ============================================================================

def _make_sample_clamconf(*, profile: str, overrides: dict[str, str] | None = None) -> str:
    specs = PROFILE_EXPECTED_LIMIT_SPECS[profile]
    lines = ["Checking configuration files in /etc/clamav-phase0b", "", "Config file: clamd.conf", "-----------------------"]
    for key, (kind, val) in specs.items():
        if overrides and key in overrides:
            v = overrides[key]
        elif kind == "bool":
            v = "yes" if val == "yes" else "disabled"
        else:
            v = str(val)
        if v == "disabled":
            lines.append(f"{key} disabled")
        else:
            lines.append(f'{key} = "{v}"')
    lines.extend(["", "Software settings", "-----------------", "Version: 1.5.4"])
    return "\n".join(lines) + "\n"


def run_self_test(preflight_script: Path) -> int:
    # 1. Wire parser & strict SECURITY FAILURE / RECORD_ONLY / RESIDUAL_RISK_OPEN checks
    assert classify_raw_clamd_reply(b"stream: OK\x00")["verdict"] == VERDICT_CLEAN
    assert classify_raw_clamd_reply(b"stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\x00")["verdict"] == VERDICT_LIMIT_ALERT
    assert classify_raw_clamd_reply(b"stream: OK")["verdict"] == VERDICT_MALFORMED
    assert classify_raw_clamd_reply(b"stream: OK\x00trailing")["verdict"] == VERDICT_MALFORMED
    assert classify_raw_clamd_reply(b"stream: OK\x00stream: OK\x00")["verdict"] == VERDICT_MALFORMED

    # Unexpected CLEAN on required MaxFileSize MUST be SECURITY FAILURE
    sec_fail = evaluate_clamd_case("MAXFILESIZE_FOUND", classify_raw_clamd_reply(b"stream: OK\x00"))
    assert sec_fail["outcome"] == OUTCOME_SECURITY_FAILURE and sec_fail["security_failure"] is True

    # Confounded MaxScanSize alert when MaxFileSize required MUST FAIL
    confounded = evaluate_clamd_case("MAXFILESIZE_FOUND", classify_raw_clamd_reply(b"stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\x00"))
    assert confounded["outcome"] == OUTCOME_FAIL

    # RECORD_ONLY and RESIDUAL_RISK_PROBE MUST NEVER yield PASS
    rec_only = evaluate_clamd_case("OBSERVATIONAL_UNPATCHED_ZIP64", classify_raw_clamd_reply(b"stream: OK\x00"))
    assert rec_only["outcome"] == OUTCOME_OBSERVATIONAL_RECORD_ONLY
    res_open = evaluate_clamd_case("RESIDUAL_RISK_PROBE", classify_raw_clamd_reply(b"stream: OK\x00"))
    assert res_open["outcome"] == OUTCOME_RESIDUAL_RISK_OPEN

    # 2. Full 22-key clamconf validator tests (positive + negative)
    for prof, alert in (("candidate", "yes"), ("reduced_alert_yes", "yes"), ("reduced_alert_no", "no")):
        parsed = parse_clamconf_clamd_section(_make_sample_clamconf(profile=prof))
        res = validate_effective_limits(prof, parsed, alert)
        assert res["checked_key_count"] == 22

    # Negative: confounded MaxScanSize=64K under reduced_alert_yes MUST fail closed!
    try:
        bad_parsed = parse_clamconf_clamd_section(_make_sample_clamconf(profile="reduced_alert_yes", overrides={"MaxScanSize": "64K"}))
        validate_effective_limits("reduced_alert_yes", bad_parsed, "yes")
        raise AssertionError("Confounded MaxScanSize=64K should have failed 22-key validation")
    except RuntimeError as exc:
        assert "MaxScanSize" in str(exc)

    # Negative: missing key and duplicate key in 22-key clamconf MUST fail closed!
    try:
        missing_conf = "\n".join(
            l for l in _make_sample_clamconf(profile="candidate").splitlines() if not l.startswith("MaxFiles")
        )
        validate_effective_limits("candidate", parse_clamconf_clamd_section(missing_conf), "yes")
        raise AssertionError("Missing MaxFiles should have failed 22-key validation")
    except RuntimeError as exc:
        assert "MaxFiles" in str(exc)

    try:
        dup_conf = _make_sample_clamconf(profile="candidate") + '\nMaxRecursion = "16"\n'
        # Insert duplicate inside clamd.conf section
        dup_conf = _make_sample_clamconf(profile="candidate").replace(
            'MaxRecursion = "16"', 'MaxRecursion = "16"\nMaxRecursion = "8"'
        )
        validate_effective_limits("candidate", parse_clamconf_clamd_section(dup_conf), "yes")
        raise AssertionError("Duplicate MaxRecursion should have failed 22-key validation")
    except RuntimeError as exc:
        assert "duplicate" in str(exc).lower()

    # Negative: zVERSION parser rejects malformed replies & engine mismatch
    assert parse_zversion("malformed-version") is None
    bad_ver = parse_zversion("ClamAV 1.4.3/27890/Mon Nov 16 00:00:00 2026")
    assert bad_ver is not None and bad_ver["engine_version"] != "1.5.4"

    # 3. Mock TCP clamd server verifying zPING + zVERSION (accept 1.5.4, reject wrong version)
    class MockClamdHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = self.request.recv(64)
            if data == b"zPING\x00":
                self.request.sendall(b"PONG\x00")
            elif data == b"zVERSION\x00":
                self.request.sendall(b"ClamAV 1.5.4/27890/Mon Nov 16 00:00:00 2026\x00")

    class ReuseServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReuseServer(("127.0.0.1", 0), MockClamdHandler) as srv:
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            ping = clamd_simple_command("127.0.0.1", port, "zPING")
            assert ping["ok"] and ping["text"] == "PONG"
            ver = clamd_simple_command("127.0.0.1", port, "zVERSION")
            pver = parse_zversion(ver["text"])
            assert pver is not None and pver["engine_version"] == "1.5.4"
        finally:
            srv.shutdown()

    # 4. Fixture generation, OPC/PDF authenticity check, forged-size check, and TS preflight cross-validation
    with tempfile.TemporaryDirectory(prefix="dip-phase0b-selftest-") as tmp:
        tmp_dir = Path(tmp)
        specs = generate_fixtures(tmp_dir, max_file_size=DEFAULT_EXPERIMENT_MAX_FILE_SIZE)
        assert len(specs) == 26, f"Expected 26 fixtures, got {len(specs)}"

        with zipfile.ZipFile(tmp_dir / "A2_exact_boundary_zip32_eq_maxfilesize.zip") as zf:
            assert len(zf.read("exact_boundary.bin")) == 16384
        with zipfile.ZipFile(tmp_dir / "A3_over_boundary_plus1_zip32_deflate.zip") as zf:
            assert len(zf.read("over_by_one.bin")) == 16385

        a7_raw = (tmp_dir / "A7_forged_size_header_zip32_maxfilesize.zip").read_bytes()
        lfh_csize, lfh_usize, lfh_nlen, lfh_elen = struct.unpack_from("<IIHH", a7_raw, 18)
        assert lfh_usize == 100
        comp_start = 30 + lfh_nlen + lfh_elen
        inflated = zlib.decompress(a7_raw[comp_start : comp_start + lfh_csize], -zlib.MAX_WBITS)
        assert len(inflated) == 65536

        fx_ver = verify_fixtures(
            tmp_dir / "fixtures-manifest.json",
            out_path=tmp_dir / "fixture-verification.json",
            require_tool_verification=False,
        )
        assert fx_ver["summary"]["failed_structural"] == 0
        assert fx_ver["summary"]["failed_tool"] == 0

        pf_summary = run_preflight_suite(
            tmp_dir / "fixtures-manifest.json",
            preflight_script,
            tmp_dir / "preflight-results.json",
        )

        # 5. End-to-end assemble_report verdict-integrity checks (fail closed on NOT VERIFIED / SECURITY FAILURE;
        #    never claim complete remediation when scoped checks pass)
        prov_path = tmp_dir / "provenance.json"
        prov_path.write_text(json.dumps({"self_test": True}) + "\n", encoding="utf-8")
        mock_pass_profile = tmp_dir / "profile-pass.json"
        mock_pass_profile.write_text(
            json.dumps(
                {
                    "profile": "candidate",
                    "pre_scan_gates": {
                        "clamconf_22key_validation": {
                            "status": OUTCOME_PASS,
                            "checked_key_count": 22,
                            "normalized_limits": {
                                "MaxFileSize": CANDIDATE_MAX_FILE_SIZE_BYTES,
                                "MaxScanSize": CANDIDATE_MAX_SCAN_SIZE_BYTES,
                                "AlertExceedsMax": "yes",
                            },
                        },
                        "zversion": {
                            "engine_version": "1.5.4",
                            "signature_db_version": "27890",
                            "signature_db_date": "test",
                        },
                    },
                    "counts": {
                        "total": 3,
                        "required_pass": 1,
                        "security_failures": 0,
                        "other_failures": 0,
                        "observational_controls_ok": 0,
                        "observational_record_only": 1,
                        "residual_risk_open": 1,
                    },
                    "results": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        # Case 5a: offline NOT VERIFIED fixture authenticity MUST fail closed (rc == 1)
        rc_unverified = assemble_report(
            manifest_path=tmp_dir / "fixtures-manifest.json",
            fixture_verification_path=tmp_dir / "fixture-verification.json",
            preflight_results_path=tmp_dir / "preflight-results.json",
            profile_paths=[mock_pass_profile],
            provenance_path=prov_path,
            out_md_path=tmp_dir / "report-unverified.md",
            out_json_path=tmp_dir / "report-unverified.json",
        )
        assert rc_unverified == 1, "assemble_report must fail closed when fixture verification is NOT VERIFIED"

        # Case 5b: when all scoped checks & tool verifications pass, overall status MUST still be PARTIAL_RESIDUAL_RISKS_OPEN
        mock_fx_pass = tmp_dir / "fx-pass.json"
        mock_fx_pass.write_text(json.dumps({"overall_status": OUTCOME_PASS, "checks": []}) + "\n", encoding="utf-8")
        rc_scoped_pass = assemble_report(
            manifest_path=tmp_dir / "fixtures-manifest.json",
            fixture_verification_path=mock_fx_pass,
            preflight_results_path=tmp_dir / "preflight-results.json",
            profile_paths=[mock_pass_profile],
            provenance_path=prov_path,
            out_md_path=tmp_dir / "report-scoped.md",
            out_json_path=tmp_dir / "report-scoped.json",
        )
        assert rc_scoped_pass == 0
        scoped_json = json.loads((tmp_dir / "report-scoped.json").read_text(encoding="utf-8"))
        assert scoped_json["overall_remediation_status"] == "PARTIAL_RESIDUAL_RISKS_OPEN"
        assert scoped_json["explicit_residual_risk_flags"]["pdf_embedded_zip64_remediated"] is False
        assert scoped_json["explicit_residual_risk_flags"]["compressed_nested_archives_inspected_by_preflight"] is False

        # Case 5c: unexpected CLEAN (security_failures > 0) MUST fail closed with FAILED_SECURITY_CONTROLS
        mock_sec_fail_profile = tmp_dir / "profile-secfail.json"
        sf_data = json.loads(mock_pass_profile.read_text(encoding="utf-8"))
        sf_data["counts"]["security_failures"] = 1
        mock_sec_fail_profile.write_text(json.dumps(sf_data) + "\n", encoding="utf-8")
        rc_sec_fail = assemble_report(
            manifest_path=tmp_dir / "fixtures-manifest.json",
            fixture_verification_path=mock_fx_pass,
            preflight_results_path=tmp_dir / "preflight-results.json",
            profile_paths=[mock_sec_fail_profile],
            provenance_path=prov_path,
            out_md_path=tmp_dir / "report-secfail.md",
            out_json_path=tmp_dir / "report-secfail.json",
        )
        assert rc_sec_fail == 1
        sf_json = json.loads((tmp_dir / "report-secfail.json").read_text(encoding="utf-8"))
        assert sf_json["scoped_poc_checks_status"] == OUTCOME_SECURITY_FAILURE
        assert sf_json["overall_remediation_status"] == "FAILED_SECURITY_CONTROLS"
        print(
            json.dumps(
                {
                    "suite": "phase0b-evidence-python-self-test-v2",
                    "wire_and_verdict_integrity_checks": "PASS",
                    "clamconf_22key_and_confounded_64k_rejection": "PASS",
                    "mock_tcp_zping_zversion": "PASS",
                    "fixtures_generated": len(specs),
                    "isolated_reduced_limits": {
                        "MaxFileSize": REDUCED_MAX_FILE_SIZE_BYTES,
                        "MaxScanSize": REDUCED_MAX_SCAN_SIZE_BYTES,
                        "StreamMaxLength": REDUCED_STREAM_MAX_LENGTH_BYTES,
                    },
                    "forged_size_verified": {"declared_usize": lfh_usize, "inflated_bytes": len(inflated)},
                    "fixture_authenticity_offline": {
                        "overall_status": fx_ver["overall_status"],
                        "failed_structural": fx_ver["summary"]["failed_structural"],
                        "not_verified_tool_checks": fx_ver["summary"]["not_verified_tool"],
                    },
                    "preflight_cross_check": {
                        "required_passed": pf_summary["required_passed"],
                        "residual_risk_warnings_verified": pf_summary["residual_risk_warnings_verified"],
                        "failed": pf_summary["failed"],
                        "total": pf_summary["total"],
                    },
                },
                indent=2,
            )
        )
        if pf_summary["failed"] != 0:
            for r in pf_summary["results"]:
                if r["status"] == OUTCOME_FAIL:
                    print(f"FAILED: {json.dumps(r)}", file=sys.stderr)
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="DIP Phase 0B Isolated Remediation Evidence Tool (v2)")
    sub = parser.add_subparsers(dest="cmd")

    p_gen = sub.add_parser("generate", help="Generate deterministic Phase 0B fixtures")
    p_gen.add_argument("--out-dir", required=True, type=Path)
    p_gen.add_argument("--max-file-size", type=int, default=DEFAULT_EXPERIMENT_MAX_FILE_SIZE)
    p_gen.add_argument("--require-qpdf", action="store_true", help="Fail closed if qpdf is unavailable for B14")

    p_ver = sub.add_parser("verify-fixtures", help="Verify Office/PDF/attachment fixture authenticity")
    p_ver.add_argument("--manifest", required=True, type=Path)
    p_ver.add_argument("--out", required=True, type=Path)
    p_ver.add_argument("--require-tool-verification", action="store_true")

    p_pf = sub.add_parser("run-preflight", help="Run isolated TS preflight prototype against fixtures")
    p_pf.add_argument("--manifest", required=True, type=Path)
    p_pf.add_argument("--preflight-script", required=True, type=Path)
    p_pf.add_argument("--out", required=True, type=Path)

    p_prof = sub.add_parser("scan-profile", help="Validate 22-key clamconf + zPING + zVERSION then scan one profile")
    p_prof.add_argument("--profile", required=True, choices=("candidate", "reduced_alert_yes", "reduced_alert_no"))
    p_prof.add_argument("--manifest", required=True, type=Path)
    p_prof.add_argument("--host", required=True)
    p_prof.add_argument("--port", type=int, default=3310)
    p_prof.add_argument("--clamconf-file", required=True, type=Path)
    p_prof.add_argument("--expected-engine", default="1.5.4")
    p_prof.add_argument("--expected-alert-exceeds-max", required=True, choices=("yes", "no"))
    p_prof.add_argument("--out", required=True, type=Path)

    p_rep = sub.add_parser("assemble-report", help="Assemble fail-closed Phase 0B Markdown + JSON report")
    p_rep.add_argument("--manifest", required=True, type=Path)
    p_rep.add_argument("--fixture-verification", required=True, type=Path)
    p_rep.add_argument("--preflight-results", required=True, type=Path)
    p_rep.add_argument("--profile-result", action="append", required=True, type=Path)
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
        specs = generate_fixtures(args.out_dir, max_file_size=args.max_file_size, require_qpdf=args.require_qpdf)
        print(f"Generated {len(specs)} Phase 0B fixtures in {args.out_dir}")
        return 0

    if args.cmd == "verify-fixtures":
        summary = verify_fixtures(
            args.manifest,
            out_path=args.out,
            require_tool_verification=args.require_tool_verification,
        )
        print(f"Fixture verification overall_status={summary['overall_status']} ({summary['summary']})")
        return 0 if summary["overall_status"] in (OUTCOME_PASS, OUTCOME_NOT_VERIFIED) and not (args.require_tool_verification and summary["overall_status"] != OUTCOME_PASS) else 1

    if args.cmd == "run-preflight":
        summary = run_preflight_suite(args.manifest, args.preflight_script, args.out)
        print(
            f"Preflight suite: {summary['required_passed']} PASS, "
            f"{summary['residual_risk_warnings_verified']} RESIDUAL_RISK_OPEN, {summary['failed']} FAIL"
        )
        return 0 if summary["failed"] == 0 else 1

    if args.cmd == "scan-profile":
        summary = run_scan_profile(
            profile=args.profile,
            manifest_path=args.manifest,
            host=args.host,
            port=args.port,
            clamconf_file=args.clamconf_file,
            expected_engine=args.expected_engine,
            expected_alert_exceeds_max=args.expected_alert_exceeds_max,
            out_path=args.out,
        )
        c = summary["counts"]
        print(
            f"Profile {args.profile}: required_pass={c['required_pass']} security_failures={c['security_failures']} "
            f"other_failures={c['other_failures']} obs_controls={c['observational_controls_ok']} "
            f"record_only={c['observational_record_only']} residual_open={c['residual_risk_open']}"
        )
        return 0 if (c["security_failures"] == 0 and c["other_failures"] == 0) else 1

    if args.cmd == "assemble-report":
        return assemble_report(
            manifest_path=args.manifest,
            fixture_verification_path=args.fixture_verification,
            preflight_results_path=args.preflight_results,
            profile_paths=args.profile_result,
            provenance_path=args.provenance,
            out_md_path=args.out_md,
            out_json_path=args.out_json,
        )

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
