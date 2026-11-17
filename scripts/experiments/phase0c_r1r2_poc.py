#!/usr/bin/env python3
"""DIP Phase 0C -- minimal ISOLATED OFFLINE PoC for R1 (PDF-embedded ZIP64) and
R2 (bounded inspection of compressed nested ZIP archives).

EXPERIMENTAL ONLY. NOT production integration. NOT a Change Request approval.
NO new production dependencies: Python standard library only (struct, zlib, re,
hashlib, dataclasses, time, tracemalloc, shutil, typing, json).

Architecture corrections honoured (see docs/operations/experimental/phase0c-r1r2-offline-poc.md):
  1. The approved PRE-STORAGE boundary is unchanged: in src/lib/jobs/orchestrator.ts
     validateUpload -> requireCleanUpload -> storage.put. A post-storage worker scan
     does NOT satisfy it. This PoC never stores anything and never claims placement.
  2. qpdf --json / PDF.js are NOT exhaustive PDF stream inspectors. qpdf's
     `--json=1 --json-key=objects --decode-level=none` (used in production only for
     signature detection) enumerates object metadata; PDF.js exposes a bounded subset
     of decoded image XObjects. Neither is used here as proof of stream coverage.
  3. ONE cumulative ResourceBudget is threaded through PDF parsing, attachment
     extraction, nested-archive traversal and (offline) scanner feeding. Extraction
     and scanning share the SAME time / memory / disk / byte ceilings.
  4. Encrypted-PDF detection and post-unlock/decrypted-output scanning are recorded
     as explicit OPEN security requirements, not silently assumed.
  5. A raw clamd `stream: OK` CLEAN is NOT proof of complete nested-content
     inspection (Phase 0A `D_eicar_zip64` produced `stream: OK` on a ZIP64 bypass).
     A CLEAN verdict with incomplete coverage can NEVER yield COMPLETE_SAFE_SCAN.

Resource-safety note: the production baseline `MaxScanSize 400M` is a CUMULATIVE
scan-size budget, NOT a materialised extraction footprint. CI runs the worker under
a `size=256m` tmpfs. This PoC therefore performs ZERO filesystem extraction: members
are read in bounded streaming chunks, nested containers are held only in a bounded
in-memory buffer, and `temp_disk_bytes_used` is accounted and enforced (0 used).
No 400 MiB materialisation is claimed or performed.

Verdict taxonomy (per case / per object): INSPECTED | REJECTED | UNSUPPORTED |
NOT_VERIFIED. Fail closed on any unsupported, malformed, ambiguous or incomplete
inspection. No content is executed; no archive path is used as a filesystem path.

Revision (this cycle — focused security correctness review of PR #16):
  * Finding 1: DEFLATE members require the proper end-of-stream marker;
    truncated streams and unexpected trailing compressed bytes are rejected
    (trailing bytes accepted only as a verified 16/24-byte ZIP data descriptor);
    every decompression output chunk is strictly bounded (no unbounded flush).
  * Finding 2: per-member limit accounting corrected — a member exactly at the
    per-member ceiling is allowed, one byte over is rejected; the cumulative
    expanded-byte ceiling is enforced independently and shared by nested reads.
  * Finding 3: the generic exception handler emits a bounded structured code
    (no reliance on a non-guaranteed error.code); fixture generation is inside
    the fail-closed boundary.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import shutil
import sys
import struct
import time
import tracemalloc
import zlib
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, Protocol

# ---------------------------------------------------------------------------
# Verdict / reason constants
# ---------------------------------------------------------------------------
INSPECTED = "INSPECTED"
REJECTED = "REJECTED"
UNSUPPORTED = "UNSUPPORTED"
NOT_VERIFIED = "NOT_VERIFIED"

COMPLETE_SAFE_SCAN = "COMPLETE_SAFE_SCAN"
NOT_COMPLETE_SAFE_SCAN = "NOT_COMPLETE_SAFE_SCAN"

EXPERIMENT_ID = "DIP-PHASE-0C-R1R2-OFFLINE-POC"
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class BudgetExceeded(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RejectionError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class UnsupportedError(Exception):
    """Structurally valid-but-out-of-scope construct: classified UNSUPPORTED
    (never accepted, never reported as corrupt)."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# ONE cumulative end-to-end resource budget (extraction + scanning + timeouts)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ResourceLimits:
    """Conservative OFFLINE ceilings. Experimental only; NOT production sizing."""
    max_input_bytes: int = 4 * 1024 * 1024             # 4 MiB top-level input
    max_expanded_bytes: int = 16 * 1024 * 1024         # 16 MiB cumulative expanded
    max_member_bytes: int = 2 * 1024 * 1024            # 2 MiB actual per member
    max_entries: int = 256                             # cumulative entries/attachments
    max_depth: int = 3                                 # root=0
    max_cpu_seconds: float = 3.0
    max_wall_clock_seconds: float = 5.0
    max_memory_bytes: int = 32 * 1024 * 1024           # 32 MiB reserve-enforced
    max_temp_disk_bytes: int = 8 * 1024 * 1024         # 8 MiB (PoC writes ZERO)
    max_materialized_object_bytes: int = 8 * 1024 * 1024  # bounded re-parse buffer
    chunk_bytes: int = 64 * 1024

    def as_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


DEFAULT_RESOURCE_LIMITS = ResourceLimits()


class ResourceBudget:
    """Single budget shared by PDF parse, extraction, recursion and scanner feed.

    Byte accounting is deliberately NON-DOUBLE-COUNTING: every byte produced by
    decompression is charged once to `expanded_bytes` at the level that produced it.
    Scanner bytes are tracked separately as `scanned_bytes` but are checked against
    the SAME wall-clock, CPU, memory and temp-disk ceilings.
    """

    def __init__(self, limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS, *,
                 monotonic: Callable[[], float] = time.monotonic,
                 process_time: Callable[[], float] = time.process_time) -> None:
        self.limits = limits
        self._monotonic = monotonic
        self._process_time = process_time
        self._wall_start = monotonic()
        self._cpu_start = process_time()
        self.input_bytes = 0
        self.expanded_bytes = 0
        self.scanned_bytes = 0
        self.entries = 0
        self.max_depth_seen = 0
        self.temp_disk_bytes = 0
        self.reserved_memory_bytes = 0
        self.peak_reserved_memory_bytes = 0
        self.full_extraction_materialized = False
        self.filesystem_writes = 0
        self.limits_hit: list[str] = []

    def _hit(self, code: str) -> None:
        if code not in self.limits_hit:
            self.limits_hit.append(code)
        raise BudgetExceeded(code)

    def check_time(self) -> None:
        if self._monotonic() - self._wall_start > self.limits.max_wall_clock_seconds:
            self._hit("WALL_CLOCK_LIMIT")
        if self._process_time() - self._cpu_start > self.limits.max_cpu_seconds:
            self._hit("CPU_TIME_LIMIT")

    def charge_input(self, count: int) -> None:
        if self.input_bytes + count > self.limits.max_input_bytes:
            self._hit("INPUT_BYTE_LIMIT")
        self.input_bytes += count
        self.check_time()

    def charge_expanded(self, count: int, *, member_bytes: int = 0) -> None:
        """Charge one decompressed chunk against BOTH ceilings.

        Accounting contract (Finding-2 fix): `count` is the current chunk size;
        `member_bytes` is this member's CUMULATIVE expanded bytes INCLUDING the
        current chunk (the caller must pass its running total). The per-member
        ceiling is evaluated against `member_bytes` ALONE — a member exactly at
        the ceiling is allowed, one byte over is rejected, and the chunk is
        never counted twice. The cumulative ceiling is evaluated independently
        (`expanded_bytes + count`) and is shared across nested members.
        """
        if self.expanded_bytes + count > self.limits.max_expanded_bytes:
            self._hit("EXPANDED_BYTE_LIMIT")
        if member_bytes > self.limits.max_member_bytes:
            self._hit("MEMBER_BYTE_LIMIT")
        self.expanded_bytes += count
        self.check_time()

    def charge_scanned(self, count: int) -> None:
        """Scanner feed shares the SAME end-to-end budget."""
        self.scanned_bytes += count
        self.check_time()
        if self.temp_disk_bytes > self.limits.max_temp_disk_bytes:
            self._hit("TEMP_DISK_LIMIT")

    def count_entry(self) -> None:
        self.entries += 1
        if self.entries > self.limits.max_entries:
            self._hit("ENTRY_COUNT_LIMIT")
        self.check_time()

    def check_depth(self, depth: int) -> None:
        self.max_depth_seen = max(self.max_depth_seen, depth)
        if depth > self.limits.max_depth:
            self._hit("RECURSION_DEPTH_LIMIT")
        self.check_time()

    def reserve_memory(self, count: int) -> None:
        if self.reserved_memory_bytes + count > self.limits.max_memory_bytes:
            self._hit("MEMORY_LIMIT")
        if count > self.limits.max_materialized_object_bytes:
            self._hit("MATERIALIZED_OBJECT_LIMIT")
        self.reserved_memory_bytes += count
        self.peak_reserved_memory_bytes = max(self.peak_reserved_memory_bytes, self.reserved_memory_bytes)

    def release_memory(self, count: int) -> None:
        self.reserved_memory_bytes = max(0, self.reserved_memory_bytes - count)

    def account_temp_disk(self, count: int) -> None:
        # This PoC NEVER writes extraction output to disk. The hook exists so a
        # future live design cannot silently exceed the tmpfs ceiling.
        if count:
            self.filesystem_writes += 1
        if self.temp_disk_bytes + count > self.limits.max_temp_disk_bytes:
            self._hit("TEMP_DISK_LIMIT")
        self.temp_disk_bytes += count

    def snapshot(self) -> dict[str, object]:
        return {
            "limits": self.limits.as_dict(),
            "input_bytes": self.input_bytes,
            "expanded_bytes": self.expanded_bytes,
            "scanned_bytes": self.scanned_bytes,
            "entry_count": self.entries,
            "max_depth_seen": self.max_depth_seen,
            "temp_disk_bytes_used": self.temp_disk_bytes,
            "temp_disk_bytes_ceiling": self.limits.max_temp_disk_bytes,
            "filesystem_writes": self.filesystem_writes,
            "full_extraction_materialized": self.full_extraction_materialized,
            "peak_reserved_memory_bytes": self.peak_reserved_memory_bytes,
            "resource_limits_hit": list(self.limits_hit),
            "elapsed_wall_seconds": round(self._monotonic() - self._wall_start, 6),
            "elapsed_cpu_seconds": round(self._process_time() - self._cpu_start, 6),
        }


# ---------------------------------------------------------------------------
# Scanner adapters (OFFLINE ONLY; no socket, no subprocess, no live clamd)
# ---------------------------------------------------------------------------
class ScannerAdapter(Protocol):
    name: str
    def feed(self, chunk: bytes, budget: ResourceBudget) -> None: ...
    def finish(self) -> dict[str, object]: ...


class OfflineEicarControlProbe:
    """Deterministic offline CONTROL, deliberately NOT a malware scanner.

    Detects only the harmless standard EICAR test signature. It is used for
    independent positive/negative controls and to demonstrate scanner-feed
    streaming. Its result is NEVER a ClamAV CLEAN/INFECTED verdict.
    """
    name = "OFFLINE_EICAR_CONTROL_PROBE"

    def __init__(self) -> None:
        self._tail = b""
        self._found = False
        self._bytes = 0

    def feed(self, chunk: bytes, budget: ResourceBudget) -> None:
        window = self._tail + chunk
        if EICAR_SIGNATURE in window:
            self._found = True
        self._tail = window[-(len(EICAR_SIGNATURE) - 1):] if len(EICAR_SIGNATURE) > 1 else b""
        self._bytes += len(chunk)
        budget.charge_scanned(len(chunk))

    def finish(self) -> dict[str, object]:
        return {
            "role": "OFFLINE_SIGNATURE_CONTROL",
            "is_clamav_scanner": False,
            "signature": "EICAR_SIGNATURE_PRESENT" if self._found else "EICAR_SIGNATURE_ABSENT",
            "scanner_verdict": NOT_VERIFIED,
            "scanner_reason": "CLAMAV_OFFLINE_UNAVAILABLE_CONTROL_PROBE_ONLY",
            "bytes_fed": self._bytes,
        }


class FakeAlwaysCleanScanner:
    """INVARIANT TEST STUB ONLY. Simulates a raw `CLEAN` reply.

    Used solely to prove that CLEAN + incomplete coverage can never produce
    COMPLETE_SAFE_SCAN. Never used in the shipped offline case suite.
    """
    name = "FAKE_ALWAYS_CLEAN_STUB"

    def __init__(self) -> None:
        self._bytes = 0

    def feed(self, chunk: bytes, budget: ResourceBudget) -> None:
        self._bytes += len(chunk)
        budget.charge_scanned(len(chunk))

    def finish(self) -> dict[str, object]:
        return {
            "role": "INVARIANT_TEST_STUB",
            "is_clamav_scanner": True,
            "signature": "NONE",
            "scanner_verdict": "CLEAN",
            "scanner_reason": "SYNTHETIC_STUB_FOR_COVERAGE_INVARIANT",
            "bytes_fed": self._bytes,
        }


# ---------------------------------------------------------------------------
# Coverage ledger
# ---------------------------------------------------------------------------
@dataclass
class ObjectRecord:
    object_path: str
    depth: int
    detected_content_type: str
    structural_verdict: str
    verdict: str
    extracted_bytes: int
    scanner_verdict: str = "NOT_SCANNED"
    scanner_reason: str = "NOT_SCANNED"
    offline_control_signature: str = "NOT_APPLICABLE"
    skipped: bool = False
    skip_reason: str | None = None
    resource_limits_hit: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


class CoverageLedger:
    def __init__(self, case_id: str, budget: ResourceBudget) -> None:
        self.case_id = case_id
        self.budget = budget
        self.objects: list[ObjectRecord] = []
        self.skipped_objects: list[dict[str, object]] = []

    def add(self, record: ObjectRecord) -> None:
        self.objects.append(record)
        if record.skipped:
            self.skipped_objects.append({
                "object_path": record.object_path,
                "depth": record.depth,
                "reason": record.skip_reason,
                "verdict": record.verdict,
            })

    def skip(self, path: str, depth: int, reason: str, *, verdict: str = NOT_VERIFIED) -> None:
        self.add(ObjectRecord(
            object_path=path, depth=depth, detected_content_type="UNKNOWN",
            structural_verdict="NOT_INSPECTED", verdict=verdict, extracted_bytes=0,
            scanner_verdict="NOT_SCANNED", scanner_reason=reason,
            skipped=True, skip_reason=reason,
        ))

    def reject(self, path: str, depth: int, code: str, *, extracted_bytes: int = 0,
               detected: str = "UNKNOWN", notes: Iterable[str] = ()) -> None:
        self.add(ObjectRecord(
            object_path=path, depth=depth, detected_content_type=detected,
            structural_verdict=code, verdict=REJECTED, extracted_bytes=extracted_bytes,
            scanner_verdict="NOT_SCANNED", scanner_reason=code,
            resource_limits_hit=[code] if code.endswith("LIMIT") else [],
            notes=list(notes),
        ))

    def unsupported(self, path: str, depth: int, code: str, *,
                    notes: Iterable[str] = ()) -> None:
        self.add(ObjectRecord(
            object_path=path, depth=depth, detected_content_type="UNKNOWN",
            structural_verdict=code, verdict=UNSUPPORTED, extracted_bytes=0,
            scanner_verdict="NOT_SCANNED", scanner_reason=code,
            notes=list(notes),
        ))

    def case_verdict(self) -> str:
        """Verdict of the TARGETED object graph only. Coverage gaps are reported
        separately in `coverage()` and can never be silently counted as inspected.
        """
        if not self.objects:
            return NOT_VERIFIED
        verdicts = [record.verdict for record in self.objects if not record.skipped]
        if not verdicts:
            return NOT_VERIFIED
        if REJECTED in verdicts:
            return REJECTED
        if UNSUPPORTED in verdicts:
            return UNSUPPORTED
        if NOT_VERIFIED in verdicts:
            return NOT_VERIFIED
        return INSPECTED

    def coverage(self, *, stream_gaps: Iterable[str] = ()) -> dict[str, object]:
        gaps = list(stream_gaps)
        targeted = [record for record in self.objects if not record.skipped]
        inspected = sum(1 for record in targeted if record.verdict == INSPECTED)
        rejected = sum(1 for record in targeted if record.verdict == REJECTED)
        unsupported = sum(1 for record in targeted if record.verdict == UNSUPPORTED)
        not_verified = sum(1 for record in targeted if record.verdict == NOT_VERIFIED)
        reasons: list[str] = []
        if self.skipped_objects:
            reasons.append("SKIPPED_OBJECTS_PRESENT")
        if gaps:
            reasons.append("ARBITRARY_PDF_STREAMS_NOT_INSPECTED")
        if rejected or unsupported or not_verified:
            reasons.append("NON_INSPECTED_TARGET_VERDICTS")
        if self.budget.limits_hit:
            reasons.append("RESOURCE_LIMIT_HIT")
        reasons.append("CLAMAV_SCANNER_NOT_VERIFIED_OFFLINE")
        structural = "COMPLETE" if targeted and inspected == len(targeted) and not gaps else "INCOMPLETE"
        return {
            "structural_coverage": structural,
            "end_to_end_coverage": "INCOMPLETE",  # offline: clamd NOT VERIFIED, always
            "completeness": "INCOMPLETE",
            "reasons": reasons,
            "objects_total": len(self.objects),
            "targeted_objects": len(targeted),
            "inspected": inspected,
            "rejected": rejected,
            "unsupported": unsupported,
            "not_verified": not_verified,
            "skipped_objects": list(self.skipped_objects),
            "uninspected_stream_gaps": gaps,
            "resource_limits_hit": list(self.budget.limits_hit),
        }


def derive_conclusion(coverage: dict[str, object], *, clamav_verified: bool,
                      scanner_all_clean: bool, resource_limits_hit: Iterable[str] = ()) -> dict[str, object]:
    """CLEAN + incomplete coverage can NEVER produce COMPLETE_SAFE_SCAN."""
    blockers: list[str] = []
    if coverage.get("completeness") != "COMPLETE":
        blockers.append("COVERAGE_INCOMPLETE")
    if coverage.get("end_to_end_coverage") != "COMPLETE":
        blockers.append("END_TO_END_COVERAGE_INCOMPLETE")
    if coverage.get("skipped_objects"):
        blockers.append("SKIPPED_OBJECTS_PRESENT")
    if coverage.get("uninspected_stream_gaps"):
        blockers.append("ARBITRARY_PDF_STREAMS_NOT_INSPECTED")
    if coverage.get("rejected") or coverage.get("unsupported") or coverage.get("not_verified"):
        blockers.append("NON_INSPECTED_TARGET_VERDICTS")
    if not clamav_verified:
        blockers.append("CLAMAV_SCANNER_NOT_VERIFIED")
    if not scanner_all_clean:
        blockers.append("SCANNER_VERDICT_NOT_ALL_CLEAN")
    if list(resource_limits_hit):
        blockers.append("RESOURCE_LIMIT_HIT")
    conclusion = COMPLETE_SAFE_SCAN if not blockers and scanner_all_clean else NOT_COMPLETE_SAFE_SCAN
    return {"overall_conclusion": conclusion, "blockers": blockers,
            "clamav_verified": clamav_verified, "scanner_all_clean": scanner_all_clean}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def sniff_content_type(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "application/zip"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return "application/vnd.ms-office"
    if not data:
        return "application/octet-stream"
    if all(byte in b"\t\n\r\x20-\x7e" for byte in data[:512]):
        return "text/plain"
    return "application/octet-stream"


_UNSAFE_PATH_PARTS = {"..", ".", ""}


def safe_member_path(name: str) -> str:
    """Return a VIRTUAL ledger label only. NEVER used for filesystem extraction.

    Rejects absolute paths, drive letters, backslashes, parent traversal, NUL and
    control characters, and leading/trailing whitespace components.
    """
    if not isinstance(name, str) or not name:
        raise RejectionError("UNSAFE_MEMBER_PATH", "empty member name")
    if "\x00" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise RejectionError("UNSAFE_MEMBER_PATH", "control character in member name")
    if "\\" in name or re.match(r"^[A-Za-z]:", name) or name.startswith(("/", "~")):
        raise RejectionError("UNSAFE_MEMBER_PATH", "absolute / drive / backslash path")
    parts = name.split("/")
    if any(part.strip() in _UNSAFE_PATH_PARTS or ".." in part for part in parts):
        raise RejectionError("UNSAFE_MEMBER_PATH", "parent traversal component")
    return "/".join(part.strip() for part in parts if part.strip())


# ---------------------------------------------------------------------------
# Bounded ZIP parser (deliberately NOT zipfile.open: it truncates at DECLARED
# file_size; we inflate to EOF and count ACTUAL bytes instead).
# ---------------------------------------------------------------------------
EOCD_SIG = b"PK\x05\x06"
ZIP64_EOCD_SIG = b"PK\x06\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"
CDH_SIG = b"PK\x01\x02"
LFH_SIG = b"PK\x03\x04"
SUPPORTED_METHODS = {0, 8}


@dataclass
class _CentralEntry:
    name: str
    flags: int
    method: int
    crc: int
    csize: int
    usize: int
    local_offset: int
    zip64_extra: bool
    zip64_sizes: bool = False  # CDH used 0xFFFFFFFF sentinels (resolved via extra)


def _resolve_zip64_extra(extra: bytes, *, csize: int, usize: int,
                         local_offset: int) -> tuple[int, int, int, bool]:
    """Resolve 0xFFFFFFFF sentinels from the 0x0001 TLV extra field (APPNOTE)."""
    pos, values = 0, []
    found = False
    while pos + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + size > len(extra):
            raise RejectionError("MALFORMED_ZIP_EXTRA_FIELD", "TLV length overflow")
        if tag == 0x0001:
            found = True
            qpos = 0
            body = extra[pos:pos + size]
            while qpos + 8 <= len(body):
                values.append(struct.unpack_from("<Q", body, qpos)[0])
                qpos += 8
        pos += size
    if not found:
        return csize, usize, local_offset, False
    index = 0
    if usize == 0xFFFFFFFF:
        if index >= len(values):
            raise RejectionError("ZIP64_SENTINEL_UNRESOLVED", "missing usize")
        usize = values[index]; index += 1
    if csize == 0xFFFFFFFF:
        if index >= len(values):
            raise RejectionError("ZIP64_SENTINEL_UNRESOLVED", "missing csize")
        csize = values[index]; index += 1
    if local_offset == 0xFFFFFFFF:
        if index >= len(values):
            raise RejectionError("ZIP64_SENTINEL_UNRESOLVED", "missing offset")
        local_offset = values[index]; index += 1
    return csize, usize, local_offset, True


def _parse_central_directory(data: bytes, budget: ResourceBudget) -> tuple[list[_CentralEntry], list[str]]:
    flags_detected: list[str] = []
    search_from = max(0, len(data) - (22 + 65535))
    eocd = data.rfind(EOCD_SIG, search_from)
    if eocd < 0 or eocd + 22 > len(data):
        raise RejectionError("MALFORMED_ZIP_NO_EOCD")
    disk, cd_disk, entries_disk, entries_total, cd_size, cd_offset, comment_len = struct.unpack_from(
        "<HHHHIIH", data, eocd + 4
    )
    if disk != 0 or cd_disk != 0 or entries_disk != entries_total:
        raise RejectionError("MULTI_DISK_ZIP_UNSUPPORTED")
    if eocd + 22 + comment_len > len(data):
        raise RejectionError("MALFORMED_ZIP_EOCD_COMMENT")

    if entries_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        flags_detected.append("ZIP64_EOCD_SENTINEL")
        # APPNOTE 4.4.4: the ZIP64 EOCD locator sits IMMEDIATELY before the
        # classic EOCD, and the ZIP64 EOCD record immediately before the
        # locator. The locator is therefore validated POSITIONALLY — a ZIP64
        # magic byte pattern inside member content can no longer masquerade as
        # one. Locator layout: sig(4) disk_number(4) zip64_eocd_offset(8)
        # total_disk_count(4). Both disk fields are 32-bit; multi-disk
        # archives are unsupported and fail closed.
        if eocd < 20 or data[eocd - 20:eocd - 16] != ZIP64_LOCATOR_SIG:
            raise RejectionError("ZIP64_SENTINEL_WITHOUT_LOCATOR")
        locator_disk = struct.unpack_from("<I", data, eocd - 16)[0]
        locator_total_disks = struct.unpack_from("<I", data, eocd - 4)[0]
        if locator_disk != 0 or locator_total_disks != 1:
            raise RejectionError("MULTI_DISK_ZIP_UNSUPPORTED")
        # locator layout: sig(4) disk(4) offset(8) total_disks(4); the 8-byte
        # offset field therefore starts at eocd-12.
        z64_offset = struct.unpack_from("<Q", data, eocd - 12)[0]
        if (z64_offset + 56 > len(data) or z64_offset >= eocd - 20
                or data[z64_offset:z64_offset + 4] != ZIP64_EOCD_SIG):
            raise RejectionError("ZIP64_EOCD_MISSING")
        z64_disk, z64_cd_disk = struct.unpack_from("<II", data, z64_offset + 16)
        if z64_disk not in (0, 0xFFFF) or z64_cd_disk not in (0, 0xFFFF):
            raise RejectionError("MULTI_DISK_ZIP_UNSUPPORTED")
        entries_total = struct.unpack_from("<Q", data, z64_offset + 32)[0]
        cd_size = struct.unpack_from("<Q", data, z64_offset + 40)[0]
        cd_offset = struct.unpack_from("<Q", data, z64_offset + 48)[0]
        flags_detected.append("ZIP64_EOCD_LOCATOR_PRESENT")
    if entries_total > budget.limits.max_entries:
        budget._hit("ENTRY_COUNT_LIMIT")
    if cd_offset + cd_size > len(data):
        raise RejectionError("MALFORMED_ZIP_CENTRAL_DIRECTORY_RANGE")

    entries: list[_CentralEntry] = []
    pos = cd_offset
    for _ in range(entries_total):
        if pos + 46 > len(data) or data[pos:pos + 4] != CDH_SIG:
            raise RejectionError("MALFORMED_ZIP_CENTRAL_DIRECTORY_HEADER")
        (version_made, version_needed, gp_flags, method, _mtime, _mdate, crc,
         csize_raw, usize_raw, name_len, extra_len, comment_len, disk_start,
         _int_attrs, _ext_attrs, local_offset) = struct.unpack_from("<HHHHHHIIIHHHHHII", data, pos + 4)
        name_start = pos + 46
        extra_start = name_start + name_len
        end = extra_start + extra_len + comment_len
        if end > len(data):
            raise RejectionError("MALFORMED_ZIP_CENTRAL_DIRECTORY_HEADER")
        name = data[name_start:extra_start].decode("utf-8", errors="replace")
        extra = data[extra_start:extra_start + extra_len]
        csize, usize, local_offset, had_extra = _resolve_zip64_extra(
            extra, csize=csize_raw, usize=usize_raw, local_offset=local_offset
        )
        if had_extra:
            flags_detected.append("ZIP64_EXTRA_FIELD_PRESENT")
        if gp_flags & 0x0001 or gp_flags & 0x0040 or gp_flags & 0x2000 or method == 99:
            flags_detected.append("ENCRYPTED_MEMBER")
        if disk_start not in (0, 0xFFFF):
            raise RejectionError("MULTI_DISK_ZIP_UNSUPPORTED")
        if csize_raw == 0xFFFFFFFF or usize_raw == 0xFFFFFFFF:
            flags_detected.append("ZIP64_CDH_SENTINEL")
        zip64_sizes = csize_raw == 0xFFFFFFFF or usize_raw == 0xFFFFFFFF
        entries.append(_CentralEntry(name, gp_flags, method, crc, csize, usize,
                                     local_offset, had_extra, zip64_sizes))
        budget.count_entry()
        budget.check_time()
        pos = end
    return entries, sorted(set(flags_detected))


@dataclass
class _InflateResult:
    """Terminal state of a bounded raw-DEFLATE stream.

    Finding-1 fix: a DEFLATE member is ACCEPTED ONLY IF the end-of-stream
    marker was actually reached (`eof=True`) after ALL declared compressed
    bytes were consumed. A truncated stream (eof stays False) is reported and
    rejected by the caller. `trailing_bytes` reports compressed bytes that
    follow the end-of-stream marker WITHIN the declared size window; those are
    valid only as a ZIP data descriptor, which the caller validates separately.
    No unbounded `flush()` is ever performed: every yielded chunk is strictly
    bounded by the `max_length` argument of `decompress()`.
    """
    eof: bool = False
    trailing_bytes: int = 0


def _inflate_bounded(compressed: memoryview, chunk_bytes: int) -> tuple[Iterable[bytes], _InflateResult]:
    """Stream decompressed output in strictly bounded chunks.

    Returns `(chunks, result)`. Progress is guaranteed on every inner
    iteration: `decompress(pending, chunk_bytes)` either consumes input
    (`unconsumed_tail` shrinks) or yields bounded output; a call with
    non-empty input never returns without one of the two.
    """
    result = _InflateResult()

    def stream() -> Iterable[bytes]:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        total = len(compressed)
        position = 0
        pending = b""
        while position < total and not decompressor.eof:
            block = bytes(compressed[position:position + chunk_bytes])
            position += len(block)
            pending = block
            while pending and not decompressor.eof:
                out = decompressor.decompress(pending, chunk_bytes)
                pending = decompressor.unconsumed_tail
                if out:
                    yield out  # strictly <= chunk_bytes (max_length bound)
        # Terminal state — the stream is complete ONLY if the DEFLATE
        # end-of-stream marker was reached (a truncated stream that reproduces
        # every decompressed byte must still be rejected).
        result.eof = decompressor.eof
        if decompressor.eof:
            # Trailing bytes after the end marker: the remainder of the last
            # fed block (CPython exposes it via unused_data, and possibly via
            # unconsumed_tail) plus any blocks never fed at all.
            unused = decompressor.unused_data
            result.trailing_bytes = max(len(pending), len(unused) if unused else 0) \
                + (total - position)
        else:
            result.trailing_bytes = 0

    return stream(), result


def _parse_lfh_zip64(extra: bytes, *, lfh_csize_raw: int, lfh_usize_raw: int,
                     lfh_position: int, cdh_csize: int, cdh_usize: int,
                     streaming: bool) -> bool:
    """Parse and validate the local header's 0x0001 ZIP64 extra field (APPNOTE 4.3.14).

    Returns True when the member carries ZIP64 local-header metadata — size
    sentinels (0xFFFFFFFF) and/or a 0x0001 extra field. That evidence, combined
    with the CDH evidence, selects the signed data-descriptor width; the width
    is NEVER guessed from the descriptor bytes themselves.

    Fail-closed rules:
      * TLV overflow or duplicate 0x0001 TLV in the LFH extra ⇒ rejected;
      * LFH size sentinels WITHOUT a 0x0001 extra ⇒ rejected
        (`MALFORMED_ZIP64_LFH_EXTRA`);
      * a non-streaming member (bit 3 not set) whose sentinel is not resolved
        by a NON-ZERO 64-bit value ⇒ rejected (zero placeholders are only
        legitimate under bit-3 streaming, where the descriptor carries the
        verified sizes — CPython `force_zip64` over a non-seekable stream
        writes exactly this);
      * non-zero provided values are verified metadata and must agree with the
        Central Directory (usize/csize) and with the ACTUAL LFH position
        (local offset); contradictions are rejected;
      * a non-zero disk-start value ⇒ multi-disk ⇒ rejected.

    Field order inside the local-header 0x0001 body (APPNOTE): uncompressed
    size, compressed size, local header offset, disk start — each 8 bytes,
    only as many as present.
    """
    lfh_zip64 = (lfh_csize_raw == 0xFFFFFFFF) or (lfh_usize_raw == 0xFFFFFFFF)
    pos = 0
    body: bytes | None = None
    while pos + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + size > len(extra):
            raise RejectionError("MALFORMED_ZIP_EXTRA_FIELD", "LFH extra TLV length overflow")
        if tag == 0x0001:
            if body is not None:
                raise RejectionError("MALFORMED_ZIP_EXTRA_FIELD", "duplicate LFH 0x0001 TLV")
            body = extra[pos:pos + size]
        pos += size
    if body is None:
        if lfh_zip64:
            raise RejectionError("MALFORMED_ZIP64_LFH_EXTRA",
                                 "LFH size sentinels without a 0x0001 ZIP64 extra field")
        return False
    lfh_zip64 = True
    if len(body) % 8 != 0 or len(body) > 32:
        raise RejectionError("MALFORMED_ZIP64_LFH_EXTRA",
                             "LFH 0x0001 body must hold 1..4 ordered 8-byte fields")
    values = [struct.unpack_from("<Q", body, i)[0] for i in range(0, len(body), 8)]
    if len(values) >= 1 and values[0] and values[0] != cdh_usize:
        raise RejectionError("MALFORMED_LFH_CDH_MISMATCH",
                             "LFH zip64 uncompressed size contradicts the Central Directory")
    if len(values) >= 2 and values[1] and values[1] != cdh_csize:
        raise RejectionError("MALFORMED_LFH_CDH_MISMATCH",
                             "LFH zip64 compressed size contradicts the Central Directory")
    if len(values) >= 3 and values[2] and values[2] != lfh_position:
        raise RejectionError("MALFORMED_ZIP64_LFH_EXTRA",
                             "LFH zip64 local-header offset contradicts the actual position")
    if len(values) >= 4 and values[3]:
        raise RejectionError("MULTI_DISK_ZIP_UNSUPPORTED", "LFH zip64 disk start non-zero")
    if not streaming:
        # Non-streaming member: the sentinel must be resolved by a NON-ZERO value.
        if lfh_usize_raw == 0xFFFFFFFF and (len(values) < 1 or values[0] == 0):
            raise RejectionError("MALFORMED_ZIP64_LFH_EXTRA",
                                 "LFH usize sentinel not resolved by a non-zero 0x0001 value")
        if lfh_csize_raw == 0xFFFFFFFF and (len(values) < 2 or values[1] == 0):
            raise RejectionError("MALFORMED_ZIP64_LFH_EXTRA",
                                 "LFH csize sentinel not resolved by a non-zero 0x0001 value")
    return True


_DATA_DESCRIPTOR_SIG = b"PK\x07\x08"
_KNOWN_RECORD_SIGS = (LFH_SIG, CDH_SIG, EOCD_SIG, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG)


def _validate_data_descriptor(*, data: bytes, data_start: int, compressed_size: int,
                              flags: int, zip64_sizes: bool,
                              actual: int, crc: int,
                              next_local_offset: int | None = None) -> None:
    """Validate the optional data descriptor that FOLLOWS the member data.

    Standards placement (Finding 1 correction): the descriptor occurs
    immediately AFTER the compressed member data, at
    `data_start + compressed_size`. The Central Directory compressed-size
    field describes the compressed file data and does NOT include the
    descriptor.

    Width selection uses VERIFIED format metadata from BOTH headers, never
    descriptor sniffing: a member with ZIP64 local-header metadata (LFH size
    sentinels or a 0x0001 extra field, validated by `_parse_lfh_zip64`) OR
    ZIP64 central-directory metadata (CDH 0xFFFFFFFF sentinels resolved from
    the 0x0001 extra) requires the signed 24-byte ZIP64 form —
    Signature(4) + CRC32(4) + CompressedSize64(8) + UncompressedSize64(8)
    (APPNOTE 4.3.9; Go archive/zip; CPython zipfile ``<LLQQ``). This covers
    the legitimate CPython ``force_zip64`` streaming combination where the
    CDH keeps ordinary small 32-bit sizes (no sentinels) but the LFH carries
    ZIP64 metadata. All other members require the signed 16-byte form —
    Signature(4) + CRC32(4) + CompressedSize32(4) + UncompressedSize32(4)
    (CPython zipfile ``<LLLL``).

    The legacy UNSIGNED form (no signature) is out of scope: it raises
    UnsupportedError (classified UNSUPPORTED, documented compatibility
    impact) and is never silently accepted.

    Field validation ties the descriptor to the Central Directory and the
    ACTUAL read; the record following the descriptor must be a valid local
    header / central directory record, and a following local header must be
    exactly where the next Central Directory entry's local offset says.
    """
    descriptor_start = data_start + compressed_size
    if not (flags & 0x0008):
        # No descriptor expected. A descriptor signature immediately after the
        # data is a contradictory structure (undeclared descriptor).
        if (descriptor_start + 4 <= len(data)
                and data[descriptor_start:descriptor_start + 4] == _DATA_DESCRIPTOR_SIG):
            raise RejectionError("UNDECLARED_DATA_DESCRIPTOR",
                                 "data descriptor present but general-purpose bit 3 not set")
        return
    # Bit 3 set: the descriptor is REQUIRED.
    width = 24 if zip64_sizes else 16
    if descriptor_start + width > len(data):
        raise RejectionError("TRUNCATED_DATA_DESCRIPTOR",
                             f"{width}-byte descriptor extends past end of data")
    descriptor = data[descriptor_start:descriptor_start + width]
    if descriptor[:4] != _DATA_DESCRIPTOR_SIG:
        if width == 16 and descriptor_start + 12 <= len(data):
            u_crc, u_csize, u_usize = struct.unpack_from("<LLL", descriptor, 0)
            if u_crc == crc and u_csize == compressed_size and u_usize == actual:
                raise UnsupportedError(
                    "UNSIGNED_DATA_DESCRIPTOR_UNSUPPORTED",
                    "legacy unsigned data descriptor (no signature): out of scope; "
                    "compatibility impact: archives from legacy streaming writers that "
                    "omit the descriptor signature are not inspected (fail-closed)")
        raise RejectionError("INVALID_DATA_DESCRIPTOR",
                             "missing data descriptor signature (bit 3 set)")
    if width == 16:
        d_crc, d_csize, d_usize = struct.unpack_from("<LLL", descriptor, 4)
    else:
        d_crc = struct.unpack_from("<I", descriptor, 4)[0]
        d_csize = struct.unpack_from("<Q", descriptor, 8)[0]
        d_usize = struct.unpack_from("<Q", descriptor, 16)[0]
    if d_crc != crc or d_csize != compressed_size or d_usize != actual:
        raise RejectionError(
            "INVALID_DATA_DESCRIPTOR",
            f"descriptor fields contradict central directory / actual read "
            f"(crc {d_crc:#x}!={crc:#x}, csize {d_csize}!={compressed_size}, usize {d_usize}!={actual})")
    following = descriptor_start + width
    if following + 4 > len(data):
        raise RejectionError("TRUNCATED_DATA_DESCRIPTOR",
                             "no record follows the data descriptor")
    following_sig = data[following:following + 4]
    if following_sig not in _KNOWN_RECORD_SIGS:
        raise RejectionError("INVALID_DATA_DESCRIPTOR",
                             "no valid local header / central directory record follows the "
                             "descriptor (incompatible or ambiguous width/layout)")
    if following_sig == LFH_SIG:
        if next_local_offset is None:
            raise RejectionError("INVALID_DATA_DESCRIPTOR",
                                 "untracked local header follows the descriptor")
        if next_local_offset != following:
            raise RejectionError("INVALID_DATA_DESCRIPTOR",
                                 "following local header offset contradicts the descriptor boundary")


def _stream_member(budget: ResourceBudget, *, data: bytes, entry: _CentralEntry,
                   scanner: ScannerAdapter,
                   next_local_offset: int | None = None) -> tuple[int, int, bytes | None, str, bool]:
    """Stream ONE member in bounded chunks. Returns (actual, crc, nested_bytes, first_type, lfh_zip64).

    Standards data-descriptor placement (Finding-1 correction): the member's
    compressed data occupies `data_start .. data_start + csize` EXACTLY — the
    CDH compressed-size field never includes the descriptor. The optional
    data descriptor is validated at `data_start + csize` by
    `_validate_data_descriptor`. DEFLATE streams must reach the end-of-stream
    marker; any bytes after it WITHIN the compressed window are rejected.
    """
    if entry.local_offset + 30 > len(data) or data[entry.local_offset:entry.local_offset + 4] != LFH_SIG:
        raise RejectionError("MALFORMED_ZIP_LOCAL_HEADER")
    lfh_name_len, lfh_extra_len = struct.unpack_from("<HH", data, entry.local_offset + 26)
    data_start = entry.local_offset + 30 + lfh_name_len + lfh_extra_len
    if data_start + entry.csize > len(data):
        raise RejectionError("MALFORMED_ZIP_MEMBER_RANGE")
    lfh_flags, lfh_method = struct.unpack_from("<HH", data, entry.local_offset + 6)
    if lfh_flags != entry.flags or lfh_method != entry.method:
        raise RejectionError("MALFORMED_LFH_CDH_MISMATCH")
    lfh_csize_raw, lfh_usize_raw = struct.unpack_from("<II", data, entry.local_offset + 18)
    lfh_extra = data[entry.local_offset + 30 + lfh_name_len:data_start]
    # ZIP64 local-header metadata (sentinels and/or 0x0001 extra) is validated
    # here, together with the CDH metadata, to select the descriptor width.
    lfh_zip64 = _parse_lfh_zip64(
        lfh_extra, lfh_csize_raw=lfh_csize_raw, lfh_usize_raw=lfh_usize_raw,
        lfh_position=entry.local_offset, cdh_csize=entry.csize,
        cdh_usize=entry.usize, streaming=bool(entry.flags & 0x0008))

    if entry.flags & 0x0001 or entry.flags & 0x0040 or entry.flags & 0x2000 or entry.method == 99:
        raise RejectionError("ENCRYPTED_MEMBER", "encrypted archive member: no key, fail closed")
    if entry.method not in SUPPORTED_METHODS:
        raise RejectionError("UNSUPPORTED_COMPRESSION_METHOD", f"method={entry.method}")

    chunk_bytes = budget.limits.chunk_bytes
    if entry.method == 0:
        # STORED: the payload IS the on-disk data, so csize == usize must hold
        # EXACTLY — for a stored member the compressed data and the file data
        # are the same bytes, and the descriptor sits OUTSIDE that window.
        if entry.usize != entry.csize:
            raise RejectionError(
                "MALFORMED_ZIP_MEMBER_RANGE",
                "STORED member: csize must equal usize (data descriptors never "
                "occupy the compressed-size window)")
        payload_window = memoryview(data)[data_start:data_start + entry.usize]
        chunks = (bytes(payload_window[i:i + chunk_bytes])
                  for i in range(0, len(payload_window), chunk_bytes))
        inflate_result = None
    else:
        compressed = memoryview(data)[data_start:data_start + entry.csize]
        chunks, inflate_result = _inflate_bounded(compressed, chunk_bytes)

    actual = 0
    crc = 0
    first_chunk = b""
    nested: bytearray | None = None
    nested_size = 0
    is_nested = False
    for chunk in chunks:
        if not chunk:
            continue
        if not first_chunk:
            first_chunk = chunk[:16]
            # Content sniffing is decisive, NEVER the declared filename extension.
            is_nested = sniff_content_type(first_chunk) == "application/zip"
            if is_nested:
                nested = bytearray()
        actual += len(chunk)
        budget.charge_expanded(len(chunk), member_bytes=actual)
        crc = zlib.crc32(chunk, crc) & 0xFFFFFFFF
        scanner.feed(chunk, budget)
        if nested is not None:
            if nested_size + len(chunk) > budget.limits.max_materialized_object_bytes:
                raise RejectionError("NESTED_CONTAINER_TOO_LARGE")
            nested.extend(chunk)
            nested_size += len(chunk)
    crc &= 0xFFFFFFFF

    # DEFLATE terminal validation: the end-of-stream marker is mandatory;
    # bytes after it WITHIN the compressed window are unexpected trailing
    # compressed data (never silently reclassified as a descriptor).
    if inflate_result is not None and not inflate_result.eof:
        raise RejectionError("TRUNCATED_DEFLATE_STREAM",
                             "DEFLATE end-of-stream marker not reached")
    if inflate_result is not None and inflate_result.trailing_bytes:
        raise RejectionError("UNEXPECTED_TRAILING_COMPRESSED_DATA",
                             "bytes after the DEFLATE end marker inside the compressed window")

    # Data descriptor: AFTER the compressed data at data_start + csize.
    _validate_data_descriptor(
        data=data, data_start=data_start, compressed_size=entry.csize,
        flags=entry.flags, zip64_sizes=(lfh_zip64 or entry.zip64_sizes),
        actual=actual, crc=crc,
        next_local_offset=next_local_offset,
    )

    nested_bytes: bytes | None = None
    if nested is not None:
        budget.reserve_memory(len(nested))
        nested_bytes = bytes(nested)
    return actual, crc, nested_bytes, sniff_content_type(first_chunk), lfh_zip64


def _inspect_one_member(budget: ResourceBudget, ledger: CoverageLedger, *,
                        object_path: str, member_path: str, data: bytes,
                        entry: _CentralEntry, depth: int,
                        scanner_factory: Callable[[], ScannerAdapter],
                        next_local_offset: int | None = None) -> None:
    budget.check_depth(depth)  # member depth also counts against the recursion budget
    scanner = scanner_factory()
    try:
        actual, crc, nested_bytes, detected, lfh_zip64 = _stream_member(
            budget, data=data, entry=entry, scanner=scanner,
            next_local_offset=next_local_offset
        )
    except UnsupportedError as error:
        # Structurally out of scope (e.g. legacy unsigned data descriptor):
        # classified UNSUPPORTED, never accepted, never reported as corrupt.
        ledger.unsupported(member_path, depth, error.code,
                           notes=[error.detail] if error.detail else [])
        raise
    except RejectionError as error:
        if error.code == "UNSUPPORTED_COMPRESSION_METHOD":
            # Fail closed, but classify with the correct taxonomy: the member is
            # NOT inspected because the compressor is out of supported scope.
            ledger.unsupported(member_path, depth, error.code,
                               notes=[error.detail] if error.detail else [])
        else:
            ledger.reject(member_path, depth, error.code, detected="UNKNOWN",
                          notes=[error.detail] if error.detail else [])
        raise
    except (zlib.error, struct.error, ValueError) as error:
        ledger.reject(member_path, depth, "CORRUPT_MEMBER", detected="UNKNOWN",
                      notes=[type(error).__name__])
        raise RejectionError("CORRUPT_MEMBER", type(error).__name__)

    scan = scanner.finish()
    if crc != entry.crc:
        ledger.reject(member_path, depth, "CRC_MISMATCH", extracted_bytes=actual,
                      detected=detected, notes=["declared CRC did not match ACTUAL inflated bytes"])
        raise RejectionError("CRC_MISMATCH")
    if actual != entry.usize:
        ledger.reject(member_path, depth, "DECLARED_SIZE_MISMATCH", extracted_bytes=actual,
                      detected=detected,
                      notes=[f"declared_uncompressed_size={entry.usize}",
                             "declared size was NOT trusted; actual bytes were counted"])
        raise RejectionError("DECLARED_SIZE_MISMATCH")

    notes = [f"declared_size={entry.usize}", f"method={entry.method}"]
    if entry.zip64_extra:
        notes.append("ZIP64_EXTRA_FIELD_RESOLVED")
    if lfh_zip64:
        notes.append("ZIP64_LFH_METADATA")
    record = ObjectRecord(
        object_path=member_path, depth=depth, detected_content_type=detected,
        structural_verdict="BOUNDED_STREAMING_READ_COMPLETE", verdict=INSPECTED,
        extracted_bytes=actual, scanner_verdict=str(scan["scanner_verdict"]),
        scanner_reason=str(scan["scanner_reason"]),
        offline_control_signature=str(scan["signature"]), notes=notes,
    )
    ledger.add(record)

    if nested_bytes is not None:
        try:
            # The nested container IS this member's content: same depth level.
            inspect_zip_container(budget, ledger, object_path=member_path,
                                  data=nested_bytes, depth=depth,
                                  scanner_factory=scanner_factory)
        finally:
            budget.release_memory(len(nested_bytes))


def inspect_zip_container(budget: ResourceBudget, ledger: CoverageLedger, *,
                          object_path: str, data: bytes, depth: int,
                          scanner_factory: Callable[[], ScannerAdapter]) -> str:
    """Bounded, streaming, recursive ZIP inspection. Fail closed on any gap."""
    budget.check_depth(depth)
    if len(data) > budget.limits.max_materialized_object_bytes:
        ledger.reject(object_path, depth, "MATERIALIZED_OBJECT_LIMIT",
                      detected=sniff_content_type(data))
        raise RejectionError("MATERIALIZED_OBJECT_LIMIT")
    budget.reserve_memory(len(data))
    try:
        try:
            entries, zip_flags = _parse_central_directory(data, budget)
        except RejectionError as error:
            ledger.reject(object_path, depth, error.code, detected="application/zip",
                          notes=[error.detail] if error.detail else [])
            raise
        container_scanner = scanner_factory()
        container_scanner.feed(data[:min(len(data), budget.limits.chunk_bytes)], budget)
        container_scan = container_scanner.finish()
        structural = ("ZIP64_STRUCTURES_PRESENT_BOUNDED_STDLIB_PARSE"
                      if any(flag.startswith("ZIP64") for flag in zip_flags)
                      else "WELL_FORMED_ZIP32")
        notes = [f"zip_flags={','.join(zip_flags) or 'NONE'}",
                 "raw_clamd_CLEAN_would_not_prove_nested_inspection"]
        if "ZIP64" in structural:
            notes.append("Phase 0A D_eicar_zip64 -> stream: OK (ClamAV 1.5.4 ZIP64 bypass)")
        ledger.add(ObjectRecord(
            object_path=object_path, depth=depth, detected_content_type="application/zip",
            structural_verdict=structural, verdict=INSPECTED, extracted_bytes=len(data),
            scanner_verdict=str(container_scan["scanner_verdict"]),
            scanner_reason=str(container_scan["scanner_reason"]),
            offline_control_signature=str(container_scan["signature"]), notes=notes,
        ))
        for entry in entries:
            budget.check_time()
            try:
                label = safe_member_path(entry.name)
            except RejectionError as error:
                ledger.reject(f"{object_path}::/{entry.name!r}", depth + 1, error.code,
                              detected="application/zip")
                raise
            later_offsets = [e.local_offset for e in entries
                             if e.local_offset > entry.local_offset]
            _inspect_one_member(budget, ledger, object_path=object_path,
                                member_path=f"{object_path}::/{label}", data=data,
                                entry=entry, depth=depth + 1,
                                scanner_factory=scanner_factory,
                                next_local_offset=min(later_offsets)
                                if later_offsets else None)
        return structural
    finally:
        budget.release_memory(len(data))


# ---------------------------------------------------------------------------
# Narrow PDF attachment-tree parser (NOT exhaustive stream inspection)
# ---------------------------------------------------------------------------
_OBJECT_RE = re.compile(rb"(?m)^(\d+)\s+(\d+)\s+obj\b")
_REF_RE = re.compile(rb"(\d+)\s+(\d+)\s+R")
_NAMES_PAIR_RE = re.compile(rb"\(([^)]*)\)\s*(\d+)\s+(\d+)\s+R")
_STREAM_LENGTH_RE = re.compile(rb"/Length\s+(\d+)(?!\s+\d+\s+R)")


@dataclass
class _PdfObject:
    number: int
    body: bytes
    stream: bytes | None
    stream_error: str | None


def _parse_pdf_objects(data: bytes, budget: ResourceBudget) -> tuple[dict[int, _PdfObject], list[str]]:
    gaps: list[str] = []
    matches = list(_OBJECT_RE.finditer(data))
    if not matches:
        raise RejectionError("MALFORMED_PDF_NO_OBJECTS")
    objects: dict[int, _PdfObject] = {}
    for index, match in enumerate(matches):
        number = int(match.group(1))
        start = match.end()
        end = data.find(b"endobj", start)
        if end < 0:
            raise RejectionError("MALFORMED_PDF_UNTERMINATED_OBJECT")
        body = data[start:end]
        stream_bytes: bytes | None = None
        stream_error: str | None = None
        stream_marker = re.search(rb"\bstream\r?\n", body)
        if stream_marker:
            dictionary = body[:stream_marker.start()]
            if b"/Length" not in dictionary:
                stream_error = "PDF_STREAM_WITHOUT_LENGTH"
            elif re.search(rb"/Length\s+\d+\s+\d+\s+R", dictionary):
                stream_error = "INDIRECT_PDF_STREAM_LENGTH_UNSUPPORTED"
            else:
                length_match = _STREAM_LENGTH_RE.search(dictionary)
                if not length_match:
                    stream_error = "PDF_STREAM_LENGTH_UNPARSEABLE"
                else:
                    length = int(length_match.group(1))
                    if length > budget.limits.max_materialized_object_bytes:
                        budget._hit("MATERIALIZED_OBJECT_LIMIT")
                    stream_start = stream_marker.end()
                    stream_bytes = body[stream_start:stream_start + length]
                    remainder = body[stream_start + length:stream_start + length + 12]
                    if b"endstream" not in remainder:
                        stream_error = "PDF_STREAM_LENGTH_MISMATCH"
            gaps.append(f"object_{number}_arbitrary_stream")
        if number in objects:
            gaps.append("DUPLICATE_OBJECT_IDS_AMBIGUOUS")
        objects[number] = _PdfObject(number, body, stream_bytes, stream_error)
        budget.check_time()
    return objects, sorted(set(gaps))


def inspect_pdf(budget: ResourceBudget, ledger: CoverageLedger, *,
                object_path: str, data: bytes, depth: int,
                scanner_factory: Callable[[], ScannerAdapter]) -> list[str]:
    """Narrow, explicitly scoped PDF parsing.

    SUPPORTED (attachment-only): /EmbeddedFiles name tree, /Filespec + /EF /F|/UF
    references, /FileAttachment annotations, /AF associated files.
    NOT SUPPORTED / NOT VERIFIED: arbitrary PDF streams, /ObjStm compressed object
    streams, filtered (FlateDecode) embedded streams, indirect /Length, encryption,
    incremental revisions, duplicate object ids, malformed xref, /Kids name trees.
    qpdf --json and PDF.js are NOT used and are NOT exhaustive stream inspectors.
    """
    if not data.startswith(b"%PDF-"):
        ledger.reject(object_path, depth, "MALFORMED_PDF_MAGIC", detected="UNKNOWN")
        raise RejectionError("MALFORMED_PDF_MAGIC")
    if b"startxref" not in data or b"%%EOF" not in data or b"trailer" not in data:
        ledger.reject(object_path, depth, "MALFORMED_PDF", detected="application/pdf",
                      notes=["missing xref/trailer/EOF: fail closed, no recovery attempted"])
        raise RejectionError("MALFORMED_PDF")

    gaps: list[str] = ["ARBITRARY_PDF_STREAMS_NOT_INSPECTED"]
    if b"/Encrypt" in data:
        ledger.add(ObjectRecord(
            object_path=f"{object_path}::/Encrypt", depth=depth,
            detected_content_type="application/pdf",
            structural_verdict="ENCRYPTED_PDF_CANNOT_INSPECT_WITHOUT_DECRYPTION",
            verdict=UNSUPPORTED, extracted_bytes=0, scanner_verdict="NOT_SCANNED",
            scanner_reason="ENCRYPTED_PDF_REQUIRES_POST_UNLOCK_OUTPUT_SCAN",
            notes=["SEC-REQ-02 encrypted-PDF detection; SEC-REQ-03 post-unlock output scan",
                   "fail closed: no decryption attempted in the isolated PoC",
                   "genuine AES-256/R6 fixture is NOT_VERIFIED offline (qpdf absent); "
                   "synthetic markers are parser probes only, never real encryption"],
        ))
        gaps.append("ENCRYPTED_PDF_NOT_INSPECTED")
        return gaps
    if data.count(b"%%EOF") > 1:
        ledger.add(ObjectRecord(
            object_path=f"{object_path}::/IncrementalRevisions", depth=depth,
            detected_content_type="application/pdf",
            structural_verdict="INCREMENTAL_REVISIONS_DETECTED", verdict=NOT_VERIFIED,
            extracted_bytes=0, scanner_verdict="NOT_SCANNED",
            scanner_reason="PARSER_READS_LATEST_TRAILER_ONLY",
            notes=["earlier revision objects are NOT enumerated; parser ambiguity"],
        ))
        gaps.append("INCREMENTAL_REVISIONS_NOT_VERIFIED")
    if b"/ObjStm" in data:
        gaps.append("COMPRESSED_OBJECT_STREAMS_NOT_VERIFIED")
        ledger.add(ObjectRecord(
            object_path=f"{object_path}::/ObjStm", depth=depth,
            detected_content_type="application/pdf",
            structural_verdict="COMPRESSED_OBJECT_STREAMS_NOT_INSPECTED",
            verdict=NOT_VERIFIED, extracted_bytes=0, scanner_verdict="NOT_SCANNED",
            scanner_reason="NO_OBJSTM_DECODE_IN_ISOLATED_POC",
            notes=["objects hidden inside /ObjStm are NOT enumerated",
                   "qpdf --json / PDF.js are NOT claimed as exhaustive stream inspectors"],
        ))

    objects, object_gaps = _parse_pdf_objects(data, budget)
    gaps.extend(f"PDF_OBJECT_GAP_{gap}" for gap in object_gaps)
    if "DUPLICATE_OBJECT_IDS_AMBIGUOUS" in object_gaps:
        ledger.add(ObjectRecord(
            object_path=f"{object_path}::/AmbiguousObjects", depth=depth,
            detected_content_type="application/pdf",
            structural_verdict="DUPLICATE_OBJECT_IDS_AMBIGUOUS", verdict=NOT_VERIFIED,
            extracted_bytes=0, scanner_verdict="NOT_SCANNED",
            scanner_reason="PARSER_AMBIGUITY_FAIL_CLOSED",
            notes=["duplicate indirect object numbers: no winner is assumed"],
        ))

    catalog = next((obj for obj in objects.values() if b"/Type /Catalog" in obj.body), None)
    if catalog is None:
        ledger.reject(object_path, depth, "MALFORMED_PDF_NO_CATALOG", detected="application/pdf")
        raise RejectionError("MALFORMED_PDF_NO_CATALOG")

    filespec_refs: list[tuple[int, str]] = []
    embedded_tree = re.search(rb"/EmbeddedFiles\s+(\d+)\s+(\d+)\s+R", catalog.body)
    if embedded_tree:
        tree = objects.get(int(embedded_tree.group(1)))
        if tree is None:
            ledger.reject(object_path, depth, "EMBEDDED_FILES_TREE_MISSING",
                          detected="application/pdf")
            raise RejectionError("EMBEDDED_FILES_TREE_MISSING")
        if b"/Kids" in tree.body:
            ledger.add(ObjectRecord(
                object_path=f"{object_path}::/Names/Kids", depth=depth,
                detected_content_type="application/pdf",
                structural_verdict="NAME_TREE_KIDS_UNSUPPORTED", verdict=UNSUPPORTED,
                extracted_bytes=0, scanner_verdict="NOT_SCANNED",
                scanner_reason="NAME_TREE_KIDS_NOT_IMPLEMENTED",
            ))
            gaps.append("NAME_TREE_KIDS_UNSUPPORTED")
        for name_match in _NAMES_PAIR_RE.finditer(tree.body):
            filespec_refs.append((int(name_match.group(2)), "EmbeddedFiles/NameTree"))
    af_matches = re.search(rb"/AF\s*\[(.*?)\]", catalog.body, re.DOTALL)
    if af_matches:
        for ref in _REF_RE.finditer(af_matches.group(1)):
            filespec_refs.append((int(ref.group(1)), "AF/AssociatedFiles"))
    for obj in objects.values():
        if b"/Type /Page" in obj.body and b"/Type /Pages" not in obj.body:
            annots = re.search(rb"/Annots\s*\[(.*?)\]", obj.body, re.DOTALL)
            if not annots:
                continue
            for ref in _REF_RE.finditer(annots.group(1)):
                annot = objects.get(int(ref.group(1)))
                if annot is None or b"/Subtype /FileAttachment" not in annot.body:
                    continue
                fs = re.search(rb"/FS\s+(\d+)\s+(\d+)\s+R", annot.body)
                if fs:
                    filespec_refs.append((int(fs.group(1)), "Annots/FileAttachment"))
                else:
                    ledger.skip(f"{object_path}::/Annots/FileAttachment", depth,
                                "FILEATTACHMENT_ANNOTATION_WITHOUT_FS")

    referenced_filespecs = {number for number, _ in filespec_refs}
    for number, obj in objects.items():
        if b"/Type /Filespec" in obj.body and number not in referenced_filespecs:
            ledger.skip(f"{object_path}::/Filespec#{number}", depth,
                        "UNREFERENCED_FILESPEC_NOT_INSPECTED")

    embedded_numbers: list[tuple[int, str]] = []
    for number, source in filespec_refs:
        spec = objects.get(number)
        if spec is None:
            ledger.skip(f"{object_path}::/{source}/Filespec", depth,
                        "FILESPEC_REFERENCE_UNRESOLVED")
            continue
        ef = re.search(rb"/EF\s*<<(.*?)>>", spec.body, re.DOTALL)
        if not ef:
            ledger.skip(f"{object_path}::/{source}/Filespec", depth,
                        "FILESPEC_WITHOUT_EF_REFERENCE")
            continue
        for key, number, _generation in re.findall(rb"/(F|UF)\s+(\d+)\s+(\d+)\s+R", ef.group(1)):
            embedded_numbers.append((int(number), f"{source}/EF/{key.decode('ascii')}"))
    if not embedded_numbers and filespec_refs:
        ledger.skip(f"{object_path}::/EF", depth, "NO_RESOLVABLE_EF_STREAM_REFERENCE")

    inspected_streams: set[int] = set()
    for number, source in embedded_numbers:
        obj = objects.get(number)
        if obj is None or obj.stream is None:
            ledger.add(ObjectRecord(
                object_path=f"{object_path}::/{source}", depth=depth + 1,
                detected_content_type="UNKNOWN",
                structural_verdict=obj.stream_error or "EMBEDDED_FILE_STREAM_UNRESOLVED",
                verdict=UNSUPPORTED, extracted_bytes=0, scanner_verdict="NOT_SCANNED",
                scanner_reason="EMBEDDED_FILE_STREAM_NOT_DECODED",
                notes=["filtered/indirect/malformed stream: no filter decoder implemented"],
            ))
            gaps.append("FILTERED_OR_INDIRECT_PDF_STREAM_UNSUPPORTED")
            continue
        if b"/Filter" in obj.body[:obj.body.find(b"stream")]:
            ledger.add(ObjectRecord(
                object_path=f"{object_path}::/{source}", depth=depth + 1,
                detected_content_type="UNKNOWN",
                structural_verdict="FILTERED_EMBEDDED_FILE_STREAM", verdict=UNSUPPORTED,
                extracted_bytes=0, scanner_verdict="NOT_SCANNED",
                scanner_reason="NO_PDF_FILTER_DECODER_IN_ISOLATED_POC",
                notes=["qpdf --json / PDF.js are NOT exhaustive stream inspectors"],
            ))
            gaps.append("FILTERED_PDF_STREAM_UNSUPPORTED")
            continue
        inspected_streams.add(number)
        payload = obj.stream
        budget.count_entry()
        budget.charge_expanded(len(payload), member_bytes=len(payload))
        detected = sniff_content_type(payload)
        scanner = scanner_factory()
        for offset in range(0, len(payload), budget.limits.chunk_bytes):
            scanner.feed(payload[offset:offset + budget.limits.chunk_bytes], budget)
        scan = scanner.finish()
        ledger.add(ObjectRecord(
            object_path=f"{object_path}::/{source}", depth=depth + 1,
            detected_content_type=detected,
            structural_verdict="REFERENCED_EMBEDDED_FILE_STREAM_EXTRACTED",
            verdict=INSPECTED, extracted_bytes=len(payload),
            scanner_verdict=str(scan["scanner_verdict"]),
            scanner_reason=str(scan["scanner_reason"]),
            offline_control_signature=str(scan["signature"]),
            notes=[f"pdf_reference_source={source}"],
        ))
        if detected == "application/zip":
            inspect_zip_container(budget, ledger,
                                  object_path=f"{object_path}::/{source}",
                                  data=payload, depth=depth + 2,
                                  scanner_factory=scanner_factory)

    for number, obj in objects.items():
        if obj.stream is not None and number not in inspected_streams:
            ledger.skip(f"{object_path}::/Stream#{number}", depth,
                        "ARBITRARY_PDF_STREAM_NOT_INSPECTED")
    return sorted(set(gaps))


# ---------------------------------------------------------------------------
# Case harness
# ---------------------------------------------------------------------------
@dataclass
class CaseSpec:
    case_id: str
    track: str
    description: str
    expected_verdict: str
    kind: str                                   # "pdf" | "zip"
    builder: Callable[[], bytes]
    limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS
    scanner_factory: Callable[[], ScannerAdapter] = OfflineEicarControlProbe
    notes: list[str] = field(default_factory=list)


def tool_capabilities() -> dict[str, object]:
    """Unverified capabilities are recorded as NOT_VERIFIED, never PASS."""
    return {
        "qpdf_binary_present": bool(shutil.which("qpdf")),
        "pdfdetach_binary_present": bool(shutil.which("pdfdetach")),
        "clamscan_binary_present": bool(shutil.which("clamscan")),
        "qpdf_json_stream_inspection": {
            "verdict": NOT_VERIFIED,
            "reason": "OFFLINE_POC_DOES_NOT_EXECUTE_EXTERNAL_TOOLS; qpdf --json=1 --json-key=objects --decode-level=none enumerates object metadata only, NOT exhaustive PDF stream inspection",
        },
        "pdfjs_stream_inspection": {
            "verdict": NOT_VERIFIED,
            "reason": "PDF.js exposes a bounded subset of decoded image XObjects; NOT an exhaustive arbitrary-PDF-stream inspector and NOT used in this PoC",
        },
        "pdfdetach_attachment_parity": {
            "verdict": NOT_VERIFIED,
            "reason": "pdfdetach absent offline; attachment byte-parity NOT verified",
        },
        "genuine_encrypted_pdf_fixture": {
            "verdict": NOT_VERIFIED,
            "reason": "qpdf absent offline; genuine AES-256/R6 fixture NOT generated and NOT fabricated",
        },
        "clamav_live_scan": {
            "verdict": NOT_VERIFIED,
            "reason": "LIVE_CLAMAV_EXPERIMENTS_FORBIDDEN_IN_PHASE_0C_OFFLINE_STEP",
        },
    }


SECURITY_REQUIREMENTS = [
    {"id": "SEC-REQ-01", "requirement": "R1/R2 inspection must complete BEFORE permanent storage (validateUpload -> requireCleanUpload -> storage.put)", "status": "OPEN_UNRESOLVED_PLACEMENT"},
    {"id": "SEC-REQ-02", "requirement": "Encrypted-PDF detection at ingress must fail closed (no claim of inspection of ciphertext)", "status": "NOT_VERIFIED"},
    {"id": "SEC-REQ-03", "requirement": "Post-unlock / decrypted PDF output must be scanned before it is persisted or reused", "status": "NOT_VERIFIED"},
    {"id": "SEC-REQ-04", "requirement": "Nested-content inspection completeness must be proven per object; raw clamd CLEAN is not proof", "status": "OPEN"},
    {"id": "SEC-REQ-05", "requirement": "One cumulative end-to-end budget covering extraction + scanning + timeouts + memory + disk", "status": "ENFORCED_IN_OFFLINE_POC"},
    {"id": "SEC-REQ-06", "requirement": "No new production dependency, no production path modification, no live workflow", "status": "ENFORCED_IN_OFFLINE_POC"},
]


def _ensure_terminal(ledger: CoverageLedger, code: str, data: bytes,
                     *, notes: Iterable[str] = ()) -> None:
    """Guarantee a case that raised ends with a terminal (REJECTED/UNSUPPORTED)
    record so it can never be reported as fully INSPECTED. Skipped records and
    already-recorded terminal verdicts are left untouched.
    """
    if any(record.verdict in (REJECTED, UNSUPPORTED) for record in ledger.objects
           if not record.skipped):
        return
    ledger.reject("input", 0, code, detected=sniff_content_type(data), notes=list(notes))


def _bounded_message(error: BaseException, limit: int = 200) -> str:
    """Bounded, structured description of an unexpected exception (Finding-3).

    Never relies on attributes the exception is not guaranteed to have; the
    result is length-capped so it can be embedded in a report verbatim.
    """
    message = str(error)
    if len(message) > limit - 64:
        message = message[: limit - 64] + "...<truncated>"
    return f"{type(error).__name__}: {message}"


def run_case(spec: CaseSpec) -> dict[str, object]:
    budget = ResourceBudget(spec.limits)
    ledger = CoverageLedger(spec.case_id, budget)
    data: bytes | None = None
    gaps: list[str] = []
    error_code: str | None = None
    try:
        # Fixture generation is inside the fail-closed boundary: an unexpected
        # builder failure must yield a structured REJECTED case, never a crash
        # of the suite or an unreported case (Finding-3).
        data = spec.builder()
        budget.charge_input(len(data))
        if spec.kind == "pdf":
            gaps = inspect_pdf(budget, ledger, object_path="input.pdf", data=data,
                               depth=0, scanner_factory=spec.scanner_factory)
        else:
            inspect_zip_container(budget, ledger, object_path="input.bin", data=data,
                                  depth=0, scanner_factory=spec.scanner_factory)
    except BudgetExceeded as error:
        error_code = error.code
        _ensure_terminal(ledger, error.code, data or b"")
    except UnsupportedError as error:
        error_code = error.code
        _ensure_terminal(ledger, error.code, data or b"",
                         notes=[error.detail] if error.detail else [])
    except RejectionError as error:
        error_code = error.code
        _ensure_terminal(ledger, error.code, data or b"",
                         notes=[error.detail] if error.detail else [])
    except Exception as error:  # fail closed on any unexpected condition
        # Finding-3 fix: use an explicit bounded code; an arbitrary exception
        # (e.g. RuntimeError/KeyError) is NOT guaranteed to carry `.code`.
        error_code = "UNEXPECTED_PARSER_ERROR"
        _ensure_terminal(ledger, error_code, data or b"", notes=[_bounded_message(error)])

    coverage = ledger.coverage(stream_gaps=gaps)
    scanner_clean_flags = [record.scanner_verdict == "CLEAN" for record in ledger.objects
                           if record.scanner_verdict not in ("NOT_SCANNED", NOT_VERIFIED)]
    conclusion = derive_conclusion(
        coverage, clamav_verified=False,
        scanner_all_clean=bool(scanner_clean_flags) and all(scanner_clean_flags),
        resource_limits_hit=budget.limits_hit,
    )
    effective_data = data if data is not None else b""
    return {
        "case_id": spec.case_id,
        "track": spec.track,
        "description": spec.description,
        "expected_verdict": spec.expected_verdict,
        "observed_verdict": ledger.case_verdict(),
        "verdict_match": ledger.case_verdict() == spec.expected_verdict,
        "input_bytes": len(effective_data),
        "input_sha256": hashlib.sha256(effective_data).hexdigest(),
        "error_code": error_code,
        "notes": list(spec.notes),
        "coverage": coverage,
        "conclusion": conclusion,
        "objects": [record.as_dict() for record in ledger.objects],
        "budget": budget.snapshot(),
    }


def _load_fixture_module():
    """Load the sibling experimental fixture module (stdlib only)."""
    import importlib.util
    from pathlib import Path

    import sys

    module_path = Path(__file__).resolve().with_name("phase0c_r1r2_fixtures.py")
    spec = importlib.util.spec_from_file_location("phase0c_r1r2_fixtures", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Phase 0C fixture module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # required for dataclass on Python 3.11
    spec.loader.exec_module(module)
    return module


def _zip64_with_16byte_descriptor(payload: bytes) -> bytes:
    """ZIP64 member (sentinels resolved) followed by a WRONG 16-byte descriptor."""
    module = _load_fixture_module()
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return module.build_zip(
        [module.Member(name="p16.bin", payload=payload, method=0, version_needed=45,
                       flags=0x0008, lfh_zip64=True, cdh_zip64=True,
                       raw_compressed=payload,
                       raw_data_descriptor=module.zip_data_descriptor_16(
                           crc, len(payload), len(payload)))],
        zip64_eocd=True,
    )


def _member_with_descriptor_garbage(payload: bytes) -> bytes:
    """Member + valid 16-byte descriptor + 4 garbage bytes before the next record."""
    module = _load_fixture_module()
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    dd = module.zip_data_descriptor_16(crc, len(payload), len(payload))
    # splice the garbage directly after the descriptor: rebuild then locate.
    base = module.build_zip(
        [module.Member(name="g.bin", payload=payload, method=0, flags=0x0008,
                       raw_compressed=payload, raw_data_descriptor=dd)])
    marker = dd + b"PK\x01\x02"
    idx = base.find(marker)
    return base[:idx + 4] + b"\x00\xff\x13\x37" + base[idx + 4 + 4:]


def build_case_suite() -> list[CaseSpec]:
    """R1 + R2 + independent controls. EICAR is the ONLY detection signature."""
    fx = _load_fixture_module()

    cases: list[CaseSpec] = []

    # ----------------------------- R1 --------------------------------------
    cases.append(CaseSpec(
        "R1-01", "R1", "PDF /EmbeddedFiles name tree -> /Filespec -> /EF ZIP64 EICAR attachment",
        INSPECTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip64(fx.EICAR_BYTES, "eicar.txt")),
        notes=["attachment-only coverage; arbitrary PDF streams remain NOT_VERIFIED"],
    ))
    cases.append(CaseSpec(
        "R1-02", "R1", "/Filespec with BOTH /EF /F and /UF references (two resolved streams)",
        INSPECTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.EICAR_BYTES), mode="filespec_ef"),
    ))
    cases.append(CaseSpec(
        "R1-03", "R1", "FileAttachment annotation -> /FS -> /Filespec -> /EF",
        INSPECTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.BENIGN_BYTES), mode="annotation"),
    ))
    cases.append(CaseSpec(
        "R1-04", "R1", "/AF associated-files array on Catalog -> /Filespec -> /EF",
        INSPECTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.EICAR_BYTES), mode="af"),
    ))
    cases.append(CaseSpec(
        "R1-05", "R1", "Benign ZIP32 attached via /EmbeddedFiles (negative structural control)",
        INSPECTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.BENIGN_BYTES)),
    ))
    cases.append(CaseSpec(
        "R1-06", "R1", "Unreferenced /EmbeddedFile stream with NO /EF reference (arbitrary-stream gap)",
        NOT_VERIFIED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.EICAR_BYTES), mode="unreferenced"),
        notes=["proves attachment-only coverage cannot close R1"],
    ))
    cases.append(CaseSpec(
        "R1-07", "R1", "SYNTHETIC /Encrypt marker probe: parser fail-closed on encrypted PDF",
        UNSUPPORTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.BENIGN_BYTES),
                                  synthetic_encrypt_marker=True),
        notes=["SYNTHETIC MARKER ONLY; genuine AES-256 fixture NOT generated (qpdf absent)",
               "SEC-REQ-02 / SEC-REQ-03 remain explicit requirements"],
    ))
    cases.append(CaseSpec(
        "R1-08", "R1", "Incremental revisions (2x %%EOF): earlier revision objects not enumerated",
        NOT_VERIFIED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.BENIGN_BYTES), incremental_revision=True),
    ))
    cases.append(CaseSpec(
        "R1-09", "R1", "Compressed /ObjStm marker + arbitrary page/content streams",
        NOT_VERIFIED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.BENIGN_BYTES),
                                  include_object_stream_marker=True),
        notes=["qpdf --json and PDF.js are NOT claimed as exhaustive stream inspection"],
    ))
    cases.append(CaseSpec(
        "R1-10", "R1", "Malformed PDF (no xref/startxref/%%EOF): fail closed",
        REJECTED, "pdf",
        lambda: fx.build_pdf(fx.PdfSpec(attachment=fx.zip32(fx.BENIGN_BYTES),
                                        malformed=True)),
    ))
    cases.append(CaseSpec(
        "R1-11", "R1", "Duplicate indirect object ids: parser ambiguity -> NOT_VERIFIED",
        NOT_VERIFIED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.BENIGN_BYTES),
                                  duplicate_object_ids=True),
    ))
    cases.append(CaseSpec(
        "R1-12", "R1", "Filtered (/FlateDecode) embedded file stream: no decoder in isolated PoC",
        UNSUPPORTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.EICAR_BYTES),
                                  compress_attachment_stream=True),
    ))
    cases.append(CaseSpec(
        "R1-13", "R1", "Attachment stream exceeds bounded materialisation ceiling",
        REJECTED, "pdf",
        lambda: fx.pdf_attachment(fx.zip32(fx.BENIGN_BYTES)),
        limits=replace(DEFAULT_RESOURCE_LIMITS, max_materialized_object_bytes=64),
        notes=["resource-limit enforcement; no disk spill"],
    ))

    # ----------------------------- R2 --------------------------------------
    cases.append(CaseSpec(
        "R2-01", "R2", "ZIP32 containing ZIP32 (EICAR at depth 2)",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("outer/inner.zip", fx.zip32(fx.EICAR_BYTES), method=8)]),
    ))
    cases.append(CaseSpec(
        "R2-02", "R2", "ZIP32 containing ZIP64 (full EOCD + locator + sentinels) with EICAR",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("outer/inner.zip", fx.zip64(fx.EICAR_BYTES), method=8)]),
        notes=["stdlib bounded parse INSPECTS what ClamAV 1.5.4 silently bypasses; clamd verdict NOT_VERIFIED"],
    ))
    cases.append(CaseSpec(
        "R2-03", "R2", "DEFLATE-compressed nested archive (streaming bounded inflate)",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("outer/inner.zip",
                                        fx.zip32(fx.EICAR_BYTES, method=8), method=8)]),
    ))
    cases.append(CaseSpec(
        "R2-04", "R2", "Spoofed extension: nested ZIP stored as notes.txt (content sniff, not name)",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("notes.txt", fx.zip32(fx.EICAR_BYTES), method=8)]),
    ))
    cases.append(CaseSpec(
        "R2-05", "R2", "Nested archive depth limit exceeded (chain of 5, ceiling depth=3)",
        REJECTED, "zip",
        lambda: fx.nested_zip_chain(5, fx.EICAR_BYTES),
        notes=["RECURSION_DEPTH_LIMIT hit; fail closed"],
    ))
    cases.append(CaseSpec(
        "R2-06", "R2", "Corrupt member (declared CRC mismatch on ACTUAL inflated bytes)",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("bad.bin", fx.EICAR_BYTES, method=8, crc=0x12345678)]),
    ))
    cases.append(CaseSpec(
        "R2-07", "R2", "Encrypted archive member (flag bit 0): no key, fail closed",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("locked.bin", fx.BENIGN_BYTES, flags=0x0001)]),
    ))
    cases.append(CaseSpec(
        "R2-08", "R2", "Unsupported compression method (LZMA=14): fail closed",
        UNSUPPORTED, "zip",
        lambda: fx.build_zip([fx.Member("lzma.bin", fx.BENIGN_BYTES, method=14)]),
    ))
    cases.append(CaseSpec(
        "R2-09", "R2", "Path traversal member name ../../evil.txt: rejected, never extracted",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("../../evil.txt", fx.BENIGN_BYTES)]),
        notes=["no filesystem extraction exists in this PoC"],
    ))
    cases.append(CaseSpec(
        "R2-10", "R2", "Forged declared uncompressed size: ACTUAL inflated bytes counted instead",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("forged.bin", b"A" * 4096, method=8, usize_lie=8)]),
        notes=["declared size is NEVER trusted"],
    ))
    cases.append(CaseSpec(
        "R2-11", "R2", "Cumulative expanded-byte ceiling hit (tiny experimental ceiling)",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("big.bin", b"A" * 4096, method=8)]),
        limits=replace(DEFAULT_RESOURCE_LIMITS, max_expanded_bytes=64),
    ))
    cases.append(CaseSpec(
        "R2-12", "R2", "Entry-count ceiling hit (tiny experimental ceiling)",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member(f"f{i}.txt", b"x") for i in range(6)]),
        limits=replace(DEFAULT_RESOURCE_LIMITS, max_entries=2),
    ))

    # --- Finding-1 regression cases (DEFLATE terminal strictness) ----------
    cases.append(CaseSpec(
        "R2-13", "R2", "Truncated DEFLATE stream: CRC and uncompressed size still match, end marker absent",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("trunc.bin", fx.EICAR_BYTES, method=8,
                                        raw_compressed=fx.deflate_truncated(fx.EICAR_BYTES))]),
        notes=["TRUNCATED_DEFLATE_STREAM: produced bytes alone are never proof of a complete stream"],
    ))
    cases.append(CaseSpec(
        "R2-14", "R2", "Unexpected trailing compressed bytes after the DEFLATE end marker (within declared csize)",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("trail.bin", fx.EICAR_BYTES, method=8,
                                        raw_compressed=fx.deflate_two_block(fx.EICAR_BYTES) + b"\x00\xffz")]),
        notes=["UNEXPECTED_TRAILING_COMPRESSED_DATA: trailing data is rejected, not silently skipped"],
    ))
    _dd16_eicar = fx.zip_data_descriptor_16(
        zlib.crc32(fx.EICAR_BYTES) & 0xFFFFFFFF, len(fx.EICAR_BYTES), len(fx.EICAR_BYTES))
    cases.append(CaseSpec(
        "R2-15", "R2", "Valid signed 16-byte data descriptor AFTER a STORED member (bit 3) is accepted",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd.bin", fx.EICAR_BYTES, method=0, flags=0x0008,
                                        raw_compressed=fx.EICAR_BYTES,
                                        raw_data_descriptor=_dd16_eicar)]),
        notes=["descriptor read at data_start + csize (CDH csize excludes the descriptor); "
               "validated field-by-field against the ACTUAL read"],
    ))
    cases.append(CaseSpec(
        "R2-16", "R2", "Data-descriptor flag set but no descriptor present",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("nod.bin", fx.EICAR_BYTES, method=0, flags=0x0008)]),
        notes=["INVALID_DATA_DESCRIPTOR: bit 3 set => descriptor required; fail closed on the gap"],
    ))

    # --- Finding-2 regression cases (per-member accounting boundary) -------
    cases.append(CaseSpec(
        "R2-17", "R2", "Member exactly at the per-member ceiling (multi-chunk read): allowed",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("exact.bin", b"A" * 256)]),
        limits=replace(DEFAULT_RESOURCE_LIMITS, max_member_bytes=256, chunk_bytes=64),
        notes=["exactly-at-ceiling must be allowed (double counting removed)"],
    ))
    cases.append(CaseSpec(
        "R2-18", "R2", "Member one byte over the per-member ceiling (multi-chunk read): rejected",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("over.bin", b"A" * 257)]),
        limits=replace(DEFAULT_RESOURCE_LIMITS, max_member_bytes=256, chunk_bytes=64),
        notes=["one byte above the ceiling is rejected (MEMBER_BYTE_LIMIT)"],
    ))
    cases.append(CaseSpec(
        "R2-19", "R2", "LFH/CDH method mismatch: rejected, never classified inspected",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("mm.bin", fx.BENIGN_BYTES, lfh_method_override=8)]),
        notes=["LFH method 8 vs CDH method 0 => MALFORMED_LFH_CDH_MISMATCH"],
    ))
    cases.append(CaseSpec(
        "R2-20", "R2", "Truncated ZIP container (EOCD cut): fail closed",
        REJECTED, "zip",
        lambda: fx.zip32(fx.BENIGN_BYTES)[:-12],
        notes=["truncated EOCD => MALFORMED_ZIP_NO_EOCD, no recovery attempted"],
    ))
    cases.append(CaseSpec(
        "R2-21", "R2", "Cumulative expanded-byte ceiling hit across several small members",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member(f"s{i}.bin", b"B" * 90) for i in range(3)]),
        limits=replace(DEFAULT_RESOURCE_LIMITS, max_member_bytes=100, max_expanded_bytes=250),
        notes=["per-member ceiling (100) never hit; cumulative ceiling (250) hit on the 3rd member"],
    ))
    _r2_22_payload = b"A" * 500
    _r2_22_inner = fx.zip32(_r2_22_payload)
    cases.append(CaseSpec(
        "R2-22", "R2", "Nested members consume the SAME cumulative expanded budget",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("inner.zip", _r2_22_inner, method=0)]),
        limits=replace(DEFAULT_RESOURCE_LIMITS,
                       max_expanded_bytes=len(_r2_22_inner) + len(_r2_22_payload) - 1),
        notes=["outer member read + inner member read share one cumulative ceiling; "
               "the inner read trips EXPANDED_BYTE_LIMIT"],
    ))

    # --- Data-descriptor standards-compliance regression cases --------------
    _defl_eicar = fx.deflate_two_block(fx.EICAR_BYTES)
    _dd16_defl = fx.zip_data_descriptor_16(
        zlib.crc32(fx.EICAR_BYTES) & 0xFFFFFFFF, len(_defl_eicar), len(fx.EICAR_BYTES))
    cases.append(CaseSpec(
        "R2-23", "R2", "Valid signed 16-byte data descriptor AFTER a DEFLATE member (bit 3) is accepted",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_defl.bin", fx.EICAR_BYTES, method=8, flags=0x0008,
                                        raw_compressed=_defl_eicar,
                                        raw_data_descriptor=_dd16_defl)]),
        notes=["DEFLATE EOS reached, no in-window trailing, descriptor after the data: INSPECTED"],
    ))
    cases.append(CaseSpec(
        "R2-24", "R2", "Valid ZIP64 member with the signed 24-byte descriptor (sig+crc+csize64+usize64) after the data",
        INSPECTED, "zip",
        lambda: fx.zip64_with_descriptor(fx.EICAR_BYTES, method=0),
        notes=["width selected from VERIFIED metadata (0xFFFFFFFF sentinels resolved); "
               "the 24-byte form carries NO local-header offset field"],
    ))
    cases.append(CaseSpec(
        "R2-25", "R2", "Independent writer: CPython zipfile over a non-seekable stream (bit 3 + 16-byte descriptors)",
        INSPECTED, "zip",
        lambda: fx.zipfile_nonseekable_archive(
            [("stored.bin", fx.EICAR_BYTES, 0), ("deflated.txt", fx.BENIGN_BYTES, 8)]),
        notes=["provenance: CPython 3.11.2 zipfile streaming mode (LFH sizes zeroed, "
               "descriptor after the data, CDH sizes = compressed data only); the independent "
               "reader (this PoC) must accept exactly what the independent writer produced"],
    ))
    cases.append(CaseSpec(
        "R2-26", "R2", "Descriptor CRC contradicts the Central Directory CRC",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_crc.bin", fx.EICAR_BYTES, method=0, flags=0x0008,
                                        raw_compressed=fx.EICAR_BYTES,
                                        raw_data_descriptor=fx.zip_data_descriptor_16(
                                            (zlib.crc32(fx.EICAR_BYTES) + 1) & 0xFFFFFFFF,
                                            len(fx.EICAR_BYTES), len(fx.EICAR_BYTES)))]),
        notes=["INVALID_DATA_DESCRIPTOR: descriptor fields are tied to the CD and the ACTUAL read"],
    ))
    cases.append(CaseSpec(
        "R2-27", "R2", "Descriptor compressed size contradicts the Central Directory compressed size",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_csize.bin", fx.EICAR_BYTES, method=0, flags=0x0008,
                                        raw_compressed=fx.EICAR_BYTES,
                                        raw_data_descriptor=fx.zip_data_descriptor_16(
                                            zlib.crc32(fx.EICAR_BYTES) & 0xFFFFFFFF,
                                            len(fx.EICAR_BYTES) + 1, len(fx.EICAR_BYTES)))]),
        notes=["INVALID_DATA_DESCRIPTOR: the CDH compressed-size window is the compressed data ONLY"],
    ))
    cases.append(CaseSpec(
        "R2-28", "R2", "Descriptor uncompressed size contradicts the Central Directory / ACTUAL read",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_usize.bin", fx.EICAR_BYTES, method=0, flags=0x0008,
                                        raw_compressed=fx.EICAR_BYTES,
                                        raw_data_descriptor=fx.zip_data_descriptor_16(
                                            zlib.crc32(fx.EICAR_BYTES) & 0xFFFFFFFF,
                                            len(fx.EICAR_BYTES), len(fx.EICAR_BYTES) + 1))]),
        notes=["INVALID_DATA_DESCRIPTOR: declared sizes are never trusted over ACTUAL bytes"],
    ))
    cases.append(CaseSpec(
        "R2-29", "R2", "Wrong descriptor width: ZIP32 member followed by a 24-byte ZIP64 descriptor",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_w64.bin", fx.EICAR_BYTES, method=0, flags=0x0008,
                                        raw_compressed=fx.EICAR_BYTES,
                                        raw_data_descriptor=fx.zip_data_descriptor_24(
                                            zlib.crc32(fx.EICAR_BYTES) & 0xFFFFFFFF,
                                            len(fx.EICAR_BYTES), len(fx.EICAR_BYTES)))]),
        notes=["INVALID_DATA_DESCRIPTOR: non-ZIP64 member requires the 16-byte signed form; "
               "ambiguous width combinations are rejected, never sniffed"],
    ))
    cases.append(CaseSpec(
        "R2-30", "R2", "Wrong descriptor width: ZIP64 member followed by a 16-byte descriptor",
        REJECTED, "zip",
        lambda: _zip64_with_16byte_descriptor(fx.EICAR_BYTES),
        notes=["INVALID_DATA_DESCRIPTOR: ZIP64 member (sentinels resolved) requires the "
               "24-byte ZIP64 form; the 16-byte form cannot express the verified metadata"],
    ))
    cases.append(CaseSpec(
        "R2-31", "R2", "Descriptor falsely embedded INSIDE the compressed window (legacy in-window layout)",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_inwin.bin", fx.EICAR_BYTES, method=8, flags=0x0008,
                                        raw_compressed=_defl_eicar + _dd16_defl)]),
        notes=["UNEXPECTED_TRAILING_COMPRESSED_DATA: bytes after the DEFLATE end marker inside the "
               "declared csize window are rejected; the descriptor belongs OUTSIDE the window"],
    ))
    cases.append(CaseSpec(
        "R2-32", "R2", "Multi-entry ZIP with per-member descriptors and correct LFH/CDH boundaries",
        INSPECTED, "zip",
        lambda: fx.build_zip([
            fx.Member("a.bin", fx.EICAR_BYTES, method=0, flags=0x0008,
                      raw_compressed=fx.EICAR_BYTES, raw_data_descriptor=_dd16_eicar),
            fx.Member("b.txt", fx.BENIGN_BYTES, method=8, flags=0x0008,
                      raw_compressed=fx.deflate_two_block(fx.BENIGN_BYTES),
                      raw_data_descriptor=fx.zip_data_descriptor_16(
                          zlib.crc32(fx.BENIGN_BYTES) & 0xFFFFFFFF,
                          len(fx.deflate_two_block(fx.BENIGN_BYTES)), len(fx.BENIGN_BYTES))),
        ]),
        notes=["the record following each descriptor must be the next LFH exactly at the "
               "next CDH local offset (or the central directory for the last member)"],
    ))
    cases.append(CaseSpec(
        "R2-33", "R2", "Garbage record immediately after the data descriptor",
        REJECTED, "zip",
        lambda: _member_with_descriptor_garbage(fx.EICAR_BYTES),
        notes=["INVALID_DATA_DESCRIPTOR: no valid LFH/CDH record follows the descriptor "
               "(unexpected trailing bytes after the descriptor)"],
    ))
    def _patch_zip64_locator(data: bytes, field: str) -> bytes:
        out = bytearray(data)
        eocd = bytes(out).rfind(b"PK\x05\x06")
        if field == "disk":
            out[eocd - 16] = 1  # 32-bit disk number, first byte (was 0)
        else:
            out[eocd - 4] = 2   # 32-bit total disk count, first byte (was 1)
        return bytes(out)
    cases.append(CaseSpec(
        "R2-34", "R2", "Invalid ZIP64 EOCD locator: 32-bit disk number field non-zero",
        REJECTED, "zip",
        lambda: _patch_zip64_locator(fx.zip64(fx.EICAR_BYTES), "disk"),
        notes=["MULTI_DISK_ZIP_UNSUPPORTED: the locator disk field is 32 bits (not 16); "
               "non-zero disk numbers are multi-disk archives: fail closed"],
    ))
    cases.append(CaseSpec(
        "R2-35", "R2", "Invalid ZIP64 EOCD locator: 32-bit total disk count not exactly 1",
        REJECTED, "zip",
        lambda: _patch_zip64_locator(fx.zip64(fx.EICAR_BYTES), "total"),
        notes=["MULTI_DISK_ZIP_UNSUPPORTED: full locator structure validated "
               "(disk number + total disk count); multi-disk archives are out of scope"],
    ))
    cases.append(CaseSpec(
        "R2-36", "R2", "Legacy UNSIGNED 12-byte data descriptor (no signature): classified UNSUPPORTED",
        UNSUPPORTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_uns.bin", fx.EICAR_BYTES, method=0, flags=0x0008,
                                        raw_compressed=fx.EICAR_BYTES,
                                        raw_data_descriptor=fx.zip_data_descriptor_unsigned_12(
                                            zlib.crc32(fx.EICAR_BYTES) & 0xFFFFFFFF,
                                            len(fx.EICAR_BYTES), len(fx.EICAR_BYTES)))]),
        notes=["UNSIGNED_DATA_DESCRIPTOR_UNSUPPORTED: documented compatibility impact - archives "
               "from legacy streaming writers that omit the descriptor signature are NOT inspected "
               "(never silently accepted, never reported as corrupt)"],
    ))
    cases.append(CaseSpec(
        "R2-37", "R2", "Undeclared descriptor: bit 3 not set but a descriptor signature follows the data",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("dd_nobit.bin", fx.EICAR_BYTES, method=0, flags=0,
                                        raw_compressed=fx.EICAR_BYTES,
                                        raw_data_descriptor=_dd16_eicar)]),
        notes=["UNDECLARED_DATA_DESCRIPTOR: contradictory structure rejected"],
    ))
    # --- ZIP64 LFH/CDH descriptor-width interoperability cases (REVISION-5) -
    _force_payload = b"Hello DIP security fixture!" * 3
    cases.append(CaseSpec(
        "R2-38", "R2", "Independent writer: CPython zipfile force_zip64 (DEFLATE) over a non-seekable stream "
                     "(LFH 0x0001 extra + CDH small sizes + signed 24-byte descriptor)",
        INSPECTED, "zip",
        lambda: fx.zipfile_nonseekable_force_zip64("hello.txt", _force_payload, method=8),
        notes=["the legitimate LFH-ZIP64/CDH-small-size combination must be INSPECTED; width resolved "
               "from verified LFH+CDH evidence, not from the CDH sentinels alone"],
    ))
    cases.append(CaseSpec(
        "R2-39", "R2", "Independent writer: CPython zipfile force_zip64 (STORED) over a non-seekable stream",
        INSPECTED, "zip",
        lambda: fx.zipfile_nonseekable_force_zip64("hello.txt", _force_payload, method=0),
        notes=["same combination with ZIP_STORED: INSPECTED"],
    ))
    _force_crc = zlib.crc32(_force_payload) & 0xFFFFFFFF
    _force_lfh_extra_ok = struct.pack("<HH", 0x0001, 16) + len(_force_payload).to_bytes(8, "little") \
        + len(_force_payload).to_bytes(8, "little")
    cases.append(CaseSpec(
        "R2-40", "R2", "LFH size sentinels WITHOUT a 0x0001 ZIP64 extra field",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("p.bin", _force_payload, method=0, version_needed=45,
                                        lfh_size_override=(0xFFFFFFFF, 0xFFFFFFFF),
                                        lfh_extra_raw=struct.pack("<HH", 0x9999, 16)
                                        + b"\x00" * 16)]),
        notes=["MALFORMED_ZIP64_LFH_EXTRA: sentinels must be resolvable from a 0x0001 extra"],
    ))
    cases.append(CaseSpec(
        "R2-41", "R2", "LFH 0x0001 extra field with a TLV length overflow",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("p.bin", _force_payload, method=0, version_needed=45,
                                        lfh_size_override=(0xFFFFFFFF, 0xFFFFFFFF),
                                        lfh_extra_raw=struct.pack("<HH", 0x0001, 0xFFFF))]),
        notes=["MALFORMED_ZIP_EXTRA_FIELD: truncated/malformed extra structures are rejected"],
    ))
    cases.append(CaseSpec(
        "R2-42", "R2", "LFH 0x0001 compressed size contradicts the Central Directory size",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("p.bin", _force_payload, method=0, version_needed=45,
                                        lfh_size_override=(0xFFFFFFFF, 0xFFFFFFFF),
                                        lfh_extra_raw=struct.pack("<HH", 0x0001, 16)
                                        + len(_force_payload).to_bytes(8, "little")
                                        + (len(_force_payload) + 1).to_bytes(8, "little"))]),
        notes=["MALFORMED_LFH_CDH_MISMATCH: non-zero LFH zip64 values are verified against the CDH"],
    ))
    cases.append(CaseSpec(
        "R2-43", "R2", "LFH-ZIP64 member (sentinels + extra, small CDH) followed by a 16-byte descriptor",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("p.bin", _force_payload, method=0, version_needed=45,
                                        flags=0x0008,
                                        lfh_size_override=(0xFFFFFFFF, 0xFFFFFFFF),
                                        lfh_extra_raw=_force_lfh_extra_ok,
                                        raw_compressed=_force_payload,
                                        raw_data_descriptor=fx.zip_data_descriptor_16(
                                            _force_crc, len(_force_payload), len(_force_payload)))]),
        notes=["INVALID_DATA_DESCRIPTOR: LFH zip64 evidence selects the 24-byte width; a 16-byte "
               "descriptor is an incompatible width combination"],
    ))
    cases.append(CaseSpec(
        "R2-44", "R2", "LFH 0x0001 local-header offset value contradicts the actual LFH position",
        REJECTED, "zip",
        lambda: fx.build_zip([fx.Member("p.bin", _force_payload, method=0, version_needed=45,
                                        lfh_size_override=(0xFFFFFFFF, 0xFFFFFFFF),
                                        lfh_extra_raw=struct.pack("<HH", 0x0001, 24)
                                        + len(_force_payload).to_bytes(8, "little")
                                        + len(_force_payload).to_bytes(8, "little")
                                        + (12345).to_bytes(8, "little"))]),
        notes=["MALFORMED_ZIP64_LFH_EXTRA: the zip64 local-header offset, when present, must match "
               "the actual position"],
    ))
    # --------------------------- CONTROLS ----------------------------------
    cases.append(CaseSpec(
        "CTRL-POS-01", "CONTROL", "Independent POSITIVE control: direct EICAR test signature",
        INSPECTED, "zip",
        lambda: fx.zip32(fx.EICAR_BYTES),
        notes=["offline deterministic signature probe must report EICAR_SIGNATURE_PRESENT"],
    ))
    cases.append(CaseSpec(
        "CTRL-NEG-01", "CONTROL", "Independent NEGATIVE control: benign bytes, no signature",
        INSPECTED, "zip",
        lambda: fx.zip32(fx.BENIGN_BYTES),
    ))
    cases.append(CaseSpec(
        "CTRL-NEG-02", "CONTROL", "Clean nested ZIP32: all objects INSPECTED, still NOT COMPLETE_SAFE_SCAN",
        INSPECTED, "zip",
        lambda: fx.build_zip([fx.Member("inner.zip", fx.zip32(fx.BENIGN_BYTES), method=8)]),
        notes=["proves CLEAN + offline incomplete coverage never yields COMPLETE_SAFE_SCAN"],
    ))
    return cases


def run_offline_suite(*, start_tracemalloc: bool = True) -> dict[str, object]:
    """Run the whole deterministic OFFLINE suite. NO live scanner, NO network."""
    if start_tracemalloc and not tracemalloc.is_tracing():
        tracemalloc.start()
    if start_tracemalloc:
        tracemalloc.reset_peak()
    suite = build_case_suite()
    results = [run_case(spec) for spec in suite]
    peak = tracemalloc.get_traced_memory()[1] if tracemalloc.is_tracing() else 0
    if start_tracemalloc and tracemalloc.is_tracing():
        tracemalloc.stop()

    r1 = [result for result in results if result["track"] == "R1"]
    r2 = [result for result in results if result["track"] == "R2"]
    controls = [result for result in results if result["track"] == "CONTROL"]
    all_match = all(bool(result["verdict_match"]) for result in results)
    conclusions = {str(result["conclusion"]["overall_conclusion"]) for result in results}
    report: dict[str, object] = {
        "experiment_id": EXPERIMENT_ID,
        "mode": "OFFLINE_ONLY_ISOLATED_POC",
        "run_kind": "DETERMINISTIC_OFFLINE_TESTS_ONLY",
        "python_stdlib_only": True,
        "live_clamav_executed": False,
        "network_calls": 0,
        "subprocess_calls": 0,
        "filesystem_extraction_writes": sum(
            int(result["budget"]["filesystem_writes"]) for result in results  # type: ignore[index]
        ),
        "governance": {
            "CLAMAV-CR-P01": "PROPOSED — NOT APPROVED",
            "CLAMAV-CR-P02": "PROPOSED — NOT APPROVED",
            "CLAMAV-CR-P03": "PROPOSED — NOT APPROVED",
            "CLAMAV-CR-R1": "PROPOSED — NOT APPROVED",
            "CLAMAV-CR-R2": "PROPOSED — NOT APPROVED",
            "approved_decisions": "PRESERVED_VERBATIM",
            "MASTER_BASELINE": "NOT_AMENDED",
            "Security_Gate": "OPEN",
            "Licensing_Gate": "OPEN",
            "Stage_7": "NOT ACCEPTED",
            "CI": "NOT CHECKED",
            "R1": "OPEN",
            "R2": "OPEN",
            "production_source_or_dependency_changes": "NONE",
            "live_execution_workflow_created": False,
        },
        "security_boundary": {
            "approved_sequence": "validateUpload -> requireCleanUpload -> storage.put",
            "source": "src/lib/jobs/orchestrator.ts (unchanged)",
            "post_storage_worker_scan_satisfies_pre_storage": False,
            "note": "A worker scan after storage.put does NOT satisfy the approved pre-storage boundary.",
        },
        "security_requirements": SECURITY_REQUIREMENTS,
        "revisions": [
            "REVISION-1: strict DEFLATE end-of-stream required (decompressor.eof); truncated streams rejected as TRUNCATED_DEFLATE_STREAM even when CRC/size match; unexpected trailing compressed bytes rejected unless a verified 16/24-byte ZIP data descriptor (CRC/csize/usize/offset checked against ACTUAL read values); all decompression output strictly bounded per chunk; unbounded flush removed",
            "REVISION-2: per-member accounting contract corrected (member_bytes = running total INCLUDING current chunk; exactly-at-ceiling allowed, one byte over rejected); cumulative expanded-byte ceiling enforced independently and shared by nested members",
            "REVISION-3: generic exception handler no longer relies on error.code (explicit bounded code UNEXPECTED_PARSER_ERROR + length-capped message); fixture generation moved inside the fail-closed boundary (unexpected builder failure => structured REJECTED case, never a crash); ZIP64 EOCD locator now validated positionally instead of by whole-file magic search",
            "REVISION-4: ZIP data descriptor STANDARDS-COMPLIANCE correction — (a) descriptors are now read/validated at data_start + csize, i.e. AFTER the compressed member data (the CDH compressed-size field excludes the descriptor); presence is required exactly when general-purpose bit 3 is set; the record following the descriptor must be a valid LFH/CDH and a following LFH must sit exactly at the next CDH local offset; malformed/overlapping/contradictory/truncated/ambiguous structures are rejected (INVALID_DATA_DESCRIPTOR / TRUNCATED_DATA_DESCRIPTOR / UNDECLARED_DATA_DESCRIPTOR / UNEXPECTED_TRAILING_COMPRESSED_DATA); (b) the 24-byte form is the signed ZIP64 descriptor Signature(4)+CRC32(4)+CompressedSize64(8)+UncompressedSize64(8) with NO local-header-offset field (APPNOTE 4.3.9; Go archive/zip; CPython zipfile <LLQQ>); width is selected from verified metadata (CDH 0xFFFFFFFF sentinels) and incompatible widths are rejected; the legacy unsigned form is classified UNSUPPORTED (UNSIGNED_DATA_DESCRIPTOR_UNSUPPORTED); (c) ZIP64 EOCD locator disk-number and total-disk-count fields validated as 32-bit with multi-disk archives fail-closed; (d) interop evidence: CPython 3.11.2 zipfile writing to a non-seekable stream (case R2-25) is accepted by this reader",
            "REVISION-5: ZIP64 data-descriptor WIDTH RESOLUTION corrected — the signed descriptor width is now selected from CONSISTENT VALIDATED EVIDENCE across BOTH headers: LFH ZIP64 metadata (size sentinels and/or the 0x0001 extra field, parsed and cross-checked against the CDH and the ACTUAL LFH position) OR CDH 0xFFFFFFFF sentinels. This accepts the legitimate CPython `zipfile` `force_zip64` streaming combination (LFH 0x0001 extra with zeroed placeholders + CDH ordinary small 32-bit sizes + signed 24-byte descriptor, cases R2-38/R2-39) that was previously misrejected because the CDH carried no sentinels. New fail-closed codes: MALFORMED_ZIP64_LFH_EXTRA (sentinels without a 0x0001 extra, malformed/truncated 0x0001 body, contradictory local-header offset, unresolved non-streaming sentinels); inconsistent non-zero LFH/CDH sizes reuse MALFORMED_LFH_CDH_MISMATCH. No existing fail-closed test was weakened",
        ],
        "tool_capabilities": tool_capabilities(),
        "resource_budget": {
            "limits": DEFAULT_RESOURCE_LIMITS.as_dict(),
            "single_end_to_end_budget": True,
            "shared_by": ["pdf_parse", "attachment_extraction", "nested_archive_traversal", "scanner_feed"],
            "accounting_scope": {
                "level": "APPLICATION_LEVEL_POC_ACCOUNTING",
                "os_enforcement_required_in_production": True,
                "note": ("These ceilings are enforced in-process by the PoC budget only. "
                         "A production deployment must ADDITIONALLY enforce OS-level limits "
                         "(cgroup memory/CPU, bounded tmpfs size= with nosuid/nodev/noexec, "
                         "read-only rootfs, non-root user). PoC accounting is NOT an OS security boundary."),
            },
            "streaming_proof": {
                "member_read_mode": "BOUNDED_STREAMING_CHUNKS",
                "chunk_bytes": DEFAULT_RESOURCE_LIMITS.chunk_bytes,
                "nested_container_buffer": "BOUNDED_IN_MEMORY_ONLY",
                "max_materialized_object_bytes": DEFAULT_RESOURCE_LIMITS.max_materialized_object_bytes,
                "extraction_to_filesystem": False,
                "temp_disk_bytes_written": 0,
                "cumulative_expanded_ceiling_bytes": DEFAULT_RESOURCE_LIMITS.max_expanded_bytes,
                "production_reference_MaxScanSize_bytes": 400 * 1024 * 1024,
                "ci_tmpfs_ceiling_bytes": 256 * 1024 * 1024,
                "claim": "400 MiB is a CUMULATIVE scan-size reference, NOT a materialised extraction. This PoC writes 0 bytes to temp disk; streaming + reclamation are proven by construction and by budget accounting.",
            },
        },
        "verdict_taxonomy": [INSPECTED, REJECTED, UNSUPPORTED, NOT_VERIFIED],
        "cases": results,
        "controls": [result["case_id"] for result in controls],  # type: ignore[index]
        "summary": {
            "cases_total": len(results),
            "r1_cases": len(r1),
            "r2_cases": len(r2),
            "control_cases": len(controls),
            "verdict_matches": sum(1 for result in results if result["verdict_match"]),
            "all_verdicts_match": all_match,
            "rejected_cases": sum(1 for result in results if result["observed_verdict"] == REJECTED),
            "unsupported_cases": sum(1 for result in results if result["observed_verdict"] == UNSUPPORTED),
            "not_verified_cases": sum(1 for result in results if result["observed_verdict"] == NOT_VERIFIED),
            "inspected_cases": sum(1 for result in results if result["observed_verdict"] == INSPECTED),
            "conclusions_observed": sorted(conclusions),
            "complete_safe_scan_claimed": COMPLETE_SAFE_SCAN in conclusions,
            "observed_peak_traced_memory_bytes": peak,
            "total_filesystem_writes": 0,
        },
        "r1": {
            "status": "OPEN",
            "coverage_achieved": [
                "/EmbeddedFiles name tree", "/Filespec + /EF /F and /UF references",
                "FileAttachment annotations", "/AF associated files",
                "ZIP64 embedded as a referenced attachment",
            ],
            "coverage_not_verified": [
                "arbitrary PDF streams (including unreferenced /EmbeddedFile streams)",
                "compressed /ObjStm object streams and indirect /Length",
                "filtered (/FlateDecode) embedded streams",
                "genuine encrypted PDFs and post-unlock output scanning",
                "incremental revisions and parser ambiguity (duplicate object ids)",
                "malformed documents beyond fail-closed rejection",
                "qpdf --json / PDF.js exhaustive stream inspection (explicitly NOT claimed)",
            ],
            "complete_r1_remediation_claimed": False,
            "note": "Attachment-only coverage MUST NOT be reported as complete R1 remediation.",
        },
        "r2": {
            "status": "OPEN",
            "coverage_achieved": [
                "ZIP32 containing ZIP32", "ZIP32 containing ZIP64",
                "DEFLATE-compressed nested archive", "spoofed file extension",
                "nested depth limit", "corrupt member",
                "encrypted member", "unsupported compression method",
                "path traversal rejection", "forged declared size",
                "streaming bounded member reads (actual bytes, not declared size only)",
            ],
            "coverage_not_verified": [
                "live ClamAV verdict on nested content (forbidden in this offline step)",
                "multi-disk / split archives", "BZIP2/LZMA/PPMd/Zstd members",
                "ZIP64 data descriptors and 8-byte descriptor variants",
                "encrypted members WITH a key (post-decryption scanning)",
                "production-scale 400 MiB expansion under real tmpfs",
            ],
            "complete_r2_remediation_claimed": False,
        },
        "overall_conclusion": NOT_COMPLETE_SAFE_SCAN,
    }
    return report


def _summarize_report(report: dict[str, object]) -> None:
    summary = report["summary"]
    print("DIP Phase 0C -- R1/R2 minimal ISOLATED OFFLINE PoC")
    print("  mode                     : OFFLINE_ONLY_ISOLATED_POC")
    print(f"  cases_total              : {summary['cases_total']}")
    print(f"  r1 / r2 / control        : {summary['r1_cases']} / {summary['r2_cases']} / {summary['control_cases']}")
    print(f"  verdict_matches          : {summary['verdict_matches']}/{summary['cases_total']}")
    print(f"  all_verdicts_match       : {summary['all_verdicts_match']}")
    print(f"  inspected/rejected/unsupported/not_verified: "
          f"{summary['inspected_cases']}/{summary['rejected_cases']}/{summary['unsupported_cases']}/{summary['not_verified_cases']}")
    print(f"  complete_safe_scan_claimed: {summary['complete_safe_scan_claimed']}")
    print(f"  filesystem_writes        : {report['filesystem_extraction_writes']}")
    print(f"  live_clamav_executed     : {report['live_clamav_executed']}")
    print(f"  observed_peak_memory     : {summary['observed_peak_traced_memory_bytes']}")
    print(f"  overall_conclusion       : {report['overall_conclusion']}")


def main(argv: list[str]) -> int:
    """CLI for the isolated offline PoC. Subcommands: run, self-test, report.

    `run`       -> executes the full offline suite, prints summary, exit 0 on all
                    verdict matches else 1.
    `self-test` -> same as run but also asserts invariants (no live scan, no writes,
                    no COMPLETE_SAFE_SCAN, EICAR control fired). Non-zero on failure.
    `report`    -> prints the full JSON report to stdout.
    """
    import argparse

    parser = argparse.ArgumentParser(description="DIP Phase 0C R1/R2 offline PoC")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="run offline suite + summary")
    sub.add_parser("self-test", help="run offline suite + invariant assertions")
    sub.add_parser("report", help="print full JSON report")
    args = parser.parse_args(argv)

    report = run_offline_suite()
    if args.cmd == "report":
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    _summarize_report(report)

    if args.cmd == "run":
        return 0 if report["summary"]["all_verdicts_match"] else 1  # type: ignore[index]

    # self-test invariants
    failures: list[str] = []
    if not report["summary"]["all_verdicts_match"]:
        failures.append("NOT_ALL_VERDICTS_MATCH")
    if report["live_clamav_executed"]:
        failures.append("LIVE_CLAMAV_MUST_BE_FALSE")
    if report["network_calls"] != 0 or report["subprocess_calls"] != 0:
        failures.append("NO_NETWORK_OR_SUBPROCESS_ALLOWED")
    if int(report["filesystem_extraction_writes"]) != 0:
        failures.append("NO_FILESYSTEM_EXTRACTOR_WRITES_ALLOWED")
    if report["summary"]["complete_safe_scan_claimed"]:
        failures.append("COMPLETE_SAFE_SCAN_MUST_NEVER_BE_CLAIMED_OFFLINE")
    for case in report["cases"]:
        if case["case_id"] == "CTRL-POS-01":
            sigs = [str(obj.get("offline_control_signature")) for obj in case["objects"]]
            if "EICAR_SIGNATURE_PRESENT" not in sigs:
                failures.append("EICAR_POSITIVE_CONTROL_MUST_FIRE")
        if case["case_id"] == "CTRL-NEG-01":
            sigs = [str(obj.get("offline_control_signature")) for obj in case["objects"]]
            if "EICAR_SIGNATURE_ABSENT" not in sigs:
                failures.append("EICAR_NEGATIVE_CONTROL_MUST_STAY_CLEAN")
    if failures:
        print("SELF-TEST FAILURES: " + ", ".join(failures))
        return 1
    print("SELF-TEST PASS: all invariants hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
