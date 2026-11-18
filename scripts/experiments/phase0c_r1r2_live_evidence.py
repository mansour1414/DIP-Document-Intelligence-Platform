#!/usr/bin/env python3
"""Experimental Phase 0C live evidence client.

This module is intentionally separate from the offline-only default CLI. Live
network use requires ``--mode live`` and is intended to run only in the bounded
client container on the internal Docker network. It scans synthetic fixtures
only and is not production integration or authorization to dispatch a workflow.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import socket
import struct
import sys
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

import phase0c_r1r2_poc as poc

CHUNK_BYTES = 64 * 1024
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_TRANSFER_BYTES = 256 * 1024 * 1024
INDEPENDENT_ZIP_CHUNK_BYTES = 64 * 1024
INDEPENDENT_ZIP_MAX_MEMBER_BYTES = 2 * 1024 * 1024
INDEPENDENT_ZIP_MAX_EXPANDED_BYTES = MAX_EXPANDED_BYTES
INDEPENDENT_ZIP_MAX_ENTRIES = 256
INDEPENDENT_ZIP_MAX_DEPTH = 3
INDEPENDENT_ZIP_MAX_MEMORY_BYTES = 64 * 1024 * 1024
INDEPENDENT_ZIP_INFO_ESTIMATE_BYTES = 512
INDEPENDENT_ZIP_FIXED_OVERHEAD_BYTES = 128 * 1024
TOTAL_DEADLINE_SECONDS = 20 * 60
CASE_DEADLINE_SECONDS = 90
LIVE_CPU_ACCOUNTING_SECONDS = 15.0  # client process only; clamd has its own cgroup
EXPECTED_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
REQUIRED_FIXTURE_IDS = (
    "R1_pdf_embedded_zip64_residual_risk",
    "R2_compressed_nested_zip64_inside_zip32_residual_risk",
    "B10_valid_docx_control", "B11_valid_xlsx_control", "B12_valid_pptx_control",
    "B13_valid_pdf_control", "B14_encrypted_pdf_unlock_pdf_control",
)
REQUIRED_CASE_EXPECTATIONS = {
    "CTRL-EICAR-RAW": poc.INSPECTED,
    "R1-06": poc.NOT_VERIFIED, "R1-07": poc.UNSUPPORTED,
    "R1-08": poc.NOT_VERIFIED, "R1-09": poc.NOT_VERIFIED,
    "R1-10": poc.REJECTED, "R1-12": poc.UNSUPPORTED, "R1-13": poc.REJECTED,
    "R2-01": poc.INSPECTED, "R2-02": poc.INSPECTED, "R2-03": poc.INSPECTED,
    "R2-04": poc.INSPECTED, "R2-05": poc.REJECTED, "R2-06": poc.REJECTED,
    "R2-07": poc.REJECTED, "R2-08": poc.UNSUPPORTED, "R2-10": poc.REJECTED,
    "R2-11": poc.REJECTED, "R2-12": poc.REJECTED, "R2-13": poc.REJECTED,
    "R2-14": poc.REJECTED, "R2-15": poc.INSPECTED, "R2-17": poc.INSPECTED,
    "R2-18": poc.REJECTED, "R2-24": poc.INSPECTED, "R2-25": poc.INSPECTED,
    "R2-38": poc.INSPECTED, "R2-39": poc.INSPECTED,
    "CTRL-NEG-01": poc.INSPECTED, "CTRL-NEG-02": poc.INSPECTED,
    "LIMIT-INPUT-01": poc.REJECTED, "LIMIT-MEMORY-01": poc.REJECTED,
    "R1-LIVE-01": poc.INSPECTED, "R2-LIVE-01": poc.INSPECTED,
    "BENIGN-DOCX-EN-AR": poc.INSPECTED, "BENIGN-XLSX-EN-AR": poc.INSPECTED,
    "BENIGN-PPTX-EN-AR": poc.INSPECTED, "BENIGN-PDF-EN-AR": poc.NOT_VERIFIED,
    "ENCRYPTED-PDF-UNLOCK-REQUIRED": poc.UNSUPPORTED,
}
REQUIRED_EICAR_CASE_IDS = frozenset({
    "CTRL-EICAR-RAW", "R2-01", "R2-02", "R2-03", "R2-04", "R2-15",
    "R2-24", "R2-25", "R1-LIVE-01", "R2-LIVE-01",
})
EICAR_RE = re.compile(r"eicar", re.IGNORECASE)
REPLY_RE = re.compile(r"^stream: (?:(?P<signature>.+) )?(?P<status>OK|FOUND|ERROR)$")


class LiveScanError(RuntimeError):
    """Fail-closed protocol, deadline, or byte-accounting failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TransferBudget:
    def __init__(self, maximum: int = MAX_TOTAL_TRANSFER_BYTES) -> None:
        self.maximum = maximum
        self.transferred = 0

    def charge(self, count: int) -> None:
        if count < 0 or self.transferred + count > self.maximum:
            raise LiveScanError("TOTAL_TRANSFER_BYTE_LIMIT")
        self.transferred += count


class Deadline:
    def __init__(self, seconds: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self.end = clock() + seconds

    def remaining(self) -> float:
        value = self.end - self._clock()
        if value <= 0:
            raise LiveScanError("END_TO_END_DEADLINE_EXCEEDED")
        return value

    def child(self, seconds: float) -> "Deadline":
        child = object.__new__(Deadline)
        child._clock = self._clock
        child.end = min(self.end, self._clock() + seconds)
        child.remaining()
        return child


class ClamdInstreamScanner:
    """One clamd INSTREAM operation, bounded and closed on every incomplete path."""

    def __init__(self, host: str, port: int, deadline: Deadline,
                 *, connector: Callable[..., socket.socket] = socket.create_connection,
                 transfer_budget: TransferBudget | None = None,
                 max_bytes: int = MAX_EXPANDED_BYTES) -> None:
        self.host = host
        self.port = port
        self.deadline = deadline
        self.connector = connector
        self.transfer_budget = transfer_budget or TransferBudget()
        self.max_bytes = max_bytes
        self.bytes_sent = 0
        self.sock: socket.socket | None = None
        self.finished = False
        self._signature: str | None = None
        self._verdict: str | None = None

    def _open(self) -> socket.socket:
        if self.sock is None:
            try:
                self.sock = self.connector((self.host, self.port), timeout=self.deadline.remaining())
                self.sock.settimeout(self.deadline.remaining())
                self.sock.sendall(b"zINSTREAM\x00")
            except (OSError, TimeoutError, LiveScanError) as exc:
                self.abort()
                raise LiveScanError("CLAMD_CONNECT_OR_COMMAND_FAILED") from exc
        return self.sock

    def feed(self, chunk: bytes, budget: poc.ResourceBudget) -> None:
        if self.finished:
            raise LiveScanError("INSTREAM_ALREADY_FINISHED")
        if not isinstance(chunk, bytes) or not chunk or len(chunk) > CHUNK_BYTES:
            self.abort()
            raise LiveScanError("INVALID_INSTREAM_CHUNK")
        if self.bytes_sent + len(chunk) > self.max_bytes:
            self.abort()
            raise LiveScanError("INSTREAM_BYTE_LIMIT")
        try:
            budget.charge_scanned(len(chunk))
            self.transfer_budget.charge(len(chunk))
            sock = self._open()
            sock.settimeout(self.deadline.remaining())
            sock.sendall(struct.pack(">I", len(chunk)))
            sock.sendall(chunk)
            self.bytes_sent += len(chunk)
        except Exception as exc:
            self.abort()
            if isinstance(exc, LiveScanError):
                raise
            raise LiveScanError("INSTREAM_TRANSFER_FAILED") from exc

    def _read_reply(self) -> bytes:
        sock = self._open()
        sock.settimeout(self.deadline.remaining())
        data = bytearray()
        while len(data) <= 4096:
            sock.settimeout(self.deadline.remaining())
            part = sock.recv(min(1024, 4097 - len(data)))
            if not part:
                raise LiveScanError("CLAMD_PREMATURE_EOF")
            data.extend(part)
            if b"\x00" in part:
                break
        raw = bytes(data)
        if len(raw) > 4096 or raw.count(b"\x00") != 1 or not raw.endswith(b"\x00"):
            raise LiveScanError("CLAMD_MALFORMED_REPLY_FRAMING")
        # The operation uses a one-shot connection. Drain a bounded amount so
        # concatenated/trailing response data cannot be silently accepted.
        try:
            sock.settimeout(min(0.05, self.deadline.remaining()))
            trailing = sock.recv(1)
            if trailing:
                raise LiveScanError("CLAMD_TRAILING_REPLY_DATA")
        except socket.timeout:
            pass
        line = raw[:-1].decode("utf-8", errors="strict")
        match = REPLY_RE.fullmatch(line)
        if not match:
            raise LiveScanError("CLAMD_UNRECOGNIZED_REPLY")
        status = match.group("status")
        if status == "ERROR":
            raise LiveScanError("CLAMD_REPORTED_ERROR")
        self._verdict = "CLEAN" if status == "OK" else "INFECTED"
        signature = match.group("signature")
        self._signature = signature[:128] if signature else None
        return raw

    def finish(self) -> dict[str, Any]:
        if self.finished:
            raise LiveScanError("INSTREAM_ALREADY_FINISHED")
        try:
            sock = self._open()
            sock.settimeout(self.deadline.remaining())
            sock.sendall(b"\x00\x00\x00\x00")
            self._read_reply()
            self.finished = True
            return {
                "is_clamav_scanner": True,
                "scanner_verdict": self._verdict,
                "scanner_reason": "CLAMD_INSTREAM_COMPLETE",
                "signature": self._signature,
                "bytes_sent": self.bytes_sent,
                "response_framing": "ONE_NUL_TERMINATED_REPLY",
            }
        except (OSError, TimeoutError, UnicodeError, LiveScanError) as exc:
            self.abort()
            if isinstance(exc, LiveScanError):
                raise
            raise LiveScanError("CLAMD_REPLY_FAILED") from exc
        finally:
            self._close()

    def abort(self) -> None:
        """Cancel an incomplete INSTREAM by closing its one-shot connection."""
        self._close()

    def _close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __del__(self) -> None:  # defensive cancellation only; normal paths use finish/abort
        self._close()


def _scan_bytes(data: bytes, host: str, port: int, deadline: Deadline,
                *, transfer_budget: TransferBudget,
                max_bytes: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    if len(data) > max_bytes:
        raise LiveScanError("SCAN_INPUT_LIMIT")
    # The original fixture is materialized only within the 4 MiB input cap.
    budget = poc.ResourceBudget(replace(
        poc.DEFAULT_RESOURCE_LIMITS,
        max_input_bytes=max_bytes,
        max_wall_clock_seconds=max(0.001, deadline.remaining()),
        max_cpu_seconds=LIVE_CPU_ACCOUNTING_SECONDS,
    ))
    scanner = ClamdInstreamScanner(host, port, deadline, transfer_budget=transfer_budget,
                                   max_bytes=max_bytes)
    try:
        for offset in range(0, len(data), CHUNK_BYTES):
            scanner.feed(data[offset:offset + CHUNK_BYTES], budget)
        return scanner.finish()
    except Exception:
        scanner.abort()
        raise


def _command(host: str, port: int, command: bytes, deadline: Deadline) -> str:
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=deadline.remaining())
        sock.settimeout(deadline.remaining())
        sock.sendall(command + b"\x00")
        data = bytearray()
        while len(data) <= 1024:
            sock.settimeout(deadline.remaining())
            part = sock.recv(min(256, 1025 - len(data)))
            if not part:
                raise LiveScanError("CLAMD_COMMAND_PREMATURE_EOF")
            data.extend(part)
            if b"\x00" in part:
                break
        raw = bytes(data)
        if len(raw) > 1024 or raw.count(b"\x00") != 1 or not raw.endswith(b"\x00"):
            raise LiveScanError("CLAMD_COMMAND_BAD_FRAMING")
        try:
            sock.settimeout(min(0.05, deadline.remaining()))
            trailing = sock.recv(1)
            if trailing:
                raise LiveScanError("CLAMD_COMMAND_TRAILING_DATA")
        except socket.timeout:
            pass
        return raw[:-1].decode("utf-8", errors="strict")
    except (OSError, TimeoutError, UnicodeError, LiveScanError) as exc:
        if isinstance(exc, LiveScanError):
            raise
        raise LiveScanError("CLAMD_COMMAND_FAILED") from exc
    finally:
        if sock is not None:
            sock.close()


def _independent_zip_entry_count(data: bytes | bytearray, maximum: int) -> int:
    """Preflight EOCD entry count before zipfile allocates its ZipInfo table."""
    if len(data) < 22:
        raise ValueError("independent_reader_malformed_eocd")
    lower = max(0, len(data) - (22 + 65535))
    cursor = len(data)
    eocd = -1
    while True:
        candidate = data.rfind(b"PK\x05\x06", lower, cursor)
        if candidate < 0:
            break
        if candidate + 22 <= len(data):
            comment_size = struct.unpack_from("<H", data, candidate + 20)[0]
            if candidate + 22 + comment_size == len(data):
                eocd = candidate
                break
        cursor = candidate
    if eocd < 0:
        raise ValueError("independent_reader_malformed_eocd")
    disk, directory_disk, disk_entries, total_entries = struct.unpack_from("<HHHH", data, eocd + 4)
    if disk != 0 or directory_disk != 0 or disk_entries != total_entries:
        raise ValueError("independent_reader_multidisk_zip")

    locator = eocd - 20
    has_locator = locator >= 0 and data[locator:locator + 4] == b"PK\x06\x07"
    if total_entries == 0xFFFF or disk_entries == 0xFFFF or has_locator:
        if not has_locator:
            raise ValueError("independent_reader_zip64_locator_missing")
        locator_disk, zip64_offset, disk_count = struct.unpack_from("<IQI", data, locator + 4)
        if locator_disk != 0 or disk_count != 1 or zip64_offset + 56 > locator:
            raise ValueError("independent_reader_bad_zip64_locator")
        if data[zip64_offset:zip64_offset + 4] != b"PK\x06\x06":
            raise ValueError("independent_reader_bad_zip64_eocd")
        record_size = struct.unpack_from("<Q", data, zip64_offset + 4)[0]
        if record_size < 44 or zip64_offset + 12 + record_size > locator:
            raise ValueError("independent_reader_bad_zip64_eocd")
        zip64_disk, zip64_directory_disk = struct.unpack_from("<II", data, zip64_offset + 16)
        zip64_disk_entries, total_entries = struct.unpack_from("<QQ", data, zip64_offset + 24)
        if zip64_disk != 0 or zip64_directory_disk != 0 or zip64_disk_entries != total_entries:
            raise ValueError("independent_reader_multidisk_zip")
    if total_entries > maximum:
        raise ValueError("independent_reader_entry_limit")
    return total_entries


class _IndependentZipBudget:
    def __init__(self, input_bytes: int, *, max_member_bytes: int,
                 max_expanded_bytes: int, max_entries: int, max_depth: int,
                 max_memory_bytes: int) -> None:
        self.max_member_bytes = max_member_bytes
        self.max_expanded_bytes = max_expanded_bytes
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.max_memory_bytes = max_memory_bytes
        self.expanded_bytes = 0
        self.entries = 0
        self.peak_memory_bytes = input_bytes
        self.memory_bytes = input_bytes
        self.max_depth_seen = 0
        if input_bytes > max_memory_bytes:
            raise ValueError("independent_reader_memory_limit")

    def reserve(self, amount: int) -> None:
        if amount < 0 or self.memory_bytes + amount > self.max_memory_bytes:
            raise ValueError("independent_reader_memory_limit")
        self.memory_bytes += amount
        self.peak_memory_bytes = max(self.peak_memory_bytes, self.memory_bytes)

    def release(self, amount: int) -> None:
        self.memory_bytes -= amount

    def add_entries(self, count: int) -> None:
        if count < 0 or self.entries + count > self.max_entries:
            raise ValueError("independent_reader_entry_limit")
        self.entries += count

    def add_output(self, amount: int, member_bytes: int) -> None:
        if member_bytes + amount > self.max_member_bytes:
            raise ValueError("independent_reader_member_limit")
        if self.expanded_bytes + amount > self.max_expanded_bytes:
            raise ValueError("independent_reader_expansion_limit")
        self.expanded_bytes += amount


def _verify_zip_independently(data: bytes, *, eicar_expected: bool,
                              max_member_bytes: int = INDEPENDENT_ZIP_MAX_MEMBER_BYTES,
                              max_expanded_bytes: int = INDEPENDENT_ZIP_MAX_EXPANDED_BYTES,
                              max_entries: int = INDEPENDENT_ZIP_MAX_ENTRIES,
                              max_depth: int = INDEPENDENT_ZIP_MAX_DEPTH,
                              max_memory_bytes: int = INDEPENDENT_ZIP_MAX_MEMORY_BYTES) -> dict[str, Any]:
    """Stream an independent CPython zipfile verification under explicit budgets."""
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("independent_reader_input_limit")
    budget = _IndependentZipBudget(len(data), max_member_bytes=max_member_bytes,
                                   max_expanded_bytes=max_expanded_bytes,
                                   max_entries=max_entries, max_depth=max_depth,
                                   max_memory_bytes=max_memory_bytes)
    found = False
    largest_member_bytes = 0

    def visit(blob: bytes | bytearray, depth: int) -> None:
        nonlocal found, largest_member_bytes
        if depth > budget.max_depth:
            raise ValueError("independent_reader_depth_limit")
        budget.max_depth_seen = max(budget.max_depth_seen, depth)
        entry_count = _independent_zip_entry_count(blob, budget.max_entries - budget.entries)
        budget.add_entries(entry_count)
        parser_copy = len(blob)  # BytesIO owns a copy of the seekable ZIP input.
        metadata_estimate = len(blob) * 3 + entry_count * INDEPENDENT_ZIP_INFO_ESTIMATE_BYTES
        parser_overhead = INDEPENDENT_ZIP_FIXED_OVERHEAD_BYTES
        budget.reserve(parser_copy + metadata_estimate + parser_overhead)
        try:
            with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
                infos = archive.infolist()
                if len(infos) != entry_count:
                    raise ValueError("independent_reader_entry_count_mismatch")
                for info in infos:
                    actual = 0
                    digest = hashlib.sha256()
                    prefix = bytearray()
                    nested: bytearray | None = None
                    with archive.open(info, "r") as member:
                        while True:
                            chunk = member.read(INDEPENDENT_ZIP_CHUNK_BYTES)
                            if not chunk:
                                break
                            budget.reserve(len(chunk))
                            try:
                                actual += len(chunk)
                                largest_member_bytes = max(largest_member_bytes, actual)
                                budget.add_output(len(chunk), actual - len(chunk))
                                digest.update(chunk)
                                if len(prefix) < 16:
                                    prefix.extend(chunk[:16 - len(prefix)])
                                    if (nested is None and
                                            poc.sniff_content_type(bytes(prefix)) == "application/zip"):
                                        nested = bytearray()
                                if nested is not None:
                                    budget.reserve(len(chunk))
                                    nested.extend(chunk)
                            finally:
                                budget.release(len(chunk))
                    if digest.hexdigest() == EXPECTED_EICAR_SHA256:
                        found = True
                    if nested is not None:
                        try:
                            visit(nested, depth + 1)
                        finally:
                            budget.release(len(nested))
        finally:
            budget.release(parser_copy + metadata_estimate + parser_overhead)

    visit(data, 0)
    if found != eicar_expected:
        raise ValueError("independent_reader_eicar_expectation_mismatch")
    return {"status": "PASS", "reader": "python.zipfile", "eicar_found": found,
            "expanded_bytes": budget.expanded_bytes, "largest_member_bytes": largest_member_bytes,
            "entry_count": budget.entries, "max_depth_seen": budget.max_depth_seen,
            "peak_memory_bytes": budget.peak_memory_bytes,
            "limits": {"member_bytes": budget.max_member_bytes,
                       "expanded_bytes": budget.max_expanded_bytes,
                       "entries": budget.max_entries, "depth": budget.max_depth,
                       "memory_bytes": budget.max_memory_bytes}}


def _read_bounded(path: Path, deadline: Deadline, maximum: int) -> bytes:
    result = bytearray()
    with path.open("rb") as stream:
        while True:
            deadline.remaining()
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            if len(result) + len(chunk) > maximum:
                raise LiveScanError("FIXTURE_INPUT_LIMIT")
            result.extend(chunk)
    return bytes(result)


def _manifest_records(manifest_path: Path, verification_path: Path,
                      fixture_root: Path, deadline: Deadline) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    manifest_raw = _read_bounded(manifest_path, deadline, 1024 * 1024)
    verification_raw = _read_bounded(verification_path, deadline, 1024 * 1024)
    manifest = json.loads(manifest_raw.decode("utf-8"))
    verification = json.loads(verification_raw.decode("utf-8"))
    if manifest.get("schema_version") != "phase0b-fixtures-v2":
        raise ValueError("unsupported_phase0b_manifest")
    if verification.get("overall_status") != "PASS":
        raise ValueError("phase0b_fixture_verification_not_pass")
    check_list = verification.get("checks")
    fixture_list = manifest.get("fixtures")
    if (not isinstance(check_list, list) or not isinstance(fixture_list, list)
            or any(not isinstance(item, dict) for item in check_list + fixture_list)):
        raise ValueError("phase0b_fixture_records_malformed")
    check_ids = [item.get("id") for item in check_list]
    fixture_ids = [item.get("id") for item in fixture_list]
    if len(set(check_ids)) != len(check_ids) or len(set(fixture_ids)) != len(fixture_ids):
        raise ValueError("phase0b_fixture_records_duplicate")
    checks = {item.get("id"): item for item in check_list}
    fixtures = {item.get("id"): item for item in fixture_list}
    required = list(REQUIRED_FIXTURE_IDS)
    if any(name not in fixtures or name not in checks for name in required):
        raise ValueError("required_phase0b_fixture_or_verification_missing")
    for name in required:
        if checks[name].get("tool_verification_status") != "PASS":
            raise ValueError(f"independent_fixture_verification_not_pass:{name}")
        filename = fixtures[name].get("filename")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ValueError("unsafe_fixture_filename")
        path = (fixture_root / filename).resolve()
        if not path.is_relative_to(fixture_root.resolve()):
            raise ValueError("fixture_path_escape")
        content = _read_bounded(path, deadline, MAX_INPUT_BYTES)
        if len(content) != fixtures[name].get("size_bytes") or hashlib.sha256(content).hexdigest() != fixtures[name].get("sha256"):
            raise ValueError(f"fixture_manifest_hash_mismatch:{name}")
    return fixtures, verification


def _fixture_case(case_id: str, track: str, description: str, kind: str,
                  expected: str, content: bytes, *, notes: list[str] | None = None) -> poc.CaseSpec:
    return poc.CaseSpec(case_id, track, description, expected, kind,
                        lambda payload=content: payload, notes=notes or [])


def _select_cases(fixtures: dict[str, dict[str, Any]], fixture_root: Path,
                  deadline: Deadline) -> list[tuple[poc.CaseSpec, dict[str, Any]]]:
    all_cases = {spec.case_id: spec for spec in poc.build_case_suite()}
    selected_ids = [
        "R1-06", "R1-07", "R1-08", "R1-09", "R1-10", "R1-12", "R1-13",
        "R2-01", "R2-02", "R2-03", "R2-04", "R2-05", "R2-06", "R2-07",
        "R2-08", "R2-10", "R2-11", "R2-12", "R2-13", "R2-14", "R2-15",
        "R2-17", "R2-18", "R2-24", "R2-25", "R2-38", "R2-39",
        "CTRL-NEG-01", "CTRL-NEG-02",
    ]
    result: list[tuple[poc.CaseSpec, dict[str, Any]]] = []
    for case_id in selected_ids:
        deadline.remaining()
        spec = all_cases[case_id]
        data = spec.builder()
        deadline.remaining()
        independent = {"status": "NOT_VERIFIED", "reason": "not an independent-reader positive fixture"}
        if spec.kind == "zip" and spec.expected_verdict == poc.INSPECTED:
            eicar_expected = case_id in {
                "R2-01", "R2-02", "R2-03", "R2-04", "R2-15", "R2-24", "R2-25",
            }
            independent = _verify_zip_independently(data, eicar_expected=eicar_expected)
        result.append((replace(spec, builder=lambda payload=data: payload), independent))

    # Explicit live-evidence probes for the input and OS-accounted memory paths;
    # the normal expanded/member/depth/entry limits are exercised above.
    fx = poc._load_fixture_module()
    input_probe = fx.zip32(fx.BENIGN_BYTES)
    result.append((poc.CaseSpec(
        "LIMIT-INPUT-01", "LIMIT", "Input ceiling boundary (small synthetic cap)",
        poc.REJECTED, "zip", lambda payload=input_probe: payload,
        limits=replace(poc.DEFAULT_RESOURCE_LIMITS, max_input_bytes=32)),
        {"status": "PASS", "method": "synthetic_input_limit_probe"}))
    memory_probe = fx.zip32(fx.BENIGN_BYTES)
    result.append((poc.CaseSpec(
        "LIMIT-MEMORY-01", "LIMIT", "Reserved-memory ceiling boundary (small synthetic cap)",
        poc.REJECTED, "zip", lambda payload=memory_probe: payload,
        limits=replace(poc.DEFAULT_RESOURCE_LIMITS, max_memory_bytes=32,
                       max_materialized_object_bytes=4096)),
        {"status": "PASS", "method": "synthetic_memory_limit_probe"}))

    # Reuse the independently verified Phase 0B live-risk and bilingual fixtures.
    mappings = [
        ("R1_pdf_embedded_zip64_residual_risk", "R1-LIVE-01", "R1", "pdf", poc.INSPECTED,
         "Referenced PDF ZIP64 attachment with EICAR"),
        ("R2_compressed_nested_zip64_inside_zip32_residual_risk", "R2-LIVE-01", "R2", "zip", poc.INSPECTED,
         "ZIP32 containing DEFLATE-compressed ZIP64 EICAR"),
        ("B10_valid_docx_control", "BENIGN-DOCX-EN-AR", "CONTROL", "zip", poc.INSPECTED,
         "Genuine bilingual DOCX"),
        ("B11_valid_xlsx_control", "BENIGN-XLSX-EN-AR", "CONTROL", "zip", poc.INSPECTED,
         "Genuine bilingual XLSX"),
        ("B12_valid_pptx_control", "BENIGN-PPTX-EN-AR", "CONTROL", "zip", poc.INSPECTED,
         "Genuine bilingual PPTX"),
        ("B13_valid_pdf_control", "BENIGN-PDF-EN-AR", "CONTROL", "pdf", poc.NOT_VERIFIED,
         "Genuine benign PDF; full PDF parser coverage remains unverified"),
        ("B14_encrypted_pdf_unlock_pdf_control", "ENCRYPTED-PDF-UNLOCK-REQUIRED", "CONTROL", "pdf", poc.UNSUPPORTED,
         "Genuine AES-256/R6 encrypted PDF; no password supplied; post-unlock scan separate"),
    ]
    for fixture_id, case_id, track, kind, expected, description in mappings:
        record = fixtures[fixture_id]
        path = fixture_root / record["filename"]
        data = _read_bounded(path, deadline, MAX_INPUT_BYTES)
        deadline.remaining()
        case = _fixture_case(case_id, track, description, kind, expected, data,
                             notes=[f"phase0b_fixture_id={fixture_id}",
                                    f"generation_method={record.get('generation_method')}",
                                    "fixture bytes SHA-256 matched the independently verified Phase 0B manifest"])
        result.append((case, {"status": "PASS", "source": "phase0b_fixture_verification",
                              "fixture_id": fixture_id, "sha256": record["sha256"]}))
    return result


def _case_result(case: poc.CaseSpec, structural: dict[str, Any], original: dict[str, Any],
                 *, eicar_required: bool) -> str:
    if original.get("scanner_verdict") not in ("CLEAN", "INFECTED"):
        return "NOT_VERIFIED"
    if case.case_id == "BENIGN-PDF-EN-AR" and original.get("scanner_verdict") != "CLEAN":
        return "FAIL"
    if not structural.get("verdict_match"):
        return "FAIL"
    if structural.get("observed_verdict") in (poc.REJECTED, poc.UNSUPPORTED, poc.NOT_VERIFIED):
        return "PASS" if structural.get("observed_verdict") == case.expected_verdict else "FAIL"
    objects = [obj for obj in structural.get("objects", []) if isinstance(obj, dict)]
    has_explicit_roles = any("record_role" in obj for obj in objects)
    if has_explicit_roles:
        scans = [obj for obj in objects if obj.get("record_role") == "EXTRACTED_PAYLOAD"]
        if (case.expected_verdict == poc.INSPECTED and not scans) or any(
                obj.get("scanner_reason") != "CLAMD_INSTREAM_COMPLETE"
                or obj.get("scanner_verdict") not in ("CLEAN", "INFECTED")
                or obj.get("scanner_response_framing") != "ONE_NUL_TERMINATED_REPLY"
                for obj in scans):
            return "NOT_VERIFIED"
    else:
        # Backward compatibility for old adapter records without explicit roles.
        scans = [obj for obj in objects if obj.get("scanner_reason") == "CLAMD_INSTREAM_COMPLETE"]
    if case.expected_verdict == poc.INSPECTED and not scans:
        return "NOT_VERIFIED"
    if eicar_required:
        if any(obj.get("scanner_verdict") == "INFECTED"
               and EICAR_RE.search(str(obj.get("offline_control_signature", ""))) for obj in scans):
            return "PASS"
        return "FAIL" if scans else "NOT_VERIFIED"
    # Benign controls require a clean original and every inspected payload clean.
    if original.get("scanner_verdict") != "CLEAN":
        return "FAIL" if original.get("scanner_verdict") else "NOT_VERIFIED"
    if any(obj.get("scanner_verdict") != "CLEAN" for obj in scans):
        return "FAIL" if scans else "NOT_VERIFIED"
    return "PASS"


_REASON_CODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}")
_REASON_CODE_LIMIT = 24


def _safe_reason_code(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not _REASON_CODE_RE.fullmatch(candidate):
        return None
    return candidate


def _collect_reason_codes(values: list[Any]) -> tuple[list[str], int, bool]:
    codes: list[str] = []
    malformed = 0
    for value in values:
        if value is None or value == "":
            continue
        code = _safe_reason_code(value)
        if code is None:
            malformed += 1
            continue
        if code not in codes:
            codes.append(code)
    truncated = len(codes) > _REASON_CODE_LIMIT
    return codes[:_REASON_CODE_LIMIT], malformed, truncated


def _case_reason_record(*, case_id: str, expected_status: str,
                        structural: dict[str, Any] | None,
                        original: dict[str, Any] | None,
                        objects: list[dict[str, Any]], case_result: str,
                        observed_error: str | None = None) -> dict[str, Any]:
    structural_error_raw = structural.get("error_code") if isinstance(structural, dict) else None
    structural_error = _safe_reason_code(structural_error_raw)
    observed_error_code = _safe_reason_code(observed_error)
    malformed = int(structural_error_raw not in (None, "") and structural_error is None)
    malformed += int(observed_error not in (None, "") and observed_error_code is None)

    structural_values: list[Any] = []
    coverage_reason_values: list[Any] = []
    coverage_gap_values: list[Any] = []
    limit_values: list[Any] = []
    coverage = structural.get("coverage") if isinstance(structural, dict) else None
    if isinstance(coverage, dict):
        coverage_reason_values.extend(coverage.get("reasons", [])
                                      if isinstance(coverage.get("reasons"), list) else [])
        coverage_gap_values.extend(coverage.get("uninspected_stream_gaps", [])
                                   if isinstance(coverage.get("uninspected_stream_gaps"), list) else [])
        limit_values.extend(coverage.get("resource_limits_hit", [])
                            if isinstance(coverage.get("resource_limits_hit"), list) else [])
    budget = structural.get("budget") if isinstance(structural, dict) else None
    if isinstance(budget, dict):
        limit_values.extend(budget.get("resource_limits_hit", [])
                            if isinstance(budget.get("resource_limits_hit"), list) else [])
    for obj in objects:
        if not isinstance(obj, dict):
            malformed += 1
            continue
        verdict = obj.get("verdict")
        skipped = bool(obj.get("skipped"))
        if skipped or verdict != poc.INSPECTED:
            structural_values.extend((obj.get("structural_verdict"), obj.get("skip_reason")))
        obj_limits = obj.get("resource_limits_hit")
        if isinstance(obj_limits, list):
            limit_values.extend(obj_limits)
    structural_reasons, malformed_structural, structural_truncated = _collect_reason_codes(structural_values)
    coverage_reasons, malformed_coverage_reasons, coverage_reasons_truncated = _collect_reason_codes(
        coverage_reason_values)
    coverage_gaps, malformed_coverage_gaps, coverage_gaps_truncated = _collect_reason_codes(
        coverage_gap_values)
    resource_limits, malformed_limits, limits_truncated = _collect_reason_codes(limit_values)
    malformed = min(999, malformed + malformed_structural + malformed_coverage_reasons
                    + malformed_coverage_gaps + malformed_limits)
    reason_codes_truncated = (structural_truncated or coverage_reasons_truncated
                              or coverage_gaps_truncated or limits_truncated)

    has_original_response = (
        isinstance(original, dict)
        and original.get("scanner_verdict") in ("CLEAN", "INFECTED")
        and original.get("scanner_reason") == "CLAMD_INSTREAM_COMPLETE"
        and original.get("response_framing") == "ONE_NUL_TERMINATED_REPLY"
    )
    payload_objects = [obj for obj in objects
                       if isinstance(obj, dict) and obj.get("record_role") == "EXTRACTED_PAYLOAD"]
    scanner_missing = (
        not has_original_response
        or any(obj.get("scanner_reason") != "CLAMD_INSTREAM_COMPLETE"
               or obj.get("scanner_verdict") not in ("CLEAN", "INFECTED")
               or obj.get("scanner_response_framing") != "ONE_NUL_TERMINATED_REPLY"
               for obj in payload_objects)
        or (expected_status == poc.INSPECTED and case_id != "CTRL-EICAR-RAW"
            and not payload_objects)
    )
    structural_matches = (case_id == "CTRL-EICAR-RAW" or (
        isinstance(structural, dict)
        and structural.get("verdict_match") is True
        and structural.get("observed_verdict") == expected_status
    ))
    has_reason = bool(structural_error or structural_reasons or coverage_reasons
                      or coverage_gaps or resource_limits)
    if scanner_missing:
        classification = "MISSING_SCANNER_RESULT"
    elif case_result != "PASS" or (expected_status == poc.INSPECTED and not structural_matches):
        classification = "UNEXPECTED_RESULT"
    elif expected_status != poc.INSPECTED:
        applicable_reasons = (coverage_gaps or structural_reasons) if expected_status == poc.NOT_VERIFIED else (
            structural_error or structural_reasons or resource_limits)
        classification = ("EXPECTED_NEGATIVE" if structural_matches and applicable_reasons and not malformed
                          else "UNEXPECTED_RESULT")
    else:
        classification = "OBSERVED"

    integrity = "MALFORMED" if malformed else ("OBSERVED" if has_reason else "NONE_OBSERVED")
    reason = {
        "classification": classification,
        "integrity": integrity,
        "reason_codes_truncated": reason_codes_truncated,
        "observed_error_code": observed_error_code,
        "structural_error_code": structural_error,
        "structural_reason_codes": structural_reasons,
        "coverage_reason_codes": coverage_reasons,
        "coverage_gap_codes": coverage_gaps,
        "resource_limit_codes": resource_limits,
    }
    return reason


def _public_scan(result: dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {"status": "NOT_VERIFIED"}
    return {key: result.get(key) for key in
            ("scanner_verdict", "scanner_reason", "signature", "bytes_sent", "response_framing")}


def _valid_signature_database_date(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 128:
        return False
    for format_string in ("%a %b %d %H:%M:%S %Y", "%a %b %d %Y"):
        try:
            time.strptime(value.strip(), format_string)
            return True
        except ValueError:
            continue
    return False


def _core_evidence_failures(report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if report.get("schema_version") != "phase0c-live-evidence-v1":
        failures.append("REPORT_SCHEMA_INVALID")
    clamd = report.get("clamd")
    if not isinstance(clamd, dict) or clamd.get("zPING") != "PONG":
        failures.append("CLAMD_PING_EVIDENCE_MISSING")
    elif (clamd.get("engine_version") != "1.5.4"
          or not re.fullmatch(r"[0-9]{1,10}", str(clamd.get("signature_database_version", "")))
          or not _valid_signature_database_date(clamd.get("signature_database_date"))):
        failures.append("CLAMD_SIGNATURE_PROVENANCE_INVALID")

    provenance = report.get("runtime_provenance")
    runtime_check = _validate_runtime_provenance(provenance) if isinstance(provenance, dict) else {"status": "FAIL"}
    recorded_runtime = report.get("runtime_verification")
    if (runtime_check.get("status") != "PASS" or not isinstance(recorded_runtime, dict)
            or recorded_runtime.get("status") != "PASS"
            or recorded_runtime.get("checks") != runtime_check.get("checks")):
        failures.append("RUNTIME_VERIFICATION_MISSING_OR_INVALID")

    if report.get("independent_fixture_verification_overall") != "PASS":
        failures.append("PHASE0B_FIXTURE_VERIFICATION_NOT_PASS")
    fixture_records = report.get("required_fixture_verification")
    if not isinstance(fixture_records, list):
        failures.append("REQUIRED_FIXTURE_VERIFICATION_MISSING")
    else:
        by_id = {item.get("id"): item for item in fixture_records if isinstance(item, dict)}
        if len(by_id) != len(fixture_records) or set(by_id) != set(REQUIRED_FIXTURE_IDS):
            failures.append("REQUIRED_FIXTURE_SET_INVALID")
        for fixture_id in REQUIRED_FIXTURE_IDS:
            item = by_id.get(fixture_id)
            if (item is None or item.get("tool_verification_status") != "PASS"
                    or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))):
                failures.append("REQUIRED_FIXTURE_VERIFICATION_INVALID:" + fixture_id)

    records = report.get("case_results")
    if not isinstance(records, list):
        failures.append("MANDATORY_CASE_RESULTS_MISSING")
        return failures
    by_case: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("case_id"), str):
            failures.append("CASE_RESULT_MALFORMED")
            continue
        case_id = item["case_id"]
        if case_id in by_case:
            duplicates.add(case_id)
        by_case[case_id] = item
    for case_id in duplicates:
        failures.append("DUPLICATE_CASE_RESULT:" + case_id)
    for case_id, expected_coverage in REQUIRED_CASE_EXPECTATIONS.items():
        item = by_case.get(case_id)
        if item is None:
            failures.append("MANDATORY_CASE_MISSING:" + case_id)
            continue
        if item.get("TEST_CASE_RESULT") != "PASS":
            failures.append("MANDATORY_CASE_NOT_PASS:" + case_id)
        if (item.get("SECURITY_COVERAGE_STATUS") != expected_coverage
                or item.get("expected_structural_status") != expected_coverage):
            failures.append("CASE_COVERAGE_EXPECTATION_MISMATCH:" + case_id)
        reason = item.get("CASE_REASON")
        if expected_coverage == poc.INSPECTED:
            if (not isinstance(reason, dict) or reason.get("classification") != "OBSERVED"
                    or reason.get("integrity") == "MALFORMED"):
                failures.append("MANDATORY_CASE_REASON_INVALID:" + case_id)
        else:
            if not isinstance(reason, dict) or reason.get("classification") != "EXPECTED_NEGATIVE" \
                    or reason.get("integrity") != "OBSERVED":
                failures.append("MANDATORY_CASE_REASON_MISSING:" + case_id)
            else:
                structural_codes = reason.get("structural_reason_codes")
                coverage_codes = reason.get("coverage_gap_codes")
                limit_codes = reason.get("resource_limit_codes")
                has_structural_reason = (
                    _safe_reason_code(reason.get("structural_error_code")) is not None
                    or (isinstance(structural_codes, list) and any(
                        _safe_reason_code(code) is not None for code in structural_codes[:_REASON_CODE_LIMIT]))
                    or (isinstance(limit_codes, list) and any(
                        _safe_reason_code(code) is not None for code in limit_codes[:_REASON_CODE_LIMIT]))
                )
                has_coverage_gap = (
                    (isinstance(coverage_codes, list) and any(
                        _safe_reason_code(code) is not None for code in coverage_codes[:_REASON_CODE_LIMIT]))
                    or (isinstance(structural_codes, list) and any(
                        _safe_reason_code(code) is not None for code in structural_codes[:_REASON_CODE_LIMIT]))
                )
                if ((expected_coverage == poc.NOT_VERIFIED and not has_coverage_gap)
                        or (expected_coverage in (poc.REJECTED, poc.UNSUPPORTED)
                            and not has_structural_reason)):
                    failures.append("MANDATORY_CASE_STRUCTURAL_REASON_MISSING:" + case_id)
        original = item.get("ORIGINAL_CONTAINER_SCAN_RESULT")
        if (case_id.startswith(("R1-", "R2-"))
                and (not isinstance(original, dict)
                     or original.get("classification") != "OBSERVATIONAL_ONLY")):
            failures.append("ORIGINAL_CONTAINER_RESULT_NOT_OBSERVATIONAL:" + case_id)

        if (not isinstance(original, dict)
                or original.get("scanner_verdict") not in ("CLEAN", "INFECTED")
                or original.get("scanner_reason") != "CLAMD_INSTREAM_COMPLETE"
                or original.get("response_framing") != "ONE_NUL_TERMINATED_REPLY"):
            failures.append("ORIGINAL_CONTAINER_SCANNER_RESPONSE_MISSING:" + case_id)
        payloads = item.get("EXTRACTED_PAYLOAD_SCAN_RESULT")
        if not isinstance(payloads, list):
            failures.append("EXTRACTED_PAYLOAD_RESULTS_MISSING:" + case_id)
            payloads = []
        valid_payloads = []
        for payload in payloads:
            scan = payload.get("scanner_result") if isinstance(payload, dict) else None
            if (not isinstance(scan, dict)
                    or scan.get("scanner_verdict") not in ("CLEAN", "INFECTED")
                    or scan.get("reason") != "CLAMD_INSTREAM_COMPLETE"
                    or scan.get("response_framing") != "ONE_NUL_TERMINATED_REPLY"):
                failures.append("EXTRACTED_PAYLOAD_SCANNER_RESPONSE_INVALID:" + case_id)
            else:
                valid_payloads.append(scan)
        if expected_coverage == poc.INSPECTED and case_id != "CTRL-EICAR-RAW" and not valid_payloads:
            failures.append("INSPECTED_CASE_HAS_NO_PAYLOAD_RESPONSE:" + case_id)
        independent = item.get("independent_verification")
        if (item.get("input_kind") == "zip" and expected_coverage == poc.INSPECTED
                and (not isinstance(independent, dict) or independent.get("status") != "PASS")):
            failures.append("INDEPENDENT_ZIP_VERIFICATION_MISSING:" + case_id)
        if case_id in REQUIRED_EICAR_CASE_IDS:
            scans = ([original] if case_id == "CTRL-EICAR-RAW" else valid_payloads)
            if not any(scan.get("scanner_verdict") == "INFECTED"
                       and EICAR_RE.search(str(scan.get("signature", ""))) for scan in scans):
                failures.append("REQUIRED_EXTRACTED_EICAR_DETECTION_MISSING:" + case_id)
        elif expected_coverage == poc.INSPECTED and any(scan.get("scanner_verdict") != "CLEAN"
                                                         for scan in valid_payloads):
            failures.append("BENIGN_PAYLOAD_NOT_CLEAN:" + case_id)
        if (case_id.startswith("BENIGN-") or case_id.startswith("CTRL-NEG-")) and original and original.get("scanner_verdict") != "CLEAN":
            failures.append("BENIGN_ORIGINAL_NOT_CLEAN:" + case_id)

    if report.get("COMPLETE_SAFE_SCAN") is not False:
        failures.append("COMPLETE_SAFE_SCAN_MUST_REMAIN_FALSE")
    if not report.get("coverage_gaps"):
        failures.append("EXPECTED_COVERAGE_GAPS_NOT_RECORDED")
    expected_gaps = [
        {"case_id": case_id, "coverage_status": status}
        for case_id, status in REQUIRED_CASE_EXPECTATIONS.items() if status != poc.INSPECTED
    ]
    if report.get("expected_coverage_gaps") != expected_gaps:
        failures.append("EXPECTED_COVERAGE_GAP_LEDGER_INVALID")
    return sorted(set(failures))


def _cleanup_evidence_failures(cleanup: Any) -> list[str]:
    required = ("clamd_container_absent", "client_container_absent", "internal_network_absent",
                "candidate_image_absent", "client_image_absent", "scratch_absent")
    if not isinstance(cleanup, dict) or cleanup.get("status") != "PASS":
        return ["CLEANUP_STATUS_NOT_PASS"]
    failures = ["CLEANUP_VERIFICATION_MISSING_OR_FALSE:" + key for key in required
                if cleanup.get(key) is not True]
    if cleanup.get("runtime_verification_passed") is not True:
        failures.append("RUNTIME_WORKFLOW_VERIFICATION_NOT_PASS")
    return failures


def _derive_aggregate(report: dict[str, Any], *, require_cleanup: bool) -> dict[str, Any]:
    core_failures = _core_evidence_failures(report)
    cleanup_failures = _cleanup_evidence_failures(report.get("cleanup")) if require_cleanup else []
    failures = sorted(set(core_failures + cleanup_failures))
    aggregate_status = "FAIL" if failures else ("PASS" if require_cleanup else "PENDING")
    report["required_evidence"] = {
        "status": aggregate_status,
        "core_status": "PASS" if not core_failures else "FAIL",
        "cleanup_status": ("PASS" if not cleanup_failures else "FAIL") if require_cleanup else "PENDING",
        "failures": failures,
    }
    report["OVERALL_RESULT"] = "PASS" if require_cleanup and not failures else (
        "FAIL" if failures else "PENDING_CLEANUP")
    # This experimental client has known PDF and encrypted-content gaps; it never asserts full coverage.
    report["COMPLETE_SAFE_SCAN"] = False
    return report


def _validate_runtime_provenance(provenance: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "architecture": provenance.get("architecture") == "linux/arm64",
        "clamav_local_image_id": bool(re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(provenance.get("clamav_local_image_id", "")))),
        "client_local_image_id": bool(re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(provenance.get("client_local_image_id", "")))),
        "clamav_config_sha256": bool(re.fullmatch(
            r"[0-9a-f]{64}", str(provenance.get("clamav_config_sha256", "")))),
        "clamav_package_version": provenance.get("clamav_package_version")
                                  == "1.5.4+dfsg-0ubuntu0.22.04.1+dipphase0b1",
        "network_mode": provenance.get("network_mode") == "internal_no_egress",
    }
    return {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks}


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    total_deadline = Deadline(TOTAL_DEADLINE_SECONDS)
    fixture_root = Path(args.fixtures_dir).resolve()
    manifest_path = fixture_root / "fixtures-manifest.json"
    verification_path = fixture_root / "fixture-verification.json"
    fixtures, verification = _manifest_records(manifest_path, verification_path, fixture_root, total_deadline)
    provenance_path = fixture_root / "runtime-provenance.json"
    runtime_provenance = json.loads(_read_bounded(provenance_path, total_deadline, 64 * 1024).decode("utf-8"))
    runtime_verification = _validate_runtime_provenance(runtime_provenance)
    if runtime_verification["status"] != "PASS":
        raise ValueError("runtime_provenance_invalid")
    host, port = args.clamd_host, args.clamd_port
    if args.expected_engine != "1.5.4":
        raise ValueError("unexpected_expected_engine")
    ping = _command(host, port, b"zPING", total_deadline)
    if ping != "PONG":
        raise LiveScanError("CLAMD_PING_UNEXPECTED")
    version_text = _command(host, port, b"zVERSION", total_deadline)
    version_match = re.fullmatch(r"ClamAV ([^/]+)/([^/]+)/(.+)", version_text)
    if not version_match or version_match.group(1) != args.expected_engine:
        raise LiveScanError("CLAMD_VERSION_UNEXPECTED")
    engine, sig_version, sig_date = version_match.groups()
    if (not re.fullmatch(r"[0-9]{1,10}", sig_version)
            or not _valid_signature_database_date(sig_date)
            or any(ord(char) < 32 for char in sig_date)):
        raise LiveScanError("CLAMD_SIGNATURE_PROVENANCE_INVALID")

    results: list[dict[str, Any]] = []
    transfer_budget = TransferBudget()
    candidates = _select_cases(fixtures, fixture_root, total_deadline)
    fx = poc._load_fixture_module()
    direct_deadline = total_deadline.child(CASE_DEADLINE_SECONDS)
    if hashlib.sha256(fx.EICAR_BYTES).hexdigest() != EXPECTED_EICAR_SHA256:
        raise LiveScanError("EICAR_SHA256_MISMATCH")
    direct = _scan_bytes(fx.EICAR_BYTES, host, port, direct_deadline,
                         transfer_budget=transfer_budget, max_bytes=len(fx.EICAR_BYTES))
    direct_pass = (direct.get("scanner_verdict") == "INFECTED"
                   and EICAR_RE.search(str(direct.get("signature") or "")) is not None)
    direct_case_result = "PASS" if direct_pass else "FAIL"
    direct_case_reason = _case_reason_record(
        case_id="CTRL-EICAR-RAW", expected_status=poc.INSPECTED,
        structural=None, original=direct, objects=[], case_result=direct_case_result)
    results.append({
        "case_id": "CTRL-EICAR-RAW", "track": "CONTROL", "input_kind": "direct_eicar",
        "input_sha256": EXPECTED_EICAR_SHA256,
        "fixture_provenance": "Phase 0C EICAR halves recombined at runtime; SHA-256 independently pinned",
        "independent_verification": {"status": "PASS", "method": "sha256"},
        "SECURITY_COVERAGE_STATUS": poc.INSPECTED,
        "ORIGINAL_CONTAINER_SCAN_RESULT": {"classification": "DIRECT_POSITIVE_CONTROL", **_public_scan(direct)},
        "EXTRACTED_PAYLOAD_SCAN_RESULT": [],
        "expected_structural_status": poc.INSPECTED,
        "CASE_REASON": direct_case_reason,
        "error_code": None,
        "TEST_CASE_RESULT": direct_case_result,
    })

    for spec, independent in candidates:
        total_deadline.remaining()
        case_deadline = total_deadline.child(CASE_DEADLINE_SECONDS)
        data = spec.builder()
        case_deadline.remaining()
        if len(data) > MAX_INPUT_BYTES:
            case_reason = _case_reason_record(
                case_id=spec.case_id, expected_status=spec.expected_verdict,
                structural=None, original=None, objects=[], case_result="FAIL",
                observed_error="INPUT_BYTE_LIMIT")
            results.append({"case_id": spec.case_id, "track": spec.track,
                            "CASE_REASON": case_reason,
                            "TEST_CASE_RESULT": "FAIL", "SECURITY_COVERAGE_STATUS": poc.REJECTED,
                            "error_code": "INPUT_BYTE_LIMIT"})
            continue
        input_sha = hashlib.sha256(data).hexdigest()
        original: dict[str, Any] | None = None
        structural: dict[str, Any] | None = None
        error: str | None = None
        try:
            original = _scan_bytes(data, host, port, case_deadline,
                                   transfer_budget=transfer_budget, max_bytes=MAX_INPUT_BYTES)
            live_limits = replace(spec.limits,
                                  max_cpu_seconds=LIVE_CPU_ACCOUNTING_SECONDS,
                                  max_wall_clock_seconds=min(CASE_DEADLINE_SECONDS, case_deadline.remaining()))
            live_spec = replace(
                spec,
                builder=lambda payload=data: payload,
                limits=live_limits,
                scanner_factory=lambda d=case_deadline: ClamdInstreamScanner(
                    host, port, d, transfer_budget=transfer_budget),
            )
            structural = poc.run_case(live_spec, container_scanner_factory=poc.OfflineEicarControlProbe)
            case_deadline.remaining()
        except (LiveScanError, OSError, TimeoutError) as exc:
            error = str(exc)[:120]
        live_error = (structural or {}).get("error_code")
        if structural is None or (isinstance(live_error, str)
                                  and (live_error.startswith("CLAMD_")
                                       or live_error.startswith("INSTREAM_")
                                       or live_error.startswith("END_TO_END_")
                                       or live_error == "TOTAL_TRANSFER_BYTE_LIMIT")):
            coverage_status = poc.NOT_VERIFIED
            case_result = "NOT_VERIFIED"
            objects = list((structural or {}).get("objects", []))
        else:
            coverage_status = str(structural.get("observed_verdict", poc.NOT_VERIFIED))
            objects = list(structural.get("objects", []))
            eicar_required = spec.case_id in {
                "R1-01", "R1-02", "R1-04", "R2-01", "R2-02", "R2-03", "R2-04",
                "R2-15", "R2-24", "R2-25", "CTRL-POS-01", "R1-LIVE-01", "R2-LIVE-01",
            }
            case_result = _case_result(spec, structural, original or {}, eicar_required=eicar_required)
        case_reason = _case_reason_record(
            case_id=spec.case_id, expected_status=spec.expected_verdict,
            structural=structural, original=original, objects=objects,
            case_result=case_result, observed_error=error)
        payload_scans = [
            {"structural_path": obj.get("object_path"), "depth": obj.get("depth"),
             "coverage_status": obj.get("verdict"), "actual_bytes": obj.get("extracted_bytes"),
             "resource_limits_hit": obj.get("resource_limits_hit", []),
             "scanner_result": {
                 "scanner_verdict": obj.get("scanner_verdict"), "reason": obj.get("scanner_reason"),
                 "signature": obj.get("offline_control_signature"),
                 "response_framing": obj.get("scanner_response_framing"),
             }}
            for obj in objects if obj.get("record_role") == "EXTRACTED_PAYLOAD"
        ]
        results.append({
            "case_id": spec.case_id, "track": spec.track, "description": spec.description,
            "input_kind": spec.kind, "input_sha256": input_sha, "input_bytes": len(data),
            "fixture_provenance": spec.notes,
            "independent_verification": independent,
            "expected_structural_status": spec.expected_verdict,
            "CASE_REASON": case_reason,
            "SECURITY_COVERAGE_STATUS": coverage_status,
            "structural_coverage": structural.get("coverage") if structural else {"status": "NOT_VERIFIED"},
            "resource_limits": structural.get("budget") if structural else {},
            "ORIGINAL_CONTAINER_SCAN_RESULT": {
                "classification": "OBSERVATIONAL_ONLY", **_public_scan(original),
                "clean_is_not_complete_nested_inspection": True,
            },
            "EXTRACTED_PAYLOAD_SCAN_RESULT": payload_scans,
            "post_unlock_output_scan": "NOT_VERIFIED; separate requirement; no password provided",
            "TEST_CASE_RESULT": case_result,
            "error_code": error,
        })

    end = time.monotonic()
    verification_checks = {item.get("id"): item for item in verification.get("checks", [])}
    required_fixture_records = [
        {"id": fixture_id, "sha256": fixtures[fixture_id].get("sha256"),
         "tool_verification_status": verification_checks.get(fixture_id, {}).get("tool_verification_status")}
        for fixture_id in REQUIRED_FIXTURE_IDS
    ]
    report = {
        "schema_version": "phase0c-live-evidence-v1",
        "experiment_id": "DIP-PHASE-0C-R1R2-LIVE-EVIDENCE-EXPERIMENTAL",
        "mode": "EXPERIMENTAL_LIVE_CLAMAV_SYNTHETIC_FIXTURES_ONLY",
        "executed_only_when_explicit_live_mode": True,
        "clamd": {"engine_version": engine, "signature_database_version": sig_version,
                  "signature_database_date": sig_date, "zPING": "PONG"},
        "runtime_provenance": runtime_provenance,
        "runtime_verification": runtime_verification,
        "independent_fixture_verification_overall": verification.get("overall_status"),
        "required_fixture_verification": required_fixture_records,
        "single_client_deadline_seconds": TOTAL_DEADLINE_SECONDS,
        "elapsed_seconds": round(end - started, 3),
        "total_scanner_transfer_bytes": transfer_budget.transferred,
        "limits": {"input_bytes": MAX_INPUT_BYTES,
                   "total_scanner_transfer_bytes": MAX_TOTAL_TRANSFER_BYTES, "cumulative_expansion_bytes": MAX_EXPANDED_BYTES,
                   "member_output_bytes": poc.DEFAULT_RESOURCE_LIMITS.max_member_bytes,
                   "entries": poc.DEFAULT_RESOURCE_LIMITS.max_entries,
                   "depth": poc.DEFAULT_RESOURCE_LIMITS.max_depth,
                   "reparse_buffer_bytes": poc.DEFAULT_RESOURCE_LIMITS.max_materialized_object_bytes,
                   "chunk_bytes": CHUNK_BYTES, "live_case_wall_seconds": CASE_DEADLINE_SECONDS,
                   "client_cpu_accounting_seconds": LIVE_CPU_ACCOUNTING_SECONDS,
                   "cpu_memory_pids_are_container_enforced_separately": True},
        "security_boundary": {"approved_sequence": "validateUpload -> requireCleanUpload -> storage.put",
                              "production_path_changed": False,
                              "post_storage_scan_satisfies_pre_storage": False},
        "coverage_gaps": ["arbitrary_pdf_streams", "PDF_Object_Streams", "unreferenced_embedded_streams",
                          "encrypted_pdf_content", "incremental_pdf_revisions", "unsupported_compression_methods"],
        "expected_coverage_gaps": [
            {"case_id": case_id, "coverage_status": status}
            for case_id, status in REQUIRED_CASE_EXPECTATIONS.items() if status != poc.INSPECTED
        ],
        "COMPLETE_SAFE_SCAN": False,
        "governance": {"Security_Gate": "OPEN", "Licensing_Gate": "OPEN", "Stage_7": "NOT ACCEPTED",
                       "R1": "OPEN", "R2": "OPEN", "Change_Requests": "PROPOSED — NOT APPROVED"},
        "case_results": results,
        "cleanup": {"status": "PENDING_HOST_WORKFLOW_CLEANUP_VERIFICATION"},
    }
    return _derive_aggregate(report, require_cleanup=False)


def finalize_evidence(report_path: Path, cleanup_path: Path) -> dict[str, Any]:
    if report_path.stat().st_size > MAX_EVIDENCE_BYTES or cleanup_path.stat().st_size > 64 * 1024:
        raise ValueError("EVIDENCE_SIZE_LIMIT")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    cleanup = json.loads(cleanup_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("EVIDENCE_REPORT_INVALID")
    report["cleanup"] = cleanup
    report = _derive_aggregate(report, require_cleanup=True)
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if len(serialized.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise ValueError("EVIDENCE_SIZE_LIMIT")
    report_path.write_text(serialized, encoding="utf-8")
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Isolated Phase 0C live evidence client; never production")
    parser.add_argument("--mode", required=True, choices=("live", "finalize"),
                        help="live explicitly enables INSTREAM; finalize only records verified host cleanup")
    parser.add_argument("--fixtures-dir", default="/fixtures")
    parser.add_argument("--output", default="/evidence/phase0c-live-evidence.json")
    parser.add_argument("--clamd-host", default="clamav-phase0c")
    parser.add_argument("--clamd-port", type=int, default=3310)
    parser.add_argument("--expected-engine", default="1.5.4")
    parser.add_argument("--cleanup-status", default="/evidence/cleanup-status.json")
    args = parser.parse_args(argv)
    if args.mode == "finalize":
        report = finalize_evidence(Path(args.output), Path(args.cleanup_status))
        return 0 if report.get("OVERALL_RESULT") == "PASS" else 1
    try:
        report = run_live(args)
    except Exception as exc:
        report = _derive_aggregate({
            "schema_version": "phase0c-live-evidence-v1",
            "mode": "EXPERIMENTAL_LIVE_CLAMAV_SYNTHETIC_FIXTURES_ONLY",
            "TEST_CASE_RESULT": "NOT_VERIFIED",
            "error_code": exc.code if isinstance(exc, LiveScanError) else type(exc).__name__,
            "governance": {"Security_Gate": "OPEN", "Licensing_Gate": "OPEN", "Stage_7": "NOT ACCEPTED",
                           "R1": "OPEN", "R2": "OPEN", "Change_Requests": "PROPOSED — NOT APPROVED"},
            "cleanup": {"status": "PENDING_HOST_WORKFLOW_CLEANUP_VERIFICATION"},
        }, require_cleanup=False)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if len(serialized.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise SystemExit("EVIDENCE_SIZE_LIMIT")
    output.write_text(serialized, encoding="utf-8")
    return 1 if report.get("required_evidence", {}).get("core_status") != "PASS" else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
