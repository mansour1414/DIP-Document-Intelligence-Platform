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
TOTAL_DEADLINE_SECONDS = 20 * 60
CASE_DEADLINE_SECONDS = 90
LIVE_CPU_ACCOUNTING_SECONDS = 15.0  # client process only; clamd has its own cgroup
EXPECTED_EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
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


def _verify_zip_independently(data: bytes, *, eicar_expected: bool) -> dict[str, Any]:
    """Independent ZIP-reader check; never calls the Phase 0C custom parser."""
    expanded = 0
    found = False

    def visit(blob: bytes, depth: int) -> None:
        nonlocal expanded, found
        if depth > 3:
            raise ValueError("independent_reader_depth_limit")
        with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
            bad = archive.testzip()
            if bad is not None:
                raise ValueError("independent_reader_crc_failure")
            for name in archive.namelist():
                content = archive.read(name)
                expanded += len(content)
                if expanded > MAX_EXPANDED_BYTES:
                    raise ValueError("independent_reader_expansion_limit")
                if hashlib.sha256(content).hexdigest() == EXPECTED_EICAR_SHA256:
                    found = True
                elif content.startswith(b"PK\x03\x04"):
                    visit(content, depth + 1)

    visit(data, 0)
    if found != eicar_expected:
        raise ValueError("independent_reader_eicar_expectation_mismatch")
    return {"status": "PASS", "reader": "python.zipfile", "eicar_found": found,
            "expanded_bytes": expanded}


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
    checks = {item.get("id"): item for item in verification.get("checks", [])}
    fixtures = {item.get("id"): item for item in manifest.get("fixtures", [])}
    required = [
        "R1_pdf_embedded_zip64_residual_risk",
        "R2_compressed_nested_zip64_inside_zip32_residual_risk",
        "B10_valid_docx_control", "B11_valid_xlsx_control", "B12_valid_pptx_control",
        "B13_valid_pdf_control", "B14_encrypted_pdf_unlock_pdf_control",
    ]
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
    scans = [obj for obj in structural.get("objects", [])
             if obj.get("scanner_reason") == "CLAMD_INSTREAM_COMPLETE"]
    if eicar_required:
        if any(obj.get("scanner_verdict") == "INFECTED"
               and EICAR_RE.search(str(obj.get("offline_control_signature", ""))) for obj in scans):
            return "PASS"
        return "FAIL" if scans else "NOT_VERIFIED"
    # Benign direct controls require a clean original and every extracted member clean.
    if original.get("scanner_verdict") != "CLEAN":
        return "FAIL" if original.get("scanner_verdict") else "NOT_VERIFIED"
    if any(obj.get("scanner_verdict") != "CLEAN" for obj in scans):
        return "FAIL" if scans else "NOT_VERIFIED"
    return "PASS"


def _public_scan(result: dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {"status": "NOT_VERIFIED"}
    return {key: result.get(key) for key in
            ("scanner_verdict", "scanner_reason", "signature", "bytes_sent", "response_framing")}


def run_live(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    total_deadline = Deadline(TOTAL_DEADLINE_SECONDS)
    fixture_root = Path(args.fixtures_dir).resolve()
    manifest_path = fixture_root / "fixtures-manifest.json"
    verification_path = fixture_root / "fixture-verification.json"
    fixtures, verification = _manifest_records(manifest_path, verification_path, fixture_root, total_deadline)
    provenance_path = fixture_root / "runtime-provenance.json"
    runtime_provenance = json.loads(_read_bounded(provenance_path, total_deadline, 64 * 1024).decode("utf-8"))
    if (runtime_provenance.get("architecture") != "linux/arm64"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(runtime_provenance.get("clamav_local_image_id", "")))
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(runtime_provenance.get("client_local_image_id", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(runtime_provenance.get("clamav_config_sha256", "")))):
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
    results.append({
        "case_id": "CTRL-EICAR-RAW", "track": "CONTROL", "input_sha256": EXPECTED_EICAR_SHA256,
        "fixture_provenance": "Phase 0C EICAR halves recombined at runtime; SHA-256 independently pinned",
        "independent_verification": {"status": "PASS", "method": "sha256"},
        "SECURITY_COVERAGE_STATUS": poc.INSPECTED,
        "original_container_scanner_result": {"classification": "DIRECT_POSITIVE_CONTROL", **_public_scan(direct)},
        "extracted_payload_scanner_results": [],
        "TEST_CASE_RESULT": "PASS" if direct_pass else "FAIL",
    })

    for spec, independent in candidates:
        total_deadline.remaining()
        case_deadline = total_deadline.child(CASE_DEADLINE_SECONDS)
        data = spec.builder()
        case_deadline.remaining()
        if len(data) > MAX_INPUT_BYTES:
            results.append({"case_id": spec.case_id, "track": spec.track,
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
        payload_scans = [
            {"structural_path": obj.get("object_path"), "depth": obj.get("depth"),
             "coverage_status": obj.get("verdict"), "actual_bytes": obj.get("extracted_bytes"),
             "resource_limits_hit": obj.get("resource_limits_hit", []),
             "scanner_result": {
                 "verdict": obj.get("scanner_verdict"), "reason": obj.get("scanner_reason"),
                 "signature": obj.get("offline_control_signature"),
             }}
            for obj in objects if obj.get("scanner_reason") == "CLAMD_INSTREAM_COMPLETE"
        ]
        results.append({
            "case_id": spec.case_id, "track": spec.track, "description": spec.description,
            "input_sha256": input_sha, "input_bytes": len(data),
            "fixture_provenance": spec.notes,
            "independent_verification": independent,
            "expected_structural_status": spec.expected_verdict,
            "SECURITY_COVERAGE_STATUS": coverage_status,
            "structural_coverage": structural.get("coverage") if structural else {"status": "NOT_VERIFIED"},
            "resource_limits": structural.get("budget") if structural else {},
            "original_container_scanner_result": {
                "classification": "OBSERVATIONAL_ONLY", **_public_scan(original),
                "clean_is_not_complete_nested_inspection": True,
            },
            "extracted_payload_scanner_results": payload_scans,
            "post_unlock_output_scan": "NOT_VERIFIED; separate requirement; no password provided",
            "TEST_CASE_RESULT": case_result,
            "error_code": error,
        })

    end = time.monotonic()
    return {
        "schema_version": "phase0c-live-evidence-v1",
        "experiment_id": "DIP-PHASE-0C-R1R2-LIVE-EVIDENCE-EXPERIMENTAL",
        "mode": "EXPERIMENTAL_LIVE_CLAMAV_SYNTHETIC_FIXTURES_ONLY",
        "executed_only_when_explicit_live_mode": True,
        "clamd": {"engine_version": engine, "signature_database_version": sig_version,
                  "signature_database_date": sig_date, "zPING": "PONG"},
        "runtime_provenance": runtime_provenance,
        "independent_fixture_verification_overall": verification.get("overall_status"),
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
        "governance": {"Security_Gate": "OPEN", "Licensing_Gate": "OPEN", "Stage_7": "NOT ACCEPTED",
                       "R1": "OPEN", "R2": "OPEN", "Change_Requests": "PROPOSED — NOT APPROVED"},
        "case_results": results,
        "cleanup": {"status": "PENDING_HOST_WORKFLOW_CLEANUP_VERIFICATION"},
    }


def finalize_evidence(report_path: Path, cleanup_path: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    cleanup = json.loads(cleanup_path.read_text(encoding="utf-8"))
    if cleanup.get("status") not in ("PASS", "FAIL"):
        raise ValueError("cleanup_status_missing_or_invalid")
    report["cleanup"] = cleanup
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
        return 0 if report.get("cleanup", {}).get("status") == "PASS" else 1
    try:
        report = run_live(args)
    except Exception as exc:
        report = {
            "schema_version": "phase0c-live-evidence-v1",
            "mode": "EXPERIMENTAL_LIVE_CLAMAV_SYNTHETIC_FIXTURES_ONLY",
            "TEST_CASE_RESULT": "NOT_VERIFIED",
            "error_code": exc.code if isinstance(exc, LiveScanError) else type(exc).__name__,
            "governance": {"Security_Gate": "OPEN", "Licensing_Gate": "OPEN", "R1": "OPEN", "R2": "OPEN"},
            "cleanup": {"status": "PENDING_HOST_WORKFLOW_CLEANUP_VERIFICATION"},
        }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if len(serialized.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise SystemExit("EVIDENCE_SIZE_LIMIT")
    output.write_text(serialized, encoding="utf-8")
    has_failure = any(item.get("TEST_CASE_RESULT") == "FAIL" for item in report.get("case_results", []))
    return 1 if has_failure or report.get("TEST_CASE_RESULT") == "NOT_VERIFIED" else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
