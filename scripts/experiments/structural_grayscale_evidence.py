"""Sanitize and validate JSON evidence from the isolated Stage 3C PoC."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


DOCUMENT_CONTENT = "[REDACTED_DOCUMENT_CONTENT]"
DIAGNOSTIC_CONTENT = "[REDACTED_DIAGNOSTIC]"
MAX_EVIDENCE_DEPTH = 32
MAX_COLLECTION_ITEMS = 10_000
MAX_STRING_LENGTH = 2_000
MAX_LOG_BYTES = 2_048
PDF_PATH = re.compile(r"(?i)(?:file://)?(?:[a-z]:[\\/]|/)[^\s\"']*?\.pdf\b")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(authorization|credential|password|secret|token|api[_-]?key)(\s*[:=]\s*)([^\s,;]+)"
)
ENVIRONMENT_DUMP_KEY = re.compile(r"(?i)^(?:env|environ|environment|process\.env)$")
ENVIRONMENT_ASSIGNMENT = re.compile(
    r"(?i)\b(?:GITHUB|RUNNER|DATABASE|RETENTION|GROQ|PGPASSWORD|AWS|CI)_[A-Z0-9_]*\s*="
)
ARABIC_TEXT = re.compile(r"[\u0600-\u06ff]")
DIAGNOSTIC_KEYS = {"diagnostic", "error", "message", "stderr", "stdout"}


def _is_document_content_path(path: tuple[str, ...]) -> bool:
    key = path[-1] if path else ""
    if key == "text" or key.endswith("_text"):
        return True
    if key == "field_value" or key.endswith("_field_value") or "field_values" in path:
        return True
    return key == "value" and "properties" not in path[:-1]


def sanitize_evidence(value: Any, path: tuple[str, ...] = ()) -> Any:
    if len(path) > MAX_EVIDENCE_DEPTH:
        raise ValueError("Stage 3C evidence exceeds the recursion-depth limit")
    key = path[-1] if path else None
    if isinstance(value, str) and _is_document_content_path(path):
        return DOCUMENT_CONTENT
    if isinstance(value, str) and key in DIAGNOSTIC_KEYS:
        return DIAGNOSTIC_CONTENT
    if isinstance(value, dict):
        if key is not None and ENVIRONMENT_DUMP_KEY.fullmatch(key):
            raise ValueError("environment dumps are forbidden in Stage 3C evidence")
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ValueError("Stage 3C evidence dictionary exceeds the item limit")
        return {
            item_key: sanitize_evidence(item, path + (item_key,))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ValueError("Stage 3C evidence array exceeds the item limit")
        return [sanitize_evidence(item, path + ("[]",)) for item in value]
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError("Stage 3C evidence string exceeds the length limit")
        sanitized = PDF_PATH.sub("[PDF_PATH]", value)
        return SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", sanitized)
    return value


def assert_sanitized_evidence(value: Any, path: tuple[str, ...] = ()) -> None:
    if len(path) > MAX_EVIDENCE_DEPTH:
        raise ValueError("Stage 3C evidence exceeds the recursion-depth limit")
    key = path[-1] if path else None
    if isinstance(value, dict):
        if key is not None and ENVIRONMENT_DUMP_KEY.fullmatch(key):
            raise ValueError("environment dumps are forbidden in Stage 3C evidence")
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ValueError("Stage 3C evidence dictionary exceeds the item limit")
        for item_key, item in value.items():
            item_path = path + (item_key,)
            if isinstance(item, str) and _is_document_content_path(item_path) and item != DOCUMENT_CONTENT:
                raise ValueError(f"raw document content remains in evidence key {item_key}")
            if isinstance(item, str) and item_key in DIAGNOSTIC_KEYS and item != DIAGNOSTIC_CONTENT:
                raise ValueError(f"unfiltered diagnostic remains in evidence key {item_key}")
            assert_sanitized_evidence(item, item_path)
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ValueError("Stage 3C evidence array exceeds the item limit")
        for item in value:
            assert_sanitized_evidence(item, path + ("[]",))
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError("Stage 3C evidence string exceeds the length limit")
        if PDF_PATH.search(value):
            raise ValueError("temporary or source PDF path remains in Stage 3C evidence")
        credential_match = SECRET_ASSIGNMENT.search(value)
        if credential_match and credential_match.group(3) != "[REDACTED]":
            raise ValueError("credential-like value remains in Stage 3C evidence")
        if ENVIRONMENT_ASSIGNMENT.search(value):
            raise ValueError("environment assignment remains in Stage 3C evidence")
        if ARABIC_TEXT.search(value):
            raise ValueError("raw document text remains in Stage 3C evidence")


def write_sanitized_json(destination: Path, value: Any) -> None:
    sanitized = sanitize_evidence(value)
    assert_sanitized_evidence(sanitized)
    destination.write_text(
        json.dumps(sanitized, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
    )


def print_sanitized_summary(value: Any, *, stream: Any = None) -> None:
    sanitized = sanitize_evidence(value)
    assert_sanitized_evidence(sanitized)
    encoded = json.dumps(sanitized, ensure_ascii=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_LOG_BYTES:
        raise ValueError("Stage 3C log summary exceeds the byte limit")
    print(encoded, file=stream or sys.stdout)


def sanitize_json_file(source: Path, destination: Path) -> None:
    write_sanitized_json(destination, json.loads(source.read_text(encoding="utf-8")))


def audit_artifact_directory(root: Path) -> dict[str, int]:
    json_files = sorted(root.rglob("*.json"))
    if not json_files:
        raise ValueError("Stage 3C evidence contains no JSON files")
    for path in json_files:
        value = json.loads(path.read_text(encoding="utf-8"))
        assert_sanitized_evidence(value)
    if any(root.rglob("*.pdf")):
        raise ValueError("PDF outputs are forbidden in the Stage 3C evidence artifact")
    return {"validated_json_files": len(json_files)}
