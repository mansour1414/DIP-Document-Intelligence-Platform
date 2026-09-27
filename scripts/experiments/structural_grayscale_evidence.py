"""Sanitize and validate JSON evidence from the isolated Stage 3C PoC."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


DOCUMENT_CONTENT = "[REDACTED_DOCUMENT_CONTENT]"
PDF_PATH = re.compile(r"(?i)(?:file://)?(?:[a-z]:[\\/]|/)[^\s\"']*?\.pdf\b")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(authorization|credential|password|secret|token|api[_-]?key)(\s*[:=]\s*)([^\s,;]+)"
)
ENVIRONMENT_DUMP_KEY = re.compile(r"(?i)^(?:env|environ|environment|process\.env)$")
ENVIRONMENT_ASSIGNMENT = re.compile(
    r"(?i)\b(?:GITHUB|RUNNER|DATABASE|RETENTION|GROQ|PGPASSWORD|AWS|CI)_[A-Z0-9_]*\s*="
)
ARABIC_TEXT = re.compile(r"[\u0600-\u06ff]")
DOCUMENT_KEYS = {"text", "field_value", "value"}


def sanitize_evidence(value: Any, key: str | None = None) -> Any:
    if key in DOCUMENT_KEYS and isinstance(value, str):
        return DOCUMENT_CONTENT
    if key == "field_values" and isinstance(value, dict):
        return {field: DOCUMENT_CONTENT for field in value}
    if isinstance(value, dict):
        if key is not None and ENVIRONMENT_DUMP_KEY.fullmatch(key):
            raise ValueError("environment dumps are forbidden in Stage 3C evidence")
        return {item_key: sanitize_evidence(item, item_key) for item_key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_evidence(item, key) for item in value]
    if isinstance(value, str):
        sanitized = PDF_PATH.sub("[PDF_PATH]", value)
        return SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", sanitized)
    return value


def assert_sanitized_evidence(value: Any, key: str | None = None) -> None:
    if isinstance(value, dict):
        if key is not None and ENVIRONMENT_DUMP_KEY.fullmatch(key):
            raise ValueError("environment dumps are forbidden in Stage 3C evidence")
        for item_key, item in value.items():
            if item_key in DOCUMENT_KEYS and isinstance(item, str) and item != DOCUMENT_CONTENT:
                raise ValueError(f"raw document content remains in evidence key {item_key}")
            if item_key == "field_values" and isinstance(item, dict):
                if any(field_value != DOCUMENT_CONTENT for field_value in item.values()):
                    raise ValueError("raw form field values remain in Stage 3C evidence")
            assert_sanitized_evidence(item, item_key)
        return
    if isinstance(value, list):
        for item in value:
            assert_sanitized_evidence(item, key)
        return
    if isinstance(value, str):
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
