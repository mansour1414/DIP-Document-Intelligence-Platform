"""Fail-closed, sanitized subprocess handling for grayscale experiments.

This QA-only module deliberately excludes argv, stdout, and environment data
from failure diagnostics.  It is not part of the production worker runtime.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


MAX_STDERR_CHARACTERS = 2_000
MAX_STDERR_LINES = 20
_SECRET_NAME = re.compile(r"(?:authorization|credential|password|secret|token|api[_-]?key)", re.I)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(authorization|credential|password|secret|token|api[_-]?key)(\s*[:=]\s*)([^\s,;]+)"
)
_PDF_PATH = re.compile(r"(?i)(?:file://)?[^\s\"']+\.pdf\b")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^/@\s]+@")


def sanitize_stderr(stderr: str | None) -> str:
    """Return bounded diagnostics without document paths or secret values."""

    value = (stderr or "").replace("\x00", "")
    for name, secret in os.environ.items():
        if secret and len(secret) >= 4 and _SECRET_NAME.search(name):
            value = value.replace(secret, "[REDACTED]")
    value = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
    value = _URL_USERINFO.sub(r"\1[REDACTED]@", value)
    value = _PDF_PATH.sub("[PDF_PATH]", value)
    lines = [line[:500] for line in value.splitlines()[:MAX_STDERR_LINES]]
    bounded = "\n".join(lines).strip()[:MAX_STDERR_CHARACTERS]
    return bounded or "[no stderr]"


def run_checked(
    arguments: list[str], *, operation: str, cwd: Path
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess and raise a sanitized, operation-scoped error."""

    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        diagnostic = {
            "operation": operation,
            "exit_status": None,
            "stderr": f"{type(error).__name__}: subprocess launch failed",
        }
        raise RuntimeError(
            "isolated subprocess failed: "
            + json.dumps(diagnostic, ensure_ascii=True, separators=(",", ":"))
        ) from error
    if result.returncode != 0:
        diagnostic = {
            "operation": operation,
            "exit_status": result.returncode,
            "stderr": sanitize_stderr(result.stderr),
        }
        raise RuntimeError(
            "isolated subprocess failed: "
            + json.dumps(diagnostic, ensure_ascii=True, separators=(",", ":"))
        )
    return result
