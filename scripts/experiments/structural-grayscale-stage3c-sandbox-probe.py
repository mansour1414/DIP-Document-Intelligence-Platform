#!/usr/bin/env python3
"""Fail-closed Linux sandbox and native-runtime evidence for Stage 3C."""

from __future__ import annotations

import glob
import importlib.metadata
import json
import os
import pathlib
import resource
import shutil
import subprocess
import sys

import pikepdf
from PIL import Image, features


EXPECTED_PACKAGES = {
    "pikepdf": "10.13.0.post1",
    "Pillow": "12.3.0",
    "lxml": "6.1.3",
    "packaging": "26.3",
    "reportlab": "4.4.9",
    "pypdf": "6.10.0",
    "pypdfium2": "5.13.0",
    "uharfbuzz": "0.56.2",
}
EXPECTED_QPDF_PACKAGE = "11.3.0-1+deb12u1"
EXPECTED_EMBEDDED_LIBQPDF = "12.3.2"
EXPECTED_LITTLECMS_RUNTIME = "2.19"
EXPECTED_MEMORY_BYTES = "805306368"
EXPECTED_PIDS = "128"


def command(arguments: list[str]) -> str:
    completed = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=20)
    return completed.stdout.strip()


def ldd_inventory(pattern: str) -> dict[str, list[str]]:
    inventory = {}
    matches = sorted(glob.glob(pattern))
    if not matches:
        raise AssertionError(f"native library pattern has no matches: {pattern}")
    for path in matches:
        output = command(["ldd", path])
        inventory[path] = [line.strip() for line in output.splitlines() if line.strip()]
    return inventory


def cgroup_value(name: str) -> str:
    path = pathlib.Path("/sys/fs/cgroup") / name
    if not path.exists():
        raise AssertionError(f"required cgroup v2 control is unavailable: {name}")
    return path.read_text(encoding="utf-8").strip()


def main() -> int:
    output = pathlib.Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    if (os.getuid(), os.getgid()) != (10001, 10001):
        raise AssertionError("Stage 3C must run as UID/GID 10001")
    root_read_only = False
    root_probe = pathlib.Path("/stage3b/stage3c-root-write-probe")
    try:
        root_probe.write_text("forbidden", encoding="utf-8")
    except OSError:
        root_read_only = True
    finally:
        root_probe.unlink(missing_ok=True)
    if not root_read_only:
        raise AssertionError("root filesystem is writable")

    mounts = pathlib.Path("/proc/mounts").read_text(encoding="utf-8")
    required_mounts = {
        "root_read_only": any(
            fields[1] == "/" and "ro" in fields[3].split(",")
            for fields in (line.split() for line in mounts.splitlines())
        ),
        "tmp_64m": any(
            fields[1] == "/tmp" and "size=65536k" in fields[3].split(",")
            for fields in (line.split() for line in mounts.splitlines())
        ),
        "tmp_dip_256m": any(
            fields[1] == "/tmp/dip" and "size=262144k" in fields[3].split(",")
            for fields in (line.split() for line in mounts.splitlines())
        ),
    }
    if not all(required_mounts.values()):
        raise AssertionError(f"required read-only/tmpfs mounts are missing: {required_mounts}")

    interfaces = sorted(path.name for path in pathlib.Path("/sys/class/net").iterdir())
    route_path = pathlib.Path("/proc/net/route")
    routes = route_path.read_text(encoding="utf-8").splitlines()[1:] if route_path.exists() else []
    default_route = any(line.split()[1] == "00000000" for line in routes if len(line.split()) >= 2)
    if default_route or interfaces != ["lo"]:
        raise AssertionError(f"processing network namespace is not isolated: interfaces={interfaces}")

    cgroup = {
        "cpu.max": cgroup_value("cpu.max"),
        "memory.max": cgroup_value("memory.max"),
        "pids.max": cgroup_value("pids.max"),
    }
    if cgroup["memory.max"] != EXPECTED_MEMORY_BYTES or cgroup["pids.max"] != EXPECTED_PIDS:
        raise AssertionError(f"unexpected cgroup limits: {cgroup}")
    cpu_quota = cgroup["cpu.max"].split()[0]
    if cpu_quota == "max":
        raise AssertionError("CPU cgroup is unbounded")

    versions = {name: importlib.metadata.version(name) for name in EXPECTED_PACKAGES}
    if versions != EXPECTED_PACKAGES:
        raise AssertionError(f"Python dependency version mismatch: {versions}")
    qpdf_package = command(["dpkg-query", "-W", "-f=${Version}", "qpdf"])
    if qpdf_package != EXPECTED_QPDF_PACKAGE:
        raise AssertionError(f"qpdf package mismatch: {qpdf_package}")
    if pikepdf.__libqpdf_version__ != EXPECTED_EMBEDDED_LIBQPDF:
        raise AssertionError(f"embedded libqpdf mismatch: {pikepdf.__libqpdf_version__}")
    littlecms_version = features.version("littlecms2")
    if littlecms_version != EXPECTED_LITTLECMS_RUNTIME:
        raise AssertionError(f"LittleCMS runtime mismatch: {littlecms_version}")
    if shutil.which("gs") or pathlib.Path("/usr/bin/gs").exists() or pathlib.Path("/usr/local/bin/gs").exists():
        raise AssertionError("Ghostscript is present")
    if features.check_feature("libimagequant"):
        raise AssertionError("libimagequant must be disabled")

    site_packages = pathlib.Path(pikepdf.__file__).resolve().parent.parent
    native_inventory = {}
    native_inventory.update(ldd_inventory(str(site_packages / "pikepdf" / "_core*.so")))
    native_inventory.update(ldd_inventory(str(site_packages / "PIL" / "_imaging*.so")))
    flattened_native = "\n".join(line for lines in native_inventory.values() for line in lines)
    if "libqpdf-" not in flattened_native or "liblcms2-" not in flattened_native:
        raise AssertionError("required bundled libqpdf/LittleCMS linkage was not observed")
    if "libimagequant" in flattened_native:
        raise AssertionError("libimagequant linkage was observed")

    evidence = {
        "scope": "isolated-stage3c-ci-gate-only",
        "uid": os.getuid(),
        "gid": os.getgid(),
        "root_read_only": root_read_only,
        "mounts": required_mounts,
        "network": {"interfaces": interfaces, "default_route": default_route},
        "cgroup": cgroup,
        "rlimits": {
            "cpu": resource.getrlimit(resource.RLIMIT_CPU),
            "address_space": resource.getrlimit(resource.RLIMIT_AS),
            "processes": resource.getrlimit(resource.RLIMIT_NPROC),
            "files": resource.getrlimit(resource.RLIMIT_NOFILE),
        },
        "python_packages": versions,
        "qpdf_cli_package": qpdf_package,
        "qpdf_cli_version": command(["qpdf", "--version"]).splitlines()[0],
        "pikepdf_version": pikepdf.__version__,
        "embedded_libqpdf_version": pikepdf.__libqpdf_version__,
        "pillow_version": Image.__version__,
        "littlecms_version": littlecms_version,
        "libimagequant_enabled": features.check_feature("libimagequant"),
        "ghostscript_present": False,
        "native_elf": native_inventory,
    }
    output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
