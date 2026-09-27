#!/usr/bin/env python3
"""Regression coverage for reviewed Stage 3C ICC fixture provisioning."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROVISIONER_PATH = ROOT / "scripts" / "experiments" / "provision-structural-grayscale-stage3c-icc.py"
SOURCE_PACKAGE = ROOT / "node_modules" / "pdfjs-dist"

spec = importlib.util.spec_from_file_location("stage3c_icc_provisioner", PROVISIONER_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load Stage 3C ICC provisioner")
provisioner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = provisioner
spec.loader.exec_module(provisioner)


class IccFixtureProvisioningTests(unittest.TestCase):
    def make_package(self, root: pathlib.Path) -> pathlib.Path:
        package = root / "pdfjs-dist"
        (package / "iccs").mkdir(parents=True)
        (package / "package.json").write_text(
            json.dumps({"name": "pdfjs-dist", "version": "6.3.289"}), encoding="utf-8"
        )
        return package

    def test_reviewed_fixture_is_provisioned_and_revalidated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dip-stage3c-icc-") as temporary:
            output = pathlib.Path(temporary) / "output"
            evidence = provisioner.provision(SOURCE_PACKAGE, output)
            self.assertEqual(evidence["sha256"], provisioner.load_manifest()["profile"]["sha256"])
            staged = (output / "CGATS001Compat-v2-micro.icc").read_bytes()
            provisioner.validate_cmyk_icc(staged, provisioner.load_manifest())
            self.assertTrue((output / "CGATS001Compat-v2-micro.LICENSE.txt").is_file())
            self.assertTrue((output / "CGATS001Compat-v2-micro.provenance.json").is_file())

    def test_missing_fixture_fails_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dip-stage3c-icc-") as temporary:
            root = pathlib.Path(temporary)
            package = self.make_package(root)
            shutil.copyfile(SOURCE_PACKAGE / "iccs" / "LICENSE", package / "iccs" / "LICENSE")
            output = root / "output"
            with self.assertRaisesRegex(provisioner.FixtureProvisioningError, "profile is missing"):
                provisioner.provision(package, output)
            self.assertFalse(output.exists())

    def test_checksum_mismatch_fails_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dip-stage3c-icc-") as temporary:
            root = pathlib.Path(temporary)
            package = self.make_package(root)
            profile = bytearray((SOURCE_PACKAGE / "iccs" / "CGATS001Compat-v2-micro.icc").read_bytes())
            profile[-1] ^= 0x01
            (package / "iccs" / "CGATS001Compat-v2-micro.icc").write_bytes(profile)
            shutil.copyfile(SOURCE_PACKAGE / "iccs" / "LICENSE", package / "iccs" / "LICENSE")
            output = root / "output"
            with self.assertRaisesRegex(provisioner.FixtureProvisioningError, "checksum mismatch"):
                provisioner.provision(package, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
