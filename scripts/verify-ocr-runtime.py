"""Fail closed unless the approved DIP OCR runtime is present and Ghostscript is absent."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from shutil import which
from subprocess import run
from tempfile import TemporaryDirectory
import sys

from PIL import Image, ImageDraw


def fail(message: str) -> None:
    print(f"OCR runtime policy violation: {message}", file=sys.stderr)
    raise SystemExit(1)


for executable in ("ocrmypdf", "tesseract"):
    if which(executable) is None:
        fail(f"required executable '{executable}' was not found")

if which("gs") is not None:
    fail("Ghostscript executable 'gs' is present in the approved OCR runtime")

try:
    ocrmypdf_version = version("ocrmypdf")
    pdfium_version = version("pypdfium2")
except PackageNotFoundError as error:
    fail(f"required Python package '{error.name}' was not found")

if ocrmypdf_version != "17.10.0":
    fail(f"OCRmyPDF must be 17.10.0, found {ocrmypdf_version}")
if pdfium_version != "5.13.0":
    fail(f"pypdfium2 must be 5.13.0, found {pdfium_version}")

cli_version = run(
    ["ocrmypdf", "--version"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
if cli_version != ocrmypdf_version:
    fail(
        "OCRmyPDF CLI/package version mismatch: "
        f"CLI={cli_version!r}, package={ocrmypdf_version!r}"
    )

languages = run(
    ["tesseract", "--list-langs"],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()
available_languages = {item.strip() for item in languages[1:] if item.strip()}
missing_languages = {"ara", "eng"} - available_languages
if missing_languages:
    fail(f"missing Tesseract language packs: {', '.join(sorted(missing_languages))}")

with TemporaryDirectory(prefix="dip-ocr-runtime-") as directory:
    fixture = Path(directory) / "input.png"
    output = Path(directory) / "output.pdf"
    image = Image.new("L", (320, 120), color=255)
    ImageDraw.Draw(image).text((20, 45), "DIP OCR runtime", fill=0)
    image.save(fixture, dpi=(300, 300))

    capability = run(
        [
            "ocrmypdf",
            "--skip-text",
            "--rotate-pages",
            "--deskew",
            "--output-type",
            "pdf",
            "--optimize",
            "0",
            "--rasterizer",
            "pypdfium",
            "--ocr-engine",
            "tesseract",
            "--language",
            "eng",
            "--image-dpi",
            "300",
            str(fixture),
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if capability.returncode != 0:
        diagnostic = (capability.stderr or capability.stdout).strip()[-2000:]
        fail(
            "approved OCR CLI capability probe failed "
            f"(exit {capability.returncode}): {diagnostic}"
        )
    if not output.is_file() or not output.read_bytes().startswith(b"%PDF-"):
        fail("approved OCR CLI capability probe did not produce a valid PDF signature")

print(
    "Approved OCR runtime verified: "
    f"OCRmyPDF {ocrmypdf_version}, pypdfium2 {pdfium_version}, "
    "Tesseract languages ara+eng, Ghostscript absent"
)
