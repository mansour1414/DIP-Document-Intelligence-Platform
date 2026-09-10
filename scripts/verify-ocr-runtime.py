"""Fail closed unless the approved DIP OCR runtime is present and Ghostscript is absent."""

from importlib.metadata import PackageNotFoundError, version
from shutil import which
from subprocess import run
import sys


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

help_text = run(
    ["ocrmypdf", "--help"],
    check=True,
    capture_output=True,
    text=True,
).stdout
for option in ("--output-type", "--optimize", "--rasterizer", "--ocr-engine"):
    if option not in help_text:
        fail(f"OCRmyPDF does not expose required option {option}")

print(
    "Approved OCR runtime verified: "
    f"OCRmyPDF {ocrmypdf_version}, pypdfium2 {pdfium_version}, "
    "Tesseract languages ara+eng, Ghostscript absent"
)
