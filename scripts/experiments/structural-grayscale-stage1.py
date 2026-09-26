#!/usr/bin/env python3
"""Isolated Stage 1 PoC for a DIP-owned structural grayscale engine.

This is deliberately not imported by the application or worker.  It supports
only DeviceGray/RGB/CMYK convenience operators in page content and one text
widget's normal appearance stream.  Everything else fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import pikepdf
import pypdfium2 as pdfium
from PIL import Image, ImageChops, ImageStat, features
from pypdf import PdfReader
from reportlab.lib.colors import CMYKColor, Color
from reportlab.pdfgen.canvas import Canvas


MAX_INPUT_BYTES = 1_000_000
MAX_OUTPUT_BYTES = 2_000_000
MAX_DECODED_STREAM_BYTES = 2_000_000
MAX_OBJECTS = 500
MAX_STREAMS = 100
MAX_PAGES = 10
MAX_RECURSION_DEPTH = 16
MAX_SECONDS = 10.0
SUPPORTED_COLOR_OPERATORS = {"g": 1, "G": 1, "rg": 3, "RG": 3, "k": 4, "K": 4}
UNSUPPORTED_COLOR_OPERATORS = {"cs", "CS", "sc", "SC", "scn", "SCN", "sh"}


class UnsupportedPdf(RuntimeError):
    """The Stage 1 subset cannot transform this PDF safely."""


@dataclass
class Metrics:
    source_sha256: str
    output_sha256: str
    pages: int
    source_text: str
    output_text: str
    field_name: str
    field_type: str
    field_value: str
    source_max_chroma: int
    output_max_chroma: int
    expected_max_chroma: int
    output_expected_mae: float
    output_expected_max_delta: int
    output_colored_pixels: int
    transformed_instructions: int
    elapsed_ms: int
    pikepdf_version: str
    libqpdf_version: str
    lcms_version: str
    fail_closed_cases: list[str]
    temporary_cleanup_verified: bool


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def srgb_to_linear(value: float) -> float:
    value = clamp01(value)
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def linear_to_srgb(value: float) -> float:
    value = clamp01(value)
    return 12.92 * value if value <= 0.0031308 else 1.055 * value ** (1 / 2.4) - 0.055


def rgb_gray(red: float, green: float, blue: float) -> float:
    luminance = (
        0.2126 * srgb_to_linear(red)
        + 0.7152 * srgb_to_linear(green)
        + 0.0722 * srgb_to_linear(blue)
    )
    return clamp01(linear_to_srgb(luminance))


def cmyk_gray(cyan: float, magenta: float, yellow: float, black: float) -> float:
    # Stage 1 only: an explicitly provisional DeviceCMYK fallback. DeviceCMYK
    # has no defined colorimetry without a profile/output intent.
    red = (1.0 - clamp01(cyan)) * (1.0 - clamp01(black))
    green = (1.0 - clamp01(magenta)) * (1.0 - clamp01(black))
    blue = (1.0 - clamp01(yellow)) * (1.0 - clamp01(black))
    return rgb_gray(red, green, blue)


def color_to_gray(operator: str, operands: list[float]) -> tuple[str, float]:
    if operator in {"g", "G"}:
        return operator, clamp01(operands[0])
    if operator in {"rg", "RG"}:
        gray = rgb_gray(*operands)
    else:
        gray = cmyk_gray(*operands)
    return ("G" if operator[0].isupper() else "g"), gray


class DeviceColorTokenFilter(pikepdf.TokenFilter):
    """Replace only complete DeviceRGB/CMYK convenience instructions."""

    def __init__(self) -> None:
        super().__init__()
        self.buffer: list[pikepdf.Token] = []
        self.failure: str | None = None
        self.transformed = 0

    def handle_token(self, token: pikepdf.Token):
        if token.type_ == pikepdf.TokenType.inline_image:
            self.failure = self.failure or "inline images are outside the Stage 1 subset"
        if token.type_ == pikepdf.TokenType.eof:
            released = [*self.buffer, token]
            self.buffer.clear()
            return released

        self.buffer.append(token)
        if token.type_ != pikepdf.TokenType.word:
            return None

        operator = token.value
        instruction = self.buffer
        self.buffer = []
        if operator in UNSUPPORTED_COLOR_OPERATORS:
            self.failure = self.failure or f"unsupported color operator: {operator}"
            return instruction
        if operator not in SUPPORTED_COLOR_OPERATORS:
            return instruction

        values = [
            float(part.value)
            for part in instruction[:-1]
            if part.type_ in {pikepdf.TokenType.integer, pikepdf.TokenType.real}
        ]
        expected = SUPPORTED_COLOR_OPERATORS[operator]
        non_layout = [
            part
            for part in instruction[:-1]
            if part.type_ not in {
                pikepdf.TokenType.integer,
                pikepdf.TokenType.real,
                pikepdf.TokenType.space,
                pikepdf.TokenType.comment,
            }
        ]
        if len(values) != expected or non_layout:
            self.failure = self.failure or f"malformed {operator} instruction"
            return instruction

        gray_operator, gray = color_to_gray(operator, values)
        self.transformed += operator not in {"g", "G"}
        return [
            pikepdf.Token(pikepdf.TokenType.space, b"\n"),
            pikepdf.Token(pikepdf.TokenType.real, f"{gray:.6f}".encode("ascii")),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.word, gray_operator.encode("ascii")),
            pikepdf.Token(pikepdf.TokenType.space, b"\n"),
        ]


def filtered_stream_bytes(stream: pikepdf.Stream) -> tuple[bytes, int]:
    wrapper = pikepdf.Page(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Page,
            MediaBox=pikepdf.Array([0, 0, 100, 100]),
            Resources=pikepdf.Dictionary(),
            Contents=stream,
        )
    )
    token_filter = DeviceColorTokenFilter()
    result = wrapper.get_filtered_contents(token_filter)
    if token_filter.failure:
        raise UnsupportedPdf(token_filter.failure)
    if len(result) > MAX_DECODED_STREAM_BYTES:
        raise UnsupportedPdf("decoded stream byte limit exceeded")
    return result, token_filter.transformed


def write_gray_array(target: pikepdf.Object, key: str) -> int:
    array = target.get(key)
    if array is None:
        return 0
    values = [float(value) for value in array]
    if len(values) == 1:
        gray = clamp01(values[0])
    elif len(values) == 3:
        gray = rgb_gray(*values)
    elif len(values) == 4:
        gray = cmyk_gray(*values)
    else:
        raise UnsupportedPdf(f"unsupported {key} color component count")
    target[key] = pikepdf.Array([round(gray, 6)])
    return int(len(values) > 1)


def transform_da(value: str) -> tuple[str, int]:
    owner = pikepdf.Pdf.new()
    with owner:
        raw = owner.make_stream(value.encode("latin-1"))
        filtered, count = filtered_stream_bytes(raw)
        return filtered.decode("latin-1").strip(), count


def reject_unsafe_or_unsupported(pdf: pikepdf.Pdf, source_size: int) -> None:
    if source_size > MAX_INPUT_BYTES:
        raise UnsupportedPdf("input byte limit exceeded")
    if len(pdf.pages) == 0 or len(pdf.pages) > MAX_PAGES:
        raise UnsupportedPdf("page limit exceeded")
    objects = list(pdf.objects)
    if len(objects) > MAX_OBJECTS:
        raise UnsupportedPdf("object limit exceeded")
    streams = [obj for obj in objects if isinstance(obj, pikepdf.Stream)]
    if len(streams) > MAX_STREAMS:
        raise UnsupportedPdf("stream count limit exceeded")
    visited: set[tuple[object, ...]] = set()

    def inspect_structure(obj: pikepdf.Object, depth: int) -> None:
        if depth > MAX_RECURSION_DEPTH:
            raise UnsupportedPdf("object recursion depth limit exceeded")
        try:
            objgen = obj.objgen
        except (AttributeError, TypeError):
            objgen = (0, 0)
        identity = ("indirect", *objgen) if objgen != (0, 0) else ("direct", id(obj))
        if identity in visited:
            return
        visited.add(identity)
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            if obj.get("/ByteRange") is not None or obj.get("/Type") == pikepdf.Name.Sig:
                raise UnsupportedPdf("signed PDFs are rejected")
            for value in obj.values():
                inspect_structure(value, depth + 1)
        elif isinstance(obj, pikepdf.Array):
            for value in obj:
                inspect_structure(value, depth + 1)

    inspect_structure(pdf.Root, 0)
    for page in pdf.pages:
        resources = page.obj.get("/Resources", {})
        if resources.get("/Pattern") or resources.get("/Shading"):
            raise UnsupportedPdf("patterns and shadings are outside the Stage 1 subset")
        for _, xobject in page.form_xobjects.items():
            if xobject.get("/Subtype") == pikepdf.Name.Image:
                raise UnsupportedPdf("embedded images are outside the Stage 1 subset")
            raise UnsupportedPdf("page Form XObjects require the Stage 2 recursion module")


def transform(source: Path, destination: Path) -> int:
    started = time.monotonic()
    try:
        pdf = pikepdf.Pdf.open(source)
    except pikepdf.PasswordError as error:
        raise UnsupportedPdf("encrypted PDFs require an authorized separate path") from error
    with pdf:
        reject_unsafe_or_unsupported(pdf, source.stat().st_size)
        transformations = 0
        for page in pdf.pages:
            contents = page.obj.get("/Contents")
            if contents is not None:
                if isinstance(contents, pikepdf.Array):
                    decoded = b"\n".join(bytes(stream.read_bytes()) for stream in contents)
                    if len(decoded) > MAX_DECODED_STREAM_BYTES:
                        raise UnsupportedPdf("decoded page stream byte limit exceeded")
                    page.obj["/Contents"] = pdf.make_stream(decoded)
                output, count = filtered_stream_bytes(page.obj["/Contents"])
                page.obj["/Contents"].write(output)
                transformations += count

            annotations = page.obj.get("/Annots", [])
            for annotation in annotations:
                if annotation.get("/Subtype") != pikepdf.Name.Widget:
                    raise UnsupportedPdf("only one text widget annotation is supported")
                if annotation.get("/FT") != pikepdf.Name.Tx:
                    raise UnsupportedPdf("only text widgets are supported")
                appearance = annotation.get("/AP", {}).get("/N")
                if not isinstance(appearance, pikepdf.Stream):
                    raise UnsupportedPdf("widget must have one direct normal appearance stream")
                appearance_output, count = filtered_stream_bytes(appearance)
                appearance.write(appearance_output)
                transformations += count
                mk = annotation.get("/MK")
                if mk:
                    transformations += write_gray_array(mk, "/BG")
                    transformations += write_gray_array(mk, "/BC")
                da = annotation.get("/DA")
                if da is not None:
                    transformed_da, count = transform_da(str(da))
                    annotation["/DA"] = pikepdf.String(transformed_da)
                    transformations += count

        acroform = pdf.Root.get("/AcroForm")
        if acroform and acroform.get("/DA") is not None:
            transformed_da, count = transform_da(str(acroform["/DA"]))
            acroform["/DA"] = pikepdf.String(transformed_da)
            transformations += count
        if time.monotonic() - started > MAX_SECONDS:
            raise TimeoutError("Stage 1 CPU/wall-clock budget exceeded")
        pdf.save(destination, deterministic_id=True, compress_streams=True)
    if destination.stat().st_size > MAX_OUTPUT_BYTES:
        destination.unlink(missing_ok=True)
        raise UnsupportedPdf("output byte limit exceeded")
    with pikepdf.Pdf.open(destination) as reopened:
        reopened.check_pdf_syntax()
    return transformations


def make_fixture(path: Path, grayscale: bool) -> None:
    canvas = Canvas(str(path), pagesize=(420, 320), pageCompression=0, invariant=1)
    if grayscale:
        text_gray = rgb_gray(0.82, 0.12, 0.18)
        fill_gray = rgb_gray(0.10, 0.72, 0.30)
        line_gray = cmyk_gray(0.80, 0.10, 0.20, 0.10)
        widget_bg = rgb_gray(0.15, 0.30, 0.90)
        widget_border = rgb_gray(0.90, 0.25, 0.10)
        widget_text = rgb_gray(0.70, 0.05, 0.50)
        canvas.setFillGray(text_gray)
        canvas.setStrokeGray(line_gray)
        canvas.setFillGray(fill_gray)
    else:
        canvas.setFillColorRGB(0.82, 0.12, 0.18)
        canvas.setStrokeColorCMYK(0.80, 0.10, 0.20, 0.10)
        canvas.setFillColorRGB(0.10, 0.72, 0.30)
    canvas.rect(44, 175, 330, 70, fill=1, stroke=1)
    if grayscale:
        canvas.setFillGray(text_gray)
    else:
        canvas.setFillColorRGB(0.82, 0.12, 0.18)
    canvas.setFont("Helvetica", 16)
    canvas.drawString(52, 270, "DIP searchable vector text")
    canvas.setFont("Helvetica", 10)
    canvas.drawString(52, 250, "RGB fill + CMYK stroke + preserved AcroForm")
    if grayscale:
        fill = Color(widget_bg, widget_bg, widget_bg)
        border = Color(widget_border, widget_border, widget_border)
        text = Color(widget_text, widget_text, widget_text)
    else:
        fill = Color(0.15, 0.30, 0.90)
        border = Color(0.90, 0.25, 0.10)
        text = Color(0.70, 0.05, 0.50)
    canvas.acroForm.textfield(
        name="customer_note",
        value="Preserved field value",
        x=52,
        y=80,
        width=300,
        height=36,
        fillColor=fill,
        borderColor=border,
        textColor=text,
        borderWidth=2,
        forceBorder=True,
    )
    canvas.showPage()
    canvas.save()


def render(path: Path, png_path: Path, scale: float = 2.0) -> Image.Image:
    document = pdfium.PdfDocument(str(path))
    try:
        bitmap = document[0].render(scale=scale, rev_byteorder=True)
        image = bitmap.to_pil().convert("RGB")
        image.save(png_path)
        return image
    finally:
        document.close()


def max_chroma(image: Image.Image) -> tuple[int, int]:
    pixels = image.get_flattened_data()
    maximum = 0
    colored = 0
    for red, green, blue in pixels:
        delta = max(red, green, blue) - min(red, green, blue)
        maximum = max(maximum, delta)
        colored += int(delta > 1)
    return maximum, colored


def validate(
    source: Path,
    output: Path,
    expected: Path,
    workdir: Path,
    count: int,
    elapsed_ms: int,
    fail_closed_cases: list[str],
) -> Metrics:
    source_reader = PdfReader(str(source))
    output_reader = PdfReader(str(output))
    source_text = source_reader.pages[0].extract_text().strip()
    output_text = output_reader.pages[0].extract_text().strip()
    fields = output_reader.get_fields() or {}
    field = fields["customer_note"]
    source_image = render(source, workdir / "source.png")
    output_image = render(output, workdir / "output.png")
    expected_image = render(expected, workdir / "expected.png")
    source_chroma, _ = max_chroma(source_image)
    output_chroma, colored = max_chroma(output_image)
    expected_chroma, _ = max_chroma(expected_image)
    difference = ImageChops.difference(output_image, expected_image)
    stat = ImageStat.Stat(difference)
    mae = sum(stat.mean) / 3.0
    max_delta = max(channel[1] for channel in difference.getextrema())
    if source_text != output_text:
        raise AssertionError("searchable text changed")
    if field.get("/V") != "Preserved field value" or field.get("/FT") != "/Tx":
        raise AssertionError("field identity, type, or value changed")
    if output_chroma > 1 or colored:
        raise AssertionError("output still contains colored rendered pixels")
    if mae > 0.50 or max_delta > 48:
        raise AssertionError(f"visual result diverged from independent expected fixture: {mae=}, {max_delta=}")
    return Metrics(
        source_sha256=sha256(source),
        output_sha256=sha256(output),
        pages=len(output_reader.pages),
        source_text=source_text,
        output_text=output_text,
        field_name="customer_note",
        field_type=str(field.get("/FT")),
        field_value=str(field.get("/V")),
        source_max_chroma=source_chroma,
        output_max_chroma=output_chroma,
        expected_max_chroma=expected_chroma,
        output_expected_mae=round(mae, 6),
        output_expected_max_delta=max_delta,
        output_colored_pixels=colored,
        transformed_instructions=count,
        elapsed_ms=elapsed_ms,
        pikepdf_version=pikepdf.__version__,
        libqpdf_version=pikepdf.__libqpdf_version__,
        lcms_version=str(features.version("littlecms2")),
        fail_closed_cases=fail_closed_cases,
        temporary_cleanup_verified=True,
    )


def verify_fail_closed_cases(source: Path, workdir: Path) -> list[str]:
    cases: list[tuple[str, Path]] = []

    unsupported = workdir / "unsupported-colorspace.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        original = bytes(pdf.pages[0].Contents.read_bytes())
        pdf.pages[0].Contents.write(b"/DeviceRGB cs\n0.1 0.2 0.3 sc\n" + original)
        pdf.save(unsupported)
    cases.append(("unsupported-color-space", unsupported))

    signed = workdir / "signed-marker.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        pdf.Root["/Stage1SignatureProbe"] = pikepdf.Dictionary(
            Type=pikepdf.Name.Sig,
            ByteRange=pikepdf.Array([0, 1, 2, 3]),
        )
        pdf.save(signed)
    cases.append(("signed", signed))

    encrypted = workdir / "encrypted.pdf"
    with pikepdf.Pdf.open(source) as pdf:
        pdf.save(
            encrypted,
            encryption=pikepdf.Encryption(
                owner="stage1-owner",
                user="stage1-user",
                R=6,
                aes=True,
            ),
        )
    cases.append(("encrypted", encrypted))

    malformed = workdir / "malformed.pdf"
    source_bytes = source.read_bytes()
    malformed.write_bytes(source_bytes[: max(64, len(source_bytes) // 3)])
    cases.append(("malformed", malformed))

    rejected: list[str] = []
    for name, candidate in cases:
        destination = workdir / f"unexpected-{name}.pdf"
        try:
            transform(candidate, destination)
        except (UnsupportedPdf, pikepdf.PdfError):
            if destination.exists():
                raise AssertionError(f"{name} left a partial output")
            rejected.append(name)
        else:
            raise AssertionError(f"{name} was not rejected")
    return rejected


def self_test(output_directory: Path) -> Metrics:
    output_directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dip-gray-stage1-") as temporary:
        temporary_path = Path(temporary)
        source = temporary_path / "source.pdf"
        expected = temporary_path / "expected.pdf"
        make_fixture(source, grayscale=False)
        make_fixture(expected, grayscale=True)
        final_source = output_directory / "source.pdf"
        final_expected = output_directory / "expected.pdf"
        final_output = output_directory / "output.pdf"
        shutil.copy2(source, final_source)
        shutil.copy2(expected, final_expected)
        fail_closed_cases = verify_fail_closed_cases(source, temporary_path)
        started = time.monotonic()
        count = transform(source, final_output)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        metrics = validate(
            final_source,
            final_output,
            final_expected,
            output_directory,
            count,
            elapsed_ms,
            fail_closed_cases,
        )
        (output_directory / "metrics.json").write_text(
            json.dumps(asdict(metrics), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if temporary_path.exists() is False:
            raise AssertionError("temporary directory disappeared before context cleanup")
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("tmp/pdfs/structural-grayscale-stage1/results"))
    args = parser.parse_args()
    if not args.self_test:
        parser.error("Stage 1 exposes only --self-test; it is not a production converter")
    metrics = self_test(args.output_dir)
    print(json.dumps(asdict(metrics), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
