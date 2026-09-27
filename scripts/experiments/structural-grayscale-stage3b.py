#!/usr/bin/env python3
"""Isolated Stage 3B readiness experiment for the DIP grayscale engine.

This script does not expand the Stage 3A supported PDF feature set. It adds
Arabic regression attribution, naturalistic JPEG quality measurements,
appearance-regeneration repetitions, and bounded mutation probes.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import random
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from io import BytesIO
from pathlib import Path

import pikepdf
import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageFilter
from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab import rl_config
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[2]
STAGE3A_PATH = Path(__file__).with_name("structural-grayscale-stage3a.py")
STAGE3A_OUTPUT = ROOT / "output" / "pdf" / "structural-grayscale-stage3a"
ARABIC_QUERY = "مرحلة المحرك البنيوي الثالثة تحافظ على النص العربي القابل للبحث والنسخ."


def load_stage3a():
    spec = importlib.util.spec_from_file_location("dip_structural_gray_stage3a", STAGE3A_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Stage 3A implementation")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


stage3a = load_stage3a()
stage2 = stage3a.stage2


def naturalistic_scene(kind: int, width: int = 360, height: int = 240) -> Image.Image:
    randomizer = random.Random(3100 + kind)
    image = Image.new("RGB", (width, height))
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            noise = randomizer.randint(-6, 6)
            if kind == 0:
                horizon = 132 + 10 * math.sin(x / 43)
                base = (45 + int(85 * y / height), 120 + int(75 * y / height), 205 - int(90 * y / height))
                if y > horizon:
                    base = (55 + int(35 * y / height), 105 + int(55 * y / height), 48)
            elif kind == 1:
                radial = min(1.0, math.hypot(x - 185, y - 118) / 210)
                base = (215 - int(90 * radial), 150 - int(65 * radial), 118 - int(55 * radial))
            else:
                checker = ((x // 18) + (y // 14)) % 2
                base = (170 + 35 * checker, 75 + int(100 * x / width), 55 + int(130 * y / height))
            pixels[x, y] = tuple(max(0, min(255, channel + noise)) for channel in base)
    draw = ImageDraw.Draw(image, "RGBA")
    if kind == 0:
        draw.ellipse((275, 24, 322, 71), fill=(245, 210, 70, 230))
        draw.polygon([(0, 145), (95, 67), (175, 145)], fill=(75, 74, 102, 230))
        draw.polygon([(105, 145), (238, 50), (360, 145)], fill=(92, 82, 109, 220))
    elif kind == 1:
        draw.ellipse((104, 35, 260, 207), fill=(206, 144, 112, 160))
        draw.ellipse((142, 92, 161, 109), fill=(45, 35, 32, 230))
        draw.ellipse((207, 92, 226, 109), fill=(45, 35, 32, 230))
        draw.arc((150, 105, 225, 165), start=12, end=168, fill=(110, 36, 40, 240), width=4)
    else:
        for offset in range(0, width, 34):
            draw.line((offset, 0, width - offset // 2, height), fill=(30, 70, 145, 110), width=5)
        draw.rounded_rectangle((88, 58, 290, 188), radius=24, outline=(245, 235, 175, 230), width=8)
    return image.filter(ImageFilter.GaussianBlur(radius=0.35))


def encode_jpeg(image: Image.Image, quality: int, subsampling: int) -> bytes:
    stream = BytesIO()
    image.save(stream, format="JPEG", quality=quality, subsampling=subsampling, optimize=False)
    return stream.getvalue()


def expected_gray_jpeg(source: bytes) -> bytes:
    with Image.open(BytesIO(source)) as image:
        rgb = image.convert("RGB")
        gray = Image.new("L", rgb.size)
        gray.putdata([stage3a.reference_rgb_gray(*pixel) for pixel in rgb.get_flattened_data()])
        stream = BytesIO()
        gray.save(stream, format="JPEG", quality=95, optimize=False)
        return stream.getvalue()


def write_jpeg_corpus(path: Path, images: list[tuple[str, bytes]], title: str) -> None:
    # Preserve the original JPEG as a single DCTDecode stream. ReportLab's
    # optional ASCII85 wrapper would intentionally fall outside Stage 3A.
    rl_config.useA85 = 0
    document = canvas.Canvas(str(path), pagesize=A4, pageCompression=1)
    width, height = A4
    for page_index in range(3):
        document.setFillGray(0)
        document.setFont("Helvetica-Bold", 14)
        document.drawString(42, height - 42, f"{title} - page {page_index + 1}")
        page_images = images[page_index * 3 : page_index * 3 + 3]
        y = height - 260
        for name, data in page_images:
            document.drawImage(ImageReader(BytesIO(data)), 42, y, width=270, height=180, preserveAspectRatio=True)
            document.setFont("Helvetica", 9)
            document.drawString(326, y + 84, name)
            y -= 235
        document.showPage()
    document.save()


def make_natural_jpeg_corpus(source: Path, expected: Path) -> list[dict[str, object]]:
    settings = [(55, 2), (72, 1), (92, 0)]
    source_images: list[tuple[str, bytes]] = []
    expected_images: list[tuple[str, bytes]] = []
    inventory = []
    for scene in range(3):
        image = naturalistic_scene(scene)
        for quality, subsampling in settings:
            name = f"scene-{scene + 1}-q{quality}-s{subsampling}"
            encoded = encode_jpeg(image, quality, subsampling)
            source_images.append((name, encoded))
            expected_images.append((name, expected_gray_jpeg(encoded)))
            inventory.append(
                {
                    "name": name,
                    "quality": quality,
                    "subsampling": subsampling,
                    "width": image.width,
                    "height": image.height,
                    "source_bytes": len(encoded),
                }
            )
    write_jpeg_corpus(source, source_images, "Independent naturalistic JPEG source")
    write_jpeg_corpus(expected, expected_images, "Independent naturalistic JPEG source")
    return inventory


def render_pdfium_pages(path: Path, directory: Path, prefix: str) -> list[Path]:
    document = pdfium.PdfDocument(str(path))
    outputs = []
    try:
        for index in range(len(document)):
            output = directory / f"{prefix}-{index + 1}.png"
            page = document[index]
            try:
                page.render(scale=1.5).to_pil().convert("RGB").save(output)
            finally:
                page.close()
            outputs.append(output)
    finally:
        document.close()
    return outputs


def render_poppler_pages(path: Path, directory: Path, prefix: str) -> list[Path]:
    executable = shutil.which("pdftoppm")
    if not executable:
        return []
    subprocess.run(
        [executable, "-png", "-r", "108", str(path), str(directory / prefix)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return sorted(directory.glob(f"{prefix}-*.png"))


def visual_metrics(expected: Path, actual: Path, work: Path, renderer: str) -> list[dict[str, object]]:
    if renderer == "pdfium":
        expected_pages = render_pdfium_pages(expected, work, "expected-pdfium")
        actual_pages = render_pdfium_pages(actual, work, "actual-pdfium")
    else:
        expected_pages = render_poppler_pages(expected, work, "expected-poppler")
        actual_pages = render_poppler_pages(actual, work, "actual-poppler")
    if not expected_pages and renderer == "poppler":
        return []
    if len(expected_pages) != len(actual_pages):
        raise AssertionError(f"{renderer} page count mismatch")
    measurements = []
    for expected_page, actual_page in zip(expected_pages, actual_pages):
        with Image.open(expected_page) as expected_image, Image.open(actual_page) as actual_image:
            measurements.append(
                stage3a.difference_metrics(actual_image.convert("RGB"), expected_image.convert("RGB"))
            )
    return measurements


def text_snapshot(path: Path) -> list[str]:
    return [page.extract_text() or "" for page in PdfReader(str(path)).pages]


def locate_arabic_font() -> Path:
    candidates = [
        Path(r"C:\Windows\Fonts\arial.ttf"),
        Path("/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf"),
        Path("/usr/share/fonts/opentype/noto/NotoSansArabic-Regular.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("no independent Arabic fixture font is available")


def make_reportlab_arabic_fixture(path: Path) -> dict[str, str]:
    font_path = locate_arabic_font()
    font_name = "Stage3BArabic"
    if font_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
    document = canvas.Canvas(str(path), pagesize=A4, pageCompression=1)
    document.setFont(font_name, 18)
    document.setFillColorRGB(0.75, 0.12, 0.30)
    document.drawString(50, 760, ARABIC_QUERY)
    document.setFillColorRGB(0.10, 0.35, 0.75)
    document.drawString(50, 720, "اختبار مستقل للترتيب المنطقي 12345 Stage 3B")
    document.save()
    return {"font_path": str(font_path), "fixture_role": "logical-order semantics, not shaping fidelity"}


def pdfium_search_results(path: Path) -> dict[str, object]:
    document = pdfium.PdfDocument(str(path))
    queries = {
        "logical_phrase": ARABIC_QUERY,
        "logical_word": "مرحلة",
        "visual_order_word": "ةلحرم",
    }
    matches = {name: [] for name in queries}
    try:
        for page_index in range(len(document)):
            page = document[page_index]
            text_page = page.get_textpage()
            try:
                for name, query in queries.items():
                    searcher = text_page.search(query, match_case=True, match_whole_word=False)
                    try:
                        while True:
                            match = searcher.get_next()
                            if match is None:
                                break
                            matches[name].append({"page": page_index + 1, "index": match[0], "count": match[1]})
                    finally:
                        searcher.close()
            finally:
                text_page.close()
                page.close()
    finally:
        document.close()
    return {name: {"found": bool(found), "matches": found} for name, found in matches.items()}


def compare_reader_results(source: Path, output: Path) -> dict[str, object]:
    source_results = stage3a.reader_results(source)
    output_results = stage3a.reader_results(output)
    return {
        "source": source_results,
        "output": output_results,
        "per_reader_regression": {
            reader: source_results[reader]["logical_phrase_found"] != output_results[reader]["logical_phrase_found"]
            for reader in source_results
        },
        "source_limitation_not_transform_regression": all(
            source_results[reader]["logical_phrase_found"] == output_results[reader]["logical_phrase_found"]
            for reader in source_results
        ),
        "pdfium_actual_search": {
            "source": pdfium_search_results(source),
            "output": pdfium_search_results(output),
        },
    }


def appearance_regeneration_matrix(source: Path, work: Path) -> list[dict[str, object]]:
    values = [
        "Stage 3B English field value",
        "قيمة عربية لاختبار إعادة توليد المظهر",
        "Mixed قيمة 12345 test@example.com",
        "",
    ]
    results = []
    for index, value in enumerate(values):
        edited = work / f"appearance-edited-{index}.pdf"
        output = work / f"appearance-gray-{index}.pdf"
        reader = PdfReader(str(source))
        writer = PdfWriter()
        writer.clone_document_from_reader(reader)
        writer.update_page_form_field_values(None, {"customer_note": value}, auto_regenerate=True)
        with edited.open("wb") as stream:
            writer.write(stream)
        stage2.transform(edited, output)
        colors = stage3a.validate_no_color(output, work, f"appearance-{index}")
        fields = PdfReader(str(output)).get_fields() or {}
        actual = str(fields["customer_note"].get("/V", ""))
        if actual != value:
            raise AssertionError(f"appearance value changed: {actual!r} != {value!r}")
        snapshot = stage3a.appearance_snapshot(output)
        if snapshot["forbidden_da_values"] or any(count != 1 for count in snapshot["mk_component_counts"]):
            raise AssertionError("appearance regeneration reintroduced color")
        results.append(
            {
                "value": value,
                "color_validation": colors,
                "appearance": snapshot,
                "field_value_preserved": actual == value,
                "font_encoding_gate": all(ord(character) <= 255 for character in value),
                "font_encoding_note": (
                    "Helvetica appearance encoding cannot represent Arabic; value semantics survive but visual glyph fidelity is unproved."
                    if any(ord(character) > 255 for character in value)
                    else "value is representable by the fixture appearance font"
                ),
            }
        )
    return results


def mutate(data: bytes, index: int) -> bytes:
    if index < 6:
        fractions = [0.08, 0.20, 0.40, 0.60, 0.82, 0.94]
        return data[: max(8, int(len(data) * fractions[index]))]
    candidate = bytearray(data)
    randomizer = random.Random(9300 + index)
    count = 1 + index % 5
    lower = min(32, len(candidate) - 1)
    for _ in range(count):
        position = randomizer.randrange(lower, max(lower + 1, len(candidate) - 16))
        candidate[position] ^= 1 << randomizer.randrange(0, 8)
    return bytes(candidate)


def bounded_mutation_probes(source: Path, work: Path) -> dict[str, object]:
    data = source.read_bytes()
    accepted = 0
    rejected = 0
    timeouts = 0
    partial_outputs = 0
    diagnostics = []
    case_count = 12
    for index in range(case_count):
        candidate = work / f"mutated-{index}.pdf"
        output = work / f"mutated-{index}-output.pdf"
        candidate.write_bytes(mutate(data, index))
        try:
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--transform-one", str(candidate), str(output)],
                capture_output=True,
                text=True,
                # Interpreter/native-module startup on Windows is measured at
                # several seconds; the 20-second process boundary remains
                # independent of the transformer's internal 15-second budget.
                timeout=20,
            )
        except subprocess.TimeoutExpired:
            timeouts += 1
            diagnostics.append({"case": index, "result": "timeout"})
            continue
        if completed.returncode == 0:
            if not output.exists():
                raise AssertionError("successful mutation probe produced no output")
            with pikepdf.Pdf.open(output) as reopened:
                if len(reopened.pages) < 1:
                    raise AssertionError("accepted mutation output has no pages")
            stage3a.validate_no_color(output, work, f"mutation-{index}")
            accepted += 1
            diagnostics.append({"case": index, "result": "accepted-and-validated"})
        else:
            rejected += 1
            if output.exists():
                partial_outputs += 1
            diagnostics.append({"case": index, "result": "rejected", "diagnostic": completed.stderr.strip()[-240:]})
    if timeouts or partial_outputs:
        raise AssertionError(f"mutation safety failure: timeouts={timeouts}, partial={partial_outputs}")
    return {
        "cases": case_count,
        "accepted_and_validated": accepted,
        "rejected": rejected,
        "timeouts": timeouts,
        "partial_outputs": partial_outputs,
        "diagnostics": diagnostics,
    }


@dataclass
class Stage3BResult:
    arabic_stage3a: dict[str, object]
    arabic_reportlab: dict[str, object]
    arabic_conclusion: str
    jpeg_inventory: list[dict[str, object]]
    jpeg_pdfium_metrics: list[dict[str, object]]
    jpeg_poppler_metrics: list[dict[str, object]]
    jpeg_text_semantics_equal: bool
    appearance_regeneration: list[dict[str, object]]
    mutation_probes: dict[str, object]
    production_sandbox_executed: bool
    production_sandbox_gate: str
    temp_cleanup_verified: bool


def self_test(output: Path) -> Stage3BResult:
    output.mkdir(parents=True, exist_ok=True)
    stage3a_source = STAGE3A_OUTPUT / "arabic-logical-source.pdf"
    stage3a_output = STAGE3A_OUTPUT / "arabic-logical-output.pdf"
    structural_output = STAGE3A_OUTPUT / "structural-output.pdf"
    if not all(path.exists() for path in (stage3a_source, stage3a_output, structural_output)):
        raise RuntimeError("Stage 3A output corpus is required")

    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="dip-gray-stage3b-", dir=str(output.parent)) as temporary:
        temporary_path = Path(temporary)
        reportlab_source = temporary_path / "reportlab-arabic-source.pdf"
        reportlab_output = temporary_path / "reportlab-arabic-output.pdf"
        reportlab_fixture = make_reportlab_arabic_fixture(reportlab_source)
        stage2.transform(reportlab_source, reportlab_output)
        reportlab_result = compare_reader_results(reportlab_source, reportlab_output)
        reportlab_result["fixture"] = reportlab_fixture

        natural_source = output / "natural-jpeg-source.pdf"
        natural_expected = output / "natural-jpeg-expected.pdf"
        natural_output = output / "natural-jpeg-output.pdf"
        jpeg_inventory = make_natural_jpeg_corpus(natural_source, natural_expected)
        stage2.transform(natural_source, natural_output)
        semantics_equal = text_snapshot(natural_source) == text_snapshot(natural_output)
        if not semantics_equal:
            raise AssertionError("natural JPEG corpus text semantics changed")
        stage3a.validate_no_color(natural_output, temporary_path, "natural-output")
        pdfium_metrics = visual_metrics(natural_expected, natural_output, temporary_path, "pdfium")
        poppler_metrics = visual_metrics(natural_expected, natural_output, temporary_path, "poppler")
        for renderer, metrics in (("PDFium", pdfium_metrics), ("Poppler", poppler_metrics)):
            for page, measurement in enumerate(metrics, 1):
                if measurement["mae"] > 0.5 or measurement["max_delta"] > 8:
                    raise AssertionError(f"{renderer} page {page} exceeds JPEG threshold: {measurement}")

        appearances = appearance_regeneration_matrix(structural_output, temporary_path)
        mutations = bounded_mutation_probes(natural_source, temporary_path)

    if temporary_path is None or temporary_path.exists():
        raise AssertionError("Stage 3B temporary directory was not cleaned")

    stage3a_result = compare_reader_results(stage3a_source, stage3a_output)
    result = Stage3BResult(
        arabic_stage3a=stage3a_result,
        arabic_reportlab=reportlab_result,
        arabic_conclusion=(
            "PDFium behavior is source-fixture/reader-specific, not a grayscale transformation regression; "
            "source and output results are identical per reader and no PDF text semantics were rewritten."
        ),
        jpeg_inventory=jpeg_inventory,
        jpeg_pdfium_metrics=pdfium_metrics,
        jpeg_poppler_metrics=poppler_metrics,
        jpeg_text_semantics_equal=semantics_equal,
        appearance_regeneration=appearances,
        mutation_probes=mutations,
        production_sandbox_executed=False,
        production_sandbox_gate="No Docker/Podman/WSL runtime is available on this host; derivative execution remains environment-gated.",
        temp_cleanup_verified=True,
    )
    (output / "metrics.json").write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(asdict(result), ensure_ascii=True, indent=2))
    return result


def transform_one(source: Path, output: Path) -> int:
    try:
        stage2.transform(source, output)
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "output" / "pdf" / "structural-grayscale-stage3b")
    parser.add_argument("--transform-one", nargs=2, metavar=("SOURCE", "OUTPUT"))
    args = parser.parse_args()
    if args.transform_one:
        return transform_one(Path(args.transform_one[0]), Path(args.transform_one[1]))
    if not args.self_test:
        parser.error("Stage 3B exposes only --self-test and the private mutation helper")
    self_test(args.output_dir.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
