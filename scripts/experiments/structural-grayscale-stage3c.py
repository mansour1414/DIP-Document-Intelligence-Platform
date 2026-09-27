#!/usr/bin/env python3
"""Isolated Linux-sandbox gate for the DIP structural grayscale PoC.

This is QA-only orchestration. It runs the bounded Stage 2, 3A and 3B
experiments, adds Unicode-capable widget and mutation probes, and publishes
sanitized JSON evidence. It is not a production converter.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pikepdf
from pypdf import PdfReader
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from structural_grayscale_evidence import (
    print_sanitized_summary,
    sanitize_json_file,
    write_sanitized_json,
)


ROOT = Path(__file__).resolve().parents[2]
STAGE3B_PATH = Path(__file__).with_name("structural-grayscale-stage3b.py")
FONT_CANDIDATES = (
    Path("/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf"),
    Path("/usr/share/fonts/opentype/noto/NotoSansArabic-Regular.ttf"),
    Path(r"C:\Windows\Fonts\arial.ttf"),
)


def load_stage3b():
    spec = importlib.util.spec_from_file_location("dip_structural_gray_stage3b_stage3c", STAGE3B_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Stage 3B implementation")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


stage3b = load_stage3b()
stage3a = stage3b.stage3a
stage2 = stage3b.stage2


def locate_unicode_font() -> Path:
    for candidate in FONT_CANDIDATES:
        if candidate.exists():
            return candidate
    raise RuntimeError("the reviewed Unicode-capable Arabic fixture font is unavailable")


def make_appearance_pdf(
    path: Path, value: str, grayscale: bool, font_path: Path, fixture_name: str
) -> None:
    fixture_directory = os.environ.get("DIP_STAGE3C_WIDGET_FIXTURE_DIR")
    if fixture_directory:
        fixture = Path(fixture_directory) / fixture_name
        if not fixture.is_file():
            raise RuntimeError(f"independent widget fixture is missing: {fixture.name}")
        shutil.copyfile(fixture, path)
        return
    font_name = "Stage3CUnicode"
    if font_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
    document = canvas.Canvas(str(path), pagesize=(500, 70), invariant=1, pageCompression=0)
    if grayscale:
        document.setFillGray(stage2.rgb_gray((0.76, 0.10, 0.35)))
    else:
        document.setFillColorRGB(0.76, 0.10, 0.35)
    document.setFont(font_name, 16)
    direction = "rtl" if re.search(r"[\u0600-\u06ff]", value) else "ltr"
    document.drawString(12, 25, value, direction=direction, shaping=True)
    document.save()


def appearance_form(target: pikepdf.Pdf, appearance_pdf: Path) -> tuple[pikepdf.Stream, pikepdf.Dictionary, str]:
    with pikepdf.Pdf.open(appearance_pdf) as appearance:
        page = appearance.pages[0]
        source_resources = page.obj["/Resources"]
        if not source_resources.is_indirect:
            source_resources = appearance.make_indirect(source_resources)
        resources = target.copy_foreign(source_resources)
        contents = page.obj["/Contents"]
        streams = list(contents) if isinstance(contents, pikepdf.Array) else [contents]
        payload = b"\n".join(bytes(stream.read_bytes()) for stream in streams)
        form = target.make_stream(
            payload,
            pikepdf.Dictionary(
                Type=pikepdf.Name.XObject,
                Subtype=pikepdf.Name.Form,
                FormType=1,
                BBox=pikepdf.Array([0, 0, 500, 70]),
                Resources=resources,
            ),
        )
        fonts = resources.get("/Font")
        if not fonts or not list(fonts.keys()):
            raise AssertionError("Unicode appearance did not embed a font resource")
        font_key = str(next(iter(fonts.keys())))
        return form, fonts, font_key


def make_widget_fixture(
    path: Path,
    values: dict[str, str],
    *,
    grayscale: bool,
    font_path: Path,
    fixture_variant: str,
) -> None:
    base = path.with_suffix(".base.pdf")
    document = canvas.Canvas(str(base), pagesize=A4, invariant=1, pageCompression=0)
    document.setFillGray(0.1)
    document.setFont("Helvetica-Bold", 14)
    document.drawString(48, A4[1] - 48, "DIP Stage 3C Unicode widget fixture")
    document.save()
    appearance_paths: list[Path] = []
    try:
        with pikepdf.Pdf.open(base) as pdf:
            page = pdf.pages[0]
            fields = pikepdf.Array()
            annotations = pikepdf.Array(page.obj.get("/Annots", []))
            default_fonts = pikepdf.Dictionary()
            default_font_key = None
            for index, (name, value) in enumerate(values.items()):
                appearance_path = path.with_name(f"{path.stem}-{index}.appearance.pdf")
                appearance_paths.append(appearance_path)
                make_appearance_pdf(
                    appearance_path,
                    value,
                    grayscale,
                    font_path,
                    f"{fixture_variant}-{index}.pdf",
                )
                form, fonts, font_key = appearance_form(pdf, appearance_path)
                for key, font in fonts.items():
                    default_fonts[key] = font
                default_font_key = default_font_key or font_key
                y = 610 - index * 120
                color_operator = "0.331016 g" if grayscale else "0.760000 0.100000 0.350000 rg"
                mk_background = pikepdf.Array([0.65]) if grayscale else pikepdf.Array([0.10, 0.62, 0.83])
                mk_border = pikepdf.Array([0.25]) if grayscale else pikepdf.Array([0.82, 0.12, 0.24])
                field = pikepdf.Dictionary(
                    Type=pikepdf.Name.Annot,
                    Subtype=pikepdf.Name.Widget,
                    Rect=pikepdf.Array([48, y, 548, y + 70]),
                    F=4,
                    FT=pikepdf.Name.Tx,
                    T=pikepdf.String(name),
                    V=pikepdf.String(value),
                    DA=pikepdf.String(f"{font_key} 16 Tf {color_operator}"),
                    MK=pikepdf.Dictionary(BG=mk_background, BC=mk_border),
                    AP=pikepdf.Dictionary(N=form, R=form, D=form),
                    P=page.obj,
                )
                field_ref = pdf.make_indirect(field)
                fields.append(field_ref)
                annotations.append(field_ref)
            if default_font_key is None:
                raise AssertionError("fixture has no default font")
            page.obj["/Annots"] = annotations
            pdf.Root["/AcroForm"] = pdf.make_indirect(
                pikepdf.Dictionary(
                    Fields=fields,
                    DR=pikepdf.Dictionary(Font=default_fonts),
                    DA=pikepdf.String(f"{default_font_key} 16 Tf 0 g"),
                    NeedAppearances=False,
                )
            )
            pdf.save(path, deterministic_id=True, compress_streams=True)
    finally:
        base.unlink(missing_ok=True)
        for appearance_path in appearance_paths:
            appearance_path.unlink(missing_ok=True)


def edit_widget_fixture(
    source: Path,
    path: Path,
    values: dict[str, str],
    *,
    grayscale: bool,
    font_path: Path,
    fixture_variant: str,
) -> None:
    appearance_paths: list[Path] = []
    try:
        with pikepdf.Pdf.open(source) as pdf:
            widgets = [
                annotation
                for page in pdf.pages
                for annotation in page.obj.get("/Annots", [])
                if annotation.get("/Subtype") == pikepdf.Name.Widget
            ]
            if len(widgets) != len(values):
                raise AssertionError("widget edit fixture count changed")
            default_fonts = pdf.Root["/AcroForm"].get("/DR", {}).get("/Font", pikepdf.Dictionary())
            for index, (widget, (name, value)) in enumerate(zip(widgets, values.items(), strict=True)):
                if str(widget.get("/T", "")) != name:
                    raise AssertionError("widget edit fixture identity changed")
                appearance_path = path.with_name(f"{path.stem}-{index}.appearance.pdf")
                appearance_paths.append(appearance_path)
                make_appearance_pdf(
                    appearance_path,
                    value,
                    grayscale,
                    font_path,
                    f"{fixture_variant}-{index}.pdf",
                )
                form, fonts, font_key = appearance_form(pdf, appearance_path)
                for key, font in fonts.items():
                    default_fonts[key] = font
                color_operator = "0.331016 g" if grayscale else "0.760000 0.100000 0.350000 rg"
                widget["/V"] = pikepdf.String(value)
                widget["/DA"] = pikepdf.String(f"{font_key} 16 Tf {color_operator}")
                widget["/MK"] = pikepdf.Dictionary(
                    BG=pikepdf.Array([0.65]) if grayscale else pikepdf.Array([0.10, 0.62, 0.83]),
                    BC=pikepdf.Array([0.25]) if grayscale else pikepdf.Array([0.82, 0.12, 0.24]),
                )
                widget["/AP"] = pikepdf.Dictionary(N=form, R=form, D=form)
            pdf.Root["/AcroForm"]["/DR"]["/Font"] = default_fonts
            pdf.Root["/AcroForm"]["/NeedAppearances"] = False
            pdf.save(path, deterministic_id=True, compress_streams=True)
    finally:
        for appearance_path in appearance_paths:
            appearance_path.unlink(missing_ok=True)


def font_is_embedded_unicode(font: pikepdf.Object) -> bool:
    base_font = str(font.get("/BaseFont", ""))
    descendants = font.get("/DescendantFonts", [])
    descriptors = [font.get("/FontDescriptor")]
    descriptors.extend(descendant.get("/FontDescriptor") for descendant in descendants)
    embedded = any(
        descriptor is not None
        and any(descriptor.get(key) is not None for key in ("/FontFile", "/FontFile2", "/FontFile3"))
        for descriptor in descriptors
    )
    return embedded and ("NotoSansArabic" in base_font or "Arial" in base_font or bool(descendants))


def widget_snapshot(path: Path) -> dict[str, object]:
    reader_fields = PdfReader(str(path)).get_fields() or {}
    field_values = {name: str(field.get("/V", "")) for name, field in sorted(reader_fields.items())}
    field_types = {name: str(field.get("/FT", "")) for name, field in sorted(reader_fields.items())}
    states = {"N": 0, "R": 0, "D": 0}
    embedded_fonts = 0
    widget_count = 0
    widget_object_ids: list[str] = []
    with pikepdf.Pdf.open(path) as pdf:
        for page in pdf.pages:
            for annotation in page.obj.get("/Annots", []):
                if annotation.get("/Subtype") != pikepdf.Name.Widget:
                    continue
                widget_count += 1
                widget_object_ids.append(f"{annotation.objgen[0]} {annotation.objgen[1]}")
                for state in states:
                    appearance = annotation.get("/AP", {}).get(f"/{state}")
                    if isinstance(appearance, pikepdf.Stream):
                        states[state] += 1
                        resources = appearance.get("/Resources") or pikepdf.Dictionary()
                        for font in (resources.get("/Font") or pikepdf.Dictionary()).values():
                            if font_is_embedded_unicode(font):
                                embedded_fonts += 1
    return {
        "widget_count": widget_count,
        "field_values": field_values,
        "field_types": field_types,
        "widget_object_ids": widget_object_ids,
        "appearance_states": states,
        "embedded_unicode_font_references": embedded_fonts,
    }


def render_with_forms(path: Path, target: Path):
    document = stage3a.pdfium.PdfDocument(str(path))
    try:
        document.init_forms()
        image = document[0].render(scale=1.5, rev_byteorder=True, may_draw_forms=True).to_pil().convert("RGB")
        image.save(target)
        return image
    finally:
        document.close()


def validate_widget_no_color(path: Path, work: Path, label: str) -> dict[str, int]:
    image = render_with_forms(path, work / f"{label}.png")
    maximum, colored = stage2.chroma(image)
    residual = stage2.structural_grayscale_assertions(path)
    # Form text is RGB-subpixel antialiased by PDFium, so pixel chroma is a
    # diagnostic rather than a color-space assertion. Structural scanning and
    # comparison with an independently generated grayscale fixture are the
    # fail-closed checks.
    if residual:
        raise AssertionError(f"{label} contains residual widget color operators")
    return {"max_chroma": maximum, "colored_pixels": colored, "residual_color_operators": residual}


def unicode_widget_gate(work: Path) -> dict[str, object]:
    font_path = locate_unicode_font()
    original_values = {
        "arabic_note": "قيمة عربية قابلة للتحرير والبحث",
        "mixed_note": "DIP 3C قيمة مختلطة 12345 test@example.com",
    }
    edited_values = {
        "arabic_note": "تم تعديل القيمة العربية بأمان",
        "mixed_note": "Edited آمن 67890 grayscale@example.com",
    }
    source = work / "unicode-widget-source.pdf"
    expected = work / "unicode-widget-expected.pdf"
    output = work / "unicode-widget-output.pdf"
    edited_gray_input = work / "unicode-widget-edited-gray-input.pdf"
    edited_gray = work / "unicode-widget-edited-gray.pdf"
    edited_expected = work / "unicode-widget-edited-expected.pdf"
    edited_color = work / "unicode-widget-edited-color.pdf"
    edited_color_reprocessed = work / "unicode-widget-edited-color-reprocessed.pdf"

    make_widget_fixture(
        source, original_values, grayscale=False, font_path=font_path, fixture_variant="source"
    )
    make_widget_fixture(
        expected, original_values, grayscale=True, font_path=font_path, fixture_variant="expected"
    )
    stage2.transform(source, output)
    before = widget_snapshot(source)
    after = widget_snapshot(output)
    if before["field_values"] != after["field_values"] or before["widget_count"] != after["widget_count"]:
        raise AssertionError("Unicode widget identity/value semantics changed")
    if after["embedded_unicode_font_references"] < 6:
        raise AssertionError("Unicode widget appearances lost their embedded font")
    output_color = validate_widget_no_color(output, work, "stage3c-unicode-output")
    original_visual = stage3a.difference_metrics(
        render_with_forms(output, work / "unicode-output.png"),
        render_with_forms(expected, work / "unicode-expected.png"),
    )
    if original_visual["mae"] > 0.5 or original_visual["max_delta"] > 8:
        raise AssertionError(f"Unicode widget visual threshold exceeded: {original_visual}")

    edit_widget_fixture(
        output,
        edited_gray_input,
        edited_values,
        grayscale=True,
        font_path=font_path,
        fixture_variant="edited-gray",
    )
    make_widget_fixture(
        edited_expected,
        edited_values,
        grayscale=True,
        font_path=font_path,
        fixture_variant="edited-gray",
    )
    stage2.transform(edited_gray_input, edited_gray)
    gray_edit_snapshot = widget_snapshot(edited_gray)
    if gray_edit_snapshot["field_values"] != edited_values:
        raise AssertionError("Unicode-aware field edit did not persist canonical values")
    for identity_key in ("field_types", "widget_object_ids"):
        if gray_edit_snapshot[identity_key] != after[identity_key]:
            raise AssertionError(f"Unicode-aware field edit changed {identity_key}")
    gray_edit_color = validate_widget_no_color(edited_gray, work, "stage3c-unicode-edit-gray")
    gray_edit_visual = stage3a.difference_metrics(
        render_with_forms(edited_gray, work / "unicode-edit-gray.png"),
        render_with_forms(edited_expected, work / "unicode-edit-expected.png"),
    )

    edit_widget_fixture(
        output,
        edited_color,
        edited_values,
        grayscale=False,
        font_path=font_path,
        fixture_variant="edited-color",
    )
    colored_image = render_with_forms(edited_color, work / "stage3c-unicode-edit-colored.png")
    edited_expected_image = render_with_forms(
        edited_expected, work / "stage3c-unicode-edit-expected-colored-check.png"
    )
    colored_maximum, colored_pixels = stage2.chroma(colored_image)
    colored_difference = stage3a.difference_metrics(colored_image, edited_expected_image)
    colored_regeneration = {
        "max_chroma": colored_maximum,
        "colored_pixels": colored_pixels,
        "difference_from_grayscale_expected": colored_difference,
    }
    if colored_difference["max_delta"] <= 8 or colored_difference["mae"] <= 0.05:
        raise AssertionError("colored regeneration probe was not visually distinguishable from grayscale")
    stage2.transform(edited_color, edited_color_reprocessed)
    reprocessed_color = validate_widget_no_color(
        edited_color_reprocessed, work, "stage3c-unicode-edit-reprocessed"
    )
    reprocessed_snapshot = widget_snapshot(edited_color_reprocessed)
    if reprocessed_snapshot["field_values"] != edited_values:
        raise AssertionError("reprocessed Unicode field values changed")
    for identity_key in ("field_types", "widget_object_ids"):
        if reprocessed_snapshot[identity_key] != after[identity_key]:
            raise AssertionError(f"reprocessed Unicode field edit changed {identity_key}")
    reprocessed_visual = stage3a.difference_metrics(
        render_with_forms(edited_color_reprocessed, work / "unicode-edit-reprocessed.png"),
        edited_expected_image,
    )
    if reprocessed_visual["mae"] > 0.5 or reprocessed_visual["max_delta"] > 8:
        raise AssertionError(f"reprocessed Unicode widget visual threshold exceeded: {reprocessed_visual}")

    return {
        "font_path": str(font_path),
        "source_snapshot": before,
        "output_snapshot": after,
        "output_color": output_color,
        "output_visual": original_visual,
        "independent_grayscale_regeneration_reprocessed": {
            "snapshot": gray_edit_snapshot,
            "color": gray_edit_color,
            "visual": gray_edit_visual,
        },
        "colored_external_regeneration": {
            "before_reprocessing": colored_regeneration,
            "reprocessed_color": reprocessed_color,
            "reprocessed_visual": reprocessed_visual,
            "reprocessed_snapshot": reprocessed_snapshot,
            "policy": "external colored regeneration is not silently trusted; the whole document must be reprocessed or rejected",
        },
    }


def fuzz_mutation(data: bytes, index: int) -> bytes:
    if index < 8:
        fraction = (index + 1) / 10
        return data[: max(8, int(len(data) * fraction))]
    candidate = bytearray(data)
    randomizer = random.Random(33000 + index)
    for _ in range(1 + index % 9):
        position = randomizer.randrange(8, max(9, len(candidate) - 8))
        candidate[position] ^= 1 << randomizer.randrange(8)
    return bytes(candidate)


def bounded_fuzz_gate(source: Path, work: Path, case_count: int = 24) -> dict[str, object]:
    started = time.monotonic()
    accepted = rejected = timeouts = partial_outputs = 0
    diagnostics: list[dict[str, object]] = []
    data = source.read_bytes()
    with tempfile.TemporaryDirectory(prefix="dip-gray-stage3c-fuzz-", dir=str(work)) as temporary:
        fuzz_root = Path(temporary)
        for index in range(case_count):
            candidate = fuzz_root / f"case-{index}.pdf"
            output = fuzz_root / f"case-{index}-output.pdf"
            candidate.write_bytes(fuzz_mutation(data, index))
            try:
                completed = subprocess.run(
                    [sys.executable, str(STAGE3B_PATH), "--transform-one", str(candidate), str(output)],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
            except subprocess.TimeoutExpired:
                timeouts += 1
                if output.exists():
                    partial_outputs += 1
                output.unlink(missing_ok=True)
                diagnostics.append({"case": index, "result": "timeout-killed"})
                continue
            if completed.returncode == 0:
                if not output.exists():
                    raise AssertionError("accepted fuzz case produced no output")
                with pikepdf.Pdf.open(output) as reopened:
                    if not reopened.pages or reopened.check_pdf_syntax():
                        raise AssertionError("accepted fuzz output failed reopen/syntax validation")
                stage3a.validate_no_color(output, fuzz_root, f"fuzz-{index}")
                accepted += 1
                diagnostics.append({"case": index, "result": "accepted-and-validated"})
            else:
                rejected += 1
                if output.exists():
                    partial_outputs += 1
                    output.unlink(missing_ok=True)
                diagnostic = completed.stderr.strip().splitlines()[-1:] or ["safe rejection"]
                diagnostics.append({"case": index, "result": "rejected", "diagnostic": diagnostic[0][-180:]})
    if partial_outputs or accepted + rejected + timeouts != case_count:
        raise AssertionError(
            f"fuzz gate failed: cases={case_count}, accounted={accepted + rejected + timeouts}, "
            f"partial_outputs={partial_outputs}"
        )
    return {
        "cases": case_count,
        "accepted_and_validated": accepted,
        "rejected": rejected,
        "timeout_killed_safe_rejections": timeouts,
        "partial_outputs": partial_outputs,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "diagnostics": diagnostics,
    }


def run_stage3c(corpus_root: Path, artifact_dir: Path) -> dict[str, object]:
    expected_root = Path(os.environ.get("DIP_GRAYSCALE_CORPUS_ROOT", "")).resolve()
    if expected_root != corpus_root.resolve():
        raise RuntimeError("DIP_GRAYSCALE_CORPUS_ROOT must be set before Stage 3C starts")
    widget_fixture_value = os.environ.get("DIP_STAGE3C_WIDGET_FIXTURE_DIR")
    if not widget_fixture_value:
        raise RuntimeError("independent Chromium widget fixtures are required")
    widget_fixture_root = Path(widget_fixture_value)
    expected_widget_fixtures = {
        f"{variant}-{index}.pdf"
        for variant in ("source", "expected", "edited-gray", "edited-color")
        for index in range(2)
    }
    if {path.name for path in widget_fixture_root.glob("*.pdf")} != expected_widget_fixtures:
        raise RuntimeError("independent Chromium widget fixture set is incomplete or unexpected")
    corpus_root.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    stage2_dir = corpus_root / "structural-grayscale-stage2"
    stage3a_dir = corpus_root / "structural-grayscale-stage3a"
    stage3b_dir = corpus_root / "structural-grayscale-stage3b"
    stage2_result = stage2.self_test(stage2_dir)
    stage3a_result = stage3a.self_test(stage3a_dir)
    stage3b_result = stage3b.self_test(stage3b_dir)

    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="dip-gray-stage3c-", dir=str(corpus_root)) as temporary:
        temporary_path = Path(temporary)
        unicode_widgets = unicode_widget_gate(temporary_path)
        fuzz = bounded_fuzz_gate(stage3b_dir / "natural-jpeg-source.pdf", temporary_path)
    if temporary_path is None or temporary_path.exists():
        raise AssertionError("Stage 3C temporary directory was not cleaned")

    for source, name in (
        (stage2_dir / "metrics.json", "stage2-metrics.json"),
        (stage3a_dir / "metrics.json", "stage3a-metrics.json"),
        (stage3b_dir / "metrics.json", "stage3b-metrics.json"),
    ):
        sanitize_json_file(source, artifact_dir / name)

    result = {
        "scope": "isolated-stage3c-ci-gate-only",
        "production_adoption_approved": False,
        "prior_corpora": {
            "stage2_locales": len(stage2_result.corpus),
            "stage2_fail_closed_cases": len(stage2_result.fail_closed_cases),
            "stage3a_fail_closed_cases": len(stage3a_result.fail_closed_cases),
            "stage3b_mutation_cases": stage3b_result.mutation_probes["cases"],
        },
        "unicode_widgets": unicode_widgets,
        "bounded_fuzz": fuzz,
        "supported_scope_expanded": False,
        "unsupported": stage3a_result.unsupported,
        "temp_cleanup_verified": True,
    }
    write_sanitized_json(artifact_dir / "stage3c-metrics.json", result)
    print_sanitized_summary({
        "scope": result["scope"],
        "production_adoption_approved": False,
        "bounded_fuzz": {
            key: result["bounded_fuzz"][key]
            for key in (
                "cases",
                "accepted_and_validated",
                "rejected",
                "timeout_killed_safe_rejections",
                "partial_outputs",
            )
        },
        "temp_cleanup_verified": result["temp_cleanup_verified"],
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.self_test:
        parser.error("Stage 3C exposes only --self-test; it is not a production converter")
    run_stage3c(args.corpus_root.resolve(), args.artifact_dir.resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print_sanitized_summary({
            "operation": "stage3c-sandbox-gate",
            "status": "failed",
            "error_type": type(error).__name__,
        }, stream=sys.stderr)
        raise SystemExit(1) from None
