#!/usr/bin/env python3
"""Isolated Stage 3A capability-expansion PoC for structural grayscale.

This QA-only experiment extends Stage 2 at runtime. It is intentionally not a
production converter and is not imported by the application or worker. It uses
no MuPDF, PyMuPDF, Ghostscript, or page rasterization.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import sys
import tempfile
import unicodedata
from dataclasses import asdict, dataclass
from io import BytesIO
from pathlib import Path

import pikepdf
import pypdfium2 as pdfium
from PIL import Image, ImageChops, ImageCms, ImageStat
from pypdf import PdfReader, PdfWriter

from structural_grayscale_subprocess import run_checked


ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = Path(os.environ.get("DIP_GRAYSCALE_CORPUS_ROOT", ROOT / "output" / "pdf"))
STAGE2_PATH = Path(__file__).with_name("structural-grayscale-stage2.py")
BROWSER_HELPER = Path(__file__).with_name("structural-grayscale-stage3a-browser.mjs")
MAX_JPEG_BYTES = 2_000_000
MAX_ICC_BYTES = 1_000_000
REVIEWED_CMYK_ICC_SHA256 = "73e1ba37d2bad5bab2a964f40a9eed96209666efc067c3322626214bbef234a0"
REVIEWED_CMYK_ICC_SIZE = 8464
ARABIC_LOGICAL_TEXT = "مرحلة المحرك البنيوي الثالثة تحافظ على النص العربي القابل للبحث والنسخ."
ARABIC_PAGE_TEXT = (
    "اختبار الترتيب المنطقي للنص العربي\n"
    + ARABIC_LOGICAL_TEXT
    + "\nالرقم 12345، والبريد test@example.com، والعبارة الإنجليزية Stage 3A تبقى في مواضعها.\n"
    + "نص عربي مستقل مولد بواسطة Chromium للتحقق متعدد القارئات.\nرابط اختبار البنية"
)


def load_stage2():
    spec = importlib.util.spec_from_file_location("dip_structural_gray_stage2", STAGE2_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Stage 2 implementation")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


stage2 = load_stage2()
UnsupportedPdf = stage2.UnsupportedPdf
original_color_spec = stage2.color_spec


def reviewed_cmyk_icc_profile() -> Path:
    configured = os.environ.get("DIP_STAGE3A_CMYK_ICC_PROFILE")
    path = (
        Path(configured)
        if configured
        else ROOT / "node_modules" / "pdfjs-dist" / "iccs" / "CGATS001Compat-v2-micro.icc"
    )
    try:
        data = path.read_bytes()
    except FileNotFoundError as error:
        raise RuntimeError("reviewed CMYK ICC fixture profile is unavailable") from error
    if len(data) != REVIEWED_CMYK_ICC_SIZE:
        raise RuntimeError("reviewed CMYK ICC fixture profile size is invalid")
    if hashlib.sha256(data).hexdigest() != REVIEWED_CMYK_ICC_SHA256:
        raise RuntimeError("reviewed CMYK ICC fixture profile checksum is invalid")
    if data[0:4] != len(data).to_bytes(4, "big") or data[36:40] != b"acsp":
        raise RuntimeError("reviewed CMYK ICC fixture profile header is invalid")
    if data[12:16] != b"scnr" or data[16:20] != b"CMYK" or data[20:24] != b"Lab ":
        raise RuntimeError("reviewed CMYK ICC fixture profile is not the approved CMYK input profile")
    try:
        cms_profile = ImageCms.ImageCmsProfile(BytesIO(data)).profile
    except Exception as error:
        raise RuntimeError("reviewed CMYK ICC fixture profile is not LittleCMS-compatible") from error
    if cms_profile.xcolor_space != "CMYK" or cms_profile.connection_space != "Lab ":
        raise RuntimeError("reviewed CMYK ICC fixture profile reports incompatible color spaces")
    return path


def lab_to_gray(values: tuple[float, ...], white: tuple[float, float, float], ranges: tuple[float, float, float, float]) -> float:
    if len(values) != 3:
        raise UnsupportedPdf("Lab requires three components")
    lightness = max(0.0, min(100.0, values[0]))
    a_star = max(ranges[0], min(ranges[1], values[1]))
    b_star = max(ranges[2], min(ranges[3], values[2]))
    fy = (lightness + 16.0) / 116.0
    fx = fy + a_star / 500.0
    fz = fy - b_star / 200.0

    delta = 6.0 / 29.0

    def inverse(value: float) -> float:
        return value**3 if value > delta else 3 * delta**2 * (value - 4.0 / 29.0)

    x, y, z = white[0] * inverse(fx), white[1] * inverse(fy), white[2] * inverse(fz)
    # Bradford D50-to-D65 adaptation. PDF Lab fixtures use D50.
    xd = 0.9555766 * x - 0.0230393 * y + 0.0631636 * z
    yd = -0.0282895 * x + 1.0099416 * y + 0.0210077 * z
    zd = 0.0122982 * x - 0.0204830 * y + 1.3299098 * z
    return stage2.rgb_gray(stage2.xyz_d65_to_srgb((xd, yd, zd)))


def reference_rgb_gray(red: int, green: int, blue: int) -> int:
    """Independent fixture-side implementation of the approved sRGB policy."""
    def linear(component: int) -> float:
        value = component / 255.0
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    luminance = 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
    encoded = 12.92 * luminance if luminance <= 0.0031308 else 1.055 * luminance ** (1 / 2.4) - 0.055
    return round(max(0.0, min(1.0, encoded)) * 255)


def reference_profile_gray(mode: str, samples: tuple[int, ...], source_profile: bytes) -> float:
    image = Image.new(mode, (1, 1), samples)
    converted = ImageCms.profileToProfile(
        image,
        ImageCms.ImageCmsProfile(BytesIO(source_profile)),
        ImageCms.createProfile("sRGB"),
        outputMode="RGB",
        renderingIntent=0,
    )
    red, green, blue = converted.getpixel((0, 0))
    return reference_rgb_gray(red, green, blue) / 255.0


def stage3_color_spec(value: pikepdf.Object, resources: pikepdf.Object | None = None):
    if isinstance(value, pikepdf.Array) and len(value) >= 2:
        family = str(value[0])
        if family == "/Lab":
            dictionary = value[1]
            white_values = stage2.number_array(dictionary.get("/WhitePoint"), 3, [0.9642, 1.0, 0.8249])
            white = tuple(white_values)
            if abs(white[1] - 1.0) > 0.0001 or min(white) <= 0:
                raise UnsupportedPdf("invalid Lab white point")
            ranges = tuple(stage2.number_array(dictionary.get("/Range"), 4, [-100.0, 100.0, -100.0, 100.0]))
            if ranges[0] >= ranges[1] or ranges[2] >= ranges[3]:
                raise UnsupportedPdf("invalid Lab range")
            return stage2.ColorSpec("/Lab", 3, lambda operands: lab_to_gray(operands, white, ranges))
        if family == "/Separation":
            if len(value) != 4:
                raise UnsupportedPdf("malformed Separation color space")
            alternate = stage3_color_spec(value[2], resources)
            function = value[3]
            if alternate.pattern or not hasattr(function, "get") or int(function.get("/FunctionType", 0)) != 2:
                raise UnsupportedPdf("Separation requires a Type 2 tint transform")
            domain = tuple(float(item) for item in function.get("/Domain", [0.0, 1.0]))
            if domain != (0.0, 1.0):
                raise UnsupportedPdf("unsupported Separation domain")
            c0 = tuple(float(item) for item in function.get("/C0", [0.0] * alternate.components))
            c1 = tuple(float(item) for item in function.get("/C1", [1.0] * alternate.components))
            exponent = float(function.get("/N", 1.0))
            if len(c0) != alternate.components or len(c1) != alternate.components or not math.isfinite(exponent) or exponent <= 0:
                raise UnsupportedPdf("invalid Separation tint transform")

            def convert(operands: tuple[float, ...]) -> float:
                tint = stage2.clamp01(operands[0]) ** exponent
                mapped = tuple(start + tint * (end - start) for start, end in zip(c0, c1))
                return alternate.convert(mapped)

            return stage2.ColorSpec("/Separation", 1, convert)
        if family == "/DeviceN":
            raise UnsupportedPdf("DeviceN remains unsupported in Stage 3A")
    return original_color_spec(value, resources)


def filter_names(stream: pikepdf.Stream) -> list[str]:
    filters = stream.get("/Filter")
    if filters is None:
        return []
    if isinstance(filters, pikepdf.Name):
        return [str(filters)]
    return [str(item) for item in filters]


def image_to_srgb(image: Image.Image) -> Image.Image:
    profile = image.info.get("icc_profile")
    if image.mode == "CMYK" and not profile:
        raise UnsupportedPdf("unprofiled CMYK images remain unsupported")
    if profile:
        if len(profile) > MAX_ICC_BYTES:
            raise UnsupportedPdf("image ICC profile byte limit exceeded")
        try:
            return ImageCms.profileToProfile(
                image,
                ImageCms.ImageCmsProfile(BytesIO(profile)),
                ImageCms.createProfile("sRGB"),
                outputMode="RGB",
                renderingIntent=0,
            )
        except Exception as error:
            raise UnsupportedPdf("image ICC transform failed") from error
    if image.mode not in {"RGB", "RGBA", "L", "LA"}:
        raise UnsupportedPdf(f"unsupported unprofiled image mode {image.mode}")
    return image.convert("RGB")


def stage3_image_to_gray(stream: pikepdf.Stream, stats, budget) -> None:
    names = filter_names(stream)
    if names not in ([], ["/FlateDecode"], ["/DCTDecode"]):
        raise UnsupportedPdf(f"unsupported image filter chain: {names}")
    if names != ["/DCTDecode"]:
        return stage2_original_image_to_gray(stream, stats, budget)
    if bool(stream.get("/ImageMask", False)):
        return
    width, height = int(stream.get("/Width", 0)), int(stream.get("/Height", 0))
    if width <= 0 or height <= 0 or width * height > stage2.MAX_IMAGE_PIXELS:
        raise UnsupportedPdf("JPEG dimensions exceed the Stage 3A limit")
    raw_jpeg = bytes(stream.read_raw_bytes())
    if not raw_jpeg.startswith(b"\xff\xd8") or len(raw_jpeg) > MAX_JPEG_BYTES:
        raise UnsupportedPdf("invalid or oversized JPEG stream")
    if stream.get("/Mask") is not None:
        raise UnsupportedPdf("color-key and explicit JPEG masks are unsupported")
    color_space = stream.get("/ColorSpace")
    if str(color_space) == "/DeviceCMYK":
        raise UnsupportedPdf("unprofiled CMYK JPEG images remain unsupported")
    if isinstance(color_space, pikepdf.Array) and str(color_space[0]) != "/ICCBased":
        raise UnsupportedPdf("unsupported JPEG color space")
    if isinstance(color_space, pikepdf.Name) and str(color_space) not in {"/DeviceRGB", "/DeviceGray"}:
        raise UnsupportedPdf("unsupported JPEG color space")
    soft_mask = stream.get("/SMask")
    if soft_mask is not None:
        if not isinstance(soft_mask, pikepdf.Stream) or str(soft_mask.get("/ColorSpace")) != "/DeviceGray":
            raise UnsupportedPdf("only DeviceGray JPEG soft masks are supported")
    try:
        image = pikepdf.PdfImage(stream).as_pil_image()
        image.load()
    except Exception as error:
        raise UnsupportedPdf("JPEG decoding failed") from error
    budget.images += 1
    if budget.images > stage2.MAX_IMAGES:
        raise UnsupportedPdf("image count limit exceeded")
    budget.add_decoded(width * height * max(1, len(image.getbands())))
    if image.mode == "L":
        gray = image
    else:
        rgb = image_to_srgb(image)
        gray = Image.new("L", rgb.size)
        gray.putdata([
            round(stage2.rgb_gray(tuple(channel / 255.0 for channel in pixel)) * 255)
            for pixel in rgb.get_flattened_data()
        ])
    encoded = BytesIO()
    gray.save(encoded, format="JPEG", quality=95, subsampling=0, optimize=True)
    payload = encoded.getvalue()
    if len(payload) > MAX_JPEG_BYTES:
        raise UnsupportedPdf("grayscale JPEG output exceeds limit")
    stream.write(payload, filter=pikepdf.Name.DCTDecode)
    stream["/ColorSpace"] = pikepdf.Name.DeviceGray
    stream["/BitsPerComponent"] = 8
    for key in ("/Decode", "/DecodeParms"):
        if key in stream:
            del stream[key]
    stats.image_xobjects += 1


stage2_original_image_to_gray = stage2.image_to_gray
stage2.color_spec = stage3_color_spec
stage2.image_to_gray = stage3_image_to_gray


class Stage3Transformer(stage2.StructuralTransformer):
    def transform_shading(self, shading: pikepdf.Object, resources: pikepdf.Object, depth: int) -> None:
        shading_type = int(shading.get("/ShadingType", 0))
        if shading_type not in {2, 3}:
            raise UnsupportedPdf("Stage 3A supports axial and radial shadings only")
        spec = stage3_color_spec(shading.get("/ColorSpace"), resources)
        function = shading.get("/Function")
        if isinstance(function, pikepdf.Array) or not hasattr(function, "get") or int(function.get("/FunctionType", 0)) != 2:
            raise UnsupportedPdf("Stage 3A shading requires one Type 2 function")
        function["/C0"] = stage2.transform_color_array(
            function.get("/C0", pikepdf.Array([0.0] * spec.components)), spec
        )
        function["/C1"] = stage2.transform_color_array(
            function.get("/C1", pikepdf.Array([1.0] * spec.components)), spec
        )
        shading["/ColorSpace"] = pikepdf.Name.DeviceGray
        self.stats.shadings += 1


stage2.StructuralTransformer = Stage3Transformer


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).replace("\u00a0", " ").split())


def canonical_search_text(value: str) -> str:
    variants = str.maketrans({"ی": "ي", "ى": "ي", "ک": "ك", "ھ": "ه", "ۀ": "ه"})
    normalized = unicodedata.normalize("NFKC", value).translate(variants)
    return "".join(character for character in normalized if not character.isspace())


def pdfjs_text(path: Path) -> str:
    result = run_checked(
        ["node", str(BROWSER_HELPER), "extract", str(path)],
        operation="pdfjs-text-extraction",
        cwd=ROOT,
    )
    return json.loads(result.stdout)["text"]


def pdfium_text(path: Path) -> str:
    document = pdfium.PdfDocument(str(path))
    pages: list[str] = []
    try:
        for page in document:
            text_page = page.get_textpage()
            try:
                pages.append(text_page.get_text_range())
            finally:
                text_page.close()
    finally:
        document.close()
    return "\n".join(pages)


def pypdf_text(path: Path) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)


def reader_results(path: Path) -> dict[str, dict[str, object]]:
    readers = {"pypdf": pypdf_text(path), "pdfium": pdfium_text(path), "pdfjs": pdfjs_text(path)}
    return {
        name: {
            "logical_phrase_found": canonical_search_text(ARABIC_LOGICAL_TEXT) in canonical_search_text(text),
            "text": normalize_text(text),
        }
        for name, text in readers.items()
    }


def add_logical_actual_text(path: Path) -> None:
    """Add an independently encoded logical-order invisible text layer.

    Chromium's Windows font subset emits visual-order presentation glyphs.
    The fixture therefore adds a Type3 text layer whose ToUnicode CMap maps
    explicit one-byte codes to the original Unicode sequence. Its glyphs are
    empty and use text render mode 3, so it changes search/copy semantics but
    cannot alter the visual golden page.
    """
    characters = list(dict.fromkeys(ARABIC_PAGE_TEXT.replace("\n", "")))
    if len(characters) > 254:
        raise AssertionError("logical fixture exceeds one-byte CMap capacity")
    codes = {character: index + 1 for index, character in enumerate(characters)}
    differences = pikepdf.Array([1] + [pikepdf.Name(f"/g{index + 1}") for index in range(len(characters))])
    cmap_lines = [
        b"/CIDInit /ProcSet findresource begin",
        b"12 dict begin begincmap",
        b"/CIDSystemInfo << /Registry (DIP) /Ordering (Stage3A) /Supplement 0 >> def",
        b"/CMapName /DIPStage3ALogical def /CMapType 2 def",
        b"1 begincodespacerange <00> <FF> endcodespacerange",
        f"{len(characters)} beginbfchar".encode("ascii"),
    ]
    for character, code in codes.items():
        target = character.encode("utf-16-be").hex().upper()
        cmap_lines.append(f"<{code:02X}> <{target}>".encode("ascii"))
    cmap_lines.extend([b"endbfchar", b"endcmap CMapName currentdict /CMap defineresource pop end end"])
    with pikepdf.Pdf.open(path, allow_overwriting_input=True) as pdf:
        if len(pdf.pages) != 1:
            raise AssertionError("Arabic fixture must have one page")
        page = pdf.pages[0]
        page.contents_coalesce()
        contents = page.obj["/Contents"]
        original = bytes(contents.read_bytes())
        char_procs = pikepdf.Dictionary()
        for index in range(len(characters)):
            char_procs[f"/g{index + 1}"] = pdf.make_stream(b"")
        logical_font = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name.Font,
                Subtype=pikepdf.Name.Type3,
                FontBBox=pikepdf.Array([0, 0, 0, 0]),
                FontMatrix=pikepdf.Array([0.001, 0, 0, 0.001, 0, 0]),
                CharProcs=char_procs,
                Encoding=pikepdf.Dictionary(Type=pikepdf.Name.Encoding, Differences=differences),
                FirstChar=1,
                LastChar=len(characters),
                Widths=pikepdf.Array([0] * len(characters)),
                Resources=pikepdf.Dictionary(),
                ToUnicode=pdf.make_stream(b"\n".join(cmap_lines) + b"\n"),
            )
        )
        if page.Resources.get("/Font") is None:
            page.Resources["/Font"] = pikepdf.Dictionary()
        page.Resources.Font["/DIPLogical"] = logical_font
        logical_content = bytearray(b"\nBT /DIPLogical 1 Tf 3 Tr 0 0 Td\n")
        for line in ARABIC_PAGE_TEXT.splitlines():
            encoded = bytes(codes[character] for character in line).hex().upper().encode("ascii")
            logical_content.extend(b"<" + encoded + b"> Tj T*\n")
        logical_content.extend(b"ET\n")
        contents.write(original + bytes(logical_content))
        pdf.Root["/Lang"] = pikepdf.String("ar-SA")
        pdf.save(path)


def make_jpeg(rgb: bool, profile: bytes) -> bytes:
    image = Image.new("RGB" if rgb else "L", (48, 32))
    if rgb:
        image.putdata(
            [
                ((x * 5) % 256, (y * 8) % 256, ((x + y) * 4) % 256)
                for y in range(image.height)
                for x in range(image.width)
            ]
        )
    else:
        image.putdata(
            [
                reference_rgb_gray(x * 5 % 256, y * 8 % 256, (x + y) * 4 % 256)
                for y in range(image.height)
                for x in range(image.width)
            ]
        )
    output = BytesIO()
    image.save(output, format="JPEG", quality=95, subsampling=0, optimize=True, icc_profile=profile if rgb else None)
    return output.getvalue()


def augment_stage3_fixture(path: Path, grayscale: bool, cmyk_profile_path: Path) -> None:
    srgb = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    cmyk_profile = cmyk_profile_path.read_bytes()
    with pikepdf.Pdf.open(path, allow_overwriting_input=True) as pdf:
        page = pdf.pages[0]
        resources = page.Resources
        for key in ("/ColorSpace", "/XObject", "/Shading"):
            if resources.get(key) is None:
                resources[key] = pikepdf.Dictionary()

        jpeg = pdf.make_stream(
            make_jpeg(not grayscale, srgb),
            pikepdf.Dictionary(
                Type=pikepdf.Name.XObject,
                Subtype=pikepdf.Name.Image,
                Width=48,
                Height=32,
                BitsPerComponent=8,
                ColorSpace=pikepdf.Name.DeviceGray,
                Filter=pikepdf.Name.DCTDecode,
                Interpolate=True,
            ),
        )
        if not grayscale:
            profile = pdf.make_stream(srgb, pikepdf.Dictionary(N=3, Alternate=pikepdf.Name.DeviceRGB))
            jpeg["/ColorSpace"] = pikepdf.Array([pikepdf.Name.ICCBased, profile])
        resources.XObject["/JpegStage3"] = jpeg

        if grayscale:
            # Correct the Stage 2 expected fixture's provisional inline-image
            # bytes using the independently implemented sRGB policy. This is
            # intentionally fixture-only and does not modify the Stage 2 code.
            old_inline = bytes([65, 150, 40, 210])
            corrected_inline = bytes(
                [
                    reference_rgb_gray(255, 0, 0),
                    reference_rgb_gray(0, 255, 0),
                    reference_rgb_gray(0, 0, 255),
                    reference_rgb_gray(255, 255, 0),
                ]
            )
            for stream in page.obj["/Contents"]:
                decoded = bytes(stream.read_bytes())
                if old_inline in decoded:
                    stream.write(decoded.replace(old_inline, corrected_inline, 1))
            lab_profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("LAB", colorTemp=5000)).tobytes()
            lab_gray = reference_profile_gray(
                "LAB",
                (round(62.0 * 255 / 100), round(45.0 + 128), round(-35.0 + 128)),
                lab_profile,
            )
            spot_rgb = tuple(round(start + 0.75 * (end - start)) for start, end in zip((255, 255, 255), (217, 20, 46)))
            spot_gray = reference_rgb_gray(*spot_rgb) / 255.0
            cmyk_gray = reference_profile_gray("CMYK", (26, 178, 51, 38), cmyk_profile)
            extra = (
                b"q 120 0 0 80 40 340 cm /JpegStage3 Do Q\n"
                + f"{lab_gray:.6f} g 190 340 75 55 re f\n".encode("ascii")
                + f"{spot_gray:.6f} g 285 340 75 55 re f\n".encode("ascii")
                + f"{cmyk_gray:.6f} g 380 340 75 55 re f\n".encode("ascii")
            )
            shading_color = pikepdf.Name.DeviceGray
            c0 = pikepdf.Array([stage2.rgb_gray((1.0, 0.1, 0.2))])
            c1 = pikepdf.Array([stage2.rgb_gray((0.1, 0.3, 1.0))])
        else:
            lab = pikepdf.Array(
                [
                    pikepdf.Name.Lab,
                    pikepdf.Dictionary(
                        WhitePoint=pikepdf.Array([0.9642, 1.0, 0.8249]),
                        Range=pikepdf.Array([-100, 100, -100, 100]),
                    ),
                ]
            )
            spot = pikepdf.Array(
                [
                    pikepdf.Name.Separation,
                    pikepdf.Name.Stage3Spot,
                    pikepdf.Name.DeviceRGB,
                    pikepdf.Dictionary(
                        FunctionType=2,
                        Domain=pikepdf.Array([0, 1]),
                        C0=pikepdf.Array([1, 1, 1]),
                        C1=pikepdf.Array([0.85, 0.08, 0.18]),
                        N=1,
                    ),
                ]
            )
            cmyk_stream = pdf.make_stream(
                cmyk_profile,
                pikepdf.Dictionary(N=4, Alternate=pikepdf.Name.DeviceCMYK),
            )
            resources.ColorSpace["/Stage3Lab"] = lab
            resources.ColorSpace["/Stage3Spot"] = spot
            resources.ColorSpace["/Stage3CMYK"] = pikepdf.Array([pikepdf.Name.ICCBased, cmyk_stream])
            lab_gray = reference_profile_gray(
                "LAB",
                (round(62.0 * 255 / 100), round(45.0 + 128), round(-35.0 + 128)),
                ImageCms.ImageCmsProfile(ImageCms.createProfile("LAB", colorTemp=5000)).tobytes(),
            )
            spot_rgb = tuple(round(start + 0.75 * (end - start)) for start, end in zip((255, 255, 255), (217, 20, 46)))
            spot_gray = reference_rgb_gray(*spot_rgb) / 255.0
            cmyk_gray = reference_profile_gray("CMYK", (26, 178, 51, 38), cmyk_profile)
            extra = (
                b"q 120 0 0 80 40 340 cm /JpegStage3 Do Q\n"
                b"/Stage3Lab cs 62 45 -35 scn 190 340 75 55 re f\n"
                b"/Stage3Spot cs .75 scn 285 340 75 55 re f\n"
                b"/Stage3CMYK cs .1 .7 .2 .15 scn 380 340 75 55 re f\n"
            )
            # Store fixture reference values for independent expected generation.
            pdf.docinfo["/Stage3LabGray"] = f"{lab_gray:.6f}"
            pdf.docinfo["/Stage3SpotGray"] = f"{spot_gray:.6f}"
            pdf.docinfo["/Stage3CmykGray"] = f"{cmyk_gray:.6f}"
            shading_color = pikepdf.Name.DeviceRGB
            c0 = pikepdf.Array([1.0, 0.1, 0.2])
            c1 = pikepdf.Array([0.1, 0.3, 1.0])

        radial = pikepdf.Dictionary(
            ShadingType=3,
            ColorSpace=shading_color,
            Coords=pikepdf.Array([500, 375, 1, 500, 375, 55]),
            Function=pikepdf.Dictionary(
                FunctionType=2,
                Domain=pikepdf.Array([0, 1]),
                C0=c0,
                C1=c1,
                N=1,
            ),
            Extend=pikepdf.Array([True, True]),
        )
        resources.Shading["/Stage3Radial"] = radial
        extra += b"q 465 330 80 90 re W n /Stage3Radial sh Q\n"
        existing_contents = page.obj["/Contents"]
        streams = list(existing_contents) if isinstance(existing_contents, pikepdf.Array) else [existing_contents]
        page.obj["/Contents"] = pikepdf.Array([*streams, pdf.make_stream(extra)])
        pdf.docinfo["/Stage"] = "3A structural grayscale capability PoC"
        pdf.save(path)


def render(path: Path, target: Path, scale: float = 1.5) -> Image.Image:
    document = pdfium.PdfDocument(str(path))
    try:
        image = document[0].render(scale=scale, rev_byteorder=True).to_pil().convert("RGB")
        image.save(target)
        return image
    finally:
        document.close()


def difference_metrics(actual: Image.Image, expected: Image.Image) -> dict[str, object]:
    if actual.size != expected.size:
        raise AssertionError("render sizes differ")
    difference = ImageChops.difference(actual, expected)
    statistics = ImageStat.Stat(difference)
    extrema = difference.getextrema()
    changed = []
    edge_changed = 0
    width, height = actual.size
    actual_gray = actual.convert("L")
    expected_gray = expected.convert("L")
    for y in range(height):
        for x in range(width):
            if difference.getpixel((x, y)) != (0, 0, 0):
                changed.append((x, y))
                local = []
                for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
                    if 0 <= nx < width and 0 <= ny < height:
                        local.extend([actual_gray.getpixel((nx, ny)), expected_gray.getpixel((nx, ny))])
                center = [actual_gray.getpixel((x, y)), expected_gray.getpixel((x, y))]
                if local and max(local + center) - min(local + center) > 8:
                    edge_changed += 1
    bbox = None if not changed else [min(x for x, _ in changed), min(y for _, y in changed), max(x for x, _ in changed), max(y for _, y in changed)]
    return {
        "mae": round(sum(statistics.mean) / 3.0, 6),
        "max_delta": max(channel[1] for channel in extrema),
        "changed_pixels": len(changed),
        "changed_fraction": round(len(changed) / (width * height), 8),
        "edge_changed_fraction": round(edge_changed / len(changed), 6) if changed else 1.0,
        "bbox": bbox,
        "render_size": [width, height],
    }


def region_difference(actual: Image.Image, expected: Image.Image, box: tuple[int, int, int, int]) -> dict[str, object]:
    return difference_metrics(actual.crop(box), expected.crop(box))


def semantic_snapshot(path: Path) -> dict[str, object]:
    reader = PdfReader(str(path))
    fields = reader.get_fields() or {}
    links: list[str] = []
    for page in reader.pages:
        for reference in page.get("/Annots", []):
            annotation = reference.get_object()
            action = annotation.get("/A")
            if action and action.get("/URI"):
                links.append(str(action["/URI"]))
    return {
        "pages": len(reader.pages),
        "text": normalize_text("\n".join(page.extract_text() or "" for page in reader.pages)),
        "fields": {name: [str(field.get("/FT")), str(field.get("/V"))] for name, field in fields.items()},
        "links": links,
        "metadata": {str(key): str(value) for key, value in (reader.metadata or {}).items() if key in {"/Title", "/Author", "/Subject", "/Stage"}},
    }


def inspect_jpeg_output(path: Path) -> dict[str, object]:
    with pikepdf.Pdf.open(path) as pdf:
        images = [obj for obj in pdf.objects if isinstance(obj, pikepdf.Stream) and str(obj.get("/Subtype")) == "/Image"]
        jpeg = next(obj for obj in images if filter_names(obj) == ["/DCTDecode"])
        return {
            "filter": filter_names(jpeg),
            "color_space": str(jpeg.get("/ColorSpace")),
            "width": int(jpeg.get("/Width")),
            "height": int(jpeg.get("/Height")),
            "interpolate": bool(jpeg.get("/Interpolate", False)),
            "jpeg_magic": bytes(jpeg.read_raw_bytes()).startswith(b"\xff\xd8"),
        }


def edit_with_regeneration(source: Path, destination: Path) -> None:
    reader = PdfReader(str(source))
    writer = PdfWriter()
    writer.clone_document_from_reader(reader)
    writer.update_page_form_field_values(None, {"customer_note": "Stage 3A regenerated value"}, auto_regenerate=True)
    with destination.open("wb") as stream:
        writer.write(stream)


def appearance_snapshot(path: Path) -> dict[str, object]:
    counts = {"N": 0, "R": 0, "D": 0}
    mk_component_counts: list[int] = []
    da_values: list[str] = []
    with pikepdf.Pdf.open(path) as pdf:
        for page in pdf.pages:
            for annotation in page.obj.get("/Annots", []):
                if annotation.get("/Subtype") != pikepdf.Name.Widget:
                    continue
                appearance = annotation.get("/AP", {})
                for key in ("N", "R", "D"):
                    value = appearance.get("/" + key)
                    if isinstance(value, pikepdf.Stream):
                        counts[key] += 1
                    elif isinstance(value, pikepdf.Dictionary):
                        counts[key] += sum(isinstance(item, pikepdf.Stream) for item in value.values())
                mk = annotation.get("/MK", {})
                for key in ("/BG", "/BC"):
                    if mk.get(key) is not None:
                        mk_component_counts.append(len(mk[key]))
                if annotation.get("/DA") is not None:
                    da_values.append(str(annotation["/DA"]))
        acroform = pdf.Root.get("/AcroForm")
        if acroform and acroform.get("/DA") is not None:
            da_values.append(str(acroform["/DA"]))
    forbidden_da = [value for value in da_values if any(operator in value.split() for operator in ("rg", "RG", "k", "K"))]
    return {
        "appearance_states": counts,
        "appearance_entries": sum(counts.values()),
        "mk_component_counts": mk_component_counts,
        "da_values": da_values,
        "forbidden_da_values": forbidden_da,
    }


def validate_no_color(path: Path, work: Path, label: str) -> dict[str, int]:
    image = render(path, work / f"{label}.png")
    maximum, colored = stage2.chroma(image)
    residual = stage2.structural_grayscale_assertions(path)
    if maximum > 2 or colored or residual:
        raise AssertionError(f"{label} contains residual color")
    return {"max_chroma": maximum, "colored_pixels": colored, "residual_color_operators": residual}


def verify_fail_closed(source: Path, work: Path) -> dict[str, str]:
    def append_content(pdf: pikepdf.Pdf, page: pikepdf.Page, payload: bytes) -> None:
        current = page.obj["/Contents"]
        streams = list(current) if isinstance(current, pikepdf.Array) else [current]
        page.obj["/Contents"] = pikepdf.Array([*streams, pdf.make_stream(payload)])

    cases: list[tuple[str, Path]] = []
    with pikepdf.Pdf.open(source) as pdf:
        image = next(obj for obj in pdf.objects if isinstance(obj, pikepdf.Stream) and filter_names(obj) == ["/DCTDecode"])
        for name in ("JPXDecode", "JBIG2Decode", "CCITTFaxDecode"):
            clone = work / f"unsupported-{name}.pdf"
            image["/Filter"] = pikepdf.Name("/" + name)
            pdf.save(clone)
            cases.append((name, clone))
            image["/Filter"] = pikepdf.Name.DCTDecode
    with pikepdf.Pdf.open(source) as pdf:
        page = pdf.pages[0]
        page.Resources.ColorSpace["/DeviceNProbe"] = pikepdf.Array(
            [pikepdf.Name.DeviceN, pikepdf.Array([pikepdf.Name.Cyan, pikepdf.Name.Magenta]), pikepdf.Name.DeviceCMYK, pikepdf.Dictionary(FunctionType=4, Domain=pikepdf.Array([0, 1, 0, 1]), Range=pikepdf.Array([0, 1, 0, 1, 0, 1, 0, 1]))]
        )
        append_content(pdf, page, b"/DeviceNProbe cs .2 .5 scn 0 0 10 10 re f")
        candidate = work / "unsupported-DeviceN.pdf"
        pdf.save(candidate)
        cases.append(("DeviceN", candidate))
    with pikepdf.Pdf.open(source) as pdf:
        jpeg = next(obj for obj in pdf.objects if isinstance(obj, pikepdf.Stream) and filter_names(obj) == ["/DCTDecode"])
        jpeg["/ColorSpace"] = pikepdf.Name.DeviceCMYK
        candidate = work / "unsupported-unprofiled-cmyk.pdf"
        pdf.save(candidate)
        cases.append(("unprofiled-cmyk", candidate))
    with pikepdf.Pdf.open(source) as pdf:
        page = pdf.pages[0]
        form = page.Resources.XObject["/F1"]
        form.Resources.XObject["/CycleStage3"] = form
        form.write(bytes(form.read_bytes()) + b" /CycleStage3 Do")
        candidate = work / "cyclic-form.pdf"
        pdf.save(candidate)
        cases.append(("cyclic-form", candidate))
    with pikepdf.Pdf.open(source) as pdf:
        pdf.Root["/Stage3SignatureProbe"] = pikepdf.Dictionary(
            Type=pikepdf.Name.Sig,
            ByteRange=pikepdf.Array([0, 1, 2, 3]),
        )
        candidate = work / "signed.pdf"
        pdf.save(candidate)
        cases.append(("signed", candidate))
    with pikepdf.Pdf.open(source) as pdf:
        candidate = work / "encrypted.pdf"
        pdf.save(candidate, encryption=pikepdf.Encryption(owner="stage3-owner", user="stage3-user", R=6, aes=True))
        cases.append(("encrypted", candidate))
    malformed = work / "malformed.pdf"
    malformed.write_bytes(b"not-a-pdf")
    cases.append(("malformed", malformed))
    with pikepdf.Pdf.open(source) as pdf:
        page = pdf.pages[0]
        page.Resources.ColorSpace["/UnsupportedSpot"] = pikepdf.Array(
            [
                pikepdf.Name.Separation,
                pikepdf.Name.UnsupportedSpot,
                pikepdf.Name.DeviceRGB,
                pikepdf.Dictionary(
                    FunctionType=4,
                    Domain=pikepdf.Array([0, 1]),
                    Range=pikepdf.Array([0, 1, 0, 1, 0, 1]),
                ),
            ]
        )
        append_content(pdf, page, b"/UnsupportedSpot cs .5 scn 0 0 10 10 re f")
        candidate = work / "unsupported-tint-function.pdf"
        pdf.save(candidate)
        cases.append(("unsupported-tint-function", candidate))
    with pikepdf.Pdf.open(source) as pdf:
        jpeg = next(obj for obj in pdf.objects if isinstance(obj, pikepdf.Stream) and filter_names(obj) == ["/DCTDecode"])
        jpeg["/Width"] = 2000
        jpeg["/Height"] = 2000
        candidate = work / "oversized-image.pdf"
        pdf.save(candidate)
        cases.append(("oversized-image", candidate))

    rejected: dict[str, str] = {}
    for name, candidate in cases:
        destination = work / f"unexpected-{name}.pdf"
        try:
            stage2.transform(candidate, destination)
        except (UnsupportedPdf, pikepdf.PdfError, TimeoutError) as error:
            if destination.exists():
                raise AssertionError(f"{name} left a partial output")
            rejected[name] = f"{type(error).__name__}: {error}"
        else:
            raise AssertionError(f"{name} did not fail closed")
    return rejected


@dataclass
class Stage3Result:
    pikepdf_version: str
    libqpdf_version: str
    pillow_version: str
    lcms_version: str
    arabic_readers: dict[str, dict[str, dict[str, object]]]
    arabic_logical_order_gate: bool
    arabic_semantics_equal: bool
    arabic_visual: dict[str, object]
    structural_semantics_equal: bool
    structural_visual: dict[str, object]
    structural_visual_regions: dict[str, dict[str, object]]
    jpeg_output: dict[str, object]
    regenerated_appearance: dict[str, object]
    stage2_difference: dict[str, object]
    fail_closed_cases: dict[str, str]
    supported: list[str]
    unsupported: list[str]
    temp_cleanup_verified: bool


def self_test(output: Path) -> Stage3Result:
    output.mkdir(parents=True, exist_ok=True)
    cmyk_profile = reviewed_cmyk_icc_profile()
    temporary_path: Path | None = None
    with tempfile.TemporaryDirectory(prefix="dip-gray-stage3a-", dir=str(output.parent)) as temporary:
        temporary_path = Path(temporary)
        run_checked(
            ["node", str(BROWSER_HELPER), "generate", str(output)],
            operation="chromium-arabic-fixture-generation",
            cwd=ROOT,
        )
        arabic_source = output / "arabic-logical-source.pdf"
        arabic_expected = output / "arabic-logical-expected.pdf"
        add_logical_actual_text(arabic_source)
        add_logical_actual_text(arabic_expected)
        arabic_result = output / "arabic-logical-output.pdf"
        stage2.transform(arabic_source, arabic_result)

        readers = {
            "source": reader_results(arabic_source),
            "output": reader_results(arabic_result),
        }
        arabic_gate = all(
            reader["logical_phrase_found"]
            for document_result in readers.values()
            for reader in document_result.values()
        )
        arabic_semantics = semantic_snapshot(arabic_source) == semantic_snapshot(arabic_result)
        if not arabic_semantics:
            raise AssertionError("Arabic structural semantics changed")
        arabic_visual = difference_metrics(
            render(arabic_result, temporary_path / "arabic-output.png"),
            render(arabic_expected, temporary_path / "arabic-expected.png"),
        )
        validate_no_color(arabic_result, temporary_path, "arabic-no-color")

        structural_source = output / "structural-source.pdf"
        structural_expected = output / "structural-expected.pdf"
        structural_result = output / "structural-output.pdf"
        stage2.make_fixture(structural_source, "en", grayscale=False)
        stage2.make_fixture(structural_expected, "en", grayscale=True)
        augment_stage3_fixture(structural_source, False, cmyk_profile)
        augment_stage3_fixture(structural_expected, True, cmyk_profile)
        stage2.transform(structural_source, structural_result)

        source_semantics = semantic_snapshot(structural_source)
        result_semantics = semantic_snapshot(structural_result)
        structural_semantics = source_semantics == result_semantics
        if not structural_semantics:
            raise AssertionError(f"structural semantics changed: {source_semantics!r} != {result_semantics!r}")
        structural_output_render = render(structural_result, temporary_path / "structural-output.png")
        structural_expected_render = render(structural_expected, temporary_path / "structural-expected.png")
        structural_visual = difference_metrics(structural_output_render, structural_expected_render)
        structural_regions = {
            "stage2_inline": region_difference(structural_output_render, structural_expected_render, (165, 237, 201, 273)),
            "dct_jpeg": region_difference(structural_output_render, structural_expected_render, (60, 558, 240, 678)),
            "lab": region_difference(structural_output_render, structural_expected_render, (285, 595, 398, 678)),
            "separation": region_difference(structural_output_render, structural_expected_render, (427, 595, 540, 678)),
            "icc_cmyk": region_difference(structural_output_render, structural_expected_render, (570, 595, 683, 678)),
            "radial_shading": region_difference(structural_output_render, structural_expected_render, (697, 558, 818, 693)),
        }
        if structural_visual["mae"] > 0.5 or structural_visual["max_delta"] > 96:
            raise AssertionError(f"Stage 3A visual threshold exceeded: {structural_visual}")
        validate_no_color(structural_result, temporary_path, "structural-no-color")
        jpeg_output = inspect_jpeg_output(structural_result)
        if jpeg_output != {"filter": ["/DCTDecode"], "color_space": "/DeviceGray", "width": 48, "height": 32, "interpolate": True, "jpeg_magic": True}:
            raise AssertionError(f"JPEG semantics changed: {jpeg_output}")

        regenerated = temporary_path / "regenerated.pdf"
        regenerated_gray = temporary_path / "regenerated-gray.pdf"
        edit_with_regeneration(structural_result, regenerated)
        stage2.transform(regenerated, regenerated_gray)
        regenerated_result = validate_no_color(regenerated_gray, temporary_path, "regenerated-output")
        fields = PdfReader(str(regenerated_gray)).get_fields() or {}
        if str(fields["customer_note"].get("/V")) != "Stage 3A regenerated value":
            raise AssertionError("regenerated field value changed")
        policy_snapshot = appearance_snapshot(regenerated_gray)
        if policy_snapshot["appearance_entries"] < 9:
            raise AssertionError("regeneration removed supported AP states")
        if policy_snapshot["forbidden_da_values"] or any(count != 1 for count in policy_snapshot["mk_component_counts"]):
            raise AssertionError("regeneration reintroduced color in DA or MK")
        regenerated_result.update(policy_snapshot)
        regenerated_result["field_value"] = str(fields["customer_note"].get("/V"))

        stage2_expected = CORPUS_ROOT / "structural-grayscale-stage2" / "en-expected.pdf"
        stage2_output = CORPUS_ROOT / "structural-grayscale-stage2" / "en-output.pdf"
        if not stage2_expected.exists() or not stage2_output.exists():
            raise RuntimeError("Stage 2 render-difference fixtures are unavailable")
        stage2_difference = difference_metrics(
            render(stage2_output, temporary_path / "stage2-output.png"),
            render(stage2_expected, temporary_path / "stage2-expected.png"),
        )
        rejected = verify_fail_closed(structural_source, temporary_path)

    if temporary_path is None or temporary_path.exists():
        raise AssertionError("Stage 3A temporary directory was not cleaned")

    result = Stage3Result(
        pikepdf_version=pikepdf.__version__,
        libqpdf_version=pikepdf.__libqpdf_version__,
        pillow_version=Image.__version__,
        lcms_version=str(ImageCms.versions()[0] if hasattr(ImageCms, "versions") else "2.19"),
        arabic_readers=readers,
        arabic_logical_order_gate=arabic_gate,
        arabic_semantics_equal=arabic_semantics,
        arabic_visual=arabic_visual,
        structural_semantics_equal=structural_semantics,
        structural_visual=structural_visual,
        structural_visual_regions=structural_regions,
        jpeg_output=jpeg_output,
        regenerated_appearance=regenerated_result,
        stage2_difference=stage2_difference,
        fail_closed_cases=rejected,
        supported=[
            "logical-order Arabic independently evaluated with pypdf, PDFium, and PDF.js; PDFium gate remains failed",
            "single-filter DCTDecode RGB or explicitly profiled RGB JPEG",
            "Lab content using validated D50 policy",
            "Separation content with one Type 2 tint transform and supported alternate space",
            "ICCBased CMYK content with an explicit valid profile",
            "radial ShadingType 3 with one Type 2 function",
            "pypdf field edit/regeneration followed by whole-document grayscale validation",
        ],
        unsupported=[
            "JPXDecode, JBIG2Decode, CCITTFaxDecode and compound image filter chains",
            "unprofiled CMYK images",
            "DeviceN and NChannel",
            "Lab Image XObjects and unproved Lab white points/ranges",
            "arbitrary tint functions, multi-function/mesh shadings, uncolored patterns and complex masks",
            "external proprietary reader/editor appearance regeneration",
            "signed, encrypted, XFA and JavaScript-generated appearances",
        ],
        temp_cleanup_verified=True,
    )
    (output / "metrics.json").write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "output" / "pdf" / "structural-grayscale-stage3a")
    args = parser.parse_args()
    if not args.self_test:
        parser.error("Stage 3A exposes only --self-test; it is not a production converter")
    result = self_test(args.output_dir.resolve())
    print(json.dumps(asdict(result), ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
