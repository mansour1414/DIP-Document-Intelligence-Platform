#!/usr/bin/env python3
"""Isolated Stage 2 PoC for the DIP structural grayscale engine.

This module is intentionally disconnected from the application and worker. It
implements a bounded supported subset and rejects every unproved PDF feature.
It does not use MuPDF, PyMuPDF, Ghostscript, or page rasterization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import tempfile
import time
import zlib
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import Callable

import pikepdf
import pypdfium2 as pdfium
from PIL import Image, ImageChops, ImageCms, ImageStat, features
from pypdf import PdfReader, PdfWriter
from reportlab.lib.colors import Color
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas


MAX_INPUT_BYTES = 4_000_000
MAX_OUTPUT_BYTES = 8_000_000
MAX_TOTAL_DECODED_BYTES = 8_000_000
MAX_STREAM_DECODED_BYTES = 2_000_000
MAX_IMAGE_PIXELS = 1_000_000
MAX_IMAGES = 50
MAX_OBJECTS = 2_000
MAX_STREAMS = 400
MAX_PAGES = 10
MAX_RECURSION_DEPTH = 20
MAX_SECONDS = 15.0

DEVICE_OPERATORS = {"g": 1, "G": 1, "rg": 3, "RG": 3, "k": 4, "K": 4}
COLOR_SPACE_OPERATORS = {"cs", "CS"}
COLOR_VALUE_OPERATORS = {"sc", "SC", "scn", "SCN"}
PROHIBITED_COLOR_SPACES = {"/Separation", "/DeviceN", "/Lab"}


class UnsupportedPdf(RuntimeError):
    """Stage 2 cannot safely transform the requested PDF feature."""


def page_content_streams(page_obj: pikepdf.Object) -> list[pikepdf.Stream]:
    """Return validated page content streams without dropping malformed entries."""
    if "/Contents" not in page_obj:
        return []
    contents = page_obj["/Contents"]
    if contents is None:
        raise UnsupportedPdf("page Contents is null")
    if isinstance(contents, pikepdf.Stream):
        return [contents]
    if not isinstance(contents, pikepdf.Array):
        raise UnsupportedPdf("page Contents must be a stream or an array of streams")

    streams: list[pikepdf.Stream] = []
    for index, entry in enumerate(contents):
        if not isinstance(entry, pikepdf.Stream):
            raise UnsupportedPdf(f"page Contents entry {index} is not a stream")
        streams.append(entry)
    return streams


@dataclass
class Budget:
    decoded_bytes: int = 0
    images: int = 0
    streams: int = 0

    def add_decoded(self, amount: int) -> None:
        if amount < 0 or amount > MAX_STREAM_DECODED_BYTES:
            raise UnsupportedPdf("per-stream decoded byte limit exceeded")
        self.decoded_bytes += amount
        if self.decoded_bytes > MAX_TOTAL_DECODED_BYTES:
            raise UnsupportedPdf("total decoded byte limit exceeded")


@dataclass(frozen=True)
class ColorSpec:
    name: str
    components: int
    convert: Callable[[tuple[float, ...]], float]
    pattern: bool = False


@dataclass
class TransformStats:
    color_instructions: int = 0
    inline_images: int = 0
    image_xobjects: int = 0
    forms: int = 0
    appearances: int = 0
    patterns: int = 0
    shadings: int = 0
    shared_resources: int = 0


@dataclass
class CorpusResult:
    locale: str
    source_sha256: str
    output_sha256: str
    page_count: int
    text_equal: bool
    fields_equal: bool
    links_equal: bool
    output_colored_pixels: int
    output_max_chroma: int
    expected_colored_pixels: int
    render_mae: float
    render_max_delta: int
    edited_field_value: str
    edited_pretransform_colored_pixels: int
    edited_output_colored_pixels: int
    appearance_entries_after_edit: int
    residual_color_operators: int
    syntax_warnings: int
    stats: dict[str, int]


@dataclass
class Stage2Result:
    pikepdf_version: str
    libqpdf_version: str
    pillow_version: str
    lcms_version: str
    elapsed_ms: int
    corpus: list[CorpusResult]
    fail_closed_cases: list[str]
    unsupported_by_design: list[str]
    temp_cleanup_verified: bool


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def srgb_to_linear(value: float) -> float:
    value = clamp01(value)
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def linear_to_srgb(value: float) -> float:
    value = clamp01(value)
    return 12.92 * value if value <= 0.0031308 else 1.055 * value ** (1 / 2.4) - 0.055


def rgb_gray(values: tuple[float, ...]) -> float:
    red, green, blue = values
    luminance = (
        0.2126 * srgb_to_linear(red)
        + 0.7152 * srgb_to_linear(green)
        + 0.0722 * srgb_to_linear(blue)
    )
    return clamp01(linear_to_srgb(luminance))


def cmyk_gray(values: tuple[float, ...]) -> float:
    cyan, magenta, yellow, black = values
    # Explicit Stage 2 policy for uncalibrated DeviceCMYK content only. Image
    # XObjects in unprofiled CMYK are rejected because this fallback is not
    # accurate enough for continuous-tone image conversion.
    return rgb_gray(
        (
            (1.0 - clamp01(cyan)) * (1.0 - clamp01(black)),
            (1.0 - clamp01(magenta)) * (1.0 - clamp01(black)),
            (1.0 - clamp01(yellow)) * (1.0 - clamp01(black)),
        )
    )


def xyz_d65_to_srgb(xyz: tuple[float, float, float]) -> tuple[float, float, float]:
    x, y, z = xyz
    red = 3.2404542 * x - 1.5371385 * y - 0.4985314 * z
    green = -0.9692660 * x + 1.8760108 * y + 0.0415560 * z
    blue = 0.0556434 * x - 0.2040259 * y + 1.0572252 * z
    return tuple(linear_to_srgb(component) for component in (red, green, blue))


def number_array(value: pikepdf.Object | None, expected: int, default: list[float]) -> list[float]:
    if value is None:
        return default
    result = [float(item) for item in value]
    if len(result) != expected or not all(math.isfinite(item) for item in result):
        raise UnsupportedPdf("invalid calibrated color-space array")
    return result


@lru_cache(maxsize=512)
def icc_pixel_to_gray(profile_bytes: bytes, components: int, quantized: tuple[int, ...]) -> float:
    if components not in {3, 4}:
        raise UnsupportedPdf("only RGB and CMYK ICC profiles are supported")
    mode = "RGB" if components == 3 else "CMYK"
    source_profile = ImageCms.ImageCmsProfile(BytesIO(profile_bytes))
    destination_profile = ImageCms.createProfile("sRGB")
    image = Image.new(mode, (1, 1), quantized)
    try:
        converted = ImageCms.profileToProfile(
            image,
            source_profile,
            destination_profile,
            outputMode="RGB",
            renderingIntent=0,
        )
    except Exception as error:
        raise UnsupportedPdf("ICC transform failed") from error
    pixel = converted.getpixel((0, 0))
    return rgb_gray(tuple(channel / 255.0 for channel in pixel))


def color_spec(value: pikepdf.Object, resources: pikepdf.Object | None = None) -> ColorSpec:
    if isinstance(value, pikepdf.Name):
        name = str(value)
        aliases = {"/G": "/DeviceGray", "/RGB": "/DeviceRGB", "/CMYK": "/DeviceCMYK"}
        name = aliases.get(name, name)
        if name == "/DeviceGray":
            return ColorSpec(name, 1, lambda operands: clamp01(operands[0]))
        if name == "/DeviceRGB":
            return ColorSpec(name, 3, rgb_gray)
        if name == "/DeviceCMYK":
            return ColorSpec(name, 4, cmyk_gray)
        if name == "/Pattern":
            return ColorSpec(name, 0, lambda _: 0.0, pattern=True)
        if resources is not None:
            table = resources.get("/ColorSpace", {})
            resolved = table.get(value)
            if resolved is not None:
                return color_spec(resolved, resources)
        raise UnsupportedPdf(f"unknown color-space resource {name}")

    if not isinstance(value, pikepdf.Array) or len(value) < 2:
        raise UnsupportedPdf("malformed color space")
    family = str(value[0])
    if family in PROHIBITED_COLOR_SPACES:
        raise UnsupportedPdf(f"unsupported color space {family}")
    if family == "/CalGray":
        dictionary = value[1]
        white = number_array(dictionary.get("/WhitePoint"), 3, [1.0, 1.0, 1.0])
        if abs(white[1] - 1.0) > 0.0001 or min(white) <= 0:
            raise UnsupportedPdf("unsupported CalGray white point")
        gamma = float(dictionary.get("/Gamma", 1.0))
        if not math.isfinite(gamma) or gamma <= 0:
            raise UnsupportedPdf("invalid CalGray gamma")
        return ColorSpec(family, 1, lambda operands: linear_to_srgb(clamp01(operands[0]) ** gamma))
    if family == "/CalRGB":
        dictionary = value[1]
        white = number_array(dictionary.get("/WhitePoint"), 3, [1.0, 1.0, 1.0])
        if any(abs(actual - expected) > 0.01 for actual, expected in zip(white, [0.95047, 1.0, 1.08883])):
            raise UnsupportedPdf("Stage 2 CalRGB supports D65 only")
        gamma = number_array(dictionary.get("/Gamma"), 3, [1.0, 1.0, 1.0])
        matrix = number_array(
            dictionary.get("/Matrix"),
            9,
            [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
        )

        def convert_calrgb(operands: tuple[float, ...]) -> float:
            a, b, c = (clamp01(component) ** exponent for component, exponent in zip(operands, gamma))
            xyz = (
                matrix[0] * a + matrix[3] * b + matrix[6] * c,
                matrix[1] * a + matrix[4] * b + matrix[7] * c,
                matrix[2] * a + matrix[5] * b + matrix[8] * c,
            )
            return rgb_gray(xyz_d65_to_srgb(xyz))

        return ColorSpec(family, 3, convert_calrgb)
    if family == "/ICCBased":
        profile = value[1]
        if not isinstance(profile, pikepdf.Stream):
            raise UnsupportedPdf("ICCBased profile is not a stream")
        components = int(profile.get("/N", 0))
        profile_bytes = bytes(profile.read_bytes())
        if not profile_bytes or len(profile_bytes) > 1_000_000:
            raise UnsupportedPdf("ICC profile byte limit exceeded")

        def convert_icc(operands: tuple[float, ...]) -> float:
            quantized = tuple(round(clamp01(component) * 255) for component in operands)
            return icc_pixel_to_gray(profile_bytes, components, quantized)

        return ColorSpec(family, components, convert_icc)
    if family == "/Indexed":
        if len(value) != 4:
            raise UnsupportedPdf("malformed Indexed color space")
        base = color_spec(value[1], resources)
        if base.pattern:
            raise UnsupportedPdf("Indexed Pattern base is unsupported")
        high = int(value[2])
        if high < 0 or high > 255:
            raise UnsupportedPdf("Indexed palette limit exceeded")
        lookup_object = value[3]
        if isinstance(lookup_object, pikepdf.Stream):
            lookup = bytes(lookup_object.read_bytes())
        else:
            lookup = bytes(lookup_object)
        required = (high + 1) * base.components
        if len(lookup) < required or required > 4096:
            raise UnsupportedPdf("Indexed lookup is malformed or oversized")

        def convert_index(operands: tuple[float, ...]) -> float:
            index = max(0, min(high, round(operands[0])))
            offset = index * base.components
            samples = tuple(component / 255.0 for component in lookup[offset : offset + base.components])
            return base.convert(samples)

        return ColorSpec(family, 1, convert_index)
    raise UnsupportedPdf(f"unsupported color-space family {family}")


def layout_tokens() -> set[pikepdf.TokenType]:
    return {pikepdf.TokenType.space, pikepdf.TokenType.comment}


def replacement(operator: str, gray: float) -> list[pikepdf.Token]:
    return [
        pikepdf.Token(pikepdf.TokenType.space, b"\n"),
        pikepdf.Token(pikepdf.TokenType.real, f"{clamp01(gray):.6f}".encode("ascii")),
        pikepdf.Token(pikepdf.TokenType.space, b" "),
        pikepdf.Token(pikepdf.TokenType.word, operator.encode("ascii")),
        pikepdf.Token(pikepdf.TokenType.space, b"\n"),
    ]


class StructuralColorFilter(pikepdf.TokenFilter):
    def __init__(self, resources: pikepdf.Object, stats: TransformStats, budget: Budget) -> None:
        super().__init__()
        self.resources = resources
        self.stats = stats
        self.budget = budget
        self.buffer: list[pikepdf.Token] = []
        self.inline_buffer: list[pikepdf.Token] | None = None
        self.failure: str | None = None
        self.fill = color_spec(pikepdf.Name.DeviceGray)
        self.stroke = color_spec(pikepdf.Name.DeviceGray)
        self.stack: list[tuple[ColorSpec, ColorSpec]] = []

    def fail(self, message: str) -> None:
        self.failure = self.failure or message

    @staticmethod
    def meaningful(tokens: list[pikepdf.Token]) -> list[pikepdf.Token]:
        return [token for token in tokens if token.type_ not in layout_tokens()]

    def rewrite_inline(self, tokens: list[pikepdf.Token]) -> list[pikepdf.Token]:
        meaningful = self.meaningful(tokens)
        if not meaningful or meaningful[0].value != "BI" or meaningful[-1].value != "EI":
            raise UnsupportedPdf("malformed inline image")
        try:
            id_index = next(index for index, token in enumerate(meaningful) if token.type_ == pikepdf.TokenType.word and token.value == "ID")
            data_token = meaningful[id_index + 1]
        except (StopIteration, IndexError) as error:
            raise UnsupportedPdf("malformed inline image data") from error
        if data_token.type_ != pikepdf.TokenType.inline_image:
            raise UnsupportedPdf("missing inline image bytes")
        header = meaningful[1:id_index]
        if len(header) % 2:
            raise UnsupportedPdf("malformed inline image dictionary")
        entries: dict[str, pikepdf.Token] = {}
        for index in range(0, len(header), 2):
            key, value = header[index], header[index + 1]
            if key.type_ != pikepdf.TokenType.name_:
                raise UnsupportedPdf("malformed inline image key")
            entries[key.value] = value
        if any(key in entries for key in {"/F", "/Filter", "/D", "/Decode"}):
            raise UnsupportedPdf("filtered or decoded inline images are unsupported")
        width_token = entries.get("/W") or entries.get("/Width")
        height_token = entries.get("/H") or entries.get("/Height")
        bpc_token = entries.get("/BPC") or entries.get("/BitsPerComponent")
        cs_token = entries.get("/CS") or entries.get("/ColorSpace")
        if not all((width_token, height_token, bpc_token, cs_token)):
            raise UnsupportedPdf("inline image requires W/H/BPC/CS")
        width, height, bpc = int(width_token.value), int(height_token.value), int(bpc_token.value)
        if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS or bpc != 8:
            raise UnsupportedPdf("inline image dimensions or bit depth unsupported")
        spec = color_spec(pikepdf.Name(cs_token.value), self.resources)
        if spec.name not in {"/DeviceRGB", "/DeviceGray"}:
            raise UnsupportedPdf("inline image supports DeviceRGB/Gray only")
        expected = width * height * spec.components
        raw = data_token.raw_value
        pixels, trailer = raw[:expected], raw[expected:]
        if len(pixels) != expected or trailer.strip(b"\x00\x09\x0a\x0c\x0d\x20"):
            raise UnsupportedPdf("inline image decoded length mismatch")
        self.budget.add_decoded(len(pixels))
        if spec.components == 1:
            grayscale = pixels
        else:
            grayscale = bytes(
                round(spec.convert(tuple(pixels[offset + component] / 255.0 for component in range(3))) * 255)
                for offset in range(0, len(pixels), 3)
            )
        self.stats.inline_images += 1
        self.budget.images += 1
        if self.budget.images > MAX_IMAGES:
            raise UnsupportedPdf("image count limit exceeded")
        return [
            pikepdf.Token(pikepdf.TokenType.space, b"\n"),
            pikepdf.Token(pikepdf.TokenType.word, b"BI"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.name_, b"/W"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.integer, str(width).encode("ascii")),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.name_, b"/H"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.integer, str(height).encode("ascii")),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.name_, b"/BPC"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.integer, b"8"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.name_, b"/CS"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.name_, b"/DeviceGray"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.word, b"ID"),
            pikepdf.Token(pikepdf.TokenType.space, b" "),
            pikepdf.Token(pikepdf.TokenType.inline_image, grayscale + b" "),
            pikepdf.Token(pikepdf.TokenType.word, b"EI"),
            pikepdf.Token(pikepdf.TokenType.space, b"\n"),
        ]

    def handle_instruction(self, instruction: list[pikepdf.Token], operator: str):
        meaningful = self.meaningful(instruction[:-1])
        if operator == "q":
            self.stack.append((self.fill, self.stroke))
            return instruction
        if operator == "Q":
            if not self.stack:
                self.fail("unbalanced graphics state")
            else:
                self.fill, self.stroke = self.stack.pop()
            return instruction
        if operator in DEVICE_OPERATORS:
            expected = DEVICE_OPERATORS[operator]
            if len(meaningful) != expected or any(token.type_ not in {pikepdf.TokenType.integer, pikepdf.TokenType.real} for token in meaningful):
                self.fail(f"malformed {operator} instruction")
                return instruction
            values = tuple(float(token.value) for token in meaningful)
            spec = color_spec(pikepdf.Name.DeviceGray if expected == 1 else pikepdf.Name.DeviceRGB if expected == 3 else pikepdf.Name.DeviceCMYK)
            gray = spec.convert(values)
            if operator.isupper():
                self.stroke = color_spec(pikepdf.Name.DeviceGray)
            else:
                self.fill = color_spec(pikepdf.Name.DeviceGray)
            self.stats.color_instructions += int(expected > 1)
            return replacement("G" if operator.isupper() else "g", gray)
        if operator in COLOR_SPACE_OPERATORS:
            if len(meaningful) != 1 or meaningful[0].type_ != pikepdf.TokenType.name_:
                self.fail(f"malformed {operator} instruction")
                return instruction
            try:
                spec = color_spec(pikepdf.Name(meaningful[0].value), self.resources)
            except UnsupportedPdf as error:
                self.fail(str(error))
                return instruction
            if operator == "CS":
                self.stroke = spec
            else:
                self.fill = spec
            if spec.pattern:
                return instruction
            return [
                pikepdf.Token(pikepdf.TokenType.space, b"\n"),
                pikepdf.Token(pikepdf.TokenType.name_, b"/DeviceGray"),
                pikepdf.Token(pikepdf.TokenType.space, b" "),
                pikepdf.Token(pikepdf.TokenType.word, operator.encode("ascii")),
                pikepdf.Token(pikepdf.TokenType.space, b"\n"),
            ]
        if operator in COLOR_VALUE_OPERATORS:
            spec = self.stroke if operator[0].isupper() else self.fill
            names = [token for token in meaningful if token.type_ == pikepdf.TokenType.name_]
            numbers = [token for token in meaningful if token.type_ in {pikepdf.TokenType.integer, pikepdf.TokenType.real}]
            if spec.pattern:
                if numbers or len(names) != 1:
                    self.fail("uncolored or malformed pattern painting is unsupported")
                return instruction
            if names or len(numbers) != spec.components or len(meaningful) != spec.components:
                self.fail(f"operand count does not match {spec.name}")
                return instruction
            gray = spec.convert(tuple(float(token.value) for token in numbers))
            self.stats.color_instructions += int(spec.name != "/DeviceGray")
            return replacement("SC" if operator[0].isupper() else "sc", gray)
        return instruction

    def handle_token(self, token: pikepdf.Token):
        if self.inline_buffer is not None:
            self.inline_buffer.append(token)
            if token.type_ == pikepdf.TokenType.word and token.value == "EI":
                try:
                    result = self.rewrite_inline(self.inline_buffer)
                except UnsupportedPdf as error:
                    self.fail(str(error))
                    result = self.inline_buffer
                self.inline_buffer = None
                return result
            if token.type_ == pikepdf.TokenType.eof:
                self.fail("unterminated inline image")
                result = self.inline_buffer
                self.inline_buffer = None
                return result
            return None

        if token.type_ == pikepdf.TokenType.eof:
            if self.stack:
                self.fail("unbalanced graphics state at EOF")
            result = [*self.buffer, token]
            self.buffer.clear()
            return result
        self.buffer.append(token)
        if token.type_ != pikepdf.TokenType.word:
            return None
        if token.value == "BI":
            self.inline_buffer = self.buffer
            self.buffer = []
            return None
        instruction = self.buffer
        self.buffer = []
        return self.handle_instruction(instruction, token.value)


def filtered_stream(stream: pikepdf.Stream, resources: pikepdf.Object, stats: TransformStats, budget: Budget) -> bytes:
    wrapper = pikepdf.Page(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Page,
            MediaBox=pikepdf.Array([0, 0, 100, 100]),
            Resources=resources,
            Contents=stream,
        )
    )
    token_filter = StructuralColorFilter(resources, stats, budget)
    result = wrapper.get_filtered_contents(token_filter)
    if token_filter.failure:
        raise UnsupportedPdf(token_filter.failure)
    budget.add_decoded(len(result))
    return result


def object_identity(obj: pikepdf.Object) -> tuple[object, ...]:
    try:
        objgen = obj.objgen
    except (AttributeError, TypeError):
        objgen = (0, 0)
    return ("indirect", *objgen) if objgen != (0, 0) else ("direct", id(obj))


def image_to_gray(stream: pikepdf.Stream, stats: TransformStats, budget: Budget) -> None:
    if bool(stream.get("/ImageMask", False)):
        return
    width, height = int(stream.get("/Width", 0)), int(stream.get("/Height", 0))
    if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
        raise UnsupportedPdf("image dimensions exceed the Stage 2 limit")
    filters = stream.get("/Filter")
    filter_names = [] if filters is None else [str(filters)] if isinstance(filters, pikepdf.Name) else [str(item) for item in filters]
    if any(name not in {"/FlateDecode"} for name in filter_names):
        raise UnsupportedPdf(f"unsupported image filter: {filter_names}")
    if stream.get("/Mask") is not None:
        raise UnsupportedPdf("color-key and explicit image masks are unsupported")
    soft_mask = stream.get("/SMask")
    if soft_mask is not None:
        if not isinstance(soft_mask, pikepdf.Stream) or str(soft_mask.get("/ColorSpace")) != "/DeviceGray":
            raise UnsupportedPdf("only DeviceGray soft masks are supported")
    try:
        pdf_image = pikepdf.PdfImage(stream)
        image = pdf_image.as_pil_image()
    except Exception as error:
        raise UnsupportedPdf("image decoding failed") from error
    budget.images += 1
    if budget.images > MAX_IMAGES:
        raise UnsupportedPdf("image count limit exceeded")
    budget.add_decoded(width * height * max(1, len(image.getbands())))
    if image.mode == "L":
        gray_image = image
    else:
        icc_profile = image.info.get("icc_profile")
        if image.mode == "CMYK" and not icc_profile:
            raise UnsupportedPdf("unprofiled CMYK images are unsupported")
        if icc_profile:
            try:
                image = ImageCms.profileToProfile(
                    image,
                    ImageCms.ImageCmsProfile(BytesIO(icc_profile)),
                    ImageCms.createProfile("sRGB"),
                    outputMode="RGB",
                    renderingIntent=0,
                )
            except Exception as error:
                raise UnsupportedPdf("image ICC transform failed") from error
        else:
            image = image.convert("RGB")
        gray_image = Image.new("L", image.size)
        gray_image.putdata(
            [
                round(rgb_gray(tuple(channel / 255.0 for channel in pixel)) * 255)
                for pixel in image.get_flattened_data()
            ]
        )
    raw = gray_image.tobytes()
    budget.add_decoded(len(raw))
    stream.write(zlib.compress(raw, level=9), filter=pikepdf.Name.FlateDecode)
    stream["/ColorSpace"] = pikepdf.Name.DeviceGray
    stream["/BitsPerComponent"] = 8
    for key in ("/Decode", "/DecodeParms"):
        if key in stream:
            del stream[key]
    stats.image_xobjects += 1


def transform_color_array(array: pikepdf.Object, spec: ColorSpec) -> pikepdf.Array:
    values = tuple(float(item) for item in array)
    if len(values) != spec.components:
        raise UnsupportedPdf("color array does not match color space")
    return pikepdf.Array([round(spec.convert(values), 6)])


class StructuralTransformer:
    def __init__(self, pdf: pikepdf.Pdf) -> None:
        self.pdf = pdf
        self.budget = Budget()
        self.stats = TransformStats()
        self.done: set[tuple[object, ...]] = set()
        self.active: set[tuple[object, ...]] = set()
        self.started = time.monotonic()

    def check_time(self) -> None:
        if time.monotonic() - self.started > MAX_SECONDS:
            raise TimeoutError("Stage 2 wall-clock budget exceeded")

    def enter(self, obj: pikepdf.Object, depth: int) -> tuple[object, ...] | None:
        self.check_time()
        if depth > MAX_RECURSION_DEPTH:
            raise UnsupportedPdf("resource recursion depth exceeded")
        identity = object_identity(obj)
        if identity in self.active:
            raise UnsupportedPdf("cyclic resource graph detected")
        if identity in self.done:
            self.stats.shared_resources += 1
            return None
        self.active.add(identity)
        return identity

    def leave(self, identity: tuple[object, ...]) -> None:
        self.active.remove(identity)
        self.done.add(identity)

    def transform_stream(self, stream: pikepdf.Stream, resources: pikepdf.Object, depth: int) -> None:
        identity = self.enter(stream, depth)
        if identity is None:
            return
        try:
            output = filtered_stream(stream, resources, self.stats, self.budget)
            stream.write(output)
            self.transform_resources(resources, depth + 1)
        finally:
            if identity in self.active:
                self.leave(identity)

    def transform_form(self, form: pikepdf.Stream, inherited_resources: pikepdf.Object, depth: int) -> None:
        if str(form.get("/Subtype")) != "/Form":
            raise UnsupportedPdf("non-Form XObject reached form transformer")
        resources = form.get("/Resources")
        if resources is None:
            resources = inherited_resources
        self.transform_stream(form, resources, depth)
        self.stats.forms += 1

    def transform_pattern(self, pattern: pikepdf.Object, inherited_resources: pikepdf.Object, depth: int) -> None:
        pattern_type = int(pattern.get("/PatternType", 0))
        if pattern_type == 1 and isinstance(pattern, pikepdf.Stream):
            if int(pattern.get("/PaintType", 0)) != 1:
                raise UnsupportedPdf("uncolored tiling patterns are unsupported")
            resources = pattern.get("/Resources")
            self.transform_stream(pattern, resources if resources is not None else inherited_resources, depth)
        elif pattern_type == 2:
            self.transform_shading(pattern.get("/Shading"), inherited_resources, depth)
        else:
            raise UnsupportedPdf("unsupported pattern type")
        self.stats.patterns += 1

    def transform_shading(self, shading: pikepdf.Object, resources: pikepdf.Object, depth: int) -> None:
        identity = self.enter(shading, depth)
        if identity is None:
            return
        try:
            if int(shading.get("/ShadingType", 0)) != 2:
                raise UnsupportedPdf("only axial Type 2 shadings are supported")
            spec = color_spec(shading.get("/ColorSpace"), resources)
            function = shading.get("/Function")
            if isinstance(function, pikepdf.Array) or int(function.get("/FunctionType", 0)) != 2:
                raise UnsupportedPdf("only a single Type 2 shading function is supported")
            function["/C0"] = transform_color_array(function.get("/C0", pikepdf.Array([0.0] * spec.components)), spec)
            function["/C1"] = transform_color_array(function.get("/C1", pikepdf.Array([1.0] * spec.components)), spec)
            shading["/ColorSpace"] = pikepdf.Name.DeviceGray
            if shading.get("/Background") is not None:
                shading["/Background"] = transform_color_array(shading["/Background"], spec)
            self.stats.shadings += 1
        finally:
            if identity in self.active:
                self.leave(identity)

    def transform_resources(self, resources: pikepdf.Object, depth: int) -> None:
        if resources is None:
            return
        if depth > MAX_RECURSION_DEPTH:
            raise UnsupportedPdf("resource recursion depth exceeded")
        xobjects = resources.get("/XObject", {})
        for xobject in list(xobjects.values()):
            subtype = str(xobject.get("/Subtype"))
            if subtype == "/Image":
                xidentity = object_identity(xobject)
                if xidentity not in self.done:
                    image_to_gray(xobject, self.stats, self.budget)
                    self.done.add(xidentity)
            elif subtype == "/Form":
                self.transform_form(xobject, resources, depth + 1)
            else:
                raise UnsupportedPdf(f"unsupported XObject subtype {subtype}")
        for pattern in list(resources.get("/Pattern", {}).values()):
            self.transform_pattern(pattern, resources, depth + 1)
        for shading in list(resources.get("/Shading", {}).values()):
            self.transform_shading(shading, resources, depth + 1)
        for extgstate in list(resources.get("/ExtGState", {}).values()):
            soft_mask = extgstate.get("/SMask") if hasattr(extgstate, "get") else None
            if isinstance(soft_mask, pikepdf.Dictionary):
                group = soft_mask.get("/G")
                if isinstance(group, pikepdf.Stream):
                    self.transform_form(group, resources, depth + 1)
        color_spaces = resources.get("/ColorSpace", {})
        for name, definition in list(color_spaces.items()):
            spec = color_spec(definition, resources)
            if spec.pattern:
                continue
            color_spaces[name] = pikepdf.Name.DeviceGray

    def transform_da(self, value: str, resources: pikepdf.Object) -> str:
        owner = pikepdf.Pdf.new()
        with owner:
            stream = owner.make_stream(value.encode("latin-1"))
            output = filtered_stream(stream, resources, self.stats, self.budget)
        return output.decode("latin-1").strip()

    def transform_appearance(self, value: pikepdf.Object, inherited_resources: pikepdf.Object, depth: int) -> None:
        if isinstance(value, pikepdf.Stream):
            self.transform_form(value, inherited_resources, depth)
            self.stats.appearances += 1
            return
        if isinstance(value, pikepdf.Dictionary):
            if len(value) > 32:
                raise UnsupportedPdf("appearance-state count limit exceeded")
            for state in value.values():
                if not isinstance(state, pikepdf.Stream):
                    raise UnsupportedPdf("appearance state is not a Form stream")
                self.transform_form(state, inherited_resources, depth)
                self.stats.appearances += 1
            return
        raise UnsupportedPdf("unsupported appearance object")

    def transform_widget(self, widget: pikepdf.Object, page_resources: pikepdf.Object, depth: int) -> None:
        if widget.get("/FT") == pikepdf.Name.Sig or widget.get("/ByteRange") is not None:
            raise UnsupportedPdf("signed PDFs are rejected")
        appearances = widget.get("/AP")
        if appearances:
            for key in ("/N", "/R", "/D"):
                value = appearances.get(key)
                if value is not None:
                    self.transform_appearance(value, page_resources, depth + 1)
        mk = widget.get("/MK")
        if mk:
            for key in ("/BG", "/BC"):
                value = mk.get(key)
                if value is not None:
                    components = len(value)
                    spec = color_spec(pikepdf.Name.DeviceGray if components == 1 else pikepdf.Name.DeviceRGB if components == 3 else pikepdf.Name.DeviceCMYK if components == 4 else pikepdf.Name.Pattern)
                    if spec.pattern:
                        raise UnsupportedPdf("unsupported MK color")
                    mk[key] = transform_color_array(value, spec)
        if widget.get("/DA") is not None:
            widget["/DA"] = pikepdf.String(self.transform_da(str(widget["/DA"]), page_resources))

    def transform_field_tree(self, field_obj: pikepdf.Object, resources: pikepdf.Object, depth: int) -> None:
        if depth > MAX_RECURSION_DEPTH:
            raise UnsupportedPdf("field tree depth exceeded")
        if field_obj.get("/FT") == pikepdf.Name.Sig:
            raise UnsupportedPdf("signature fields are rejected")
        if field_obj.get("/DA") is not None:
            field_obj["/DA"] = pikepdf.String(self.transform_da(str(field_obj["/DA"]), resources))
        for child in field_obj.get("/Kids", []):
            self.transform_field_tree(child, resources, depth + 1)

    def run(self) -> None:
        for page in self.pdf.pages:
            resources = page.obj.get("/Resources")
            if resources is None:
                resources = pikepdf.Dictionary()
            content_streams = page_content_streams(page.obj)
            if content_streams:
                contents = page.obj["/Contents"]
                if isinstance(contents, pikepdf.Array):
                    try:
                        decoded = b"\n".join(bytes(stream.read_bytes()) for stream in content_streams)
                    except (pikepdf.PdfError, RuntimeError, ValueError) as error:
                        raise UnsupportedPdf("page Contents stream cannot be decoded") from error
                    self.budget.add_decoded(len(decoded))
                    page.obj["/Contents"] = self.pdf.make_stream(decoded)
                output = filtered_stream(page.obj["/Contents"], resources, self.stats, self.budget)
                page.obj["/Contents"].write(output)
            self.transform_resources(resources, 1)
            for annotation in page.obj.get("/Annots", []):
                subtype = str(annotation.get("/Subtype"))
                if subtype == "/Widget":
                    self.transform_widget(annotation, resources, 1)
                elif subtype not in {"/Link", "/Text"}:
                    raise UnsupportedPdf(f"unsupported annotation subtype {subtype}")
        acroform = self.pdf.Root.get("/AcroForm")
        if acroform:
            default_resources = acroform.get("/DR") or pikepdf.Dictionary()
            if acroform.get("/DA") is not None:
                acroform["/DA"] = pikepdf.String(self.transform_da(str(acroform["/DA"]), default_resources))
            for field_obj in acroform.get("/Fields", []):
                self.transform_field_tree(field_obj, default_resources, 1)


# Stage 3A deliberately extends these symbols in-process. Keep immutable
# references so Stage 2's own regression corpus always evaluates Stage 2 policy.
STAGE2_COLOR_SPEC = color_spec
STAGE2_IMAGE_TO_GRAY = image_to_gray
STAGE2_STRUCTURAL_TRANSFORMER = StructuralTransformer


def inspect_structure(pdf: pikepdf.Pdf, source_size: int) -> None:
    if source_size <= 0 or source_size > MAX_INPUT_BYTES:
        raise UnsupportedPdf("input byte limit exceeded")
    if not 1 <= len(pdf.pages) <= MAX_PAGES:
        raise UnsupportedPdf("page limit exceeded")
    objects = list(pdf.objects)
    if len(objects) > MAX_OBJECTS:
        raise UnsupportedPdf("object limit exceeded")
    if sum(isinstance(obj, pikepdf.Stream) for obj in objects) > MAX_STREAMS:
        raise UnsupportedPdf("stream limit exceeded")
    # Validate every page before any content stream is transformed. A malformed
    # later page therefore cannot produce an in-memory partial transformation.
    for page in pdf.pages:
        page_content_streams(page.obj)
    inspected: set[tuple[object, ...]] = set()

    def inspect(obj: pikepdf.Object, depth: int) -> None:
        if depth > MAX_RECURSION_DEPTH:
            raise UnsupportedPdf("object graph depth exceeded")
        identity = object_identity(obj)
        if identity[0] == "indirect":
            if identity in inspected:
                return
            inspected.add(identity)
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            if obj.get("/ByteRange") is not None or obj.get("/Type") == pikepdf.Name.Sig or obj.get("/FT") == pikepdf.Name.Sig:
                raise UnsupportedPdf("signed PDFs are rejected")
            for child in obj.values():
                inspect(child, depth + 1)
        elif isinstance(obj, pikepdf.Array):
            for child in obj:
                inspect(child, depth + 1)

    inspect(pdf.Root, 0)


def transform(source: Path, destination: Path) -> TransformStats:
    destination.unlink(missing_ok=True)
    try:
        pdf = pikepdf.Pdf.open(source)
    except pikepdf.PasswordError as error:
        raise UnsupportedPdf("encrypted PDFs require an authorized separate path") from error
    try:
        with pdf:
            inspect_structure(pdf, source.stat().st_size)
            transformer = StructuralTransformer(pdf)
            transformer.run()
            pdf.save(destination, deterministic_id=True, compress_streams=True)
            if destination.stat().st_size > MAX_OUTPUT_BYTES:
                raise UnsupportedPdf("output byte limit exceeded")
        with pikepdf.Pdf.open(destination) as reopened:
            warnings = reopened.check_pdf_syntax()
            if warnings:
                raise UnsupportedPdf(f"output syntax warnings: {warnings}")
        return transformer.stats
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def find_arabic_font() -> Path:
    candidates = [
        Path(r"C:\Windows\Fonts\arial.ttf"),
        Path("/usr/share/fonts/truetype/noto/NotoSansArabic-Regular.ttf"),
        Path("/usr/share/fonts/opentype/noto/NotoSansArabic-Regular.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("an Arabic-capable test font is required")


def make_base(path: Path, locale: str, grayscale: bool) -> None:
    font_path = find_arabic_font()
    font_name = "Stage2Arabic"
    if font_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(font_name, str(font_path)))
    canvas = Canvas(str(path), pagesize=(612, 792), invariant=1, pageCompression=0)
    canvas.setTitle(f"DIP structural grayscale Stage 2 {locale}")
    if grayscale:
        canvas.setFillGray(rgb_gray((0.85, 0.12, 0.20)))
    else:
        canvas.setFillColorRGB(0.85, 0.12, 0.20)
    canvas.setFont(font_name, 16)
    canvas.drawString(40, 750, "DIP Stage 2 searchable English text")
    canvas.drawRightString(
        570,
        720,
        "نص عربي قابل للبحث - المرحلة الثانية",
        shaping=True,
    )
    canvas.setFont(font_name, 10)
    canvas.drawString(40, 690, f"Golden locale: {locale}")
    canvas.linkURL("https://example.invalid/dip-stage2", (40, 680, 260, 705), relative=0)
    fill = Color(*(3 * (rgb_gray((0.20, 0.45, 0.90)),))) if grayscale else Color(0.20, 0.45, 0.90)
    border = Color(*(3 * (rgb_gray((0.90, 0.20, 0.15)),))) if grayscale else Color(0.90, 0.20, 0.15)
    text = Color(*(3 * (rgb_gray((0.60, 0.05, 0.55)),))) if grayscale else Color(0.60, 0.05, 0.55)
    value = "Preserved Arabic corpus value" if locale == "ar" else "Preserved value"
    canvas.acroForm.textfield(
        name="customer_note",
        value=value,
        x=40,
        y=70,
        width=310,
        height=34,
        fillColor=fill,
        borderColor=border,
        textColor=text,
        forceBorder=True,
    )
    canvas.acroForm.checkbox(
        name="approved",
        checked=True,
        x=380,
        y=75,
        size=24,
        fillColor=fill,
        borderColor=border,
        buttonStyle="check",
    )
    canvas.showPage()
    canvas.save()


def raw_image_pixels(grayscale: bool) -> tuple[bytes, int]:
    rgb = []
    for y in range(12):
        for x in range(12):
            rgb.append((220, 30, 40) if (x + y) % 2 else (20, 150, 230))
    if grayscale:
        return bytes(round(rgb_gray(tuple(channel / 255 for channel in pixel)) * 255) for pixel in rgb), 1
    return bytes(channel for pixel in rgb for channel in pixel), 3


def clone_appearance(pdf: pikepdf.Pdf, value: pikepdf.Object, grayscale: bool) -> pikepdf.Object:
    if isinstance(value, pikepdf.Stream):
        prefix = b"q .457707 g 0 0 8 8 re f Q\n" if grayscale else b"q .9 .1 .2 rg 0 0 8 8 re f Q\n"
        dictionary = pikepdf.Dictionary()
        for key, item in value.items():
            if str(key) not in {"/Length", "/Filter", "/DecodeParms"}:
                dictionary[key] = item
        return pdf.make_stream(prefix + bytes(value.read_bytes()), dictionary)
    if isinstance(value, pikepdf.Dictionary):
        return pikepdf.Dictionary({key: clone_appearance(pdf, state, grayscale) for key, state in value.items()})
    raise UnsupportedPdf("fixture appearance is malformed")


def augment_fixture(path: Path, grayscale: bool) -> None:
    with pikepdf.Pdf.open(path, allow_overwriting_input=True) as pdf:
        page = pdf.pages[0]
        resources = page.obj.get("/Resources")
        for key in ("/XObject", "/ColorSpace", "/Pattern", "/Shading", "/ExtGState"):
            if resources.get(key) is None:
                resources[key] = pikepdf.Dictionary()

        srgb_profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
        icc_stream = pdf.make_stream(srgb_profile, pikepdf.Dictionary(N=3, Alternate=pikepdf.Name.DeviceRGB))
        resources["/ColorSpace"]["/CSICC"] = pikepdf.Name.DeviceGray if grayscale else pikepdf.Array([pikepdf.Name.ICCBased, icc_stream])
        resources["/ColorSpace"]["/CSIDX"] = (
            pikepdf.Name.DeviceGray
            if grayscale
            else pikepdf.Array([pikepdf.Name.Indexed, pikepdf.Name.DeviceRGB, 1, pikepdf.String(bytes([235, 30, 40, 30, 120, 240]))])
        )
        resources["/ColorSpace"]["/CSCalG"] = (
            pikepdf.Name.DeviceGray
            if grayscale
            else pikepdf.Array([pikepdf.Name.CalGray, pikepdf.Dictionary(WhitePoint=pikepdf.Array([0.95047, 1, 1.08883]), Gamma=2.2)])
        )
        resources["/ColorSpace"]["/CSCalR"] = (
            pikepdf.Name.DeviceGray
            if grayscale
            else pikepdf.Array(
                [
                    pikepdf.Name.CalRGB,
                    pikepdf.Dictionary(
                        WhitePoint=pikepdf.Array([0.95047, 1, 1.08883]),
                        Gamma=pikepdf.Array([2.4, 2.4, 2.4]),
                        Matrix=pikepdf.Array([0.4124564, 0.2126729, 0.0193339, 0.3575761, 0.7151522, 0.1191920, 0.1804375, 0.0721750, 0.9503041]),
                    ),
                ]
            )
        )

        pixels, components = raw_image_pixels(grayscale)
        soft_mask_pixels = bytes(round(255 * (x + 1) / 12) for _y in range(12) for x in range(12))
        soft_mask = pdf.make_stream(
            zlib.compress(soft_mask_pixels),
            pikepdf.Dictionary(
                Type=pikepdf.Name.XObject,
                Subtype=pikepdf.Name.Image,
                Width=12,
                Height=12,
                BitsPerComponent=8,
                ColorSpace=pikepdf.Name.DeviceGray,
                Filter=pikepdf.Name.FlateDecode,
            ),
        )
        image = pdf.make_stream(
            zlib.compress(pixels),
            pikepdf.Dictionary(
                Type=pikepdf.Name.XObject,
                Subtype=pikepdf.Name.Image,
                Width=12,
                Height=12,
                BitsPerComponent=8,
                ColorSpace=pikepdf.Name.DeviceGray if grayscale else pikepdf.Array([pikepdf.Name.ICCBased, icc_stream]),
                Filter=pikepdf.Name.FlateDecode,
                SMask=soft_mask,
            ),
        )
        resources["/XObject"]["/Im1"] = image

        form2_content = b".606516 g 0 0 45 35 re f\n" if grayscale else b".1 .7 .25 rg 0 0 45 35 re f\n"
        form2 = pdf.make_stream(
            form2_content,
            pikepdf.Dictionary(Type=pikepdf.Name.XObject, Subtype=pikepdf.Name.Form, FormType=1, BBox=pikepdf.Array([0, 0, 45, 35]), Resources=pikepdf.Dictionary()),
        )
        form1_resources = pikepdf.Dictionary(XObject=pikepdf.Dictionary(F2=form2))
        form1 = pdf.make_stream(
            b"q /F2 Do Q\n",
            pikepdf.Dictionary(Type=pikepdf.Name.XObject, Subtype=pikepdf.Name.Form, FormType=1, BBox=pikepdf.Array([0, 0, 45, 35]), Resources=form1_resources),
        )
        resources["/XObject"]["/F1"] = form1
        resources["/XObject"]["/F2Shared"] = form2

        pattern_content = b".501024 g 0 0 8 8 re f\n.387952 g 0 0 4 4 re f\n" if grayscale else b"1 0 .2 rg 0 0 8 8 re f\n0 .3 1 rg 0 0 4 4 re f\n"
        pattern = pdf.make_stream(
            pattern_content,
            pikepdf.Dictionary(
                Type=pikepdf.Name.Pattern,
                PatternType=1,
                PaintType=1,
                TilingType=1,
                BBox=pikepdf.Array([0, 0, 8, 8]),
                XStep=8,
                YStep=8,
                Resources=pikepdf.Dictionary(),
            ),
        )
        resources["/Pattern"]["/P1"] = pattern

        source_spec = color_spec(pikepdf.Name.DeviceRGB)
        shading = pikepdf.Dictionary(
            ShadingType=2,
            ColorSpace=pikepdf.Name.DeviceGray if grayscale else pikepdf.Name.DeviceRGB,
            Coords=pikepdf.Array([0, 0, 100, 0]),
            Function=pikepdf.Dictionary(
                FunctionType=2,
                Domain=pikepdf.Array([0, 1]),
                C0=pikepdf.Array([source_spec.convert((1.0, 0.1, 0.1))]) if grayscale else pikepdf.Array([1, 0.1, 0.1]),
                C1=pikepdf.Array([source_spec.convert((0.1, 0.2, 1.0))]) if grayscale else pikepdf.Array([0.1, 0.2, 1]),
                N=1,
            ),
            Extend=pikepdf.Array([True, True]),
        )
        resources["/Shading"]["/Sh1"] = shading
        resources["/ExtGState"]["/GSalpha"] = pikepdf.Dictionary(Type=pikepdf.Name.ExtGState, ca=0.5, CA=0.5)

        if grayscale:
            inline = bytes([65, 150, 40, 210])
            extra = (
                b"q 48 0 0 48 40 590 cm /Im1 Do Q\n"
                b"q 24 0 0 24 110 610 cm BI /W 2 /H 2 /BPC 8 /CS /G ID " + inline + b" EI Q\n"
                b"q 1 0 0 1 170 600 cm /F1 Do Q q 1 0 0 1 225 600 cm /F2Shared Do Q\n"
                b"/Pattern cs /P1 scn 290 590 90 45 re f\n"
                b"q 390 590 130 45 re W n /Sh1 sh Q\n"
                b"q /GSalpha gs .480425 g 40 520 100 42 re f Q\n"
                b".451095 g 160 520 100 42 re f\n"
                b".484532 g 280 520 100 42 re f\n"
                b".705780 g 400 520 100 42 re f\n"
                b".399770 g 40 455 100 42 re f\n"
            )
        else:
            inline = bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0])
            extra = (
                b"q 48 0 0 48 40 590 cm /Im1 Do Q\n"
                b"q 24 0 0 24 110 610 cm BI /W 2 /H 2 /BPC 8 /CS /RGB ID " + inline + b" EI Q\n"
                b"q 1 0 0 1 170 600 cm /F1 Do Q q 1 0 0 1 225 600 cm /F2Shared Do Q\n"
                b"/Pattern cs /P1 scn 290 590 90 45 re f\n"
                b"q 390 590 130 45 re W n /Sh1 sh Q\n"
                b"q /GSalpha gs .9 .2 .3 rg 40 520 100 42 re f Q\n"
                b"/CSICC cs .85 .2 .1 scn 160 520 100 42 re f\n"
                b"/CSIDX cs 1 scn 280 520 100 42 re f\n"
                b"/CSCalG cs .7 scn 400 520 100 42 re f\n"
                b"/CSCalR cs .75 .25 .12 scn 40 455 100 42 re f\n"
            )
        old_contents = page.obj["/Contents"]
        page.obj["/Contents"] = pikepdf.Array([old_contents, pdf.make_stream(extra)])

        for annotation in page.obj.get("/Annots", []):
            if annotation.get("/Subtype") == pikepdf.Name.Widget:
                appearance = annotation.get("/AP")
                if appearance and appearance.get("/N") is not None:
                    appearance["/R"] = clone_appearance(pdf, appearance["/N"], grayscale)
                    appearance["/D"] = clone_appearance(pdf, appearance["/N"], grayscale)
        pdf.save(path)


def make_fixture(path: Path, locale: str, grayscale: bool) -> None:
    make_base(path, locale, grayscale)
    augment_fixture(path, grayscale)


def render(path: Path, png_path: Path) -> Image.Image:
    document = pdfium.PdfDocument(str(path))
    try:
        image = document[0].render(scale=1.5, rev_byteorder=True).to_pil().convert("RGB")
        image.save(png_path)
        return image
    finally:
        document.close()


def chroma(image: Image.Image) -> tuple[int, int]:
    maximum = 0
    colored = 0
    for red, green, blue in image.get_flattened_data():
        delta = max(red, green, blue) - min(red, green, blue)
        maximum = max(maximum, delta)
        colored += int(delta > 2)
    return maximum, colored


def semantic_snapshot(path: Path) -> dict[str, object]:
    reader = PdfReader(str(path))
    fields = reader.get_fields() or {}
    links = []
    for page in reader.pages:
        for annotation_ref in page.get("/Annots", []):
            annotation = annotation_ref.get_object()
            action = annotation.get("/A")
            if action and action.get("/URI"):
                links.append(str(action["/URI"]))
    return {
        "pages": len(reader.pages),
        "text": "\n".join((page.extract_text() or "") for page in reader.pages),
        "fields": {name: (str(field.get("/FT")), str(field.get("/V"))) for name, field in fields.items()},
        "links": links,
    }


class ResidualColorScanner(pikepdf.TokenFilter):
    def __init__(self) -> None:
        super().__init__()
        self.operators: list[str] = []

    def handle_token(self, token: pikepdf.Token):
        if token.type_ == pikepdf.TokenType.word and token.value in {"rg", "RG", "k", "K"}:
            self.operators.append(token.value)
        return token


def structural_grayscale_assertions(path: Path) -> int:
    residual: list[str] = []
    with pikepdf.Pdf.open(path) as pdf:
        for page in pdf.pages:
            scanner = ResidualColorScanner()
            page.get_filtered_contents(scanner)
            residual.extend(scanner.operators)
        for obj in pdf.objects:
            if not isinstance(obj, pikepdf.Stream):
                continue
            subtype = str(obj.get("/Subtype"))
            if subtype == "/Image":
                if not bool(obj.get("/ImageMask", False)) and str(obj.get("/ColorSpace")) != "/DeviceGray":
                    raise AssertionError("output image is not DeviceGray")
                continue
            if subtype == "/Form" or int(obj.get("/PatternType", 0)) == 1:
                scanner = ResidualColorScanner()
                resources = obj.get("/Resources")
                wrapper = pikepdf.Page(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Page,
                        MediaBox=pikepdf.Array([0, 0, 100, 100]),
                        Resources=resources if resources is not None else pikepdf.Dictionary(),
                        Contents=obj,
                    )
                )
                wrapper.get_filtered_contents(scanner)
                residual.extend(scanner.operators)
            if obj.get("/ShadingType") is not None and str(obj.get("/ColorSpace")) != "/DeviceGray":
                raise AssertionError("output shading is not DeviceGray")
        for obj in pdf.objects:
            if not hasattr(obj, "get"):
                continue
            resources = obj.get("/Resources")
            if resources:
                for definition in resources.get("/ColorSpace", {}).values():
                    if str(definition) != "/DeviceGray":
                        raise AssertionError("output resource color space is not DeviceGray")
    if residual:
        raise AssertionError(f"residual device color operators: {residual}")
    return len(residual)


def count_appearance_entries(path: Path) -> int:
    count = 0
    with pikepdf.Pdf.open(path) as pdf:
        for page in pdf.pages:
            for annotation in page.obj.get("/Annots", []):
                if annotation.get("/Subtype") != pikepdf.Name.Widget:
                    continue
                appearance = annotation.get("/AP", {})
                for key in ("/N", "/R", "/D"):
                    value = appearance.get(key)
                    if isinstance(value, pikepdf.Stream):
                        count += 1
                    elif isinstance(value, pikepdf.Dictionary):
                        count += sum(isinstance(item, pikepdf.Stream) for item in value.values())
    return count


def edit_field(source: Path, destination: Path, locale: str) -> str:
    reader = PdfReader(str(source))
    writer = PdfWriter()
    writer.clone_document_from_reader(reader)
    value = "Changed Arabic corpus value" if locale == "ar" else "Changed grayscale value"
    writer.update_page_form_field_values(None, {"customer_note": value}, auto_regenerate=False)
    with destination.open("wb") as stream:
        writer.write(stream)
    return value


def validate_corpus(locale: str, source: Path, expected: Path, output: Path, workdir: Path, stats: TransformStats) -> CorpusResult:
    source_snapshot = semantic_snapshot(source)
    output_snapshot = semantic_snapshot(output)
    source_image = render(source, workdir / f"{locale}-source.png")
    expected_image = render(expected, workdir / f"{locale}-expected.png")
    output_image = render(output, workdir / f"{locale}-output.png")
    output_max, output_colored = chroma(output_image)
    _expected_max, expected_colored = chroma(expected_image)
    difference = ImageChops.difference(output_image, expected_image)
    difference_stat = ImageStat.Stat(difference)
    mae = sum(difference_stat.mean) / 3.0
    max_delta = max(channel[1] for channel in difference.getextrema())
    if source_snapshot != output_snapshot:
        raise AssertionError(f"{locale} structural semantics changed")
    if output_colored or output_max > 2:
        raise AssertionError(f"{locale} output retains visible color")
    if expected_colored:
        raise AssertionError(f"{locale} expected fixture is not grayscale")
    if mae > 3.0 or max_delta > 96:
        raise AssertionError(f"{locale} visual result diverges from independent expected fixture: {mae=}, {max_delta=}")
    residual_color_operators = structural_grayscale_assertions(output)

    edited = workdir / f"{locale}-edited.pdf"
    edited_output = workdir / f"{locale}-edited-gray.pdf"
    edited_value = edit_field(output, edited, locale)
    edited_pretransform_image = render(edited, workdir / f"{locale}-edited-before-transform.png")
    _edited_pretransform_max, edited_pretransform_colored = chroma(edited_pretransform_image)
    if edited_pretransform_colored:
        raise AssertionError("field appearance regeneration reintroduced visible color before reprocessing")
    appearance_entries_after_edit = count_appearance_entries(edited)
    if appearance_entries_after_edit < 9:
        raise AssertionError("field editing removed required N/R/D appearance states")
    transform(edited, edited_output)
    edited_snapshot = semantic_snapshot(edited_output)
    if edited_snapshot["fields"]["customer_note"][1] != edited_value:
        raise AssertionError("edited field value was not preserved")
    edited_image = render(edited_output, workdir / f"{locale}-edited-gray.png")
    _edited_max, edited_colored = chroma(edited_image)
    if edited_colored:
        raise AssertionError("field editing or appearance regeneration reintroduced color")

    with pikepdf.Pdf.open(output) as pdf:
        warnings = pdf.check_pdf_syntax()
    return CorpusResult(
        locale=locale,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        output_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        page_count=int(output_snapshot["pages"]),
        text_equal=source_snapshot["text"] == output_snapshot["text"],
        fields_equal=source_snapshot["fields"] == output_snapshot["fields"],
        links_equal=source_snapshot["links"] == output_snapshot["links"],
        output_colored_pixels=output_colored,
        output_max_chroma=output_max,
        expected_colored_pixels=expected_colored,
        render_mae=round(mae, 6),
        render_max_delta=max_delta,
        edited_field_value=edited_value,
        edited_pretransform_colored_pixels=edited_pretransform_colored,
        edited_output_colored_pixels=edited_colored,
        appearance_entries_after_edit=appearance_entries_after_edit,
        residual_color_operators=residual_color_operators,
        syntax_warnings=len(warnings),
        stats={key: int(value) for key, value in asdict(stats).items()},
    )


def verify_fail_closed(source: Path, workdir: Path) -> list[str]:
    cases: list[tuple[str, Path]] = []

    def append_content(pdf: pikepdf.Pdf, page: pikepdf.Page, payload: bytes) -> None:
        streams = page_content_streams(page.obj)
        page.obj["/Contents"] = pikepdf.Array([*streams, pdf.make_stream(payload)])

    with pikepdf.Pdf.open(source) as pdf:
        page = pdf.pages[0]
        bad_image = pdf.make_stream(
            b"not-jpx",
            pikepdf.Dictionary(Type=pikepdf.Name.XObject, Subtype=pikepdf.Name.Image, Width=1, Height=1, BitsPerComponent=8, ColorSpace=pikepdf.Name.DeviceRGB, Filter=pikepdf.Name.JPXDecode),
        )
        page.Resources.XObject["/Unsupported"] = bad_image
        append_content(pdf, page, b"/Unsupported Do")
        path = workdir / "unsupported-image-filter.pdf"
        pdf.save(path)
        cases.append(("unsupported-image-filter", path))
    with pikepdf.Pdf.open(source) as pdf:
        page = pdf.pages[0]
        form = page.Resources.XObject["/F1"]
        form.Resources.XObject["/Cycle"] = form
        form.write(bytes(form.read_bytes()) + b" /Cycle Do")
        path = workdir / "cyclic-form.pdf"
        pdf.save(path)
        cases.append(("cyclic-form", path))
    with pikepdf.Pdf.open(source) as pdf:
        pdf.Root["/Stage2SignatureProbe"] = pikepdf.Dictionary(Type=pikepdf.Name.Sig, ByteRange=pikepdf.Array([0, 1, 2, 3]))
        path = workdir / "signed.pdf"
        pdf.save(path)
        cases.append(("signed", path))
    with pikepdf.Pdf.open(source) as pdf:
        path = workdir / "encrypted.pdf"
        pdf.save(path, encryption=pikepdf.Encryption(owner="stage2-owner", user="stage2-user", R=6, aes=True))
        cases.append(("encrypted", path))
    malformed = workdir / "malformed.pdf"
    data = source.read_bytes()
    malformed.write_bytes(data[: len(data) // 4])
    cases.append(("malformed", malformed))
    with pikepdf.Pdf.open(source) as pdf:
        pdf.pages[0].obj["/Contents"] = pikepdf.Array([None])
        path = workdir / "null-page-contents.pdf"
        pdf.save(path)
        cases.append(("null-page-contents", path))
    with pikepdf.Pdf.open(source) as pdf:
        pdf.pages[0].obj["/Contents"] = pikepdf.Dictionary()
        path = workdir / "malformed-page-contents.pdf"
        pdf.save(path)
        cases.append(("malformed-page-contents", path))
    with pikepdf.Pdf.open(source) as pdf:
        invalid_later_page = pdf.add_blank_page()
        invalid_later_page.obj["/Contents"] = pikepdf.Array([pdf.make_stream(b"q Q"), None])
        path = workdir / "mixed-page-contents.pdf"
        pdf.save(path)
        cases.append(("mixed-page-contents", path))
    with pikepdf.Pdf.open(source) as pdf:
        page = pdf.pages[0]
        page.Resources.ColorSpace["/Spot"] = pikepdf.Array([pikepdf.Name.Separation, pikepdf.Name.Spot, pikepdf.Name.DeviceRGB, pikepdf.Dictionary(FunctionType=2, Domain=pikepdf.Array([0, 1]), C0=pikepdf.Array([0, 0, 0]), C1=pikepdf.Array([1, 0, 0]), N=1)])
        append_content(pdf, page, b"/Spot cs .5 scn")
        path = workdir / "spot-color.pdf"
        pdf.save(path)
        cases.append(("spot-color", path))

    explicit_contents_rejections = {
        "null-page-contents",
        "malformed-page-contents",
        "mixed-page-contents",
    }
    rejected: list[str] = []
    for name, candidate in cases:
        destination = workdir / f"unexpected-{name}.pdf"
        try:
            transform(candidate, destination)
        except UnsupportedPdf:
            if destination.exists():
                raise AssertionError(f"{name} left a partial output")
            rejected.append(name)
        except (pikepdf.PdfError, TimeoutError):
            if destination.exists():
                raise AssertionError(f"{name} left a partial output")
            if name in explicit_contents_rejections:
                raise AssertionError(f"{name} was not rejected by explicit page Contents validation")
            rejected.append(name)
        else:
            raise AssertionError(f"{name} did not fail closed")
    return rejected


def _self_test(output_directory: Path) -> Stage2Result:
    output_directory.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    temp_root: Path | None = None
    corpus_results: list[CorpusResult] = []
    fail_closed_cases: list[str] = []
    with tempfile.TemporaryDirectory(prefix="dip-gray-stage2-", dir=str(output_directory.parent)) as temporary:
        temp_root = Path(temporary)
        for locale in ("en", "ar"):
            source = output_directory / f"{locale}-source.pdf"
            expected = output_directory / f"{locale}-expected.pdf"
            output = output_directory / f"{locale}-output.pdf"
            make_fixture(source, locale, grayscale=False)
            make_fixture(expected, locale, grayscale=True)
            stats = transform(source, output)
            corpus_results.append(validate_corpus(locale, source, expected, output, temp_root, stats))
        fail_closed_cases = verify_fail_closed(output_directory / "en-source.pdf", temp_root)
    if temp_root is None or temp_root.exists():
        raise AssertionError("temporary Stage 2 directory was not cleaned")
    result = Stage2Result(
        pikepdf_version=pikepdf.__version__,
        libqpdf_version=pikepdf.__libqpdf_version__,
        pillow_version=Image.__version__,
        lcms_version=str(features.version("littlecms2")),
        elapsed_ms=round((time.monotonic() - started) * 1000),
        corpus=corpus_results,
        fail_closed_cases=fail_closed_cases,
        unsupported_by_design=[
            "JPX/JBIG2/CCITT/DCT and other non-Flate image filters",
            "unprofiled CMYK images",
            "Separation/DeviceN/Lab and uncolored patterns",
            "non-axial or multi-function shadings",
            "XFA, JavaScript-generated appearances, signatures, and encrypted inputs",
            "arbitrary appearance generation and external-viewer regeneration guarantees",
        ],
        temp_cleanup_verified=True,
    )
    (output_directory / "metrics.json").write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def self_test(output_directory: Path) -> Stage2Result:
    """Run Stage 2 with its baseline policy even when Stage 3A is also loaded."""
    active_policy = (color_spec, image_to_gray, StructuralTransformer)
    try:
        globals()["color_spec"] = STAGE2_COLOR_SPEC
        globals()["image_to_gray"] = STAGE2_IMAGE_TO_GRAY
        globals()["StructuralTransformer"] = STAGE2_STRUCTURAL_TRANSFORMER
        return _self_test(output_directory)
    finally:
        globals()["color_spec"], globals()["image_to_gray"], globals()["StructuralTransformer"] = active_policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("output/pdf/structural-grayscale-stage2"))
    args = parser.parse_args()
    if not args.self_test:
        parser.error("Stage 2 exposes only --self-test; it is not a production converter")
    result = self_test(args.output_dir.resolve())
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
