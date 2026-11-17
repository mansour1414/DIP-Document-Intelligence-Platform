#!/usr/bin/env python3
"""DIP Phase 0C -- deterministic, offline-only fixture builders for R1/R2 PoC.

EXPERIMENTAL / ISOLATED. NOT production code. NO new dependencies (stdlib only).

This module builds ONLY harmless test artefacts:
  * the standard EICAR anti-virus TEST signature (split into two benign halves so
    the source itself does not statically trigger a scanner),
  * benign text controls,
  * small ZIP32 / ZIP64 containers built byte-for-byte (no external tools),
  * small ISO 32000-1-style PDFs with explicitly referenced attachment trees.

No real malware, no executable payloads, no network, no subprocess, no disk writes.
The synthetic marker probes below (e.g. /Encrypt, /ObjStm, second revision) are
LABELLED AS SYNTHETIC PARSER PROBES. They are NOT genuine encrypted PDFs and are
NEVER reported as verified qpdf/PDF.js/qpdf --json capability.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# Harmless test corpus (mirrors scripts/experiments/clamav-phase0*-evidence.py)
# ---------------------------------------------------------------------------
EICAR_PART_1 = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
EICAR_PART_2 = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_BYTES = EICAR_PART_1 + EICAR_PART_2
EICAR_EXPECTED_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
BENIGN_BYTES = b"DIP Phase 0C benign negative control. No executable content.\n"

assert hashlib.sha256(EICAR_BYTES).hexdigest() == EICAR_EXPECTED_SHA256, "EICAR test string drift"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def deflate_raw(data: bytes) -> bytes:
    """Raw DEFLATE (wbits=-15), as used by ZIP method 8."""
    comp = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-zlib.MAX_WBITS)
    return comp.compress(data) + comp.flush()


def zlib_wrapped(data: bytes) -> bytes:
    """zlib-wrapped DEFLATE, as used by PDF /Filter /FlateDecode."""
    return zlib.compress(data, 9)


# ---------------------------------------------------------------------------
# ZIP fixture builder (byte-exact; supports ZIP32, ZIP64, forged sizes, lies)
# ---------------------------------------------------------------------------
@dataclass
class Member:
    name: str
    payload: bytes
    method: int = 0                     # 0 = STORED, 8 = DEFLATE, other = unsupported
    flags: int = 0                      # bit 0 = encrypted, 0x40 / 0x2000 = strong encryption
    crc: int | None = None              # None => zlib.crc32(payload)
    usize_lie: int | None = None        # forged declared uncompressed size in CDH
    lfh_zip64: bool = False             # 0xFFFFFFFF LFH sizes + 0x0001 extra field
    cdh_zip64: bool = False             # 0xFFFFFFFF CDH sizes + 0x0001 extra field
    version_needed: int = 20
    external_attrs: int = 0


def _zip64_extra(uncompressed: int, compressed: int, local_offset: int = 0,
                 *, include_offset: bool = False) -> bytes:
    values = [uncompressed, compressed]
    if include_offset:
        values.append(local_offset)
    body = b"".join(struct.pack("<Q", value) for value in values)
    return struct.pack("<HH", 0x0001, len(body)) + body


def build_zip(members: Iterable[Member], *, zip64_eocd: bool = False) -> bytes:
    """Build a small single-disk ZIP container byte-for-byte.

    `zip64_eocd=True` appends a genuine ZIP64 EOCD record + ZIP64 EOCD locator and
    sets the classic EOCD fields to their 0xFFFF / 0xFFFFFFFF sentinels.
    """
    members = list(members)
    local_parts: list[bytes] = []
    cd_parts: list[bytes] = []
    offset = 0

    for member in members:
        name_b = member.name.encode("utf-8")
        raw = member.payload
        compressed = deflate_raw(raw) if member.method == 8 else raw
        crc = member.crc if member.crc is not None else (zlib.crc32(raw) & 0xFFFFFFFF)
        csize, usize = len(compressed), len(raw)
        flags = member.flags
        version = member.version_needed

        lfh_extra = _zip64_extra(usize, csize) if member.lfh_zip64 else b""
        cdh_extra = _zip64_extra(usize, csize) if member.cdh_zip64 else b""
        lfh_csize = 0xFFFFFFFF if member.lfh_zip64 else csize
        lfh_usize = 0xFFFFFFFF if member.lfh_zip64 else usize
        cdh_csize = 0xFFFFFFFF if member.cdh_zip64 else csize
        cdh_usize = member.usize_lie if member.usize_lie is not None else (
            0xFFFFFFFF if member.cdh_zip64 else usize
        )

        lfh = struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, version, flags, member.method, 0, 0,
            crc, lfh_csize, lfh_usize, len(name_b), len(lfh_extra),
        )
        lfh_offset = offset
        local_parts.extend([lfh, name_b, lfh_extra, compressed])
        offset += len(lfh) + len(name_b) + len(lfh_extra) + len(compressed)

        cdh = struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, version, version, flags,
            member.method, 0, 0, crc, cdh_csize, cdh_usize,
            len(name_b), len(cdh_extra), 0, 0, 0, member.external_attrs, lfh_offset,
        )
        cd_parts.extend([cdh, name_b, cdh_extra])

    cd_offset = offset
    cd_bytes = b"".join(cd_parts)
    parts: list[bytes] = [*local_parts, cd_bytes]

    if zip64_eocd:
        z64_eocd_offset = cd_offset + len(cd_bytes)
        parts.append(struct.pack(
            "<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0,
            len(members), len(members), len(cd_bytes), cd_offset,
        ))
        parts.append(struct.pack("<IIQI", 0x07064B50, 0, z64_eocd_offset, 1))

    parts.append(struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0,
        0xFFFF if zip64_eocd else len(members),
        0xFFFF if zip64_eocd else len(members),
        0xFFFFFFFF if zip64_eocd else len(cd_bytes),
        0xFFFFFFFF if zip64_eocd else cd_offset,
        0,
    ))
    return b"".join(parts)


def zip32(payload: bytes, name: str = "payload.bin", *, method: int = 0) -> bytes:
    return build_zip([Member(name=name, payload=payload, method=method)])


def zip64(payload: bytes, name: str = "payload.bin") -> bytes:
    """Genuine ZIP64 EOCD + locator + sentinels + 0x0001 extra fields (same corpus style)."""
    return build_zip(
        [Member(name=name, payload=payload, method=8, version_needed=45,
                lfh_zip64=True, cdh_zip64=True)],
        zip64_eocd=True,
    )


def nested_zip_chain(depth: int, payload: bytes, *, inner_zip64: bool = False) -> bytes:
    """Wrap `payload` in `depth` nested ZIP containers (spoofed .txt names)."""
    data = zip64(payload) if inner_zip64 else zip32(payload)
    for level in range(depth - 1):
        data = build_zip([Member(name=f"layer{level}.txt", payload=data, method=8)])
    return data


# ---------------------------------------------------------------------------
# PDF fixture builder (small ISO 32000-1 style documents with exact xref)
# ---------------------------------------------------------------------------
def _utf16be_hex(text: str) -> bytes:
    encoded = b"\xfe\xff" + text.encode("utf-16-be")
    return b"<" + encoded.hex().upper().encode("ascii") + b">"


@dataclass
class PdfSpec:
    """A narrow PDF fixture spec. Only the attachment/reference graph is varied."""
    attachment: bytes | None = None
    attachment_name: str = "attachment.bin"
    mode: str = "names_tree"        # names_tree | filespec_ef | annotation | af | unreferenced
    compress_attachment_stream: bool = False
    duplicate_object_ids: bool = False
    incremental_revision: bool = False
    synthetic_encrypt_marker: bool = False
    include_object_stream_marker: bool = False
    malformed: bool = False
    extra_catalog_refs: list[int] = field(default_factory=list)


def build_pdf(spec: PdfSpec) -> bytes:
    """Build a deterministic PDF with exact xref offsets.

    Attachment wiring supported by the PoC parser (ALL explicitly referenced):
      names_tree   : /Catalog -> /Names << /EmbeddedFiles >> -> /Names [(name) ref]
                     -> /Filespec -> /EF << /F | /UF ref >> -> /EmbeddedFile stream
      filespec_ef  : /Catalog -> /Names /EmbeddedFiles -> /Filespec with TWO /EF keys
      annotation   : /Page /Annots [ /FileAttachment /FS -> /Filespec -> /EF ]
      af           : /Catalog -> /AF [ /Filespec ] (ISO 32000-2 associated files)
      unreferenced : an /EmbeddedFile stream with NO /EF reference (coverage gap probe)

    SYNTHETIC marker probes are explicitly labelled and are NOT genuine encryption,
    object streams, or incremental-update implementations.
    """
    stream_body = b"BT /F1 12 Tf 48 720 Td (DIP Phase 0C R1 offline control) Tj ET\n"
    att = spec.attachment
    att_name_b = spec.attachment_name.encode("ascii")
    has_att = att is not None

    objects: dict[int, bytes] = {}
    objects[2] = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    objects[5] = b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    objects[4] = (
        f"4 0 obj\n<< /Length {len(stream_body)} >>\nstream\n".encode("ascii")
        + stream_body + b"endstream\nendobj\n"
    )

    if has_att:
        payload = zlib_wrapped(att) if spec.compress_attachment_stream else att
        filter_key = b" /Filter /FlateDecode" if spec.compress_attachment_stream else b""
        objects[6] = (
            b"6 0 obj\n<< /Type /Filespec /F (" + att_name_b + b") /UF "
            + _utf16be_hex(spec.attachment_name)
            + b" /EF << /F 8 0 R" + (b" /UF 8 0 R" if spec.mode == "filespec_ef" else b"")
            + b" >> /Desc (DIP Phase 0C bounded attachment probe) >>\nendobj\n"
        )
        objects[8] = (
            f"8 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fzip /Length {len(payload)}"
            + filter_key.decode("ascii")
            + f" /Params << /Size {len(att)} >> >>\nstream\n"
        ).encode("ascii") + payload + b"\nendstream\nendobj\n"
        objects[9] = b"9 0 obj\n<< /Title " + _utf16be_hex("DIP R1 | وثيقة اختبار") + b" >>\nendobj\n"
        info_ref = b" /Info 9 0 R"
        catalog_refs: list[bytes] = []

        if spec.mode in {"names_tree", "filespec_ef"}:
            objects[7] = b"7 0 obj\n<< /Names [ (" + att_name_b + b") 6 0 R ] >>\nendobj\n"
            catalog_refs.append(b" /Names << /EmbeddedFiles 7 0 R >>")
        elif spec.mode == "af":
            catalog_refs.append(b" /AF [ 6 0 R ]")
        elif spec.mode == "annotation":
            objects[10] = (
                b"10 0 obj\n<< /Type /Annot /Subtype /FileAttachment /FS 6 0 R "
                b"/Rect [ 72 72 90 90 ] /Name /PushPin >>\nendobj\n"
            )
            annots = b" /Annots [ 10 0 R ]"
        elif spec.mode == "unreferenced":
            # Deliberately NO reference from Catalog to object 8: coverage gap probe.
            pass
        else:
            raise ValueError(f"unknown PDF attachment mode: {spec.mode}")

        if spec.mode == "annotation":
            objects[3] = (
                b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R"
                + annots + b" >>\nendobj\n"
            )
        else:
            objects[3] = (
                b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n"
            )
        for ref in spec.extra_catalog_refs:
            catalog_refs.append(f" /DIPExtra {ref} 0 R".encode("ascii"))
        objects[1] = (
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R"
            + b"".join(catalog_refs) + b" >>\nendobj\n"
        )
    else:
        objects[3] = (
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n"
        )
        objects[6] = b"6 0 obj\n<< /Title " + _utf16be_hex("DIP R1 | وثيقة اختبار") + b" >>\nendobj\n"
        objects[1] = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        info_ref = b" /Info 6 0 R"

    if spec.include_object_stream_marker:
        objects[11] = (
            b"11 0 obj\n<< /Type /ObjStm /N 0 /First 0 /Length 0 >>\nstream\n"
            b"endstream\nendobj\n"
        )
    if spec.synthetic_encrypt_marker:
        objects[12] = b"12 0 obj\n<< /Filter /Standard /V 5 /R 6 >>\nendobj\n"

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for number in sorted(objects):
        offsets[number] = len(out)
        out.extend(objects[number])

    if spec.duplicate_object_ids:
        # Parser-ambiguity probe: two definitions of the same indirect object id.
        out.extend(objects[8] if has_att else objects[6])

    if spec.malformed:
        # No xref, no startxref, no %%EOF: must fail closed as MALFORMED_PDF.
        return bytes(out)

    xref_pos = len(out)
    size = max(offsets) + 1
    out.extend(f"xref\n0 {size}\n0000000000 65535 f \n".encode("ascii"))
    for number in range(1, size):
        if number in offsets:
            out.extend(f"{offsets[number]:010d} 00000 n \n".encode("ascii"))
        else:
            out.extend(b"0000000000 00000 f \n")
    encrypt_ref = b" /Encrypt 12 0 R" if spec.synthetic_encrypt_marker else b""
    out.extend(
        f"trailer\n<< /Size {size} /Root 1 0 R".encode("ascii")
        + info_ref + encrypt_ref + b" >>\n"
        + f"startxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )

    if spec.incremental_revision:
        # SYNTHETIC second-revision probe (two %%EOF markers), NOT a real update chain.
        rev_obj_at = len(out)
        out.extend(b"13 0 obj\n<< /Note (synthetic second revision marker) >>\nendobj\n")
        rev_xref_at = len(out)
        out.extend(
            f"xref\n13 1\n{rev_obj_at:010d} 00000 n \n".encode("ascii")
            + f"trailer\n<< /Size 14 /Root 1 0 R /Prev {xref_pos} >>\n".encode("ascii")
            + f"startxref\n{rev_xref_at}\n%%EOF\n".encode("ascii")
        )
    return bytes(out)


def pdf_attachment(payload: bytes, *, mode: str = "names_tree", **kwargs: object) -> bytes:
    return build_pdf(PdfSpec(attachment=payload, mode=mode, **kwargs))  # type: ignore[arg-type]

