/**
 * Phase 0B Isolated Experimental Prototype — Bounded ZIP / OOXML Structural Preflight
 *
 * STATUS: EXPERIMENTAL PROTOTYPE ONLY — NOT INTEGRATED INTO PRODUCTION UPLOAD VALIDATION.
 * Provisional governance reference: CLAMAV-CR-P02 (PROPOSED — NOT APPROVED).
 *
 * Purpose:
 *   Mitigate verified ClamAV 1.5.4 ZIP/OOXML parser gaps (upstream issues #1527, #1928)
 *   before files reach clamd, without relying on unreviewed upstream PR #1845 and WITHOUT
 *   decompressing untrusted archive payloads.
 *
 * Security invariants:
 *   1. ZERO DECOMPRESSION: strictly inspects ZIP metadata headers (EOCD, ZIP64 EOCD/Locator,
 *      Central Directory, Local File Headers, Extra Fields, and Data Descriptor geometry).
 *   2. BOUNDED RESOURCES: hard caps on input size, entry count, CD bytes, extra field bytes,
 *      and declared uncompressed sizes.
 *   3. NUANCED VERSION_NEEDED=45 HANDLING: does NOT blindly reject all version_needed=45
 *      archives; allows benign version_needed=45 archives that contain no ZIP64 structures,
 *      no 0x0001 extra fields, no ZIP64 sentinels, and no 64-bit Data Descriptors.
 *   4. EXPLICIT RESIDUAL-RISK DISCLOSURE:
 *      (a) OOXML-only preflight does NOT inspect ZIP64 archives embedded inside PDF streams
 *          (upstream ClamAV issue #1888). PDF inputs (including password-protected PDFs required
 *          by DIP's unlock-pdf tool) pass through with an explicit residual-risk warning code.
 *      (b) Zero-decompression preflight CANNOT inspect the interior of compressed nested
 *          archives (e.g., a DEFLATE-compressed ZIP64 archive stored inside a ZIP32/OOXML
 *          container). Known archive-extension nested members emit an explicit residual-risk
 *          warning, and ANY compressed nested archive regardless of filename remains an open
 *          residual risk.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export type DeclaredInputKind = 'auto' | 'docx' | 'xlsx' | 'pptx' | 'ooxml' | 'zip' | 'pdf';

export type CompressionPolicy = 'ooxml-strict' | 'clamav-supported';

export type PreflightAction = 'ALLOW' | 'ALLOW_WITH_RESIDUAL_RISK_WARNING' | 'REJECT';

export type PreflightReasonCode =
  | 'OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64'
  | 'COMPRESSED_NESTED_ARCHIVE_NOT_INSPECTED_RESIDUAL_RISK'
  | 'UNCOMPRESSED_NESTED_ARCHIVE_NOT_RECURSIVELY_INSPECTED'
  | 'BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES'
  | 'LIMIT_EXCEEDED_INPUT_SIZE'
  | 'LIMIT_EXCEEDED_MAX_ENTRIES'
  | 'LIMIT_EXCEEDED_CENTRAL_DIRECTORY_SIZE'
  | 'LIMIT_EXCEEDED_DECLARED_MEMBER_SIZE'
  | 'LIMIT_EXCEEDED_DECLARED_TOTAL_SIZE'
  | 'ZIP64_EOCD_LOCATOR_PRESENT'
  | 'ZIP64_EOCD_RECORD_PRESENT'
  | 'ZIP64_EOCD_SENTINEL'
  | 'ZIP64_CDH_SENTINEL'
  | 'ZIP64_LFH_SENTINEL'
  | 'ZIP64_EXTRA_FIELD_PRESENT'
  | 'ZIP64_DATA_DESCRIPTOR_DETECTED'
  | 'ZIP64_SIZE_OVERFLOW'
  | 'UNSUPPORTED_COMPRESSION_METHOD'
  | 'ENCRYPTED_MEMBER_TRADITIONAL'
  | 'ENCRYPTED_MEMBER_STRONG'
  | 'ENCRYPTED_CENTRAL_DIRECTORY'
  | 'ENCRYPTED_MEMBER_AES'
  | 'MALFORMED_NOT_ZIP_MAGIC'
  | 'MALFORMED_MISSING_EOCD'
  | 'MALFORMED_AMBIGUOUS_EOCD'
  | 'MALFORMED_MULTI_DISK_UNSUPPORTED'
  | 'MALFORMED_CENTRAL_DIRECTORY'
  | 'MALFORMED_LOCAL_FILE_HEADER'
  | 'MALFORMED_LFH_CDH_MISMATCH'
  | 'MALFORMED_EXTRA_FIELD'
  | 'MALFORMED_DATA_DESCRIPTOR'
  | 'MALFORMED_OVERLAPPING_MEMBERS'
  | 'MALFORMED_PREAMBLE_BYTES'
  | 'MALFORMED_TRAILING_DATA_AFTER_EOCD'
  | 'MALFORMED_OOXML_MISSING_CONTENT_TYPES';

export interface PreflightFinding {
  readonly severity: 'reject' | 'warning' | 'info';
  readonly code: PreflightReasonCode;
  readonly message: string;
  readonly entryIndex?: number;
  readonly entryName?: string;
}

export interface ZipPreflightOptions {
  readonly declaredKind?: DeclaredInputKind;
  readonly compressionPolicy?: CompressionPolicy;
  readonly maxInputBytes?: number;
  readonly maxEntries?: number;
  readonly maxCentralDirectoryBytes?: number;
  readonly maxExtraFieldBytes?: number;
  readonly maxDeclaredMemberBytes?: number;
  readonly maxDeclaredTotalBytes?: number;
  readonly requireOoxmlContentTypes?: boolean;
}

export interface ZipMemberSummary {
  readonly index: number;
  readonly name: string;
  readonly versionNeededCdh: number;
  readonly versionNeededLfh: number;
  readonly flags: number;
  readonly method: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly lfhOffset: number;
  readonly dataOffset: number;
  readonly hasDataDescriptor: boolean;
  readonly hasZip64ExtraField: boolean;
}

export interface ResidualRiskCapabilities {
  readonly inspectsPdfEmbeddedZip64: false;
  readonly inspectsCompressedNestedArchives: false;
  readonly inspectsUncompressedNestedArchivesRecursively: false;
}

export interface ZipPreflightReport {
  readonly prototypeOnly: true;
  readonly decompressionPerformed: false;
  readonly action: PreflightAction;
  readonly scope: 'ZIP_OOXML_INSPECTED' | 'NON_OOXML_PDF_PASSTHROUGH' | 'REJECTED_BEFORE_PARSE';
  readonly inputBytes: number;
  readonly declaredKind: DeclaredInputKind;
  readonly compressionPolicy: CompressionPolicy;
  readonly entryCount: number;
  readonly totalDeclaredUncompressedBytes: number;
  readonly maxMemberDeclaredUncompressedBytes: number;
  readonly benignVersionNeeded45Count: number;
  readonly residualRiskCapabilities: ResidualRiskCapabilities;
  readonly rejectCodes: readonly PreflightReasonCode[];
  readonly warningCodes: readonly PreflightReasonCode[];
  readonly infoCodes: readonly PreflightReasonCode[];
  readonly findings: readonly PreflightFinding[];
  readonly members: readonly ZipMemberSummary[];
}

// ZIP signatures (little-endian 32-bit constants)
const SIG_LFH = 0x04034b50;
const SIG_DATA_DESCRIPTOR = 0x08074b50;
const SIG_CDH = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;

// Extra field header IDs
const EXTRA_ID_ZIP64 = 0x0001;
const EXTRA_ID_WINZIP_AES = 0x9901;

// Sentinel thresholds
const SENTINEL_U16 = 0xffff;
const SENTINEL_U32 = 0xffffffff;

// Compression method allowlists
const OOXML_STRICT_METHODS: ReadonlySet<number> = new Set([0, 8]);
const CLAMAV_SUPPORTED_METHODS: ReadonlySet<number> = new Set([0, 6, 8, 9, 12]);

// Known nested archive extensions (heuristic warning only; compressed nested archives with
// arbitrary extensions also cannot be inspected under zero-decompression preflight).
const NESTED_ARCHIVE_EXTENSIONS: readonly string[] = [
  '.zip',
  '.docx',
  '.xlsx',
  '.pptx',
  '.docm',
  '.xlsm',
  '.pptm',
  '.odt',
  '.ods',
  '.odp',
  '.jar',
  '.7z',
  '.rar',
  '.tar',
  '.gz',
  '.tgz',
  '.bz2',
  '.xz',
];

/**
 * Authoritative DIP baseline & Stage 4 ClamAV reference limits (read-only metadata):
 *   - src/config/index.ts BASE_LIMITS.maxBytes = 100 MiB (104,857,600 B)
 *   - src/lib/malware/index.ts MALWARE_SCAN_MAX_BYTES = 100 MiB (104,857,600 B)
 *   - docs/operations/experimental/clamav-arm64-stage4-candidate.conf:
 *       StreamMaxLength = 110M, MaxFileSize = 110M, MaxScanSize = 400M, MaxFiles = 10000
 *
 * Defaults below are aligned with those baseline values so this experimental prototype does
 * NOT silently introduce stricter upload/scanner ceilings. The single experimental-only
 * structural bound (maxCentralDirectoryBytes = 16 MiB) has production compatibility explicitly
 * marked NOT_VERIFIED until validated against real production OOXML corpora.
 */
export const BASELINE_LIMIT_PROVENANCE = {
  dipToolMaxInputBytes: 100 * 1024 * 1024, // src/config/index.ts BASE_LIMITS.maxBytes
  dipMalwareScanMaxBytes: 100 * 1024 * 1024, // src/lib/malware/index.ts MALWARE_SCAN_MAX_BYTES
  clamdStreamMaxLengthBytes: 110 * 1024 * 1024, // clamav-arm64-stage4-candidate.conf StreamMaxLength 110M
  clamdMaxFileSizeBytes: 110 * 1024 * 1024, // clamav-arm64-stage4-candidate.conf MaxFileSize 110M
  clamdMaxScanSizeBytes: 400 * 1024 * 1024, // clamav-arm64-stage4-candidate.conf MaxScanSize 400M
  clamdMaxFiles: 10000, // clamav-arm64-stage4-candidate.conf MaxFiles 10000
  experimentalOnlyBounds: {
    maxCentralDirectoryBytes: {
      valueBytes: 16 * 1024 * 1024,
      scope: 'EXPERIMENTAL_ONLY',
      productionCompatibility: 'NOT_VERIFIED',
      rationale:
        'Bounds in-memory Central Directory parsing (~1.6 KiB average per entry across 10,000 entries); real-world corpus validation required before production adoption.',
    },
  },
} as const;

export const DEFAULT_ZIP_PREFLIGHT_LIMITS = {
  maxInputBytes: 100 * 1024 * 1024, // 100 MiB — aligned with DIP BASE_LIMITS.maxBytes & MALWARE_SCAN_MAX_BYTES
  maxEntries: 10000, // 10,000 — aligned with clamav-arm64-stage4-candidate.conf MaxFiles 10000
  maxCentralDirectoryBytes: 16 * 1024 * 1024, // 16 MiB — EXPERIMENTAL ONLY (production compatibility NOT VERIFIED)
  maxExtraFieldBytes: 65535, // 65,535 B — ZIP APPNOTE u16 ceiling
  maxDeclaredMemberBytes: 110 * 1024 * 1024, // 110 MiB — aligned with clamav-arm64-stage4-candidate.conf MaxFileSize 110M
  maxDeclaredTotalBytes: 400 * 1024 * 1024, // 400 MiB — aligned with clamav-arm64-stage4-candidate.conf MaxScanSize 400M
} as const;

interface ParsedExtraField {
  readonly id: number;
  readonly size: number;
  readonly dataOffset: number;
}

interface MemberRange {
  readonly index: number;
  readonly name: string;
  readonly lfhOffset: number;
  readonly dataOffset: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly crc32: number;
  readonly hasDataDescriptor: boolean;
  readonly endOfCompressedData: number;
}

function readU16LE(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU32LE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

/**
 * ES2017-safe unsigned 64-bit little-endian reader (no BigInt dependency).
 * Returns `{ value, overflow }` where overflow is true if > Number.MAX_SAFE_INTEGER.
 */
function readU64LESafe(bytes: Uint8Array, offset: number): { value: number; overflow: boolean } {
  const lo = readU32LE(bytes, offset);
  const hi = readU32LE(bytes, offset + 4);
  if (hi > 0x001fffff) {
    return { value: Number.MAX_SAFE_INTEGER, overflow: true };
  }
  return { value: hi * 4294967296 + lo, overflow: false };
}

function decodeEntryName(bytes: Uint8Array, offset: number, length: number, flags: number): string {
  // General Purpose Bit 11 (0x0800) indicates UTF-8 filename encoding per APPNOTE 6.3.x.
  // Decode UTF-8 so Arabic/Unicode member paths remain intact; sanitize ASCII control bytes.
  const decoded =
    (flags & 0x0800) !== 0
      ? Buffer.from(bytes.buffer, bytes.byteOffset + offset, length).toString('utf8')
      : Buffer.from(bytes.buffer, bytes.byteOffset + offset, length).toString('latin1');
  let out = '';
  for (let i = 0; i < decoded.length; i += 1) {
    const code = decoded.charCodeAt(i);
    out += code >= 0x20 && code !== 0x7f ? decoded[i] : '?';
  }
  return out;
}

function hasNestedArchiveExtension(entryName: string): boolean {
  const lowered = entryName.toLowerCase();
  for (const ext of NESTED_ARCHIVE_EXTENSIONS) {
    if (lowered.endsWith(ext)) {
      return true;
    }
  }
  return false;
}

function isPdfMagic(bytes: Uint8Array): boolean {
  return (
    bytes.length >= 5 &&
    bytes[0] === 0x25 && // %
    bytes[1] === 0x50 && // P
    bytes[2] === 0x44 && // D
    bytes[3] === 0x46 && // F
    bytes[4] === 0x2d // -
  );
}

function isZipMagic(bytes: Uint8Array): boolean {
  if (bytes.length < 4) {
    return false;
  }
  const sig = readU32LE(bytes, 0);
  return sig === SIG_LFH || sig === SIG_EOCD || sig === SIG_DATA_DESCRIPTOR;
}

function parseExtraFields(
  bytes: Uint8Array,
  startOffset: number,
  extraLength: number,
  maxExtraBytes: number,
): { fields: ParsedExtraField[]; malformed: boolean } {
  if (extraLength > maxExtraBytes || startOffset + extraLength > bytes.length) {
    return { fields: [], malformed: true };
  }
  const fields: ParsedExtraField[] = [];
  let cursor = startOffset;
  const end = startOffset + extraLength;
  while (cursor < end) {
    if (cursor + 4 > end) {
      return { fields, malformed: true };
    }
    const id = readU16LE(bytes, cursor);
    const size = readU16LE(bytes, cursor + 2);
    const dataOffset = cursor + 4;
    if (dataOffset + size > end) {
      return { fields, malformed: true };
    }
    fields.push({ id, size, dataOffset });
    cursor = dataOffset + size;
  }
  return { fields, malformed: false };
}

function uniqueCodes(
  findings: readonly PreflightFinding[],
  severity: PreflightFinding['severity'],
): PreflightReasonCode[] {
  const seen = new Set<PreflightReasonCode>();
  const ordered: PreflightReasonCode[] = [];
  for (const finding of findings) {
    if (finding.severity === severity && !seen.has(finding.code)) {
      seen.add(finding.code);
      ordered.push(finding.code);
    }
  }
  return ordered;
}

function buildReport(params: {
  scope: ZipPreflightReport['scope'];
  inputBytes: number;
  declaredKind: DeclaredInputKind;
  compressionPolicy: CompressionPolicy;
  entryCount: number;
  totalDeclaredUncompressedBytes: number;
  maxMemberDeclaredUncompressedBytes: number;
  benignVersionNeeded45Count: number;
  findings: readonly PreflightFinding[];
  members: readonly ZipMemberSummary[];
}): ZipPreflightReport {
  const rejectCodes = uniqueCodes(params.findings, 'reject');
  const warningCodes = uniqueCodes(params.findings, 'warning');
  const infoCodes = uniqueCodes(params.findings, 'info');

  let action: PreflightAction = 'ALLOW';
  if (rejectCodes.length > 0) {
    action = 'REJECT';
  } else if (warningCodes.length > 0) {
    action = 'ALLOW_WITH_RESIDUAL_RISK_WARNING';
  }

  return {
    prototypeOnly: true,
    decompressionPerformed: false,
    action,
    scope: params.scope,
    inputBytes: params.inputBytes,
    declaredKind: params.declaredKind,
    compressionPolicy: params.compressionPolicy,
    entryCount: params.entryCount,
    totalDeclaredUncompressedBytes: params.totalDeclaredUncompressedBytes,
    maxMemberDeclaredUncompressedBytes: params.maxMemberDeclaredUncompressedBytes,
    benignVersionNeeded45Count: params.benignVersionNeeded45Count,
    residualRiskCapabilities: {
      inspectsPdfEmbeddedZip64: false,
      inspectsCompressedNestedArchives: false,
      inspectsUncompressedNestedArchivesRecursively: false,
    },
    rejectCodes,
    warningCodes,
    infoCodes,
    findings: params.findings,
    members: params.members,
  };
}

/**
 * Inspect a raw file buffer using bounded ZIP/OOXML structural parsing with ZERO decompression.
 */
export function inspectZipPreflight(
  bytes: Uint8Array,
  options: ZipPreflightOptions = {},
): ZipPreflightReport {
  const declaredKind: DeclaredInputKind = options.declaredKind ?? 'auto';
  const isOoxmlDeclared =
    declaredKind === 'docx' ||
    declaredKind === 'xlsx' ||
    declaredKind === 'pptx' ||
    declaredKind === 'ooxml';
  const compressionPolicy: CompressionPolicy =
    options.compressionPolicy ?? (isOoxmlDeclared ? 'ooxml-strict' : 'clamav-supported');
  const allowedMethods =
    compressionPolicy === 'ooxml-strict' ? OOXML_STRICT_METHODS : CLAMAV_SUPPORTED_METHODS;
  const maxInputBytes = options.maxInputBytes ?? DEFAULT_ZIP_PREFLIGHT_LIMITS.maxInputBytes;
  const maxEntries = options.maxEntries ?? DEFAULT_ZIP_PREFLIGHT_LIMITS.maxEntries;
  const maxCentralDirectoryBytes =
    options.maxCentralDirectoryBytes ?? DEFAULT_ZIP_PREFLIGHT_LIMITS.maxCentralDirectoryBytes;
  const maxExtraFieldBytes =
    options.maxExtraFieldBytes ?? DEFAULT_ZIP_PREFLIGHT_LIMITS.maxExtraFieldBytes;
  const maxDeclaredMemberBytes =
    options.maxDeclaredMemberBytes ?? DEFAULT_ZIP_PREFLIGHT_LIMITS.maxDeclaredMemberBytes;
  const maxDeclaredTotalBytes =
    options.maxDeclaredTotalBytes ?? DEFAULT_ZIP_PREFLIGHT_LIMITS.maxDeclaredTotalBytes;
  const requireOoxmlContentTypes = options.requireOoxmlContentTypes ?? isOoxmlDeclared;

  const findings: PreflightFinding[] = [];
  const members: ZipMemberSummary[] = [];

  // Hard input size cap before any parsing
  if (bytes.length > maxInputBytes) {
    findings.push({
      severity: 'reject',
      code: 'LIMIT_EXCEEDED_INPUT_SIZE',
      message: `Input size ${bytes.length} exceeds maxInputBytes (${maxInputBytes}).`,
    });
    return buildReport({
      scope: 'REJECTED_BEFORE_PARSE',
      inputBytes: bytes.length,
      declaredKind,
      compressionPolicy,
      entryCount: 0,
      totalDeclaredUncompressedBytes: 0,
      maxMemberDeclaredUncompressedBytes: 0,
      benignVersionNeeded45Count: 0,
      findings,
      members,
    });
  }

  // Explicit PDF handling: preserve PDFs (including password-protected PDFs for unlock-pdf)
  // and ALWAYS surface the residual-risk warning that OOXML preflight does not inspect
  // ZIP64 payloads embedded inside PDF object streams (upstream ClamAV issue #1888).
  if (declaredKind === 'pdf' || (declaredKind === 'auto' && isPdfMagic(bytes))) {
    findings.push({
      severity: 'warning',
      code: 'OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64',
      message:
        'PDF input bypassed OOXML/ZIP preflight. OOXML-only preflight does NOT detect ZIP64 archives embedded inside PDF object streams (upstream ClamAV issue #1888). Password-protected PDFs remain compatible with unlock-pdf.',
    });
    return buildReport({
      scope: 'NON_OOXML_PDF_PASSTHROUGH',
      inputBytes: bytes.length,
      declaredKind,
      compressionPolicy,
      entryCount: 0,
      totalDeclaredUncompressedBytes: 0,
      maxMemberDeclaredUncompressedBytes: 0,
      benignVersionNeeded45Count: 0,
      findings,
      members,
    });
  }

  // Must start with a valid ZIP record signature (blocks polyglot preambles and non-ZIP masquerades)
  if (!isZipMagic(bytes)) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_NOT_ZIP_MAGIC',
      message: 'Input does not begin with a valid ZIP signature (PK\\x03\\x04, PK\\x05\\x06, or PK\\x07\\x08).',
    });
    return buildReport({
      scope: 'REJECTED_BEFORE_PARSE',
      inputBytes: bytes.length,
      declaredKind,
      compressionPolicy,
      entryCount: 0,
      totalDeclaredUncompressedBytes: 0,
      maxMemberDeclaredUncompressedBytes: 0,
      benignVersionNeeded45Count: 0,
      findings,
      members,
    });
  }

  // Locate EOCD (PK\x05\x06) within the trailing 65557-byte window (22B header + max 65535B comment)
  const minEocdSearch = Math.max(0, bytes.length - (22 + 65535));
  const candidateEocdOffsets: number[] = [];
  for (let pos = bytes.length - 22; pos >= minEocdSearch; pos -= 1) {
    if (readU32LE(bytes, pos) === SIG_EOCD) {
      const commentLen = readU16LE(bytes, pos + 20);
      if (pos + 22 + commentLen === bytes.length) {
        candidateEocdOffsets.push(pos);
      }
    }
  }

  if (candidateEocdOffsets.length === 0) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_MISSING_EOCD',
      message: 'No valid End of Central Directory (EOCD) record reaching EOF was found.',
    });
    return buildReport({
      scope: 'ZIP_OOXML_INSPECTED',
      inputBytes: bytes.length,
      declaredKind,
      compressionPolicy,
      entryCount: 0,
      totalDeclaredUncompressedBytes: 0,
      maxMemberDeclaredUncompressedBytes: 0,
      benignVersionNeeded45Count: 0,
      findings,
      members,
    });
  }

  if (candidateEocdOffsets.length > 1) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_AMBIGUOUS_EOCD',
      message: `Detected ${candidateEocdOffsets.length} valid EOCD records in trailing window (possible parser-differential archive).`,
    });
  }

  const eocdOffset = candidateEocdOffsets[0];
  const diskNumber = readU16LE(bytes, eocdOffset + 4);
  const cdStartDisk = readU16LE(bytes, eocdOffset + 6);
  const entriesOnDisk = readU16LE(bytes, eocdOffset + 8);
  const totalEntries = readU16LE(bytes, eocdOffset + 10);
  const cdSize = readU32LE(bytes, eocdOffset + 12);
  const cdOffset = readU32LE(bytes, eocdOffset + 16);
  const commentLength = readU16LE(bytes, eocdOffset + 20);

  if (eocdOffset + 22 + commentLength !== bytes.length) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_TRAILING_DATA_AFTER_EOCD',
      message: 'Unexpected trailing bytes found past EOCD comment boundary.',
    });
  }

  // Check for ZIP64 EOCD Locator immediately preceding EOCD (20 bytes before eocdOffset)
  if (eocdOffset >= 20 && readU32LE(bytes, eocdOffset - 20) === SIG_ZIP64_LOCATOR) {
    findings.push({
      severity: 'reject',
      code: 'ZIP64_EOCD_LOCATOR_PRESENT',
      message: 'ZIP64 End of Central Directory Locator (PK\\x06\\x07) detected.',
    });
    const zip64EocdOffsetInfo = readU64LESafe(bytes, eocdOffset - 12);
    if (
      !zip64EocdOffsetInfo.overflow &&
      zip64EocdOffsetInfo.value + 56 <= bytes.length &&
      readU32LE(bytes, zip64EocdOffsetInfo.value) === SIG_ZIP64_EOCD
    ) {
      findings.push({
        severity: 'reject',
        code: 'ZIP64_EOCD_RECORD_PRESENT',
        message: 'ZIP64 End of Central Directory Record (PK\\x06\\x06) detected.',
      });
    }
  }

  // Check EOCD ZIP64 sentinels
  if (
    diskNumber === SENTINEL_U16 ||
    cdStartDisk === SENTINEL_U16 ||
    entriesOnDisk === SENTINEL_U16 ||
    totalEntries === SENTINEL_U16 ||
    cdSize === SENTINEL_U32 ||
    cdOffset === SENTINEL_U32
  ) {
    findings.push({
      severity: 'reject',
      code: 'ZIP64_EOCD_SENTINEL',
      message: 'Standard EOCD contains ZIP64 sentinel value (0xFFFF / 0xFFFFFFFF).',
    });
  } else if (diskNumber !== 0 || cdStartDisk !== 0 || entriesOnDisk !== totalEntries) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_MULTI_DISK_UNSUPPORTED',
      message: 'Multi-disk or split ZIP archives are rejected.',
    });
  }

  // Enforce entry-count and central-directory size ceilings before iterating
  if (totalEntries !== SENTINEL_U16 && totalEntries > maxEntries) {
    findings.push({
      severity: 'reject',
      code: 'LIMIT_EXCEEDED_MAX_ENTRIES',
      message: `Entry count ${totalEntries} exceeds maxEntries (${maxEntries}).`,
    });
    return buildReport({
      scope: 'ZIP_OOXML_INSPECTED',
      inputBytes: bytes.length,
      declaredKind,
      compressionPolicy,
      entryCount: totalEntries,
      totalDeclaredUncompressedBytes: 0,
      maxMemberDeclaredUncompressedBytes: 0,
      benignVersionNeeded45Count: 0,
      findings,
      members,
    });
  }

  if (cdSize !== SENTINEL_U32 && cdSize > maxCentralDirectoryBytes) {
    findings.push({
      severity: 'reject',
      code: 'LIMIT_EXCEEDED_CENTRAL_DIRECTORY_SIZE',
      message: `Central Directory size ${cdSize} exceeds maxCentralDirectoryBytes (${maxCentralDirectoryBytes}).`,
    });
    return buildReport({
      scope: 'ZIP_OOXML_INSPECTED',
      inputBytes: bytes.length,
      declaredKind,
      compressionPolicy,
      entryCount: totalEntries,
      totalDeclaredUncompressedBytes: 0,
      maxMemberDeclaredUncompressedBytes: 0,
      benignVersionNeeded45Count: 0,
      findings,
      members,
    });
  }

  // Validate CD bounds (when EOCD did not use ZIP64 sentinels)
  const canWalkCentralDirectory =
    cdOffset !== SENTINEL_U32 &&
    cdSize !== SENTINEL_U32 &&
    totalEntries !== SENTINEL_U16 &&
    cdOffset + cdSize <= eocdOffset;

  if (!canWalkCentralDirectory) {
    if (
      cdOffset !== SENTINEL_U32 &&
      cdSize !== SENTINEL_U32 &&
      totalEntries !== SENTINEL_U16
    ) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_CENTRAL_DIRECTORY',
        message: `Central Directory bounds [offset=${cdOffset}, size=${cdSize}] exceed EOCD offset ${eocdOffset}.`,
      });
    }
    return buildReport({
      scope: 'ZIP_OOXML_INSPECTED',
      inputBytes: bytes.length,
      declaredKind,
      compressionPolicy,
      entryCount: totalEntries === SENTINEL_U16 ? 0 : totalEntries,
      totalDeclaredUncompressedBytes: 0,
      maxMemberDeclaredUncompressedBytes: 0,
      benignVersionNeeded45Count: 0,
      findings,
      members,
    });
  }

  // Also check if a ZIP64 EOCD record sits between end-of-CD and EOCD locator
  const cdEnd = cdOffset + cdSize;
  if (cdEnd < eocdOffset && cdEnd + 4 <= eocdOffset) {
    const gapSig = readU32LE(bytes, cdEnd);
    if (gapSig === SIG_ZIP64_EOCD) {
      findings.push({
        severity: 'reject',
        code: 'ZIP64_EOCD_RECORD_PRESENT',
        message: 'ZIP64 End of Central Directory Record (PK\\x06\\x06) follows Central Directory.',
      });
    } else if (gapSig === SIG_ZIP64_LOCATOR) {
      findings.push({
        severity: 'reject',
        code: 'ZIP64_EOCD_LOCATOR_PRESENT',
        message: 'ZIP64 End of Central Directory Locator (PK\\x06\\x07) follows Central Directory.',
      });
    } else {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_CENTRAL_DIRECTORY',
        message: `Unexpected ${eocdOffset - cdEnd}-byte gap between Central Directory end and EOCD.`,
      });
    }
  }

  let cursor = cdOffset;
  let totalDeclaredUncompressedBytes = 0;
  let maxMemberDeclaredUncompressedBytes = 0;
  let benignVersionNeeded45Count = 0;
  let hasContentTypesXml = false;
  const memberRanges: MemberRange[] = [];

  for (let i = 0; i < totalEntries; i += 1) {
    if (cursor + 46 > cdEnd) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_CENTRAL_DIRECTORY',
        message: `Central Directory truncated at entry ${i}.`,
        entryIndex: i,
      });
      break;
    }

    if (readU32LE(bytes, cursor) !== SIG_CDH) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_CENTRAL_DIRECTORY',
        message: `Invalid Central Directory File Header signature at entry ${i}.`,
        entryIndex: i,
      });
      break;
    }

    const versionNeededCdh = readU16LE(bytes, cursor + 6);
    const flagsCdh = readU16LE(bytes, cursor + 8);
    const methodCdh = readU16LE(bytes, cursor + 10);
    const crc32Cdh = readU32LE(bytes, cursor + 16);
    const csizeCdh = readU32LE(bytes, cursor + 20);
    const usizeCdh = readU32LE(bytes, cursor + 24);
    const nameLenCdh = readU16LE(bytes, cursor + 28);
    const extraLenCdh = readU16LE(bytes, cursor + 30);
    const commentLenCdh = readU16LE(bytes, cursor + 32);
    const diskStartCdh = readU16LE(bytes, cursor + 34);
    const lfhOffset = readU32LE(bytes, cursor + 42);

    const recordEnd = cursor + 46 + nameLenCdh + extraLenCdh + commentLenCdh;
    if (recordEnd > cdEnd) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_CENTRAL_DIRECTORY',
        message: `Central Directory entry ${i} variable fields exceed Central Directory boundary.`,
        entryIndex: i,
      });
      break;
    }

    const nameOffsetCdh = cursor + 46;
    const entryName = decodeEntryName(bytes, nameOffsetCdh, nameLenCdh, flagsCdh);
    if (entryName === '[Content_Types].xml') {
      hasContentTypesXml = true;
    }

    // Surface explicit residual-risk warning for nested archive members that
    // zero-decompression single-layer preflight cannot inspect internally.
    if (hasNestedArchiveExtension(entryName)) {
      if (methodCdh !== 0) {
        findings.push({
          severity: 'warning',
          code: 'COMPRESSED_NESTED_ARCHIVE_NOT_INSPECTED_RESIDUAL_RISK',
          message: `Compressed nested archive member '${entryName}' (method=${methodCdh}) cannot be inspected by zero-decompression preflight and remains an open residual risk.`,
          entryIndex: i,
          entryName,
        });
      } else {
        findings.push({
          severity: 'warning',
          code: 'UNCOMPRESSED_NESTED_ARCHIVE_NOT_RECURSIVELY_INSPECTED',
          message: `Uncompressed nested archive member '${entryName}' is not recursively inspected by single-layer preflight and remains a documented residual risk.`,
          entryIndex: i,
          entryName,
        });
      }
    }

    // Parse CDH extra fields
    const cdhExtraOffset = nameOffsetCdh + nameLenCdh;
    const parsedCdhExtra = parseExtraFields(bytes, cdhExtraOffset, extraLenCdh, maxExtraFieldBytes);
    if (parsedCdhExtra.malformed) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_EXTRA_FIELD',
        message: `Malformed CDH extra field TLV structure in entry '${entryName}'.`,
        entryIndex: i,
        entryName,
      });
    }

    let entryHasZip64Extra = false;
    let entryHasAesExtra = false;
    for (const ef of parsedCdhExtra.fields) {
      if (ef.id === EXTRA_ID_ZIP64) {
        entryHasZip64Extra = true;
      } else if (ef.id === EXTRA_ID_WINZIP_AES) {
        entryHasAesExtra = true;
      }
    }

    // ZIP64 checks in CDH
    const cdhHasZip64Sentinel =
      csizeCdh === SENTINEL_U32 ||
      usizeCdh === SENTINEL_U32 ||
      lfhOffset === SENTINEL_U32 ||
      diskStartCdh === SENTINEL_U16;
    if (cdhHasZip64Sentinel) {
      findings.push({
        severity: 'reject',
        code: 'ZIP64_CDH_SENTINEL',
        message: `Central Directory entry '${entryName}' contains ZIP64 sentinel (0xFFFF/0xFFFFFFFF).`,
        entryIndex: i,
        entryName,
      });
    }

    if (entryHasZip64Extra) {
      findings.push({
        severity: 'reject',
        code: 'ZIP64_EXTRA_FIELD_PRESENT',
        message: `Central Directory entry '${entryName}' contains ZIP64 extra field (0x0001).`,
        entryIndex: i,
        entryName,
      });
    }

    // Encryption checks (reject encrypted ZIP/OOXML; PDFs already exited above)
    if ((flagsCdh & 0x0001) !== 0) {
      findings.push({
        severity: 'reject',
        code: 'ENCRYPTED_MEMBER_TRADITIONAL',
        message: `Entry '${entryName}' has general-purpose encryption bit (0x0001) set.`,
        entryIndex: i,
        entryName,
      });
    }
    if ((flagsCdh & 0x0040) !== 0) {
      findings.push({
        severity: 'reject',
        code: 'ENCRYPTED_MEMBER_STRONG',
        message: `Entry '${entryName}' has strong-encryption bit (0x0040) set.`,
        entryIndex: i,
        entryName,
      });
    }
    if ((flagsCdh & 0x2000) !== 0) {
      findings.push({
        severity: 'reject',
        code: 'ENCRYPTED_CENTRAL_DIRECTORY',
        message: `Entry '${entryName}' has central-directory encryption bit (0x2000) set.`,
        entryIndex: i,
        entryName,
      });
    }
    if (methodCdh === 99 || entryHasAesExtra) {
      findings.push({
        severity: 'reject',
        code: 'ENCRYPTED_MEMBER_AES',
        message: `Entry '${entryName}' uses WinZip AES encryption (method 99 / extra field 0x9901).`,
        entryIndex: i,
        entryName,
      });
    } else if (!allowedMethods.has(methodCdh)) {
      findings.push({
        severity: 'reject',
        code: 'UNSUPPORTED_COMPRESSION_METHOD',
        message: `Entry '${entryName}' uses compression method ${methodCdh}, which is not permitted under '${compressionPolicy}'.`,
        entryIndex: i,
        entryName,
      });
    }

    // Track declared uncompressed size ceilings (strictly > exceeds limit)
    if (usizeCdh !== SENTINEL_U32) {
      if (usizeCdh > maxMemberDeclaredUncompressedBytes) {
        maxMemberDeclaredUncompressedBytes = usizeCdh;
      }
      totalDeclaredUncompressedBytes += usizeCdh;
      if (usizeCdh > maxDeclaredMemberBytes) {
        findings.push({
          severity: 'reject',
          code: 'LIMIT_EXCEEDED_DECLARED_MEMBER_SIZE',
          message: `Entry '${entryName}' declares uncompressed size ${usizeCdh} > maxDeclaredMemberBytes (${maxDeclaredMemberBytes}).`,
          entryIndex: i,
          entryName,
        });
      }
      if (totalDeclaredUncompressedBytes > maxDeclaredTotalBytes) {
        findings.push({
          severity: 'reject',
          code: 'LIMIT_EXCEEDED_DECLARED_TOTAL_SIZE',
          message: `Cumulative declared uncompressed size ${totalDeclaredUncompressedBytes} > maxDeclaredTotalBytes (${maxDeclaredTotalBytes}).`,
          entryIndex: i,
          entryName,
        });
      }
    }

    // Validate corresponding Local File Header (LFH)
    let versionNeededLfh = 0;
    let dataOffset = 0;
    const hasDataDescriptor = (flagsCdh & 0x0008) !== 0;

    if (lfhOffset === SENTINEL_U32 || lfhOffset + 30 > cdOffset) {
      if (lfhOffset !== SENTINEL_U32) {
        findings.push({
          severity: 'reject',
          code: 'MALFORMED_LOCAL_FILE_HEADER',
          message: `Entry '${entryName}' LFH offset ${lfhOffset} lies outside archive data area [0, ${cdOffset}).`,
          entryIndex: i,
          entryName,
        });
      }
    } else if (readU32LE(bytes, lfhOffset) !== SIG_LFH) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_LOCAL_FILE_HEADER',
        message: `Entry '${entryName}' does not have PK\\x03\\x04 signature at LFH offset ${lfhOffset}.`,
        entryIndex: i,
        entryName,
      });
    } else {
      versionNeededLfh = readU16LE(bytes, lfhOffset + 4);
      const flagsLfh = readU16LE(bytes, lfhOffset + 6);
      const methodLfh = readU16LE(bytes, lfhOffset + 8);
      const crc32Lfh = readU32LE(bytes, lfhOffset + 14);
      const csizeLfh = readU32LE(bytes, lfhOffset + 18);
      const usizeLfh = readU32LE(bytes, lfhOffset + 22);
      const nameLenLfh = readU16LE(bytes, lfhOffset + 26);
      const extraLenLfh = readU16LE(bytes, lfhOffset + 28);
      dataOffset = lfhOffset + 30 + nameLenLfh + extraLenLfh;

      if (dataOffset > cdOffset) {
        findings.push({
          severity: 'reject',
          code: 'MALFORMED_LOCAL_FILE_HEADER',
          message: `Entry '${entryName}' LFH variable header extends past Central Directory offset.`,
          entryIndex: i,
          entryName,
        });
      } else {
        const lfhName = decodeEntryName(bytes, lfhOffset + 30, nameLenLfh, flagsLfh);
        const parsedLfhExtra = parseExtraFields(
          bytes,
          lfhOffset + 30 + nameLenLfh,
          extraLenLfh,
          maxExtraFieldBytes,
        );
        if (parsedLfhExtra.malformed) {
          findings.push({
            severity: 'reject',
            code: 'MALFORMED_EXTRA_FIELD',
            message: `Malformed LFH extra field TLV structure in entry '${entryName}'.`,
            entryIndex: i,
            entryName,
          });
        }

        let lfhHasZip64Extra = false;
        let lfhHasAesExtra = false;
        for (const ef of parsedLfhExtra.fields) {
          if (ef.id === EXTRA_ID_ZIP64) {
            lfhHasZip64Extra = true;
            entryHasZip64Extra = true;
          } else if (ef.id === EXTRA_ID_WINZIP_AES) {
            lfhHasAesExtra = true;
          }
        }

        const lfhHasZip64Sentinel = csizeLfh === SENTINEL_U32 || usizeLfh === SENTINEL_U32;
        if (lfhHasZip64Sentinel) {
          findings.push({
            severity: 'reject',
            code: 'ZIP64_LFH_SENTINEL',
            message: `Local File Header for '${entryName}' contains ZIP64 sentinel (0xFFFFFFFF).`,
            entryIndex: i,
            entryName,
          });
        }

        if (lfhHasZip64Extra) {
          findings.push({
            severity: 'reject',
            code: 'ZIP64_EXTRA_FIELD_PRESENT',
            message: `Local File Header for '${entryName}' contains ZIP64 extra field (0x0001).`,
            entryIndex: i,
            entryName,
          });
        }

        if (lfhHasAesExtra) {
          findings.push({
            severity: 'reject',
            code: 'ENCRYPTED_MEMBER_AES',
            message: `Local File Header for '${entryName}' contains WinZip AES extra field (0x9901).`,
            entryIndex: i,
            entryName,
          });
        }

        // Strict CDH <-> LFH consistency checks (blocks parser differentials)
        const nameMatches = lfhName === entryName;
        const methodMatches = methodLfh === methodCdh;
        const flagsMatch = flagsLfh === flagsCdh;
        let sizesAndCrcConsistent = true;
        if (!hasDataDescriptor && !lfhHasZip64Sentinel && !cdhHasZip64Sentinel) {
          sizesAndCrcConsistent =
            crc32Lfh === crc32Cdh && csizeLfh === csizeCdh && usizeLfh === usizeCdh;
        } else if (hasDataDescriptor && !lfhHasZip64Sentinel && !cdhHasZip64Sentinel) {
          // With bit 3 (0x0008), LFH crc/csize/usize are normally 0 or equal to CDH
          const lfhZeroed = crc32Lfh === 0 && csizeLfh === 0 && usizeLfh === 0;
          const lfhMatchesCdh =
            crc32Lfh === crc32Cdh && csizeLfh === csizeCdh && usizeLfh === usizeCdh;
          sizesAndCrcConsistent = lfhZeroed || lfhMatchesCdh;
        }

        if (!nameMatches || !methodMatches || !flagsMatch || !sizesAndCrcConsistent) {
          findings.push({
            severity: 'reject',
            code: 'MALFORMED_LFH_CDH_MISMATCH',
            message: `CDH/LFH metadata mismatch for entry '${entryName}' (name=${nameMatches}, method=${methodMatches}, flags=${flagsMatch}, sizesCrc=${sizesAndCrcConsistent}).`,
            entryIndex: i,
            entryName,
          });
        }

        if (csizeCdh !== SENTINEL_U32) {
          const endOfCompressedData = dataOffset + csizeCdh;
          if (endOfCompressedData > cdOffset) {
            findings.push({
              severity: 'reject',
              code: 'MALFORMED_LOCAL_FILE_HEADER',
              message: `Entry '${entryName}' compressed payload extends past Central Directory offset (${endOfCompressedData} > ${cdOffset}).`,
              entryIndex: i,
              entryName,
            });
          } else {
            memberRanges.push({
              index: i,
              name: entryName,
              lfhOffset,
              dataOffset,
              compressedSize: csizeCdh,
              uncompressedSize: usizeCdh,
              crc32: crc32Cdh,
              hasDataDescriptor,
              endOfCompressedData,
            });
          }
        }
      }
    }

    members.push({
      index: i,
      name: entryName,
      versionNeededCdh,
      versionNeededLfh,
      flags: flagsCdh,
      method: methodCdh,
      compressedSize: csizeCdh,
      uncompressedSize: usizeCdh,
      lfhOffset,
      dataOffset,
      hasDataDescriptor,
      hasZip64ExtraField: entryHasZip64Extra,
    });

    cursor = recordEnd;
  }

  if (cursor !== cdEnd && findings.every((f) => f.code !== 'MALFORMED_CENTRAL_DIRECTORY')) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_CENTRAL_DIRECTORY',
      message: `Central Directory traversal ended at ${cursor}, expected ${cdEnd}.`,
    });
  }

  // Sort member spans by LFH offset to detect polyglot preambles, overlapping members,
  // and 64-bit (20/24-byte) ZIP64 Data Descriptors vs benign 32-bit (12/16-byte) ones.
  const sortedRanges = [...memberRanges].sort((a, b) => a.lfhOffset - b.lfhOffset);

  if (sortedRanges.length > 0 && sortedRanges[0].lfhOffset > 0) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_PREAMBLE_BYTES',
      message: `Archive has ${sortedRanges[0].lfhOffset} unreferenced preamble bytes before first LFH.`,
    });
  }

  for (let idx = 0; idx < sortedRanges.length; idx += 1) {
    const current = sortedRanges[idx];
    const nextBoundary = idx + 1 < sortedRanges.length ? sortedRanges[idx + 1].lfhOffset : cdOffset;

    if (current.endOfCompressedData > nextBoundary) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_OVERLAPPING_MEMBERS',
        message: `Entry '${current.name}' overlaps the next archive structure (${current.endOfCompressedData} > ${nextBoundary}).`,
        entryIndex: current.index,
        entryName: current.name,
      });
      continue;
    }

    const gap = nextBoundary - current.endOfCompressedData;
    const ddOffset = current.endOfCompressedData;

    if (current.hasDataDescriptor) {
      const hasDdSig = gap >= 4 && readU32LE(bytes, ddOffset) === SIG_DATA_DESCRIPTOR;
      const valid32WithSig =
        gap === 16 &&
        hasDdSig &&
        readU32LE(bytes, ddOffset + 4) === current.crc32 &&
        readU32LE(bytes, ddOffset + 8) === current.compressedSize &&
        readU32LE(bytes, ddOffset + 12) === current.uncompressedSize;
      const valid32WithoutSig =
        gap === 12 &&
        readU32LE(bytes, ddOffset) === current.crc32 &&
        readU32LE(bytes, ddOffset + 4) === current.compressedSize &&
        readU32LE(bytes, ddOffset + 8) === current.uncompressedSize;

      const isZip64WithSig =
        gap === 24 &&
        hasDdSig &&
        readU32LE(bytes, ddOffset + 4) === current.crc32 &&
        readU64LESafe(bytes, ddOffset + 8).value === current.compressedSize &&
        readU64LESafe(bytes, ddOffset + 16).value === current.uncompressedSize;
      const isZip64WithoutSig =
        gap === 20 &&
        readU32LE(bytes, ddOffset) === current.crc32 &&
        readU64LESafe(bytes, ddOffset + 4).value === current.compressedSize &&
        readU64LESafe(bytes, ddOffset + 12).value === current.uncompressedSize;

      if (isZip64WithSig || isZip64WithoutSig) {
        findings.push({
          severity: 'reject',
          code: 'ZIP64_DATA_DESCRIPTOR_DETECTED',
          message: `Entry '${current.name}' uses a ${gap}-byte ZIP64 Data Descriptor (8-byte sizes), which ClamAV 1.5.4 does not parse.`,
          entryIndex: current.index,
          entryName: current.name,
        });
      } else if (!valid32WithSig && !valid32WithoutSig) {
        findings.push({
          severity: 'reject',
          code: 'MALFORMED_DATA_DESCRIPTOR',
          message: `Entry '${current.name}' has invalid or mismatched Data Descriptor geometry (gap=${gap} bytes).`,
          entryIndex: current.index,
          entryName: current.name,
        });
      }
    } else if (gap !== 0) {
      findings.push({
        severity: 'reject',
        code: 'MALFORMED_DATA_DESCRIPTOR',
        message: `Entry '${current.name}' has ${gap} unreferenced trailing bytes between compressed payload and next header.`,
        entryIndex: current.index,
        entryName: current.name,
      });
    }
  }

  // Nuanced version_needed=45 telemetry: if an entry advertises version_needed == 45 (ZIP 4.5)
  // AND had NO ZIP64 structures/sentinels/64-bit DD, record informational telemetry and ALLOW.
  const hasAnyZip64Reject = findings.some(
    (f) => f.severity === 'reject' && f.code.startsWith('ZIP64_'),
  );
  for (const m of members) {
    if ((m.versionNeededCdh === 45 || m.versionNeededLfh === 45) && !m.hasZip64ExtraField) {
      benignVersionNeeded45Count += 1;
    }
  }
  if (benignVersionNeeded45Count > 0 && !hasAnyZip64Reject) {
    findings.push({
      severity: 'info',
      code: 'BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES',
      message: `${benignVersionNeeded45Count} member(s) advertise version_needed=45 with standard 32-bit structures and no ZIP64 headers; allowed without blind rejection.`,
    });
  }

  if (requireOoxmlContentTypes && !hasContentTypesXml) {
    findings.push({
      severity: 'reject',
      code: 'MALFORMED_OOXML_MISSING_CONTENT_TYPES',
      message: `Declared OOXML input ('${declaredKind}') is missing required [Content_Types].xml member.`,
    });
  }

  return buildReport({
    scope: 'ZIP_OOXML_INSPECTED',
    inputBytes: bytes.length,
    declaredKind,
    compressionPolicy,
    entryCount: members.length,
    totalDeclaredUncompressedBytes,
    maxMemberDeclaredUncompressedBytes,
    benignVersionNeeded45Count,
    findings,
    members,
  });
}

// ============================================================================
// Minimal Deterministic ZIP Builder (Used ONLY for Offline --self-test)
// ============================================================================

interface SyntheticEntrySpec {
  readonly name: string;
  readonly payload: Uint8Array;
  readonly versionNeeded?: number;
  readonly flags?: number;
  readonly method?: number;
  readonly declaredUncompressedSize?: number;
  readonly lfhExtra?: Uint8Array;
  readonly cdhExtra?: Uint8Array;
  readonly forceLfhSentinel?: boolean;
  readonly forceCdhSentinel?: boolean;
  readonly dataDescriptorMode?: 'none' | 'dd32-sig' | 'dd64-sig';
  readonly corruptLfhMethod?: number;
}

function crc32Bytes(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) {
    crc ^= data[i];
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function writeU16LE(buf: Uint8Array, offset: number, val: number): void {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
}

function writeU32LE(buf: Uint8Array, offset: number, val: number): void {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
  buf[offset + 2] = (val >>> 16) & 0xff;
  buf[offset + 3] = (val >>> 24) & 0xff;
}

function writeU64LE(buf: Uint8Array, offset: number, val: number): void {
  const lo = val >>> 0;
  const hi = Math.floor(val / 4294967296) >>> 0;
  writeU32LE(buf, offset, lo);
  writeU32LE(buf, offset + 4, hi);
}

function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) {
    total += c.length;
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

function asciiBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) {
    out[i] = text.charCodeAt(i) & 0x7f;
  }
  return out;
}

function buildZip64ExtraField(usize: number, csize: number): Uint8Array {
  const buf = new Uint8Array(20);
  writeU16LE(buf, 0, EXTRA_ID_ZIP64);
  writeU16LE(buf, 2, 16);
  writeU64LE(buf, 4, usize);
  writeU64LE(buf, 12, csize);
  return buf;
}

function buildAesExtraField(): Uint8Array {
  const buf = new Uint8Array(11);
  writeU16LE(buf, 0, EXTRA_ID_WINZIP_AES);
  writeU16LE(buf, 2, 7);
  writeU16LE(buf, 4, 2); // AE-2
  buf[6] = 0x41; // 'A'
  buf[7] = 0x45; // 'E'
  buf[8] = 3; // AES-256
  writeU16LE(buf, 9, 0); // actual method STORED
  return buf;
}

function buildSyntheticZip(
  entries: readonly SyntheticEntrySpec[],
  options: {
    readonly appendZip64Eocd?: boolean;
    readonly preamble?: Uint8Array;
    readonly overlapSecondWithFirst?: boolean;
  } = {},
): Uint8Array {
  const localParts: Uint8Array[] = [];
  const cdParts: Uint8Array[] = [];
  let offset = 0;

  if (options.preamble && options.preamble.length > 0) {
    localParts.push(options.preamble);
    offset += options.preamble.length;
  }

  for (let idx = 0; idx < entries.length; idx += 1) {
    const entry = entries[idx];
    const nameBytes = asciiBytes(entry.name);
    const crc = crc32Bytes(entry.payload);
    const csize = entry.payload.length;
    const usize = entry.declaredUncompressedSize ?? entry.payload.length;
    const versionNeeded = entry.versionNeeded ?? 20;
    const ddMode = entry.dataDescriptorMode ?? 'none';
    const flags = (entry.flags ?? 0) | (ddMode !== 'none' ? 0x0008 : 0);
    const method = entry.method ?? 0;
    const lfhExtra = entry.lfhExtra ?? new Uint8Array(0);
    const cdhExtra = entry.cdhExtra ?? new Uint8Array(0);

    const lfhOffset =
      options.overlapSecondWithFirst && idx === 1 ? 0 : offset;

    const lfh = new Uint8Array(30 + nameBytes.length + lfhExtra.length);
    writeU32LE(lfh, 0, SIG_LFH);
    writeU16LE(lfh, 4, versionNeeded);
    writeU16LE(lfh, 6, flags);
    writeU16LE(lfh, 8, entry.corruptLfhMethod ?? method);
    writeU32LE(lfh, 14, ddMode !== 'none' ? 0 : crc);
    writeU32LE(lfh, 18, entry.forceLfhSentinel ? SENTINEL_U32 : ddMode !== 'none' ? 0 : csize);
    writeU32LE(lfh, 22, entry.forceLfhSentinel ? SENTINEL_U32 : ddMode !== 'none' ? 0 : usize);
    writeU16LE(lfh, 26, nameBytes.length);
    writeU16LE(lfh, 28, lfhExtra.length);
    lfh.set(nameBytes, 30);
    lfh.set(lfhExtra, 30 + nameBytes.length);

    localParts.push(lfh, entry.payload);
    offset += lfh.length + entry.payload.length;

    if (ddMode === 'dd32-sig') {
      const dd = new Uint8Array(16);
      writeU32LE(dd, 0, SIG_DATA_DESCRIPTOR);
      writeU32LE(dd, 4, crc);
      writeU32LE(dd, 8, csize);
      writeU32LE(dd, 12, usize);
      localParts.push(dd);
      offset += dd.length;
    } else if (ddMode === 'dd64-sig') {
      const dd = new Uint8Array(24);
      writeU32LE(dd, 0, SIG_DATA_DESCRIPTOR);
      writeU32LE(dd, 4, crc);
      writeU64LE(dd, 8, csize);
      writeU64LE(dd, 16, usize);
      localParts.push(dd);
      offset += dd.length;
    }

    const cdh = new Uint8Array(46 + nameBytes.length + cdhExtra.length);
    writeU32LE(cdh, 0, SIG_CDH);
    writeU16LE(cdh, 4, versionNeeded);
    writeU16LE(cdh, 6, versionNeeded);
    writeU16LE(cdh, 8, flags);
    writeU16LE(cdh, 10, method);
    writeU32LE(cdh, 16, crc);
    writeU32LE(cdh, 20, entry.forceCdhSentinel ? SENTINEL_U32 : csize);
    writeU32LE(cdh, 24, entry.forceCdhSentinel ? SENTINEL_U32 : usize);
    writeU16LE(cdh, 28, nameBytes.length);
    writeU16LE(cdh, 30, cdhExtra.length);
    writeU16LE(cdh, 32, 0);
    writeU16LE(cdh, 34, 0);
    writeU32LE(cdh, 42, lfhOffset);
    cdh.set(nameBytes, 46);
    cdh.set(cdhExtra, 46 + nameBytes.length);
    cdParts.push(cdh);
  }

  const cdOffset = offset;
  const cdBytes = concatBytes(cdParts);
  const parts: Uint8Array[] = [...localParts, cdBytes];

  if (options.appendZip64Eocd) {
    const zip64EocdOffset = cdOffset + cdBytes.length;
    const z64Eocd = new Uint8Array(56);
    writeU32LE(z64Eocd, 0, SIG_ZIP64_EOCD);
    writeU64LE(z64Eocd, 4, 44);
    writeU16LE(z64Eocd, 12, 45);
    writeU16LE(z64Eocd, 14, 45);
    writeU64LE(z64Eocd, 24, entries.length);
    writeU64LE(z64Eocd, 32, entries.length);
    writeU64LE(z64Eocd, 40, cdBytes.length);
    writeU64LE(z64Eocd, 48, cdOffset);

    const z64Loc = new Uint8Array(20);
    writeU32LE(z64Loc, 0, SIG_ZIP64_LOCATOR);
    writeU32LE(z64Loc, 4, 0);
    writeU64LE(z64Loc, 8, zip64EocdOffset);
    writeU32LE(z64Loc, 16, 1);

    parts.push(z64Eocd, z64Loc);
  }

  const eocd = new Uint8Array(22);
  writeU32LE(eocd, 0, SIG_EOCD);
  writeU16LE(eocd, 8, options.appendZip64Eocd ? SENTINEL_U16 : entries.length);
  writeU16LE(eocd, 10, options.appendZip64Eocd ? SENTINEL_U16 : entries.length);
  writeU32LE(eocd, 12, options.appendZip64Eocd ? SENTINEL_U32 : cdBytes.length);
  writeU32LE(eocd, 16, options.appendZip64Eocd ? SENTINEL_U32 : cdOffset);
  parts.push(eocd);

  return concatBytes(parts);
}

interface SelfTestCase {
  readonly id: string;
  readonly expectedAction: PreflightAction;
  readonly mustContainCode?: PreflightReasonCode;
  readonly report: ZipPreflightReport;
}

export function runSelfTests(): { passed: number; failed: number; results: readonly SelfTestCase[] } {
  const contentTypes = asciiBytes('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>');

  const cases: SelfTestCase[] = [
    {
      id: 'valid_docx_control',
      expectedAction: 'ALLOW',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: '[Content_Types].xml', payload: contentTypes },
          { name: 'word/document.xml', payload: asciiBytes('<w:document/>') },
        ]),
        { declaredKind: 'docx' },
      ),
    },
    {
      id: 'valid_xlsx_control',
      expectedAction: 'ALLOW',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: '[Content_Types].xml', payload: contentTypes },
          { name: 'xl/workbook.xml', payload: asciiBytes('<workbook/>') },
        ]),
        { declaredKind: 'xlsx' },
      ),
    },
    {
      id: 'valid_pptx_control',
      expectedAction: 'ALLOW',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: '[Content_Types].xml', payload: contentTypes },
          { name: 'ppt/presentation.xml', payload: asciiBytes('<p:presentation/>') },
        ]),
        { declaredKind: 'pptx' },
      ),
    },
    {
      id: 'valid_pdf_control_with_residual_risk_warning',
      expectedAction: 'ALLOW_WITH_RESIDUAL_RISK_WARNING',
      mustContainCode: 'OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64',
      report: inspectZipPreflight(asciiBytes('%PDF-1.7\n% DIP Phase 0B PDF control\n%%EOF\n'), {
        declaredKind: 'pdf',
      }),
    },
    {
      id: 'benign_version_needed_45_docx_no_zip64',
      expectedAction: 'ALLOW',
      mustContainCode: 'BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: '[Content_Types].xml', payload: contentTypes, versionNeeded: 45 },
          { name: 'word/document.xml', payload: asciiBytes('<w:document/>'), versionNeeded: 45 },
        ]),
        { declaredKind: 'docx' },
      ),
    },
    {
      id: 'benign_version_needed_45_with_32bit_data_descriptor',
      expectedAction: 'ALLOW',
      mustContainCode: 'BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES',
      report: inspectZipPreflight(
        buildSyntheticZip([
          {
            name: '[Content_Types].xml',
            payload: contentTypes,
            versionNeeded: 45,
            dataDescriptorMode: 'dd32-sig',
          },
        ]),
        { declaredKind: 'docx' },
      ),
    },
    {
      id: 'reject_zip64_lfh_sentinel_and_extra',
      expectedAction: 'REJECT',
      mustContainCode: 'ZIP64_LFH_SENTINEL',
      report: inspectZipPreflight(
        buildSyntheticZip([
          {
            name: 'eicar.txt',
            payload: asciiBytes('payload'),
            versionNeeded: 45,
            forceLfhSentinel: true,
            lfhExtra: buildZip64ExtraField(7, 7),
          },
        ]),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'reject_zip64_eocd_and_cdh_sentinel',
      expectedAction: 'REJECT',
      mustContainCode: 'ZIP64_EOCD_LOCATOR_PRESENT',
      report: inspectZipPreflight(
        buildSyntheticZip(
          [
            {
              name: 'eicar.txt',
              payload: asciiBytes('payload'),
              versionNeeded: 45,
              forceCdhSentinel: true,
              cdhExtra: buildZip64ExtraField(7, 7),
            },
          ],
          { appendZip64Eocd: true },
        ),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'reject_zip64_data_descriptor_without_sentinels',
      expectedAction: 'REJECT',
      mustContainCode: 'ZIP64_DATA_DESCRIPTOR_DETECTED',
      report: inspectZipPreflight(
        buildSyntheticZip([
          {
            name: '[Content_Types].xml',
            payload: contentTypes,
            versionNeeded: 45,
            dataDescriptorMode: 'dd64-sig',
          },
        ]),
        { declaredKind: 'docx' },
      ),
    },
    {
      id: 'reject_unsupported_compression_lzma_14',
      expectedAction: 'REJECT',
      mustContainCode: 'UNSUPPORTED_COMPRESSION_METHOD',
      report: inspectZipPreflight(
        buildSyntheticZip([{ name: 'payload.bin', payload: asciiBytes('lzma'), method: 14 }]),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'reject_unsupported_compression_ppmd_98',
      expectedAction: 'REJECT',
      mustContainCode: 'UNSUPPORTED_COMPRESSION_METHOD',
      report: inspectZipPreflight(
        buildSyntheticZip([{ name: 'payload.bin', payload: asciiBytes('ppmd'), method: 98 }]),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'reject_encrypted_ooxml_traditional',
      expectedAction: 'REJECT',
      mustContainCode: 'ENCRYPTED_MEMBER_TRADITIONAL',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: '[Content_Types].xml', payload: contentTypes, flags: 0x0001 },
        ]),
        { declaredKind: 'docx' },
      ),
    },
    {
      id: 'reject_encrypted_ooxml_winzip_aes',
      expectedAction: 'REJECT',
      mustContainCode: 'ENCRYPTED_MEMBER_AES',
      report: inspectZipPreflight(
        buildSyntheticZip([
          {
            name: '[Content_Types].xml',
            payload: contentTypes,
            method: 99,
            lfhExtra: buildAesExtraField(),
            cdhExtra: buildAesExtraField(),
          },
        ]),
        { declaredKind: 'docx' },
      ),
    },
    {
      id: 'reject_malformed_lfh_cdh_mismatch',
      expectedAction: 'REJECT',
      mustContainCode: 'MALFORMED_LFH_CDH_MISMATCH',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: 'entry.txt', payload: asciiBytes('abc'), method: 0, corruptLfhMethod: 8 },
        ]),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'reject_malformed_truncated_missing_eocd',
      expectedAction: 'REJECT',
      mustContainCode: 'MALFORMED_MISSING_EOCD',
      report: inspectZipPreflight(asciiBytes('PK\x03\x04truncated-archive'), {
        declaredKind: 'zip',
      }),
    },
    {
      id: 'reject_malformed_overlapping_members',
      expectedAction: 'REJECT',
      mustContainCode: 'MALFORMED_OVERLAPPING_MEMBERS',
      report: inspectZipPreflight(
        buildSyntheticZip(
          [
            { name: 'a.txt', payload: asciiBytes('12345678') },
            { name: 'a.txt', payload: asciiBytes('12345678') },
          ],
          { overlapSecondWithFirst: true },
        ),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'reject_malformed_polyglot_preamble_non_zip',
      expectedAction: 'REJECT',
      mustContainCode: 'MALFORMED_NOT_ZIP_MAGIC',
      report: inspectZipPreflight(
        buildSyntheticZip([{ name: 'a.txt', payload: asciiBytes('hi') }], {
          preamble: asciiBytes('PREAMBLE'),
        }),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'reject_malformed_unreferenced_zip_preamble',
      expectedAction: 'REJECT',
      mustContainCode: 'MALFORMED_PREAMBLE_BYTES',
      report: inspectZipPreflight(
        buildSyntheticZip([{ name: 'a.txt', payload: asciiBytes('hi') }], {
          preamble: asciiBytes('PK\x03\x04decoy'),
        }),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'allow_exact_declared_member_boundary',
      expectedAction: 'ALLOW',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: 'exact.bin', payload: asciiBytes('a'), declaredUncompressedSize: 16384 },
        ]),
        { declaredKind: 'zip', maxDeclaredMemberBytes: 16384, maxDeclaredTotalBytes: 32768 },
      ),
    },
    {
      id: 'reject_exceeded_declared_member_limit',
      expectedAction: 'REJECT',
      mustContainCode: 'LIMIT_EXCEEDED_DECLARED_MEMBER_SIZE',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: 'over.bin', payload: asciiBytes('a'), declaredUncompressedSize: 16385 },
        ]),
        { declaredKind: 'zip', maxDeclaredMemberBytes: 16384, maxDeclaredTotalBytes: 32768 },
      ),
    },
    {
      id: 'allow_baseline_aligned_110m_member_and_400m_total_defaults',
      expectedAction: 'ALLOW',
      report: inspectZipPreflight(
        buildSyntheticZip([
          {
            name: 'member1.bin',
            payload: asciiBytes('a'),
            declaredUncompressedSize: 110 * 1024 * 1024,
          },
          {
            name: 'member2.bin',
            payload: asciiBytes('b'),
            declaredUncompressedSize: 110 * 1024 * 1024,
          },
        ]),
        { declaredKind: 'zip' },
      ),
    },
    {
      id: 'warn_compressed_nested_archive_residual_risk',
      expectedAction: 'ALLOW_WITH_RESIDUAL_RISK_WARNING',
      mustContainCode: 'COMPRESSED_NESTED_ARCHIVE_NOT_INSPECTED_RESIDUAL_RISK',
      report: inspectZipPreflight(
        buildSyntheticZip([
          { name: 'nested/inner_zip64.zip', payload: asciiBytes('compressed-bytes'), method: 8 },
        ]),
        { declaredKind: 'zip' },
      ),
    },
  ];

  // Verify authoritative baseline alignment invariants on exported default limits
  const baselineDefaultsOk =
    DEFAULT_ZIP_PREFLIGHT_LIMITS.maxInputBytes === 100 * 1024 * 1024 &&
    DEFAULT_ZIP_PREFLIGHT_LIMITS.maxDeclaredMemberBytes === 110 * 1024 * 1024 &&
    DEFAULT_ZIP_PREFLIGHT_LIMITS.maxDeclaredTotalBytes === 400 * 1024 * 1024 &&
    DEFAULT_ZIP_PREFLIGHT_LIMITS.maxEntries === 10000;
  if (!baselineDefaultsOk) {
    throw new Error('DEFAULT_ZIP_PREFLIGHT_LIMITS drifted from DIP/Stage 4 baseline limits');
  }

  let passed = 0;
  let failed = 0;
  for (const tc of cases) {
    const allCodes: readonly PreflightReasonCode[] = [
      ...tc.report.rejectCodes,
      ...tc.report.warningCodes,
      ...tc.report.infoCodes,
    ];
    const actionOk = tc.report.action === tc.expectedAction;
    const codeOk = tc.mustContainCode ? allCodes.includes(tc.mustContainCode) : true;
    const noDecompression = tc.report.decompressionPerformed === false;
    const residualFlagsOk =
      tc.report.residualRiskCapabilities.inspectsPdfEmbeddedZip64 === false &&
      tc.report.residualRiskCapabilities.inspectsCompressedNestedArchives === false;
    if (actionOk && codeOk && noDecompression && residualFlagsOk) {
      passed += 1;
    } else {
      failed += 1;
    }
  }

  return { passed, failed, results: cases };
}

function parseCliArgs(argv: readonly string[]): {
  mode: 'self-test' | 'inspect';
  filePath?: string;
  declaredKind: DeclaredInputKind;
  maxDeclaredMemberBytes?: number;
  maxDeclaredTotalBytes?: number;
} {
  if (argv.includes('--self-test')) {
    return { mode: 'self-test', declaredKind: 'auto' };
  }

  const inspectIdx = argv.indexOf('--inspect');
  if (inspectIdx === -1 || inspectIdx + 1 >= argv.length) {
    throw new Error(
      'Usage: clamav-phase0b-zip-preflight.mts --self-test | --inspect <file> [--kind auto|docx|xlsx|pptx|ooxml|zip|pdf] [--max-member-bytes N] [--max-total-bytes N]',
    );
  }

  let declaredKind: DeclaredInputKind = 'auto';
  const kindIdx = argv.indexOf('--kind');
  if (kindIdx !== -1 && kindIdx + 1 < argv.length) {
    const raw = argv[kindIdx + 1];
    if (
      raw === 'auto' ||
      raw === 'docx' ||
      raw === 'xlsx' ||
      raw === 'pptx' ||
      raw === 'ooxml' ||
      raw === 'zip' ||
      raw === 'pdf'
    ) {
      declaredKind = raw;
    } else {
      throw new Error(`Unsupported --kind value: ${raw}`);
    }
  }

  let maxDeclaredMemberBytes: number | undefined;
  const maxMemberIdx = argv.indexOf('--max-member-bytes');
  if (maxMemberIdx !== -1 && maxMemberIdx + 1 < argv.length) {
    maxDeclaredMemberBytes = Number(argv[maxMemberIdx + 1]);
  }

  let maxDeclaredTotalBytes: number | undefined;
  const maxTotalIdx = argv.indexOf('--max-total-bytes');
  if (maxTotalIdx !== -1 && maxTotalIdx + 1 < argv.length) {
    maxDeclaredTotalBytes = Number(argv[maxTotalIdx + 1]);
  }

  return {
    mode: 'inspect',
    filePath: argv[inspectIdx + 1],
    declaredKind,
    maxDeclaredMemberBytes,
    maxDeclaredTotalBytes,
  };
}

function main(): void {
  const parsed = parseCliArgs(process.argv.slice(2));
  if (parsed.mode === 'self-test') {
    const summary = runSelfTests();
    const output = {
      suite: 'phase0b-zip-preflight-self-test',
      passed: summary.passed,
      failed: summary.failed,
      total: summary.results.length,
      cases: summary.results.map((c) => ({
        id: c.id,
        expectedAction: c.expectedAction,
        actualAction: c.report.action,
        mustContainCode: c.mustContainCode ?? null,
        rejectCodes: c.report.rejectCodes,
        warningCodes: c.report.warningCodes,
        infoCodes: c.report.infoCodes,
        decompressionPerformed: c.report.decompressionPerformed,
      })),
    };
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    if (summary.failed > 0) {
      process.exitCode = 1;
    }
    return;
  }

  if (!parsed.filePath) {
    throw new Error('Missing --inspect file path');
  }
  const raw = readFileSync(parsed.filePath);
  const report = inspectZipPreflight(new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength), {
    declaredKind: parsed.declaredKind,
    maxDeclaredMemberBytes: parsed.maxDeclaredMemberBytes,
    maxDeclaredTotalBytes: parsed.maxDeclaredTotalBytes,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

const isDirectExecution =
  typeof process.argv[1] === 'string' &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isDirectExecution) {
  main();
}
