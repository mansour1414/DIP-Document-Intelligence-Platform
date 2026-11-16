// ============================================================================
// EXPERIMENTAL Stage 4 harness — reads DIP's PRODUCTION malware module unmodified
// (src/lib/malware/clamd.ts). It does not reimplement the client and does not stub
// the scanner: every result below comes from a real clamd 1.5.4 over TCP INSTREAM.
//
// Delta vs the Stage 3 harness:
//  * Stage 3 proved StreamMaxLength=25M *broke* the 100 MiB app ceiling (a 26 MiB
//    upload was rejected). The candidate raises it to 110M, so that case now must
//    come back CLEAN. That inversion is the point of the case.
//  * New boundary cases at DIP's exact 100 MiB ceiling and one byte past it.
//  * New security regression cases: EICAR hidden beyond MaxFiles / MaxRecursion must
//    be reported INFECTED, which only holds because AlertExceedsMax is enabled.
//    With AlertExceedsMax unset these return CLEAN (Stage 4 finding: silent-truncation
//    detection bypass).
//
// CLAM-3102 DIAGNOSTIC CORRECTION (tests 8a-8d):
//  * Limit tests are judged on the RAW clamd wire verdict, never on ClamdScanner's
//    result enum. parseClamdResponse() collapses every verdict that is not
//    "stream: OK" or "stream: <name> FOUND" into a bare SCAN_ERROR, so the enum
//    cannot distinguish a size-limit alert from a timeout, an unreachable scanner,
//    a generic clamd ERROR, or an unrelated malware detection.
//  * A limit test PASSES only when the exact expected
//    "Heuristics.Limits.Exceeded.<Limit>" name appears in a terminated raw reply.
//    CLEAN, an unrelated FOUND, a generic ERROR, a timeout, a connection failure,
//    and truncated (no NUL terminator) wire text all count as FAIL for that test.
//  * Raw replies are normalized for both real NUL terminators and the escaped
//    "\\0" form, so "stream: OK" is always recognized as CLEAN. A silent CLEAN on a
//    payload that must trip a limit is therefore reported as the regression FAIL it
//    is, instead of being masked by the client enum.
//  * Reply parsing is fully anchored. Only ONE NUL-terminated stanza with nothing
//    before or after it yields a verdict; "… FOUND trailinggarbage",
//    "garbage … FOUND", concatenated stanzas, embedded/missing terminators, and
//    other malformed text are MALFORMED/INCOMPLETE and never satisfy an assertion.
//    A partial regex match is never accepted as proof of a security limit.
//  * clamd's prefixless StreamMaxLength refusal is recognized as its own verdict.
//    Real evidence from Stage 7 run 43937894854 is "INSTREAM size limit exceeded.
//    ERROR\0" (clamd conn_reply_error() with no path/id prints no "stream:" prefix).
//    Test 6a requires exactly that reply; a generic or prefixed ERROR is not proof
//    that StreamMaxLength was enforced.
//  * Each large ZIP fixture is scanned exactly ONCE, raw, because the raw reply
//    carries all of the evidence these diagnostics need. The client enum is no
//    longer consulted for limit attribution, so no fixture is scanned twice.
//  * The original 420 MiB bomb regression assertion (test 8) is preserved verbatim
//    and no security gate has been relaxed. This file is experimental evidence only.
//  * Which alerts a given engine really emits has NOT been verified against a live
//    ClamAV runtime here. Where an alert name is unsupported or uncertain the case
//    fails and states the observation; it is never turned into a passing outcome.
//
// Offline self-check of the wire parser (no clamd required):
//   node --import tsx docs/operations/experimental/clamav-arm64-stage4-protocol.mts --self-test
// ============================================================================
import net from "node:net";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { ClamdScanner } from "../../../src/lib/malware/clamd";
import type { MalwareScanResultCode } from "../../../src/lib/malware/types";

const HOST = process.env.CLAMD_HOST ?? "clamav-stage4";
const PORT = Number(process.env.CLAMD_PORT ?? 3310);
const PAYLOADS = process.env.PAYLOAD_DIR ?? "/payloads";

const EICAR =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const MiB = 1024 * 1024;
const rows: Array<Record<string, unknown>> = [];
let failures = 0;

// Limit alerts ClamAV can raise when AlertExceedsMax is enabled. Each diagnostic
// below names the ONE alert its fixture is supposed to prove.
export const MAX_FILE_SIZE_ALERT = "Heuristics.Limits.Exceeded.MaxFileSize";
export const MAX_SCAN_SIZE_ALERT = "Heuristics.Limits.Exceeded.MaxScanSize";
export const MAX_FILES_ALERT = "Heuristics.Limits.Exceeded.MaxFiles";
export const MAX_RECURSION_ALERT = "Heuristics.Limits.Exceeded.MaxRecursion";
export const MAX_SCAN_TIME_ALERT = "Heuristics.Limits.Exceeded.MaxScanTime";

export type ClamdLimitAlert =
  | typeof MAX_FILE_SIZE_ALERT
  | typeof MAX_SCAN_SIZE_ALERT
  | typeof MAX_FILES_ALERT
  | typeof MAX_RECURSION_ALERT
  | typeof MAX_SCAN_TIME_ALERT;

const LIMIT_ALERTS: ReadonlySet<string> = new Set<string>([
  MAX_FILE_SIZE_ALERT,
  MAX_SCAN_SIZE_ALERT,
  MAX_FILES_ALERT,
  MAX_RECURSION_ALERT,
  MAX_SCAN_TIME_ALERT,
]);

// Accepted clamd reply grammar. A reply must be exactly ONE stanza, terminated by
// exactly ONE NUL, with nothing before and nothing after it:
//   "stream: OK\0"                          -> CLEAN
//   "stream: <signature> FOUND\0"           -> FOUND, or LIMIT_ALERT when the
//                                              signature is an exact
//                                              Heuristics.Limits.Exceeded.* name
//   "stream: <message> ERROR\0"             -> ERROR (generic)
//   "INSTREAM size limit exceeded. ERROR\0" -> INSTREAM_SIZE_LIMIT
//
// The last form is prefixless on purpose. clamd (server-th.c) answers an oversized
// zINSTREAM chunk with conn_reply_error(conn, "INSTREAM size limit exceeded."), and
// conn_reply() with no path and no id prints mdprintf("%s %s%c", msg, "ERROR", term).
// That exact refusal is the ONLY evidence that StreamMaxLength was enforced; a
// generic error or a prefixed "stream: ... ERROR" is not.
//
// Everything else is rejected and can never be a verdict: a missing terminator
// (INCOMPLETE); embedded, repeated, or mid-text terminators; trailing text after
// the terminator; multiple lines or concatenated stanzas; and any payload that does
// not match the grammar end to end (MALFORMED). Matching is anchored on the whole
// reply, so "… FOUND trailinggarbage", "garbage … FOUND", and concatenated stanzas
// cannot be read as a limit alert through a partial match.
export type ClamdWireVerdict =
  | { kind: "CLEAN" }
  | { kind: "FOUND"; signature: string }
  | { kind: "LIMIT_ALERT"; alert: ClamdLimitAlert }
  | { kind: "INSTREAM_SIZE_LIMIT" }
  | { kind: "ERROR"; detail: string }
  | { kind: "INCOMPLETE"; detail: string }
  | { kind: "MALFORMED"; detail: string };

// Exact wire text clamd sends when StreamMaxLength is exceeded (no prefix).
export const INSTREAM_SIZE_LIMIT_REFUSAL = "INSTREAM size limit exceeded. ERROR";

export function normalizeClamdWire(wire: string): string {
  return wire.replace(/\0/gu, "").replace(/\\0/gu, "").trim();
}

// Classifies a raw clamd reply. `terminated` reports whether the socket reader saw a
// NUL; the captured text is authoritative, so a reply without an actual terminator
// is INCOMPLETE even if the reader reported a clean end of stream.
export function classifyClamdWire(wire: string, terminated: boolean): ClamdWireVerdict {
  // The escaped "\0" form is what a previously logged reply looks like. Unify it with
  // a real NUL so terminator counting is unambiguous.
  const unified = wire.replace(/\\0/gu, "\0");
  const terminators = unified.split("\0").length - 1;

  if (terminators === 0) {
    return {
      kind: "INCOMPLETE",
      detail: `no terminator (readerSawNul=${terminated}): ${unified.trim().slice(0, 80)}`,
    };
  }
  if (terminators > 1) {
    return { kind: "MALFORMED", detail: `multiple stanzas / embedded terminator (${terminators} terminators)` };
  }

  const terminatorAt = unified.indexOf("\0");
  const afterTerminator = unified.slice(terminatorAt + 1);
  // Nothing may follow the single terminator - not even a space, tab, CR, or LF.
  // The reply ends at the NUL; any byte after it means the capture is not one
  // well-formed stanza.
  if (afterTerminator !== "") {
    return {
      kind: "MALFORMED",
      detail: `bytes after terminator: ${JSON.stringify(afterTerminator.slice(0, 40))}`,
    };
  }

  const body = unified.slice(0, terminatorAt).trim();
  if (!body) return { kind: "MALFORMED", detail: "empty reply body before terminator" };
  if (/[\r\n]/u.test(body)) {
    return { kind: "MALFORMED", detail: "multiple lines / concatenated stanzas in one reply" };
  }

  if (body === INSTREAM_SIZE_LIMIT_REFUSAL) return { kind: "INSTREAM_SIZE_LIMIT" };

  const stanza = /^(?:stream|instream):[ \t]*(\S(?:[^\r\n]*\S)?)$/iu.exec(body);
  if (!stanza) return { kind: "MALFORMED", detail: `not a single well-formed clamd stanza: ${body.slice(0, 80)}` };
  const payload = stanza[1];

  // Anchored whole-payload matches only; nothing may precede or follow the verdict.
  if (/^OK$/iu.test(payload)) return { kind: "CLEAN" };

  const detection = /^([A-Za-z0-9][A-Za-z0-9_.+-]*) FOUND$/u.exec(payload);
  if (detection) {
    const signature = detection[1];
    if (LIMIT_ALERTS.has(signature)) return { kind: "LIMIT_ALERT", alert: signature as ClamdLimitAlert };
    return { kind: "FOUND", signature };
  }

  if (/^\S.*[ \t]ERROR$/u.test(payload)) return { kind: "ERROR", detail: payload };
  return { kind: "MALFORMED", detail: `unrecognized stanza payload: ${payload.slice(0, 80)}` };
}

// A verdict that actually came from clamd: decisive outcome from a terminated,
// well-formed reply. INCOMPLETE/MALFORMED replies are never decisive.
export function isDecisiveVerdict(verdict: ClamdWireVerdict): boolean {
  return (
    verdict.kind === "CLEAN" ||
    verdict.kind === "FOUND" ||
    verdict.kind === "LIMIT_ALERT" ||
    verdict.kind === "INSTREAM_SIZE_LIMIT" ||
    verdict.kind === "ERROR"
  );
}

export type RawScanOutcome =
  | { ok: true; wire: string; terminated: boolean; elapsedMs: number; verdict: ClamdWireVerdict }
  | { ok: false; failure: "TIMEOUT" | "UNAVAILABLE"; detail: string; elapsedMs: number };

// True only when the raw reply proves exactly the expected limit alert.
export function limitAlertObserved(outcome: RawScanOutcome, expected: ClamdLimitAlert): boolean {
  return (
    outcome.ok &&
    outcome.terminated &&
    outcome.verdict.kind === "LIMIT_ALERT" &&
    outcome.verdict.alert === expected
  );
}

// True only when clamd itself refused the stream at StreamMaxLength, proven by its
// exact prefixless "INSTREAM size limit exceeded. ERROR" reply. A generic ERROR or a
// prefixed "stream: ... ERROR" is NOT proof that the stream limit was enforced.
// The outcome must also be a successful, terminator-confirmed raw read: without a
// NUL there is no complete reply, whatever verdict text was captured.
export function instreamSizeLimitRefused(outcome: RawScanOutcome): boolean {
  return outcome.ok && outcome.terminated && outcome.verdict.kind === "INSTREAM_SIZE_LIMIT";
}

export function describeOutcome(outcome: RawScanOutcome): string {
  if (!outcome.ok) return outcome.failure;
  switch (outcome.verdict.kind) {
    case "CLEAN":
      return "CLEAN";
    case "FOUND":
      return `FOUND:${outcome.verdict.signature}`;
    case "LIMIT_ALERT":
      return `LIMIT_ALERT:${outcome.verdict.alert}`;
    case "INSTREAM_SIZE_LIMIT":
      return `INSTREAM_SIZE_LIMIT:${INSTREAM_SIZE_LIMIT_REFUSAL}`;
    case "ERROR":
      return `ERROR:${outcome.verdict.detail}`;
    case "INCOMPLETE":
      return `INCOMPLETE:${outcome.verdict.detail}`;
    case "MALFORMED":
      return `MALFORMED:${outcome.verdict.detail}`;
  }
}

// Why a limit test did not pass. Recorded so the evidence log states the
// observation instead of silently turning it into a positive result.
export function diagnoseLimitOutcome(outcome: RawScanOutcome, expected: ClamdLimitAlert): string {
  if (!outcome.ok) {
    return `transport failure (${outcome.failure}): no clamd verdict was received, so no limit alert can be attributed`;
  }
  if (!outcome.terminated) {
    return "incomplete response (no NUL terminator): truncated wire text is never a valid limit detection";
  }
  switch (outcome.verdict.kind) {
    case "LIMIT_ALERT":
      return outcome.verdict.alert === expected
        ? "expected alert"
        : `different limit mechanism fired (${outcome.verdict.alert}); it does not prove ${expected}`;
    case "CLEAN":
      return "silent CLEAN (stream: OK): no limit alert was raised, so the truncation alert is absent or the limit was never reached";
    case "FOUND":
      return `unrelated malware detection (${outcome.verdict.signature}) is not a size-limit alert`;
    case "INSTREAM_SIZE_LIMIT":
      return "the StreamMaxLength refusal (INSTREAM size limit exceeded. ERROR) is not a size-limit heuristic alert";
    case "ERROR":
      return "generic clamd ERROR is not a size-limit alert";
    case "INCOMPLETE":
      return "incomplete response: never a valid limit detection";
    case "MALFORMED":
      return "malformed response: not a valid verdict";
  }
}

function rawWireOf(outcome: RawScanOutcome): string {
  return outcome.ok ? outcome.wire : `<${outcome.failure}: ${outcome.detail}>`;
}

function normalizedWireOf(outcome: RawScanOutcome): string {
  return outcome.ok ? normalizeClamdWire(outcome.wire) : `<${outcome.failure}>`;
}

function record(name: string, expected: MalwareScanResultCode | "clamd ERROR" | "n/a" | ClamdLimitAlert | typeof INSTREAM_SIZE_LIMIT_REFUSAL, got: string, extra: Record<string, unknown> = {}, ok?: boolean) {
  const pass = ok ?? got === expected;
  if (!pass) failures++;
  rows.push({ test: name, expected, actual: got, pass, ...extra });
  console.log(`${pass ? "PASS" : "FAIL"} | ${name} | expected=${expected} | actual=${got} | ${JSON.stringify(extra)}`);
}

// Binary INSTREAM framing, exactly as src/lib/malware/clamd.ts does it:
// repeated 4-byte big-endian length prefixes, terminated by a 4-byte zero length.
// Resolves with the verbatim wire text (real NULs preserved) and whether the reply
// was NUL terminated. Transport problems are reported, never thrown, so a timeout
// or an unreachable scanner stays distinguishable from a clamd verdict.
//
// After the first NUL the socket is drained for a short settle window before the
// reply is classified. clamd sends exactly one stanza, but a reply that carries
// extra bytes (a second concatenated stanza, trailing text) must be seen so the
// anchored parser can reject it instead of silently keeping only the first stanza.
const REPLY_SETTLE_MS = 40;

function rawInstream(bytes: Buffer, timeoutMs = 120000): Promise<RawScanOutcome> {
  return new Promise((resolve) => {
    const socket = net.connect(PORT, HOST);
    const startedAt = Date.now();
    let wire = "";
    let terminated = false;
    let settled = false;
    let settleTimer: NodeJS.Timeout | null = null;
    const finish = (failure?: "TIMEOUT" | "UNAVAILABLE", detail?: string) => {
      if (settled) return;
      settled = true;
      if (settleTimer) clearTimeout(settleTimer);
      socket.destroy();
      const elapsedMs = Date.now() - startedAt;
      if (failure) resolve({ ok: false, failure, detail: detail ?? failure, elapsedMs });
      else resolve({ ok: true, wire, terminated, elapsedMs, verdict: classifyClamdWire(wire, terminated) });
    };
    socket.setTimeout(timeoutMs, () => finish("TIMEOUT", `raw socket timeout after ${timeoutMs}ms`));
    socket.on("error", (error: Error) => finish("UNAVAILABLE", error.message));
    socket.on("connect", () => {
      socket.write("zINSTREAM\0");
      const chunkSize = 64 * 1024;
      for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
        const chunk = bytes.subarray(offset, Math.min(bytes.byteLength, offset + chunkSize));
        const length = Buffer.allocUnsafe(4);
        length.writeUInt32BE(chunk.byteLength);
        socket.write(length);
        socket.write(chunk);
      }
      socket.end(Buffer.alloc(4));
    });
    socket.on("data", (chunk) => {
      wire += chunk.toString("utf8");
      if (!wire.includes("\0")) return;
      terminated = true;
      // Keep reading briefly so trailing text after the terminator is seen and can
      // be rejected by the anchored parser.
      if (settleTimer === null) settleTimer = setTimeout(() => finish(), REPLY_SETTLE_MS);
    });
    socket.on("end", () => finish());
  });
}

function clamdCommand(cmd: string, timeoutMs = 15000): Promise<string> {
  return new Promise((resolve) => {
    const sock = net.connect(PORT, HOST);
    let out = "";
    sock.setTimeout(timeoutMs, () => sock.destroy());
    sock.on("error", () => resolve("<error>"));
    sock.on("connect", () => sock.write(cmd + "\0"));
    sock.on("data", (c) => {
      out += c.toString();
      if (out.includes("\0")) {
        sock.destroy();
        resolve(out.replace(/\0/g, ""));
      }
    });
    sock.on("close", () => resolve(out.replace(/\0/g, "") || "<empty>"));
  });
}

async function timedScan(
  scanner: ClamdScanner,
  buf: Buffer,
): Promise<{ result: string; ms: number; engine?: string }> {
  const t0 = Date.now();
  const r = await scanner.scan(buf);
  return { result: r.result, ms: Date.now() - t0, engine: r.engine };
}

async function main() {
  console.log(`### target=${HOST}:${PORT}`);
  const versionResponse = await clamdCommand("zVERSION");
  console.log(`### clamd zVERSION -> ${versionResponse}`);
  // NOTE: clamd has no zCONFIGS command. The effective limits are proven from the
  // daemon's own startup log (see candidate-runtime-limits.txt), not from a probe.

  const prod = new ClamdScanner({ host: HOST, port: PORT, timeoutMs: 30000, maxBytes: 100 * MiB });

  // ---- 1. CLEAN --------------------------------------------------------
  {
    const r = await timedScan(prod, Buffer.from("DIP stage4 clean payload\n", "utf8"));
    record("CLEAN", "CLEAN", r.result, { engine: r.engine, elapsedMs: r.ms });
  }

  // ---- 1b. raw wire protocol, independent of DIP's client ---------------
  // Proves the framing this harness depends on is the real clamd contract and
  // not an artifact of ClamdScanner. It also pins the fact that a clean verdict
  // is exactly "stream: OK" and an EICAR hit is "stream: ... FOUND".
  {
    const clean = await rawInstream(Buffer.from("DIP raw clean\n", "utf8"));
    const eicar = await rawInstream(Buffer.from(EICAR, "ascii"));
    console.log(`### raw zINSTREAM clean -> ${rawWireOf(clean)}`);
    console.log(`### raw zINSTREAM eicar -> ${rawWireOf(eicar)}`);
    record("raw zINSTREAM clean returns stream: OK", "CLEAN", describeOutcome(clean), {
      normalizedWire: normalizedWireOf(clean), terminated: clean.ok && clean.terminated,
    }, clean.ok && clean.terminated && clean.verdict.kind === "CLEAN" && normalizedWireOf(clean) === "stream: OK");
    record("raw zINSTREAM eicar returns FOUND", "INFECTED", describeOutcome(eicar), {
      normalizedWire: normalizedWireOf(eicar), terminated: eicar.ok && eicar.terminated,
    }, eicar.ok && eicar.terminated && eicar.verdict.kind === "FOUND" && /eicar/iu.test(eicar.verdict.signature));
  }

  // ---- 2. INFECTED (EICAR) --------------------------------------------
  {
    const r = await timedScan(prod, Buffer.from(EICAR, "ascii"));
    record("INFECTED", "INFECTED", r.result, { engine: r.engine, elapsedMs: r.ms });
  }

  // ---- 3. INVERTED: the case that failed on 1.4.3 now passes ------------
  // Stage 3 (StreamMaxLength 25M) -> SCAN_ERROR at 26 MiB, which broke the
  // operator-runbook requirement to support the 100 MiB app ceiling.
  {
    const buf = Buffer.alloc(26 * MiB, 0x41);
    const r = await timedScan(prod, buf);
    record("CLEAN (26 MiB, previously rejected by StreamMaxLength 25M)", "CLEAN", r.result, {
      inputBytes: buf.byteLength, clamdStreamMaxLength: "110M", elapsedMs: r.ms,
    });
  }

  // ---- 4. BOUNDARY: exactly DIP's 100 MiB ceiling -----------------------
  {
    const buf = Buffer.alloc(100 * MiB, 0x42);
    const r = await timedScan(prod, buf);
    record("CLEAN (exactly 100 MiB app ceiling)", "CLEAN", r.result, {
      inputBytes: buf.byteLength, elapsedMs: r.ms, withinClientTimeout: r.ms < 30000,
    });
    // Prove it fits the production client deadline, not just clamd's.
    if (r.ms >= 30000) {
      failures++;
      console.log(`FAIL | 100 MiB exceeded the 30s production client budget | elapsedMs=${r.ms}`);
      rows.push({ test: "100 MiB within 30s client budget", expected: "<30000ms", actual: `${r.ms}ms`, pass: false });
    } else {
      console.log(`PASS | 100 MiB within 30s production client budget | elapsedMs=${r.ms}`);
      rows.push({ test: "100 MiB within 30s client budget", expected: "<30000ms", actual: `${r.ms}ms`, pass: true });
    }
  }

  // ---- 5. BOUNDARY: one byte over the client ceiling --------------------
  // Must be refused client-side without any wire transfer.
  {
    const buf = Buffer.alloc(100 * MiB + 1, 0x43);
    const r = await timedScan(prod, buf);
    record("SCAN_ERROR (100 MiB + 1, client maxBytes guard)", "SCAN_ERROR", r.result, {
      inputBytes: buf.byteLength, maxBytes: 100 * MiB, elapsedMs: r.ms,
    });
  }

  // ---- 6. BOUNDARY: above clamd StreamMaxLength 110M --------------------
  // Two DISTINCT bounds must both hold, and they must not be confused:
  //
  //   6a) clamd's own StreamMaxLength 110M. Proved on the RAW wire, because
  //       ClamdScanner collapses clamd's error text to a bare SCAN_ERROR and
  //       would therefore be unable to attribute the rejection to clamd. This is
  //       the assertion that the raised limit did not remove the upper bound.
  //   6b) DIP's client maxBytes 100M. This is a SECOND, earlier guard: it
  //       rejects before any socket is opened, so it returns in ~0 ms. It is
  //       defence in depth, NOT the clamd limit.
  {
    // 6a: give the scanner a ceiling above the payload so nothing rejects
    // client-side, and observe what clamd actually says on the wire.
    const buf = Buffer.alloc(120 * MiB, 0x44);
    const raw = await rawInstream(buf);
    console.log(`### raw zINSTREAM 120 MiB (over StreamMaxLength 110M) -> ${rawWireOf(raw)}`);
    // The refusal must be clamd's exact prefixless StreamMaxLength reply,
    // "INSTREAM size limit exceeded. ERROR". A generic clamd ERROR (or any other
    // error text) is NOT proof that StreamMaxLength was enforced, and an
    // incomplete/malformed reply is no proof at all.
    const clamdRefused = instreamSizeLimitRefused(raw);
    record("clamd itself refuses a 120 MiB stream (StreamMaxLength 110M, INSTREAM size limit)",
      INSTREAM_SIZE_LIMIT_REFUSAL, describeOutcome(raw), {
        inputBytes: buf.byteLength,
        normalizedWire: normalizedWireOf(raw),
        diagnosis: clamdRefused
          ? "clamd emitted its exact prefixless INSTREAM size-limit refusal"
          : "no StreamMaxLength refusal: a generic ERROR, a prefixed stream: ERROR, an incomplete reply, or a different verdict does not prove the stream limit was enforced",
      }, clamdRefused);

    // 6b: the production client refuses the same input on its own guard.
    const r = await timedScan(prod, buf);
    record("SCAN_ERROR (120 MiB, DIP client maxBytes 100M guard, no wire transfer)",
      "SCAN_ERROR", r.result, {
        inputBytes: buf.byteLength, maxBytes: 100 * MiB, elapsedMs: r.ms,
        rejectedClientSide: r.ms < 50,
      });
  }

  // ---- 7. SECURITY: EICAR hidden beyond MaxFiles must NOT be CLEAN ------
  for (const [label, file] of [
    ["beyond MaxFiles", "bypass_maxfiles.zip"],
    ["beyond MaxRecursion", "bypass_nested.zip"],
  ] as const) {
    const p = `${PAYLOADS}/${file}`;
    if (!existsSync(p)) {
      record(`INFECTED (EICAR ${label})`, "INFECTED", "<payload-missing>", { path: p });
      continue;
    }
    const buf = readFileSync(p);
    const r = await timedScan(prod, buf);
    record(`INFECTED (EICAR ${label})`, "INFECTED", r.result, {
      path: file, inputBytes: buf.byteLength, elapsedMs: r.ms,
    });
  }

  // ---- 8. DECOMPRESSION BOMB: must terminate inside the time budget ----
  {
    const p = `${PAYLOADS}/bomb.zip`;
    if (existsSync(p)) {
      const buf = readFileSync(p);
      const r = await timedScan(prod, buf);
      // Either it is caught, or it terminates with a defined non-CLEAN outcome.
      // It must never silently pass as CLEAN while exceeding the scan budget.
      record("bomb (420 MiB decompressed) is not silently CLEAN", "SCAN_ERROR", r.result, {
        inputBytes: buf.byteLength, elapsedMs: r.ms,
      }, r.result !== "CLEAN" && r.ms < 30000);
    }
  }

  // ---- 8a-8d. DIAGNOSTIC: CLAM-3102 ZIP limit-alert attribution ---------
  // Each case is judged against the raw clamd reply and requires the exact alert
  // for the limit mechanism it is meant to prove. A non-CLEAN client result is
  // NOT evidence: SCAN_TIMEOUT, SCANNER_UNAVAILABLE, a generic SCAN_ERROR, and an
  // unrelated malware FOUND all leave the limit unproven and must fail the case.
  //
  // Every fixture is scanned exactly once here (raw). Test 8 above keeps its
  // original ClamdScanner regression assertion and is the only client scan of a
  // large fixture in this section.
  const limitDiagnostics: readonly {
    fixture: string;
    subject: string;
    expectedAlert: ClamdLimitAlert;
    assertNotSilentClean: boolean;
    mechanism: string;
  }[] = [
    {
      fixture: "bomb.zip",
      subject: "bomb.zip (single 420 MiB member, forced ZIP64)",
      expectedAlert: MAX_FILE_SIZE_ALERT,
      assertNotSilentClean: true,
      mechanism:
        "the DEFLATE member is trimmed at MaxFileSize=110M in unzip.c, and CLAM-3102 reports that trim as Heuristics.Limits.Exceeded.MaxFileSize (not MaxScanSize: the trimmed layer is only 110M of the 400M budget)",
    },
    {
      fixture: "bomb-zip32.zip",
      subject: "bomb-zip32.zip (same 420 MiB member, ZIP32)",
      expectedAlert: MAX_FILE_SIZE_ALERT,
      assertNotSilentClean: true,
      mechanism:
        "identical DEFLATE trim path without the ZIP64 header, so the alert must be the same as bomb.zip",
    },
    {
      fixture: "oversized-member.zip",
      subject: "oversized-member.zip (single 115 MiB member)",
      expectedAlert: MAX_FILE_SIZE_ALERT,
      assertNotSilentClean: false,
      mechanism:
        "115 MiB > MaxFileSize 110M and the aggregate stays far below MaxScanSize 400M, so the per-file trim alert must fire and MaxScanSize must not",
    },
    {
      fixture: "aggregate-scansize.zip",
      subject: "aggregate-scansize.zip (5 x 90 MiB members, 450 MiB aggregate)",
      expectedAlert: MAX_SCAN_SIZE_ALERT,
      assertNotSilentClean: false,
      mechanism:
        "each member 90 MiB < MaxFileSize 110M while the 450 MiB aggregate > MaxScanSize 400M, so only the aggregate budget can fire and it is reported as Heuristics.Limits.Exceeded.MaxScanSize",
    },
  ];

  for (const diagnostic of limitDiagnostics) {
    const path = `${PAYLOADS}/${diagnostic.fixture}`;
    const shared = {
      fixture: diagnostic.fixture,
      path,
      mechanism: diagnostic.mechanism,
      expectedAlert: diagnostic.expectedAlert,
    };

    // A missing fixture must FAIL loudly: skipping it would read as "no failures".
    if (!existsSync(path)) {
      record(`${diagnostic.subject} reports ${diagnostic.expectedAlert}`,
        diagnostic.expectedAlert, "<payload-missing>",
        { ...shared, diagnosis: "required diagnostic fixture is missing; no limit alert can be proven" },
        false);
      continue;
    }

    const buf = readFileSync(path);
    const outcome = await rawInstream(buf, 120000);
    console.log(`### RAW wire ${diagnostic.fixture} -> ${rawWireOf(outcome)}`);
    const evidence = {
      ...shared,
      inputBytes: buf.byteLength,
      elapsedMs: outcome.elapsedMs,
      normalizedWire: normalizedWireOf(outcome),
      rawWire: JSON.stringify(rawWireOf(outcome)),
      terminated: outcome.ok && outcome.terminated,
    };

    if (diagnostic.assertNotSilentClean) {
      const decisive = outcome.ok && outcome.terminated && isDecisiveVerdict(outcome.verdict);
      const silentClean = outcome.ok && outcome.verdict.kind === "CLEAN";
      record(`${diagnostic.subject} raw wire is not silent CLEAN`, "clamd ERROR",
        describeOutcome(outcome), {
          ...evidence,
          diagnosis: silentClean
            ? "silent CLEAN: clamd returned stream: OK for a payload that exceeds MaxFileSize (the CLAM-3102 regression)"
            : decisive
              ? "decisive non-CLEAN wire verdict"
              : "no decisive verdict: an incomplete reply is not evidence",
        }, decisive && !silentClean);
    }

    record(`${diagnostic.subject} reports ${diagnostic.expectedAlert}`,
      diagnostic.expectedAlert, describeOutcome(outcome), {
        ...evidence,
        observedAlert: outcome.ok && outcome.verdict.kind === "LIMIT_ALERT" ? outcome.verdict.alert : null,
        diagnosis: diagnoseLimitOutcome(outcome, diagnostic.expectedAlert),
      }, limitAlertObserved(outcome, diagnostic.expectedAlert));
  }

  // ---- 9. SCAN_ERROR: zero-length input --------------------------------
  {
    const r = await timedScan(prod, Buffer.alloc(0));
    record("SCAN_ERROR (zero-length guard)", "SCAN_ERROR", r.result, {});
  }

  // ---- 10. SCAN_ERROR: over a small client maxBytes --------------------
  {
    const tiny = new ClamdScanner({ host: HOST, port: PORT, timeoutMs: 30000, maxBytes: 8 });
    const r = await timedScan(tiny, Buffer.alloc(4096, 0x42));
    record("SCAN_ERROR (over client maxBytes)", "SCAN_ERROR", r.result, { maxBytes: 8 });
  }

  // ---- 11. SCAN_TIMEOUT: real clamd, real deadline ---------------------
  {
    const tiny = new ClamdScanner({ host: HOST, port: PORT, timeoutMs: 1, maxBytes: 100 * MiB });
    const r = await timedScan(tiny, Buffer.from(EICAR, "ascii"));
    record("SCAN_TIMEOUT (1ms deadline vs live clamd)", "SCAN_TIMEOUT", r.result, { elapsedMs: r.ms });
  }

  // ---- 12. SCANNER_UNAVAILABLE: closed port ----------------------------
  {
    const dead = new ClamdScanner({ host: HOST, port: 1, timeoutMs: 5000, maxBytes: MiB });
    const r = await timedScan(dead, Buffer.from("x", "utf8"));
    record("SCANNER_UNAVAILABLE (closed port)", "SCANNER_UNAVAILABLE", r.result, {});
  }

  // ---- 13. SCANNER_UNAVAILABLE: unresolvable host ----------------------
  {
    const dns = new ClamdScanner({ host: "clamd-does-not-exist.invalid", port: PORT, timeoutMs: 5000, maxBytes: 1024 });
    const r = await timedScan(dns, Buffer.from("x", "utf8"));
    record("SCANNER_UNAVAILABLE (bad DNS)", "SCANNER_UNAVAILABLE", r.result, {});
  }

  // ---- 14. companion metadata probe (production ClamdScanner unchanged) --
  // ClamdScanner intentionally remains unmodified. The experimental service
  // gate obtains attribution through clamd's standard zVERSION command and
  // validates the exact engine/signature fields before accepting the candidate.
  {
    const match = /^ClamAV\s+([^/]+)\/(\d+)\/(.+)$/u.exec(versionResponse.trim());
    const engineVersion = match?.[1] ?? "<undefined>";
    const signatureVersion = match ? `${match[2]}/${match[3]}` : "<undefined>";
    record("engineVersion attributed by zVERSION companion probe", "n/a", engineVersion,
      { source: "zVERSION", productionClientUnchanged: true }, /^\d+\.\d+\.\d+/u.test(engineVersion));
    record("signatureVersion attributed by zVERSION companion probe", "n/a", signatureVersion,
      { source: "zVERSION", productionClientUnchanged: true }, /^\d+\/.+/u.test(signatureVersion));
  }

  writeFileSync("/tmp/poc-results.json", JSON.stringify({ target: `${HOST}:${PORT}`, rows, failures }, null, 2));
  console.log(`### FAILURES=${failures}`);
}

// ---------------------------------------------------------------------------
// Offline self-check: terminator normalization, the anchored reply grammar, exact
// limit-alert classification, the StreamMaxLength refusal, and every negative case
// that must never satisfy an assertion. Needs no clamd, so the parser can be
// validated in a bounded local run:
//   node --import tsx docs/operations/experimental/clamav-arm64-stage4-protocol.mts --self-test
// ---------------------------------------------------------------------------
function okOutcome(wire: string, terminated = true): RawScanOutcome {
  return { ok: true, wire, terminated, elapsedMs: 0, verdict: classifyClamdWire(wire, terminated) };
}

function transportOutcome(failure: "TIMEOUT" | "UNAVAILABLE"): RawScanOutcome {
  return { ok: false, failure, detail: `simulated ${failure}`, elapsedMs: 0 };
}

function runSelfTest(): boolean {
  let failed = 0;
  let checks = 0;
  const check = (name: string, pass: boolean, detail: string) => {
    checks++;
    if (!pass) failed++;
    console.log(`${pass ? "PASS" : "FAIL"} | selftest | ${name} | ${detail}`);
  };

  // Normalization: real NUL and escaped "\0" must both collapse.
  const normalizationCases: Array<[string, string, string]> = [
    ["real NUL terminator", "stream: OK\0", "stream: OK"],
    ["escaped \\0 terminator", "stream: OK\\0", "stream: OK"],
    ["CRLF reply with real NUL", "stream: OK\r\n\0", "stream: OK"],
    ["both terminator forms", "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\\0\0", "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND"],
    ["prefixless INSTREAM refusal", "INSTREAM size limit exceeded. ERROR\0", INSTREAM_SIZE_LIMIT_REFUSAL],
    ["empty reply", "", ""],
  ];
  for (const [name, wire, expected] of normalizationCases) {
    const actual = normalizeClamdWire(wire);
    check(`normalize ${name}`, actual === expected, `normalized=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`);
  }

  // Anchored grammar. A verdict exists only for ONE well-formed, NUL-terminated
  // stanza with nothing before or after it. Numbered cases 1-10 are the required
  // coverage from the review finding.
  const verdictCases: Array<{ name: string; wire: string; terminated: boolean; kind: ClamdWireVerdict["kind"]; alert?: ClamdLimitAlert; signature?: string }> = [
    // 1. valid CLEAN with a real NUL
    { name: "1 valid CLEAN with real NUL", wire: "stream: OK\0", terminated: true, kind: "CLEAN" },
    { name: "1b valid CLEAN with escaped terminator", wire: "stream: OK\\0", terminated: true, kind: "CLEAN" },
    // 2. valid exact MaxFileSize alert
    { name: "2 valid exact MaxFileSize alert", wire: "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0", terminated: true, kind: "LIMIT_ALERT", alert: MAX_FILE_SIZE_ALERT },
    // 3. valid exact MaxScanSize alert
    { name: "3 valid exact MaxScanSize alert", wire: "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0", terminated: true, kind: "LIMIT_ALERT", alert: MAX_SCAN_SIZE_ALERT },
    // 4. the observed prefixless StreamMaxLength refusal (Stage 7 run 43937894854)
    { name: "4 observed prefixless INSTREAM size-limit refusal", wire: "INSTREAM size limit exceeded. ERROR\0", terminated: true, kind: "INSTREAM_SIZE_LIMIT" },
    // 5. FOUND with trailing garbage
    { name: "5 FOUND with trailing garbage", wire: "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND trailinggarbage\0", terminated: true, kind: "MALFORMED" },
    { name: "5b FOUND with trailing stanza text", wire: "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND.\0", terminated: true, kind: "MALFORMED" },
    // 6. FOUND with leading garbage
    { name: "6 FOUND with leading garbage", wire: "stream: garbage Heuristics.Limits.Exceeded.MaxFileSize FOUND\0", terminated: true, kind: "MALFORMED" },
    { name: "6b FOUND with leading prefix junk", wire: "stream: x stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0", terminated: true, kind: "MALFORMED" },
    // 7. multiple concatenated stanzas
    { name: "7 concatenated CLEAN stanzas", wire: "stream: OK\0stream: OK\0", terminated: true, kind: "MALFORMED" },
    { name: "7b alert stanza concatenated with CLEAN stanza", wire: "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0stream: OK\0", terminated: true, kind: "MALFORMED" },
    { name: "7c newline separated stanzas", wire: "stream: OK\nstream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0", terminated: true, kind: "MALFORMED" },
    // 8. embedded or missing terminators
    { name: "8 missing terminator on alert", wire: "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND", terminated: false, kind: "INCOMPLETE" },
    { name: "8b missing terminator on CLEAN", wire: "stream: OK", terminated: false, kind: "INCOMPLETE" },
    { name: "8c embedded terminator followed by garbage", wire: "stream: OK\0garbage", terminated: true, kind: "MALFORMED" },
    { name: "8d empty body with terminator", wire: "\0", terminated: true, kind: "MALFORMED" },
    // 8g-8l: nothing at all may follow the single terminator, not even whitespace
    { name: "8g space after terminator on CLEAN", wire: "stream: OK\0 ", terminated: true, kind: "MALFORMED" },
    { name: "8h tab after terminator on CLEAN", wire: "stream: OK\0\t", terminated: true, kind: "MALFORMED" },
    { name: "8i CRLF after terminator on CLEAN", wire: "stream: OK\0\r\n", terminated: true, kind: "MALFORMED" },
    { name: "8j space after terminator on alert", wire: "stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0 ", terminated: true, kind: "MALFORMED" },
    { name: "8k trailing newline after terminator on alert", wire: "stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0\n", terminated: true, kind: "MALFORMED" },
    { name: "8l space after terminator on INSTREAM refusal", wire: "INSTREAM size limit exceeded. ERROR\0 ", terminated: true, kind: "MALFORMED" },
    { name: "8m CRLF before terminator is still valid CLEAN", wire: "stream: OK\r\n\0", terminated: true, kind: "CLEAN" },
    { name: "8e missing stanza prefix", wire: "OK\0", terminated: true, kind: "MALFORMED" },
    { name: "8f garbage reply", wire: "nonsense\0", terminated: true, kind: "MALFORMED" },
    // 9. generic ERROR (prefixed, and with a file prefix) - never a limit alert and
    //    never proof that StreamMaxLength was enforced
    { name: "9 generic ERROR", wire: "stream: INSTREAM size limit exceeded. ERROR\0", terminated: true, kind: "ERROR" },
    { name: "9b generic ERROR with file prefix", wire: "stream: Error processing command. ERROR\0", terminated: true, kind: "ERROR" },
    { name: "9c prefixless refusal with trailing garbage", wire: "INSTREAM size limit exceeded. ERROR trailinggarbage\0", terminated: true, kind: "MALFORMED" },
    // other valid forms that must keep working
    { name: "genuine EICAR detection", wire: "stream: Win.Test.EICAR_HDB-1 FOUND\0", terminated: true, kind: "FOUND", signature: "Win.Test.EICAR_HDB-1" },
    { name: "MaxFiles alert", wire: "stream: Heuristics.Limits.Exceeded.MaxFiles FOUND\0", terminated: true, kind: "LIMIT_ALERT", alert: MAX_FILES_ALERT },
    { name: "MaxRecursion alert", wire: "stream: Heuristics.Limits.Exceeded.MaxRecursion FOUND\0", terminated: true, kind: "LIMIT_ALERT", alert: MAX_RECURSION_ALERT },
    { name: "MaxScanTime alert", wire: "stream: Heuristics.Limits.Exceeded.MaxScanTime FOUND\0", terminated: true, kind: "LIMIT_ALERT", alert: MAX_SCAN_TIME_ALERT },
  ];
  for (const testCase of verdictCases) {
    const verdict = classifyClamdWire(testCase.wire, testCase.terminated);
    const kindOk = verdict.kind === testCase.kind;
    const alertOk = testCase.alert === undefined || (verdict.kind === "LIMIT_ALERT" && verdict.alert === testCase.alert);
    const signatureOk = testCase.signature === undefined || (verdict.kind === "FOUND" && verdict.signature === testCase.signature);
    check(`classify ${testCase.name}`, kindOk && alertOk && signatureOk,
      `kind=${verdict.kind} expected=${testCase.kind} wire=${JSON.stringify(testCase.wire)}`);
  }

  // Limit assertions: exactly one alert name passes, every other outcome fails.
  const maxFileSizeOutcome = okOutcome("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0");
  const maxScanSizeOutcome = okOutcome("stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0");
  check("MaxFileSize alert satisfies MaxFileSize assertion",
    limitAlertObserved(maxFileSizeOutcome, MAX_FILE_SIZE_ALERT), describeOutcome(maxFileSizeOutcome));
  check("MaxFileSize alert does NOT satisfy MaxScanSize assertion",
    !limitAlertObserved(maxFileSizeOutcome, MAX_SCAN_SIZE_ALERT), "cross-alert must fail");
  check("MaxScanSize alert satisfies MaxScanSize assertion",
    limitAlertObserved(maxScanSizeOutcome, MAX_SCAN_SIZE_ALERT), describeOutcome(maxScanSizeOutcome));
  check("MaxScanSize alert does NOT satisfy MaxFileSize assertion",
    !limitAlertObserved(maxScanSizeOutcome, MAX_FILE_SIZE_ALERT), "cross-alert must fail");

  // 10. Negatives (including timeout and unavailable scanner): none of these may
  // satisfy a limit assertion, and none may satisfy the StreamMaxLength assertion.
  const negatives: Array<{ name: string; outcome: RawScanOutcome }> = [
    { name: "1 CLEAN", outcome: okOutcome("stream: OK\0") },
    { name: "2 unrelated FOUND", outcome: okOutcome("stream: Win.Test.EICAR_HDB-1 FOUND\0") },
    { name: "5 FOUND with trailing garbage", outcome: okOutcome("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND trailinggarbage\0") },
    { name: "6 FOUND with leading garbage", outcome: okOutcome("stream: garbage Heuristics.Limits.Exceeded.MaxFileSize FOUND\0") },
    { name: "7 concatenated stanzas", outcome: okOutcome("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0stream: OK\0") },
    { name: "8 missing terminator", outcome: okOutcome("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND", false) },
    { name: "8b already terminated then more text", outcome: okOutcome("stream: OK\0garbage") },
    { name: "9 generic ERROR", outcome: okOutcome("stream: INSTREAM size limit exceeded. ERROR\0") },
    { name: "9b generic ERROR with file prefix", outcome: okOutcome("stream: Error processing command. ERROR\0") },
    { name: "9c prefixless refusal with trailing garbage", outcome: okOutcome("INSTREAM size limit exceeded. ERROR trailinggarbage\0") },
    { name: "8g space after terminator", outcome: okOutcome("stream: OK\0 ") },
    { name: "8h tab after terminator", outcome: okOutcome("stream: OK\0\t") },
    { name: "8i CRLF after terminator", outcome: okOutcome("stream: OK\0\r\n") },
    { name: "8j space after terminator on alert", outcome: okOutcome("stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND\0 ") },
    { name: "8k newline after terminator on alert", outcome: okOutcome("stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\0\n") },
    { name: "9d malformed reply", outcome: okOutcome("nonsense\0") },
    { name: "10 TIMEOUT", outcome: transportOutcome("TIMEOUT") },
    { name: "10b UNAVAILABLE", outcome: transportOutcome("UNAVAILABLE") },
  ];
  for (const negative of negatives) {
    const rejected =
      !limitAlertObserved(negative.outcome, MAX_FILE_SIZE_ALERT) &&
      !limitAlertObserved(negative.outcome, MAX_SCAN_SIZE_ALERT) &&
      !instreamSizeLimitRefused(negative.outcome);
    check(`${negative.name} never satisfies a limit or StreamMaxLength assertion`, rejected,
      `actual=${describeOutcome(negative.outcome)}`);
  }

  // 4. The StreamMaxLength assertion accepts ONLY the exact prefixless refusal.
  const refusalOutcome = okOutcome("INSTREAM size limit exceeded. ERROR\0");
  check("4 prefixless INSTREAM refusal satisfies the StreamMaxLength assertion",
    instreamSizeLimitRefused(refusalOutcome), describeOutcome(refusalOutcome));
  check("4b prefixed stream: ERROR does NOT satisfy the StreamMaxLength assertion",
    !instreamSizeLimitRefused(okOutcome("stream: INSTREAM size limit exceeded. ERROR\0")),
    "generic ERROR must not prove StreamMaxLength");
  check("4c refusal without terminator does NOT satisfy the StreamMaxLength assertion",
    !instreamSizeLimitRefused(okOutcome("INSTREAM size limit exceeded. ERROR", false)),
    "unterminated refusal must not prove StreamMaxLength");
  check("4d refusal with trailing garbage does NOT satisfy the StreamMaxLength assertion",
    !instreamSizeLimitRefused(okOutcome("INSTREAM size limit exceeded. ERROR trailinggarbage\0")),
    "trailing garbage must not prove StreamMaxLength");
  check("4e CLEAN does NOT satisfy the StreamMaxLength assertion",
    !instreamSizeLimitRefused(okOutcome("stream: OK\0")), "CLEAN is not a refusal");
  check("4f refusal with whitespace after terminator does NOT satisfy the StreamMaxLength assertion",
    !instreamSizeLimitRefused(okOutcome("INSTREAM size limit exceeded. ERROR\0 ")),
    "bytes after the terminator are not a complete reply");
  // The predicate must also require a successful, terminator-confirmed read: a verdict
  // object alone is not enough evidence.
  const refusalVerdictWithoutTerminator: RawScanOutcome = {
    ok: true,
    wire: INSTREAM_SIZE_LIMIT_REFUSAL,
    terminated: false,
    elapsedMs: 0,
    verdict: { kind: "INSTREAM_SIZE_LIMIT" },
  };
  check("4g INSTREAM_SIZE_LIMIT without a terminator does NOT satisfy the StreamMaxLength assertion",
    !instreamSizeLimitRefused(refusalVerdictWithoutTerminator),
    "terminated=false must fail even if the verdict kind matches");
  const refusalTransportFailure: RawScanOutcome = transportOutcome("UNAVAILABLE");
  check("4h transport failure does NOT satisfy the StreamMaxLength assertion",
    !instreamSizeLimitRefused(refusalTransportFailure), "ok=false must fail");
  check("4i exact prefixless refusal with a real NUL does satisfy the StreamMaxLength assertion",
    instreamSizeLimitRefused(okOutcome("INSTREAM size limit exceeded. ERROR\0")),
    "the legitimate observed reply must still pass");

  console.log(`### SELFTEST_CHECKS=${checks} ### SELFTEST_FAILURES=${failed}`);
  return failed === 0;
}

if (process.argv.includes("--self-test")) {
  process.exitCode = runSelfTest() ? 0 : 1;
} else {
  main().catch((e) => {
    console.error("HARNESS_FATAL", e);
    process.exit(1);
  });
}
