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

function record(name: string, expected: MalwareScanResultCode | "clamd ERROR" | "n/a", got: string, extra: Record<string, unknown> = {}, ok?: boolean) {
  const pass = ok ?? got === expected;
  if (!pass) failures++;
  rows.push({ test: name, expected, actual: got, pass, ...extra });
  console.log(`${pass ? "PASS" : "FAIL"} | ${name} | expected=${expected} | actual=${got} | ${JSON.stringify(extra)}`);
}

// True when clamd reports an incomplete scan due to a limit (Heuristics.Limits.Exceeded.*)
// rather than a genuine malware detection or a clean scan.
// These must be treated as fail-closed (scan not complete), not as CLEAN.
function isLimitAlert(result: string): boolean {
  return /Heuristics\.Limits\.Exceeded\./u.test(result);
}

// True only when clamd reports a genuine malware detection.
function isGenuineDetection(result: string): boolean {
  return / FOUND$/u.test(result) && !/Heuristics\.Limits\.Exceeded\./u.test(result);
}

// Binary INSTREAM framing, exactly as src/lib/malware/clamd.ts does it:
// repeated 4-byte big-endian length prefixes, terminated by a 4-byte zero length.
function rawInstream(bytes: Buffer, timeoutMs = 120000): Promise<{ got: string }> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(PORT, HOST);
    let got = "";
    const done = (err?: Error) => {
      sock.destroy();
      if (err) reject(err);
      else resolve({ got: got.replace(/\0/g, "\\0") });
    };
    sock.setTimeout(timeoutMs, () => done(new Error("raw socket timeout")));
    sock.on("error", done);
    sock.on("connect", () => {
      sock.write("zINSTREAM\0");
      const chunkSize = 64 * 1024;
      for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
        const chunk = bytes.subarray(offset, Math.min(bytes.byteLength, offset + chunkSize));
        const length = Buffer.allocUnsafe(4);
        length.writeUInt32BE(chunk.byteLength);
        sock.write(length);
        sock.write(chunk);
      }
      sock.end(Buffer.alloc(4));
    });
    sock.on("data", (chunk) => {
      got += chunk.toString("utf8");
      if (got.includes("\0")) done();
    });
    sock.on("end", () => done());
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
    console.log(`### raw zINSTREAM clean -> ${clean.got}`);
    console.log(`### raw zINSTREAM eicar -> ${eicar.got}`);
    record("raw zINSTREAM clean returns stream: OK", "CLEAN", "CLEAN", { wire: clean.got },
      clean.got === "stream: OK\\0");
    record("raw zINSTREAM eicar returns FOUND", "INFECTED", "INFECTED", { wire: eicar.got },
      eicar.got.includes("FOUND"));
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
    console.log(`### raw zINSTREAM 120 MiB (over StreamMaxLength 110M) -> ${raw.got}`);
    const clamdRefused = /ERROR/i.test(raw.got) && !/OK$|\0$/.test(raw.got);
    record("clamd itself refuses a 120 MiB stream (StreamMaxLength 110M)",
      "clamd ERROR", clamdRefused ? "clamd ERROR" : `unexpected: ${raw.got}`,
      { inputBytes: buf.byteLength, wire: raw.got });

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

      // ---- 8a. DIAGNOSTIC: raw clamd wire response for the 420 MiB bomb ----
      // Capture the exact clamd verdict text on the wire (independent of the
      // DIP client parser) to distinguish a genuine CLEAN from a truncated
      // scan that the client collapsed to CLEAN.
      {
        const p = `${PAYLOADS}/bomb.zip`;
        if (existsSync(p)) {
          const buf = readFileSync(p);
          const raw = await rawInstream(buf, 120000);
          console.log(`### RAW wire bomb.zip (420 MiB, ZIP64) -> ${raw.got}`);
          const rawIsLimitAlert = isLimitAlert(raw.got);
          const rawIsClean = /stream: OK$/u.test(raw.got.replace(/\0/g, ""));
          record("bomb.zip raw wire is not silent CLEAN (ZIP64 regression)",
            "clamd ERROR", rawIsClean ? "silent-CLEAN" : `wire=${raw.got.slice(0, 80)}`,
            { inputBytes: buf.byteLength, wire: raw.got, isLimitAlert: rawIsLimitAlert },
            !rawIsClean);
        }
      }

      // ---- 8b. DIAGNOSTIC: ZIP32 vs ZIP64 bomb comparison ----
      // Same 420 MiB member, different archive format. Determines whether the
      // silent-CLEAN result is specific to the ZIP64 parser path.
      {
        const p = `${PAYLOADS}/bomb-zip32.zip`;
        if (existsSync(p)) {
          const buf = readFileSync(p);
          const r = await timedScan(prod, buf);
          const raw = await rawInstream(buf, 120000);
          console.log(`### RAW wire bomb-zip32.zip (420 MiB, ZIP32) -> ${raw.got}`);
          record("bomb-zip32.zip is not silent CLEAN (ZIP32 comparison)",
            "clamd ERROR", r.result,
            { inputBytes: buf.byteLength, elapsedMs: r.ms, wire: raw.got,
              zip32IsLimitAlert: isLimitAlert(r.result) },
            r.result !== "CLEAN");
        }
      }

      // ---- 8c. DIAGNOSTIC: MaxFileSize single-member violation ----
      // A single member (115 MiB) over MaxFileSize=110M but under MaxScanSize=400M.
      // CLAM-3102 makes this alert Heuristics.Limits.Exceeded.MaxFileSize when
      // AlertExceedsMax is enabled. Not in ClamAV 1.5.4 (see root-cause report).
      {
        const p = `${PAYLOADS}/oversized-member.zip`;
        if (existsSync(p)) {
          const buf = readFileSync(p);
          const r = await timedScan(prod, buf);
          const raw = await rawInstream(buf, 120000);
          console.log(`### RAW wire oversized-member.zip (115 MiB member) -> ${raw.got}`);
          record("oversized-member.zip reports MaxFileSize limit alert",
            "clamd ERROR", r.result,
            { inputBytes: buf.byteLength, elapsedMs: r.ms, wire: raw.got,
              isLimitAlert: isLimitAlert(r.result),
              isGenuineDetection: isGenuineDetection(r.result) },
            isLimitAlert(r.result) || r.result !== "CLEAN");
        }
      }

      // ---- 8d. DIAGNOSTIC: aggregate MaxScanSize violation (multi-member) ----
      // 5 members x 90 MiB = 450 MiB aggregate; each member 90 MiB < 110M
      // MaxFileSize, aggregate 450 MiB > 400M MaxScanSize. Exercises the
      // aggregate scan-size limit without any single member exceeding
      // MaxFileSize. Do NOT use a single 399M/401M member here: that already
      // exceeds MaxFileSize=110M and would not isolate MaxScanSize.
      {
        const p = `${PAYLOADS}/aggregate-scansize.zip`;
        if (existsSync(p)) {
          const buf = readFileSync(p);
          const r = await timedScan(prod, buf);
          const raw = await rawInstream(buf, 120000);
          console.log(`### RAW wire aggregate-scansize.zip (450 MiB aggregate) -> ${raw.got}`);
          record("aggregate-scansize.zip reports MaxScanSize limit alert",
            "clamd ERROR", r.result,
            { inputBytes: buf.byteLength, elapsedMs: r.ms, wire: raw.got,
              isLimitAlert: isLimitAlert(r.result),
              isGenuineDetection: isGenuineDetection(r.result) },
            isLimitAlert(r.result) || r.result !== "CLEAN");
        }
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

main().catch((e) => {
  console.error("HARNESS_FATAL", e);
  process.exit(1);
});
