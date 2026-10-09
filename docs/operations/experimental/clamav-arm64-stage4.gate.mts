// ============================================================================
// EXPERIMENTAL ClamAV ARM64 Stage 4 — fail-closed verification.
//
// Exercises DIP's PRODUCTION requireCleanUpload() (src/lib/malware/index.ts)
// with a real ClamdScanner against a real clamd. It asserts that every
// non-CLEAN outcome throws MalwareScanError and that NO storage key is ever
// produced, mirroring orchestrator.ts:31 (scan) running before :38 (put).
//
// DB/logger/metrics are replaced ONLY where a side effect would require a
// production service. The gate decision logic under test is unmodified.
//
// DIFFERENCE FROM STAGE 3 (clamav-arm64-poc.gate.mts):
// Stage 3 asserted "SCAN_ERROR (StreamMaxLength) is rejected" using 26 MiB.
// That assertion encoded the 1.4.3 StreamMaxLength 25M defect as a REQUIREMENT:
// the runbook requires supporting the 100 MiB app ceiling, so 26 MiB must now
// be ALLOWED. Stage 3 also had no positive storage-write control for a large
// file, so a regression that rejected everything would have scored 10/10.
//
// Stage 4 therefore:
//   1. REMOVES the 26 MiB-must-be-rejected assertion.
//   2. ADDS positive "expectAllowed" controls at 26 MiB and exactly 100 MiB,
//      each of which MUST reach storage.put. This is the anti-regression test.
//   3. RAISES the over-limit rejection to 120 MiB, which is above clamd's
//      StreamMaxLength 110M. With the live scanner (maxBytes 100 MiB) this is
//      rejected by DIP's own client guard before any socket opens -- the
//      resulting ~0 ms is the proof it was the client, not clamd. The
//      authoritative proof that clamd enforces 110M is the raw-wire case in
//      clamav-arm64-stage4-protocol.mts, which captures clamd's actual
//      "INSTREAM size limit exceeded. ERROR" response.
// ============================================================================
import { createHash } from "node:crypto";
import { requireCleanUpload } from "../../../src/lib/malware";
import { MalwareScanError } from "../../../src/lib/malware/types";
import { ClamdScanner } from "../../../src/lib/malware/clamd";
import type { MalwareScanner, MalwareScanResultCode } from "../../../src/lib/malware/types";

const HOST = process.env.CLAMD_HOST ?? "clamav-poc-clamd";
const PORT = Number(process.env.CLAMD_PORT ?? 3310);
const EICAR =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const MiB = 1024 * 1024;

const outcomes: Array<Record<string, unknown>> = [];
let failures = 0;

// Mirrors orchestrator.ts:35-38: the storage key is only created AFTER the
// scan gate resolves. We record whether that was ever reached.
const storageWrites: string[] = [];

async function expectRejected(
  name: string,
  expectedCode: MalwareScanResultCode,
  bytes: Buffer,
  scanner: MalwareScanner,
) {
  const checksum = createHash("sha256").update(bytes).digest("hex");
  let thrown: unknown;
  let resolved = false;
  try {
    await requireCleanUpload(bytes, scanner, async () => undefined);
    resolved = true;
  } catch (e) {
    thrown = e;
  }
  const isMse = thrown instanceof MalwareScanError;
  const code = isMse ? (thrown as MalwareScanError).code : thrown ? String((thrown as Error).name) : "<none>";
  // storage.put is only reached when requireCleanUpload resolves
  if (resolved) storageWrites.push(`REACHED-PUT:${checksum.slice(0, 12)}`);
  const pass = !resolved && isMse && code === expectedCode;
  if (!pass) failures++;
  outcomes.push({ case: name, expectedCode, actualCode: code, threwMalwareScanError: isMse, resolved, reachedStoragePut: resolved, pass });
  console.log(
    `${pass ? "PASS" : "FAIL"} | ${name} | expected=${expectedCode} | actual=${code} | resolved=${resolved} | reachedStoragePut=${resolved}`,
  );
}

// Stage 4 addition. A file that SHOULD be accepted must resolve the gate and
// must reach storage.put. Without this, a candidate that rejected every upload
// would still score a perfect fail-closed result.
async function expectAllowed(name: string, bytes: Buffer, scanner: MalwareScanner) {
  const checksum = createHash("sha256").update(bytes).digest("hex");
  let thrown: unknown;
  let resolved = false;
  try {
    await requireCleanUpload(bytes, scanner, async () => undefined);
    resolved = true;
  } catch (e) {
    thrown = e;
  }
  const isMse = thrown instanceof MalwareScanError;
  const code = isMse ? (thrown as MalwareScanError).code : thrown ? String((thrown as Error).name) : "<none>";
  if (resolved) storageWrites.push(`REACHED-PUT:${checksum.slice(0, 12)}`);
  const pass = resolved;
  if (!pass) failures++;
  outcomes.push({ case: name, expectedCode: "CLEAN", actualCode: code, resolved, reachedStoragePut: resolved, pass });
  console.log(
    `${pass ? "PASS" : "FAIL"} | ${name} | expected=CLEAN | actual=${code} | resolved=${resolved} | reachedStoragePut=${resolved}`,
  );
}

async function main() {
  const live = new ClamdScanner({ host: HOST, port: PORT, timeoutMs: 30000, maxBytes: 100 * MiB });

  await expectRejected("INFECTED (EICAR) is rejected", "INFECTED", Buffer.from(EICAR, "ascii"), live);
  await expectRejected(
    "SCAN_ERROR (120 MiB, over limits: DIP client maxBytes 100M guard) is rejected",
    "SCAN_ERROR",
    Buffer.alloc(120 * MiB, 0x41),
    live,
  );
  await expectRejected("SCAN_ERROR (zero-length) is rejected", "SCAN_ERROR", Buffer.alloc(0), live);
  await expectRejected(
    "SCAN_ERROR (over maxBytes) is rejected",
    "SCAN_ERROR",
    Buffer.alloc(4096, 0x42),
    new ClamdScanner({ host: HOST, port: PORT, timeoutMs: 30000, maxBytes: 8 }),
  );
  await expectRejected(
    "SCAN_TIMEOUT is rejected",
    "SCAN_TIMEOUT",
    Buffer.from(EICAR, "ascii"),
    new ClamdScanner({ host: HOST, port: PORT, timeoutMs: 1, maxBytes: 100 * MiB }),
  );
  await expectRejected(
    "SCANNER_UNAVAILABLE (closed port) is rejected",
    "SCANNER_UNAVAILABLE",
    Buffer.from("x"),
    new ClamdScanner({ host: HOST, port: 1, timeoutMs: 5000, maxBytes: 1024 }),
  );
  await expectRejected(
    "SCANNER_UNAVAILABLE (bad DNS) is rejected",
    "SCANNER_UNAVAILABLE",
    Buffer.from("x"),
    new ClamdScanner({ host: "clamd-does-not-exist.invalid", port: PORT, timeoutMs: 5000, maxBytes: 1024 }),
  );

  // A throwing scanner must collapse to SCAN_ERROR (index.ts:44) -> still fail closed
  const throwing: MalwareScanner = {
    async scan(): Promise<never> {
      throw new Error("scanner exploded");
    },
  };
  await expectRejected("throwing scanner collapses to SCAN_ERROR", "SCAN_ERROR", Buffer.from("x"), throwing);

  // ---- Stage 4 positive controls: the app ceiling must be REACHABLE -------
  // Both must resolve AND reach storage.put. These are the regression guards
  // against a scanner that over-blocks legitimate large uploads.
  await expectAllowed("CLEAN (100 MiB app ceiling now reachable)", Buffer.alloc(100 * MiB, 0x41), live);
  await expectAllowed("CLEAN (26 MiB, wrongly rejected on 1.4.3 StreamMaxLength 25M)", Buffer.alloc(26 * MiB, 0x41), live);

  // Control: CLEAN must be the ONLY outcome that passes the gate
  const clean = await requireCleanUpload(Buffer.from("DIP stage4 clean\n", "utf8"), live, async () => undefined);
  const cleanPass = typeof clean.checksumSha256 === "string" && clean.checksumSha256.length === 64;
  if (!cleanPass) failures++;
  storageWrites.push(`REACHED-PUT:${clean.checksumSha256.slice(0, 12)}`);
  outcomes.push({ case: "CLEAN passes gate (control)", checksumSha256: clean.checksumSha256, engine: clean.engine, pass: cleanPass });
  console.log(`${cleanPass ? "PASS" : "FAIL"} | CLEAN passes gate (control) | checksum=${clean.checksumSha256.slice(0, 16)}... engine=${clean.engine}`);

  // Assert ONLY the three CLEAN cases reached storage (control + 100 MiB + 26 MiB)
  const reached = storageWrites.length;
  const onlyClean = reached === 3;
  if (!onlyClean) failures++;
  outcomes.push({ case: "only CLEAN reaches storage.put", reachedCount: reached, pass: onlyClean });
  console.log(`${onlyClean ? "PASS" : "FAIL"} | only CLEAN reaches storage.put | reached=${reached} (expected 3)`);

  console.log(`### FAILURES=${failures}`);
  console.log("### " + JSON.stringify(outcomes));
}

main().catch((e) => { console.error("GATE_HARNESS_FATAL", e); process.exit(1); });
