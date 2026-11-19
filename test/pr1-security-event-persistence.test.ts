/**
 * PR-1 regression coverage for malware security-event persistence.
 *
 * `security_events.id` is a Prisma-side `@default(uuid())` with no database
 * default, so the raw INSERT must supply the key itself. The original statement
 * omitted it, Postgres raised `23502 null value in column "id"`, and the
 * fail-closed catch swallowed the error — every rejection was logged but never
 * persisted. These tests pin the id, the severity mapping and the fail-closed
 * error handling; the database-backed proof runs in
 * `pr1-output-screening.integration.test.ts`.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  buildMalwareSecurityEvent,
  persistMalwareSecurityEvent,
  requireCleanOutput,
  type MalwareScanner,
} from "../src/lib/malware";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

test("PR-1: a security event always carries an explicit primary key", () => {
  const event = buildMalwareSecurityEvent("INFECTED", "a".repeat(64), "clamav-clamd", "output");
  assert.match(event.id, UUID_PATTERN, "the raw insert needs a UUID because the column has no database default");
  assert.equal(event.type, "MALWARE_SCAN_REJECTED");
  assert.equal(event.severity, "ERROR");
  assert.deepEqual(event.details, { result: "INFECTED", checksumSha256: "a".repeat(64), engine: "clamav-clamd", source: "output" });

  const generated = new Set(Array.from({ length: 10 }, () => buildMalwareSecurityEvent("SCAN_ERROR", "b".repeat(64), "clamav-clamd").id));
  assert.equal(generated.size, 10, "ids must be unique per event");
});

test("PR-1: severity separates an infection from an infrastructure fault", () => {
  assert.equal(buildMalwareSecurityEvent("INFECTED", "c".repeat(64), "clamav-clamd").severity, "ERROR");
  for (const code of ["SCAN_ERROR", "SCAN_TIMEOUT", "SCANNER_UNAVAILABLE"]) {
    assert.equal(buildMalwareSecurityEvent(code, "c".repeat(64), "clamav-clamd").severity, "WARNING");
  }
  assert.equal(buildMalwareSecurityEvent("INFECTED", "c".repeat(64), "clamav-clamd").details.source, "upload", "uploads stay the default source");
});

test("PR-1: persistence receives the keyed record and never throws on failure", async () => {
  const seen: unknown[] = [];
  const event = buildMalwareSecurityEvent("INFECTED", "d".repeat(64), "clamav-clamd", "output");
  await persistMalwareSecurityEvent(event, async (record) => { seen.push(record); });
  assert.equal(seen.length, 1);
  assert.equal((seen[0] as { id?: string }).id, event.id, "the executor must receive the non-null id");

  await assert.doesNotReject(
    () => persistMalwareSecurityEvent(event, async () => { throw Object.assign(new Error("insert failed"), { code: "23502" }); }),
    "a persistence fault must be logged, never rethrown: the scan decision still fails closed",
  );
});

test("PR-1: rejection still fails closed when the security event cannot be persisted", async () => {
  const scanner: MalwareScanner = { async scan() { return { result: "INFECTED", engine: "test", scannedAt: new Date(0) }; } };
  await assert.rejects(
    () => requireCleanOutput(new TextEncoder().encode("%PDF-1.7\ninfected"), scanner),
    (error: unknown) => (error as { code?: string }).code === "INFECTED",
  );
});

test("PR-1 (structure): the insert supplies the id column and a bound id parameter", async () => {
  const source = await readFile(new URL("../src/lib/malware/index.ts", import.meta.url), "utf8");
  assert.match(source, /INSERT INTO security_events \("id", "type", "severity", "details"\)/);
  assert.match(source, /VALUES \(\$\{event\.id\}::uuid/);
  assert.doesNotMatch(source, /INSERT INTO security_events \(type, severity, details\)/, "the id-less statement must not return");
  assert.match(source, /import \{ createHash, randomUUID \} from "node:crypto"/);
});
