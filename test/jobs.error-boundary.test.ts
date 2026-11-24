/**
 * FF-07 / round 2 — a synthetic canary that must never appear in persisted output.
 *
 * The canary is planted in every error shape a real failure can take, and the
 * boundary is required to drop all of it. This is the test the review asked for: it
 * fails if *any* path reintroduces a message into a job row, including a path added
 * later by someone who has not read this file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  ALLOWED_ERROR_CODES,
  isPublicErrorCode,
  jobErrorRecord,
  publicErrorCode,
  publicErrorMessage,
} from "../src/lib/jobs/error-boundary";

/** Unique enough that a substring hit is unambiguous. */
const CANARY = "CANARY_7f3a1c_SECRET_PATH_/var/task/app/internal/db.ts_CONN_redis://user:hunter2@host:6379";

void readFileSync; // keep the import list honest if assertions are trimmed

test("the canary cannot survive a native TypeError", () => {
  const error = new TypeError(`Cannot read properties of undefined (reading 'x') ${CANARY}`);
  const record = jobErrorRecord(error);
  assert.deepEqual(record, { code: "PROCESSING_FAILED" });
  assert.equal(JSON.stringify(record).includes(CANARY), false);
});

test("the canary cannot survive a Redis error that carries a key or URL", () => {
  const error = Object.assign(new Error(`ERR NOSCRIPT ${CANARY}`), { code: "ECONNREFUSED" });
  const record = jobErrorRecord(error);
  // `ECONNREFUSED` is a real code but not one this product may persist.
  assert.equal(record.code, "PROCESSING_FAILED");
  assert.equal(JSON.stringify(record).includes(CANARY), false);
});

test("the canary cannot survive a filesystem error with an absolute path", () => {
  const error = Object.assign(new Error(`ENOENT: no such file or directory, open '${CANARY}'`), { code: "ENOENT" });
  assert.deepEqual(jobErrorRecord(error), { code: "PROCESSING_FAILED" });
});

test("the canary cannot survive a parser error quoting document bytes", () => {
  const error = new Error(`Failed to parse PDF: << /Type /XObject ... ${CANARY}`);
  assert.equal(JSON.stringify(jobErrorRecord(error)).includes(CANARY), false);
});

test("the canary cannot survive an error whose code field IS the canary", () => {
  // A throw site that passes a message through `code` is the exact mistake this
  // boundary exists to stop.
  const error = Object.assign(new Error("boom"), { code: CANARY });
  assert.deepEqual(jobErrorRecord(error), { code: "PROCESSING_FAILED" });
});

test("the canary cannot survive a non-Error throw", () => {
  for (const thrown of [CANARY, { message: CANARY }, [CANARY], null, undefined, 42]) {
    assert.equal(JSON.stringify(jobErrorRecord(thrown)).includes(CANARY), false, `leaked for ${String(thrown)}`);
  }
});

test("an allowlisted domain code is preserved verbatim", () => {
  for (const code of ["FORM_UNSUPPORTED", "FORM_RESTRICTED", "MALWARE_DETECTED", "WORKER_TIMEOUT"]) {
    assert.equal(publicErrorCode(Object.assign(new Error(CANARY), { code })), code);
  }
});

test("a plausible-looking but unknown code is not persisted", () => {
  // The vocabulary is closed: a new subsystem must add its code deliberately.
  assert.equal(publicErrorCode(Object.assign(new Error("x"), { code: "SOMETHING_NEW_FAILED" })), "PROCESSING_FAILED");
  assert.equal(isPublicErrorCode("SOMETHING_NEW_FAILED"), false);
});

test("a lowercase or free-form code is rejected by shape", () => {
  for (const code of ["error", "Error: boom", "process failed", "FAILED: secret", "A"]) {
    assert.equal(publicErrorCode(Object.assign(new Error("x"), { code })), "PROCESSING_FAILED", code);
  }
});

test("a persisted record has exactly one field, and it is a code", () => {
  const record = jobErrorRecord(Object.assign(new Error(CANARY), { code: "FORM_UNSUPPORTED" }));
  assert.deepEqual(Object.keys(record), ["code"]);
  assert.equal(typeof record.code, "string");
});

test("client messages are fixed strings that never contain the canary", () => {
  const code = publicErrorCode(Object.assign(new Error(CANARY), { code: "FORM_UNSUPPORTED" }));
  const message = publicErrorMessage(code);
  assert.equal(message.includes(CANARY), false);
  assert.match(message, /not supported/u);
  // Unknown codes still produce a stable sentence.
  assert.equal(publicErrorMessage("PROCESSING_FAILED").includes(CANARY), false);
});

test("every allowlisted code is shaped like a code", () => {
  for (const code of ALLOWED_ERROR_CODES) {
    assert.match(code, /^[A-Z][A-Z0-9_]{2,63}$/u, code);
  }
});

test("the pipeline no longer persists a raw message (synthetic-canary source check)", () => {
  // The canary test above proves the boundary; this proves the *pipeline uses it*.
  const source = readFileSync(new URL("../src/lib/jobs/document-pipeline.ts", import.meta.url), "utf8");
  const failureWrites = source.split("\n").filter((line) => line.includes('status: "FAILED"'));
  assert.ok(failureWrites.length >= 2, "the job and step failure writes must both exist");
  for (const line of failureWrites) {
    assert.equal(line.includes("error.message"), false, `a raw message reached a persisted field: ${line.slice(0, 80)}`);
    assert.match(line, /jobErrorRecord\(error\)/u);
  }
  // The worker's *failure* record writes a code, never a message. (Its other
  // `toolExecution.create` is the AI success record, which carries output and has
  // no error field at all — asserting on every create line would be wrong.)
  const worker = readFileSync(new URL("../workers/document-worker.ts", import.meta.url), "utf8");
  const harness = readFileSync(new URL("../test/fill-forms.contract.test.ts", import.meta.url), "utf8");
  assert.ok(harness.length > 0);
  assert.equal(worker.includes("error: { message:"), false, "the worker must not persist a message");
  assert.match(worker, /errorCode: job\.errorCode \?\? "PROCESSING_FAILED"/u, "the failure record must persist an allowlisted code");
  // And the API never returns a message straight from an error object.
  const api = readFileSync(new URL("../src/app/api/jobs/[tool]/route.ts", import.meta.url), "utf8");
  assert.equal(/message: error\.message/u.test(api.split("\n").filter((line) => line.includes("Response.json")).join("\n")), false);
});

test("every code the processing paths actually raise is preserved, not collapsed", () => {
  // A closed vocabulary is only useful if it does not blind support. Rather than
  // listing codes by hand — which is what let `SCANNER_UNAVAILABLE` and
  // `PDF_PASSWORD_INVALID` silently collapse to `PROCESSING_FAILED` — this reads the
  // authoritative declarations and requires every member to survive the boundary.
  const formTypes = readFileSync(new URL("../src/lib/pdf/form-types.ts", import.meta.url), "utf8");
  const malwareTypes = readFileSync(new URL("../src/lib/malware/types.ts", import.meta.url), "utf8");

  const declared = new Set<string>();
  // MalwareScanResultCode: "CLEAN" | "INFECTED" | ... ; CLEAN is not an error.
  const scanUnion = malwareTypes.slice(malwareTypes.indexOf("MalwareScanResultCode =")); 
  for (const match of scanUnion.slice(0, scanUnion.indexOf(";")).matchAll(/"([A-Z_]+)"/gu)) {
    if (match[1] !== "CLEAN") declared.add(match[1]);
  }
  // FORM_VALUE_ISSUES and FORM_FILL_ERROR_CODES.
  for (const block of ["FORM_VALUE_ISSUES", "FORM_FILL_ERROR_CODES"]) {
    const start = formTypes.indexOf(`${block}`);
    const body = formTypes.slice(start, formTypes.indexOf("]", start) + 1);
    for (const match of body.matchAll(/"([A-Z][A-Z0-9_]+)"/gu)) declared.add(match[1]);
  }

  // PDF refusals have no union — `QpdfError.code` is an unconstrained string — so
  // they are read from the throw sites that produce them.
  const qpdf = readFileSync(new URL("../src/lib/pdf/qpdf.ts", import.meta.url), "utf8");
  for (const match of qpdf.matchAll(/new QpdfError\("([A-Z_]+)"/gu)) declared.add(match[1]);

  assert.ok(declared.has("SCANNER_UNAVAILABLE"), "the scanner union must be found");
  assert.ok(declared.has("PDF_PASSWORD_INVALID"), "the PDF refusal must be represented");

  const lost = [...declared].filter((code) => !isPublicErrorCode(code)).sort();
  assert.deepEqual(lost, [], `these established codes would be collapsed to PROCESSING_FAILED: ${lost.join(", ")}`);
});

test("the allowlist still rejects anything message-like", () => {
  // Widening the vocabulary must not have widened it to free text.
  for (const junk of ["Cannot read properties of undefined", "ENOENT: /var/task/x", "error: boom", "a b c"]) {
    assert.equal(isPublicErrorCode(junk), false, junk);
  }
});
