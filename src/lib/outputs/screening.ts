import { createHash } from "node:crypto";
import { logger } from "@/lib/logging";
import {
  MalwareScanError,
  getMalwareScanner,
  requireCleanOutput,
  type MalwareScanner,
  type MalwareScanResultCode,
} from "@/lib/malware";
import { recordMetric } from "@/lib/observability/metrics";
import type { ObjectStorage, StoredObject } from "@/lib/storage";
import type { WorkerOutput } from "./validation";

/**
 * PR-1 — fail-closed screening of generated document-worker outputs.
 *
 * Ordering is the security property: `validateWorkerOutputs()` runs first, then
 * every output is scanned, and only a batch whose every member returned an
 * explicit `CLEAN` verdict may reach `storage.put()`. A rejection therefore
 * happens before a single byte is written, so a failed batch can never leak an
 * unscanned object, a `File` row or a `SUCCEEDED` job.
 */

export type OutputScanFailureCode = Exclude<MalwareScanResultCode, "CLEAN">;
export type OutputScanFailure = { index: number; name: string; code: OutputScanFailureCode };
export type CleanOutputScan = {
  index: number;
  name: string;
  checksumSha256: string;
  engine: string;
  engineVersion?: string;
  signatureVersion?: string;
};

/** Worst finding wins: an infected member makes the whole batch hostile, not merely unscannable. */
const PRECEDENCE: OutputScanFailureCode[] = ["INFECTED", "SCAN_ERROR", "SCAN_TIMEOUT", "SCANNER_UNAVAILABLE"];
function dominantCode(failures: OutputScanFailure[]): OutputScanFailureCode {
  for (const code of PRECEDENCE) if (failures.some((failure) => failure.code === code)) return code;
  return "SCAN_ERROR";
}

export class OutputScanError extends MalwareScanError {
  readonly failures: OutputScanFailure[];
  /** `INFECTED` is deterministic: the same engines regenerate the same bytes, so retrying only re-alerts. */
  readonly unrecoverable: boolean;
  constructor(failures: OutputScanFailure[]) {
    super(dominantCode(failures));
    this.name = "OutputScanError";
    this.message = this.code === "INFECTED"
      ? "The generated output was rejected by security scanning."
      : "The generated output could not be scanned safely.";
    this.failures = failures;
    this.unrecoverable = failures.some((failure) => failure.code === "INFECTED");
  }
}

function logRejection(failures: OutputScanFailure[]) {
  const code = dominantCode(failures);
  recordMetric("worker_output_scan_rejected_total", failures.length, "count", { status: code.toLowerCase() });
  // Index and code only: output filenames and bytes are tenant content.
  logger.warn("worker.output_scan_rejected", {
    rejected_count: failures.length,
    result: code,
    rejected_indexes: failures.map((failure) => failure.index).join(","),
    rejected_results: failures.map((failure) => failure.code).join(","),
  });
}

/**
 * Scans **every** output before returning, so one verdict never hides another,
 * and throws before the caller can persist anything.
 */
export async function screenWorkerOutputs(
  outputs: WorkerOutput[],
  options: { scanner?: MalwareScanner } = {},
): Promise<CleanOutputScan[]> {
  let scanner: MalwareScanner;
  try {
    scanner = options.scanner ?? getMalwareScanner();
  } catch {
    // No configured scanner is a batch-wide rejection, not a per-file one.
    const failures = outputs.map((output, index) => ({ index, name: output.name, code: "SCANNER_UNAVAILABLE" as const }));
    logRejection(failures);
    throw new OutputScanError(failures);
  }

  const scans: CleanOutputScan[] = [];
  const failures: OutputScanFailure[] = [];
  for (const [index, output] of outputs.entries()) {
    try {
      const verdict = await requireCleanOutput(output.bytes, scanner);
      scans.push({
        index,
        name: output.name,
        checksumSha256: verdict.checksumSha256,
        engine: verdict.engine,
        engineVersion: verdict.engineVersion,
        signatureVersion: verdict.signatureVersion,
      });
    } catch (error) {
      const code = error instanceof MalwareScanError ? error.code : "SCAN_ERROR";
      failures.push({ index, name: output.name, code });
    }
  }
  if (failures.length) {
    logRejection(failures);
    throw new OutputScanError(failures);
  }
  return scans;
}

export type StoredOutput = { output: WorkerOutput; object: StoredObject; checksum: string };

/**
 * Raised when a concurrent attempt of the same job won the commit race. It never
 * escapes the pipeline: the losing attempt deletes only the objects it wrote and
 * returns, because the winner's output is already committed and must not be
 * failed, overwritten or deleted. It is deliberately not a `MalwareScanError`, so
 * `toDocumentQueueError()` leaves it retryable rather than unrecoverable.
 */
export class OutputCommitSupersededError extends Error {
  readonly code = "OUTPUT_COMMIT_SUPERSEDED";
  constructor() {
    super("Another attempt already committed this job's output.");
    this.name = "OutputCommitSupersededError";
  }
}

/**
 * Attempt-scoped object keys.
 *
 * `output/<userId>/<jobId>/<attemptId>/<index>-<name>` means two attempts of the same job can
 * never write the same object: a losing or stale attempt physically cannot
 * overwrite the bytes a winning attempt committed, and its compensating delete
 * can only ever remove its own objects. The metadata compare-and-set in
 * `processDocumentJob()` decides which attempt is allowed to publish, so key
 * isolation is the storage half of the guarantee and the CAS is the database
 * half — neither relies on a plain status read.
 *
 * Consequence, documented in `workers/README.md`: an attempt killed between
 * `put()` and commit leaves unreferenced objects behind, so the bucket needs a
 * lifecycle rule (or the retry's own cleanup) to expire them.
 */
export function outputStorageKey(
  job: { id: string; requesterId: string | null },
  output: WorkerOutput,
  index: number,
  attemptId: string,
) {
  return `output/${job.requesterId ?? "system"}/${job.id}/${attemptId}/${index}-${output.name.replace(/[^a-zA-Z0-9._-]/g, "_")}`;
}

/**
 * Best-effort compensating delete. A cleanup failure is logged and never masks
 * the original error.
 *
 * `isReferenced` is the ownership check: an object that a committed `File` row
 * already points at is *not* deleted, even if this attempt thinks it wrote it
 * (e.g. the transaction actually committed but the client saw a connection
 * error). Callers that cannot verify ownership simply do not delete.
 */
export async function discardStoredObjects(
  storage: ObjectStorage,
  keys: string[],
  options: { isReferenced?: (key: string) => Promise<boolean> } = {},
): Promise<{ deleted: string[]; skipped: string[] }> {
  const deleted: string[] = [];
  const skipped: string[] = [];
  for (const key of keys) {
    try {
      if (options.isReferenced && await options.isReferenced(key)) {
        skipped.push(key);
        // Never log the key itself: it embeds the tenant id and the output name.
        logger.warn("worker.output_cleanup_skipped", { reason: "referenced" });
        continue;
      }
      await storage.deleteObject(key);
      deleted.push(key);
    } catch (error) {
      logger.error("worker.output_cleanup_failed", { error_code: error instanceof Error ? error.name : "UNKNOWN" });
    }
  }
  return { deleted, skipped };
}

/**
 * Serial put with rollback. Writes are sequential so a mid-batch storage fault
 * leaves a known, bounded prefix to delete rather than an unbounded `Promise.all`
 * fan-out whose failed siblings may still complete after the rejection.
 */
export async function storeWorkerOutputs(
  outputs: WorkerOutput[],
  options: { storage: ObjectStorage; keyFor: (output: WorkerOutput, index: number) => string },
): Promise<StoredOutput[]> {
  const stored: StoredOutput[] = [];
  const written: string[] = [];
  for (const [index, output] of outputs.entries()) {
    const key = options.keyFor(output, index);
    try {
      const checksum = createHash("sha256").update(output.bytes).digest("base64");
      const object = await options.storage.put({ key, bytes: output.bytes, contentType: output.mimeType, checksum });
      stored.push({ output, object, checksum });
      written.push(key);
    } catch (error) {
      await discardStoredObjects(options.storage, written);
      throw error;
    }
  }
  return stored;
}

/** Scan the whole batch, then store it. Nothing is written unless every output is clean. */
export async function screenAndStoreWorkerOutputs(
  outputs: WorkerOutput[],
  options: { job: { id: string; requesterId: string | null }; storage: ObjectStorage; scanner?: MalwareScanner; attemptId: string },
): Promise<{ stored: StoredOutput[]; scans: CleanOutputScan[] }> {
  const scans = await screenWorkerOutputs(outputs, { scanner: options.scanner });
  const stored = await storeWorkerOutputs(outputs, {
    storage: options.storage,
    keyFor: (output, index) => outputStorageKey(options.job, output, index, options.attemptId),
  });
  return { stored, scans };
}
