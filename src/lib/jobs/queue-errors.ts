import { UnrecoverableError } from "bullmq";
import { OutputScanError } from "@/lib/outputs/screening";

/**
 * PR-1 — queue-level classification of document pipeline failures.
 *
 * The document queue is configured with `attempts: 3`. Retrying is right for a
 * scanner that is down or timing out (the next attempt can succeed) but wrong for
 * an infected output: the same engines regenerate the same bytes, so a retry only
 * repeats the rejection and re-alerts. `INFECTED` therefore ends the job on the
 * first attempt, while the database already carries the precise `INFECTED` code
 * because `processDocumentJob` records the failure before this conversion.
 */
export function toDocumentQueueError(error: unknown): Error {
  if (error instanceof OutputScanError && error.unrecoverable) return new UnrecoverableError(error.message);
  return error instanceof Error ? error : new Error("Processing failed");
}

export function isUnrecoverableQueueError(error: Error | undefined) {
  return error instanceof UnrecoverableError || error?.name === "UnrecoverableError";
}
