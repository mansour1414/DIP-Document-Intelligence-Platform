/**
 * Protocol v2 metadata types (R7D.1).
 *
 * Split from the codec so `result-validation.ts` can import types without importing the
 * encoder, which would create a cycle once the streaming validator also imports validation.
 */
import type { FailureMeta, FillMeta, InspectMeta } from "../pdf/worker-protocol";

export const WORKER_PROTOCOL_V2 = 2 as const;

export type WorkerOpV2 = "inspect" | "fill" | "verify";

/** A verify success. Metadata only; verify never carries document bytes. */
export type VerifyMeta = {
  ok: true;
  op: "verify";
  pages: number;
  widgets: number;
  preserved: number;
};

export type WorkerMetaV2 = InspectMeta | FillMeta | VerifyMeta | FailureMeta;
