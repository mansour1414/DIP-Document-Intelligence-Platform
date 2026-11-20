/**
 * Applying an expiry plan safely.
 *
 * ## The race
 *
 * Planning is not atomic with writing. Between reading queue evidence and
 * issuing the expiry `UPDATE`, a job can legitimately change state — most
 * importantly a `RETRYING`/`QUEUED` job can be claimed by a worker and become
 * `RUNNING` on a brand-new attempt. The original guard was
 *
 *     status IN ("QUEUED", "RETRYING", "RUNNING")
 *
 * which *admits* that transition: a job that was planned as `RETRYING` and then
 * legitimately claimed still matches `RUNNING`, so the sweep would terminate a
 * job that is actively processing right now. That is the same class of bug this
 * whole change exists to prevent, just moved into the write.
 *
 * ## The guard
 *
 * `Job.updatedAt` is `@updatedAt`, so Prisma bumps it on **every** row write,
 * including the claim that sets `RUNNING`. Requiring
 *
 *     updatedAt <= sweepStartedAt
 *
 * therefore makes the write optimistic: any row that changed at all since the
 * sweep began is skipped. A job claimed mid-sweep has a fresh `updatedAt` and is
 * left alone; a genuinely abandoned job has an old one and is reclaimed.
 *
 * This is expressed as a port so the behaviour can be tested without a database,
 * and so the scheduler's dry-run path cannot reach it by accident.
 */

/** Non-terminal states the sweep is ever allowed to write over. */
export const EXPIRABLE_STATUSES = ["QUEUED", "RETRYING", "RUNNING"] as const;

export type ExpiryPlanTarget = {
  id: string;
  /** Status observed during planning; recorded for observability, not asserted. */
  status: string;
};

/** Minimal surface of `prisma.job.updateMany`. */
export type ExpiryWritePort = {
  updateMany(args: {
    where: {
      id: { in: string[] };
      status: { in: readonly string[] };
      /** Optimistic guard: never touch a row that changed during the sweep. */
      updatedAt: { lte: Date };
    };
    data: { status: "EXPIRED"; errorCode: string; completedAt: Date };
  }): Promise<{ count: number }>;
};

export type ApplyExpiryPlanInput = {
  /** Ids selected by the planner. */
  expireIds: readonly string[];
  /** Sweep start time; rows modified after this are skipped. */
  sweepStartedAt: Date;
  /** Timestamps to stamp on rows the sweep expires. */
  completedAt: Date;
  errorCode?: string;
};

/**
 * Terminally expire the planned jobs, skipping any row that changed since the
 * sweep started.
 *
 * Returns the number of rows actually expired, which may be lower than
 * `expireIds.length` when a job was claimed, cancelled or completed during the
 * sweep — that difference is the race being correctly lost, not an error.
 */
export async function applyExpiryPlan(port: ExpiryWritePort, input: ApplyExpiryPlanInput): Promise<number> {
  if (input.expireIds.length === 0) return 0;
  const result = await port.updateMany({
    where: {
      id: { in: [...input.expireIds] },
      status: { in: EXPIRABLE_STATUSES },
      updatedAt: { lte: input.sweepStartedAt },
    },
    data: {
      status: "EXPIRED",
      errorCode: input.errorCode ?? "JOB_EXPIRED",
      completedAt: input.completedAt,
    },
  });
  return result.count;
}
