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

/**
 * Minimal surface of `prisma.$transaction`.
 *
 * `updateMany` alone cannot answer the question this round has to answer: *which*
 * rows were actually transitioned. A bare count cannot be mapped back to
 * identifiers, and re-reading the candidate set afterwards re-introduces the very
 * race the guard exists to prevent. The `returning`-style `updateManyAndReturn`
 * does answer it, atomically, with the write itself.
 */
export type ExpiryWritePort = {
  updateManyAndReturn(args: {
    where: {
      id: { in: string[] };
      status: { in: readonly string[] };
      /** Optimistic guard: never touch a row that changed during the sweep. */
      updatedAt: { lte: Date };
    };
    data: { status: "EXPIRED"; errorCode: string; completedAt: Date };
    select: { id: true; params: true };
  }): Promise<Array<{ id: string; params: unknown }>>;
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

export type ExpiryWriteOutcome<TExpired> = {
  /** Rows that were still expirable and were transitioned *by this write*. */
  expired: TExpired[];
  /**
   * Candidates the guard correctly skipped because something else touched them
   * during the sweep. Reported, never acted on.
   */
  skipped: number;
};

/**
 * Terminally expire the planned jobs, skipping any row that changed since the
 * sweep started, and return **the rows this write actually transitioned**.
 *
 * The distinction matters for anything that must follow the transition into
 * `EXPIRED` — specifically the encrypted form payload, which has to be destroyed
 * for jobs that expired and preserved for jobs that a worker claimed. The
 * previous version read references from the *planned* set and purged after a
 * count-only write, so a job that was claimed mid-sweep lost the payload its new
 * attempt needed. Returning the transitioned rows from the same statement makes
 * the purge follow the write instead of the plan.
 *
 * The optimistic `updatedAt` guard is unchanged: this is the same predicate,
 * only observed through its result set.
 */
export async function applyExpiryPlan(port: ExpiryWritePort, input: ApplyExpiryPlanInput): Promise<ExpiryWriteOutcome<{ id: string; params: unknown }>> {
  if (input.expireIds.length === 0) return { expired: [], skipped: 0 };
  const expired = await port.updateManyAndReturn({
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
    select: { id: true, params: true },
  });
  return { expired, skipped: input.expireIds.length - expired.length };
}
