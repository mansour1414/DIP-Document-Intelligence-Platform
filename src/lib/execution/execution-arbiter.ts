/**
 * Per-execution asynchronous arbitration (R7D.1 Continuation D1-Final: WD-F02).
 *
 * ## The race this exists to close
 *
 * `disarm` did this:
 *
 * ```
 *   read entry.record.phase        ← armed
 *   await verifyCompletion(entry)  ← N milliseconds of process and daemon I/O
 *   write the conclusion           ← still acting on the phase read before the await
 * ```
 *
 * During the await, a deadline tick could call `terminate`, or a second authenticated connection
 * could call `disarm`. Both would see `armed` and both would proceed. The observed consequences:
 * a `disarmed` record written over a `terminating` one (cancelling a mandatory kill), and two
 * grants minted for one execution.
 *
 * ## The correction
 *
 * Every operation that reads-then-writes an execution's record holds that execution's lock for the
 * whole operation, including all awaits. Serialisation, not optimism: there is no version check to
 * get wrong, because only one operation can be inside at a time.
 *
 * ## Why a queue bound
 *
 * `disarm` is reached from the authenticated control channel, so the queue depth is attacker-
 * influenced. A per-execution bound means a peer that pipelines disarms exhausts its own slot and
 * is refused, rather than growing memory. The bound is on *waiting* work; the operation in flight is
 * not counted.
 */

/** Why an operation could not run. Closed vocabulary: these become denial codes, never free text. */
export type ArbiterRefusal = "BUSY";

export type ArbiterResult<T> = { ok: true; value: T } | { ok: false; code: ArbiterRefusal };

type Waiter = { resolve: () => void };

type Lane = {
  /** True while an operation holds the lane. */
  held: boolean;
  /** FIFO of operations waiting for the lane. */
  waiters: Waiter[];
};

/**
 * A keyed mutex.
 *
 * Lanes are created on demand and removed when idle, so an attacker cannot create unbounded lanes
 * by naming unbounded execution ids — an id must be a 32-hex execution id to reach this at all,
 * and an idle lane is deleted immediately.
 */
export class ExecutionArbiter {
  private readonly lanes = new Map<string, Lane>();

  constructor(
    /** Operations that may wait on one execution. Bounds memory per execution id. */
    private readonly maxQueuedPerExecution = 4,
    /** Lanes kept while idle. Zero: a lane is released as soon as its last operation ends. */
    private readonly maxIdleLanes = 0,
  ) {}

  /** Number of executions with an operation in flight or queued. Exposed for assertions. */
  get activeLanes(): number {
    let count = 0;
    for (const lane of this.lanes.values()) {
      if (lane.held || lane.waiters.length > 0) count += 1;
    }
    return count;
  }

  /**
   * Run `operation` while holding `executionId`'s lane.
   *
   * The operation is never started twice, and it runs to completion before the next one begins —
   * including when it throws or rejects. A refusal returns `BUSY` without running anything, so a
   * caller can answer without side effects.
   */
  async run<T>(executionId: string, operation: () => Promise<T>): Promise<ArbiterResult<T>> {
    const acquired = await this.acquire(executionId);
    if (!acquired.ok) return { ok: false, code: acquired.code };
    try {
      return { ok: true, value: await operation() };
    } finally {
      this.release(executionId);
    }
  }

  private acquire(executionId: string): Promise<{ ok: true } | { ok: false; code: ArbiterRefusal }> {
    const lane = this.lanes.get(executionId) ?? { held: false, waiters: [] };
    this.lanes.set(executionId, lane);

    if (!lane.held) {
      lane.held = true;
      return Promise.resolve({ ok: true });
    }

    if (lane.waiters.length >= this.maxQueuedPerExecution) {
      this.maybeDrop(executionId, lane);
      return Promise.resolve({ ok: false, code: "BUSY" });
    }

    return new Promise((resolve) => {
      lane.waiters.push({
        resolve: () => {
          // The lane is transferred, not released-then-reacquired: there is no window in which a
          // newcomer could overtake a waiter that has been promised the lane.
          lane.held = true;
          resolve({ ok: true });
        },
      });
    });
  }

  private release(executionId: string): void {
    const lane = this.lanes.get(executionId);
    if (lane === undefined) return;
    lane.held = false;
    const next = lane.waiters.shift();
    if (next !== undefined) {
      next.resolve();
      return;
    }
    this.maybeDrop(executionId, lane);
  }

  private maybeDrop(executionId: string, lane: Lane): void {
    if (this.maxIdleLanes > 0) return;
    if (lane.held || lane.waiters.length > 0) return;
    this.lanes.delete(executionId);
  }
}
