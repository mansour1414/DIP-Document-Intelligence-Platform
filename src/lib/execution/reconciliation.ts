/**
 * Reconciliation after a crash (R7D.1 §8).
 *
 * ## The question this answers
 *
 * After a supervisor dies — or a host reboots, or the daemon becomes unreachable — the system is
 * left with a durable record that may or may not describe a container that may or may not still
 * exist. Reconciliation's job is to reduce that uncertainty *safely*, and where it cannot, to
 * stop the system rather than guess.
 *
 * ## What it refuses to do
 *
 * - **Enumerate and delete.** There is no "list all containers and remove the ones that look
 *   like ours". Every destructive action is by exact id, and only for an id this system
 *   recorded.
 * - **Prune.** `docker prune` removes containers this system never knew about. There is no
 *   situation in which that is the correct response to "I lost track of one".
 * - **Treat a missing id as absent.** A `docker create` that was issued but not returned leaves
 *   no id and a container that may still appear.
 * - **Treat a fixed interval as proof.** Waiting and then looking is not evidence; the evidence
 *   is an exact inspection that positively reports absence.
 * - **Resume jobs.** An execution interrupted mid-flight is not restarted here. Its caller is
 *   gone, its body was never fully received, and restarting would produce a document nobody
 *   asked for.
 *
 * ## Quarantine
 *
 * Anything unresolved is quarantined: the phase becomes terminal, admission blocks, and a human
 * decides. That is deliberately inconvenient. The alternative is a system that resolves its own
 * uncertainty by deleting things.
 */

import type { OwnershipJournal, SupervisorRecord, WatchdogRecord } from "./ownership-journal";
import { classifyForRecovery } from "./ownership-journal";
import type { DockerOutcome } from "./docker-lifecycle";

/** What reconciliation concluded about one record. Closed, because a caller acts on it. */
export type ReconciliationVerdict =
  /** The record is terminal and nothing exists: safe to leave as history. */
  | { executionId: string; kind: "resolved"; detail: string }
  /** A container id is recorded and confirmed absent. The record may be advanced. */
  | { executionId: string; kind: "container-absent"; containerId: string }
  /** A container id is recorded and the container still exists: a termination debt. */
  | { executionId: string; kind: "termination-debt"; containerId: string; phase: SupervisorRecord["phase"] }
  /** An intent exists with no container id: the container may appear. Quarantine, do not guess. */
  | { executionId: string; kind: "ambiguous-create"; detail: string }
  /** The daemon could not be asked, so nothing is known. Quarantine and retry later. */
  | { executionId: string; kind: "unavailable"; detail: string }
  /** The watchdog's independent view disagrees with the supervisor's. Quarantine. */
  | { executionId: string; kind: "conflicting-authority"; detail: string }
  /** The record failed validation. Quarantine: a record that cannot be parsed cannot be acted on. */
  | { executionId: string; kind: "unreadable"; detail: string }
  /** A boot from a previous life. The container namespace it described does not exist. */
  | { executionId: string; kind: "previous-boot"; detail: string };

export type ReconciliationReport = {
  /** Every verdict, in the order the records were read. */
  verdicts: ReconciliationVerdict[];
  /** Executions that must be quarantined before admission resumes. */
  quarantine: string[];
  /** True when no record is in a state that permits new work. */
  clear: boolean;
};

export type ReconciliationOptions = {
  journal: OwnershipJournal;
  bootId: string;
  /** Exact-id inspection. Never a list, never a selector. */
  inspect: (containerId: string) => Promise<DockerOutcome<{ raw: string }>>;
  /**
   * How many times to re-inspect an id that was not found before concluding the container is
   * absent. Re-inspection is not a delay-based proof: it exists because `docker create` racing a
   * removal can briefly report neither present nor absent, and one instantaneous read is not
   * evidence either way.
   */
  inspectAttempts?: number;
};

/**
 * Classify every record in the journal.
 *
 * Read-only. This function does not delete, does not advance phases and does not touch the
 * daemon except to inspect a specific id that a record already names. Actions are the caller's,
 * based on the verdicts, and each action is separately gated.
 */
export async function reconcile(options: ReconciliationOptions): Promise<ReconciliationReport> {
  const verdicts: ReconciliationVerdict[] = [];
  const quarantine: string[] = [];

  for (const executionId of options.journal.listSupervisor()) {
    let supervisor: SupervisorRecord | null;
    try {
      supervisor = options.journal.readSupervisor(executionId);
    } catch (error) {
      // A record that cannot be parsed is not an empty record. Quarantine it: acting on a
      // misparsed record means acting on fields that may be from a different schema.
      verdicts.push({ executionId, kind: "unreadable", detail: error instanceof Error ? error.message : "unparseable" });
      quarantine.push(executionId);
      continue;
    }
    if (supervisor === null) {
      verdicts.push({ executionId, kind: "unreadable", detail: "the record disappeared while listed" });
      quarantine.push(executionId);
      continue;
    }

    let watchdog: WatchdogRecord | null;
    try {
      watchdog = options.journal.readWatchdog(executionId);
    } catch (error) {
      verdicts.push({ executionId, kind: "unreadable", detail: error instanceof Error ? error.message : "unparseable watchdog record" });
      quarantine.push(executionId);
      continue;
    }

    // Boot identity first, before any daemon work. A record from a previous boot describes a
    // container namespace that no longer exists; its container id means nothing here, and asking
    // the daemon about it could match an unrelated container that reused the id space.
    if (supervisor.bootId !== options.bootId) {
      verdicts.push({ executionId, kind: "previous-boot", detail: `recorded ${supervisor.bootId}, running ${options.bootId}` });
      // A previous-boot record is *not* quarantined: it cannot block admission on this host
      // forever. It is reported and left as history. What it must never do is authorize a
      // destructive action, and it does not, because every path below is skipped.
      continue;
    }

    const classification = classifyForRecovery(supervisor);

    if (classification === "quarantined") {
      verdicts.push({ executionId, kind: "termination-debt", containerId: supervisor.containerId ?? "", phase: supervisor.phase });
      quarantine.push(executionId);
      continue;
    }

    if (classification === "ambiguous-create") {
      // No id, and a create may have been in flight. The container may appear later; removing
      // "whatever is there" is exactly the broad deletion this module forbids.
      verdicts.push({ executionId, kind: "ambiguous-create", detail: `phase=${supervisor.phase}` });
      quarantine.push(executionId);
      continue;
    }

    if (classification === "resolved") {
      // Terminal and complete. If a watchdog record exists it must agree.
      if (watchdog !== null && watchdog.phase === "armed") {
        verdicts.push({ executionId, kind: "conflicting-authority", detail: "the supervisor concludes but the watchdog is still armed" });
        quarantine.push(executionId);
        continue;
      }
      verdicts.push({ executionId, kind: "resolved", detail: `phase=${supervisor.phase}` });
      continue;
    }

    // `needs-container-lookup`: a container id is recorded. Ask about exactly that id.
    const containerId = supervisor.containerId!;
    const inspection = await inspectWithRetries(options.inspect, containerId, options.inspectAttempts ?? 3);
    if (inspection === null) {
      verdicts.push({ executionId, kind: "unavailable", detail: "the daemon could not be asked" });
      quarantine.push(executionId);
      continue;
    }
    if (inspection) {
      // Present. This is a termination debt: the container exists and the supervisor is gone.
      verdicts.push({ executionId, kind: "termination-debt", containerId, phase: supervisor.phase });
      quarantine.push(executionId);
      continue;
    }
    verdicts.push({ executionId, kind: "container-absent", containerId });
  }

  // Watchdog records with no supervisor record. These are retained, never deleted, and they
  // block admission: an orphaned watchdog record is evidence that something was armed and that
  // the supervisor that armed it no longer has a record of why.
  for (const executionId of options.journal.listWatchdog()) {
    if (options.journal.listSupervisor().includes(executionId)) continue;
    verdicts.push({
      executionId,
      kind: "conflicting-authority",
      detail: "a watchdog record exists without a supervisor record; retained, not deleted",
    });
    quarantine.push(executionId);
  }

  return { verdicts, quarantine, clear: quarantine.length === 0 };
}

/**
 * Inspect an exact id, retrying only on ambiguity.
 *
 * Returns `true` present, `false` absent, `null` "cannot tell". A definite daemon error is not
 * absence and not presence: it is the third answer, and the caller must quarantine on it.
 */
async function inspectWithRetries(
  inspect: (containerId: string) => Promise<DockerOutcome<{ raw: string }>>,
  containerId: string,
  attempts: number,
): Promise<boolean | null> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const outcome = await inspect(containerId);
    if (outcome.ok) return true;
    // A definite NOT_FOUND is absence. Everything else — an outage, a timeout, a daemon error —
    // is "cannot tell", because reading an outage as absence is the mistake that releases a
    // document whose container may still be running.
    if (outcome.fault === "NOT_FOUND" && !outcome.ambiguous) return false;
    if (outcome.fault !== "TIMEOUT" && !outcome.ambiguous) return null;
  }
  return null;
}

/**
 * The actions reconciliation may take, and on what evidence.
 *
 * Separate from the classification so the decision and its execution cannot be confused, and so
 * every destructive action can be tested against its precondition directly.
 */
export type ReconciliationAction =
  | { kind: "leave"; executionId: string }
  | { kind: "quarantine"; executionId: string; reason: string }
  | { kind: "advance-absent"; executionId: string; containerId: string }
  | { kind: "terminate-and-remove"; executionId: string; containerId: string };

/**
 * Decide the action for one verdict.
 *
 * `terminate-and-remove` is only ever reached with an exact id that an inspection positively
 * reported present, and only for a record on this host. There is no path from "unavailable" or
 * "ambiguous" to a destructive action.
 */
export function actionFor(verdict: ReconciliationVerdict): ReconciliationAction {
  switch (verdict.kind) {
    case "resolved":
      return { kind: "leave", executionId: verdict.executionId };
    case "previous-boot":
      return { kind: "leave", executionId: verdict.executionId };
    case "container-absent":
      return { kind: "advance-absent", executionId: verdict.executionId, containerId: verdict.containerId };
    case "termination-debt":
      // Only with a real id. An empty id means the record never had one, which is the
      // ambiguous-create case and must not become a destructive action.
      if (verdict.containerId === "" || !/^[a-f0-9]{64}$/u.test(verdict.containerId)) {
        return { kind: "quarantine", executionId: verdict.executionId, reason: "termination debt without a usable container id" };
      }
      return { kind: "terminate-and-remove", executionId: verdict.executionId, containerId: verdict.containerId };
    case "ambiguous-create":
      return { kind: "quarantine", executionId: verdict.executionId, reason: "an in-flight create may still produce a container" };
    case "unavailable":
      return { kind: "quarantine", executionId: verdict.executionId, reason: "the daemon could not be asked" };
    case "conflicting-authority":
      return { kind: "quarantine", executionId: verdict.executionId, reason: verdict.detail };
    case "unreadable":
      return { kind: "quarantine", executionId: verdict.executionId, reason: verdict.detail };
  }
}

/**
 * Whether new work may be admitted.
 *
 * A single unresolved record blocks admission. That is the intended behaviour: the profile is
 * one executor, and an execution whose ownership is uncertain is an execution that may still own
 * the machine's only slot.
 */
export function admissionAllowed(report: ReconciliationReport): boolean {
  return report.quarantine.length === 0;
}
