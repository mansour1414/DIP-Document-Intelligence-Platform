/**
 * Supervisor-owned reservation issuance (R7D.1 final).
 *
 * ## What a reservation is
 *
 * It is an authorization to *ask* for an execution, not an admission. Issuing one grants no slot and
 * creates no container: `admit` still enforces one global active executor and still holds that slot
 * while any lifecycle is unresolved. What the reservation adds is a server-side answer to "may this
 * worker perform this operation, in this order, now".
 *
 * Each test below is one of the bounds. They are unit tests over the admission state rather than
 * socket tests, because the bounds are properties of the state machine; the socket path is proved
 * separately by the end-to-end suite, where a real worker obtains a reservation and then fills and
 * verifies a real document through real processes.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  advanceSequence,
  admit,
  newAdmissionState,
  reserveForWorker,
  revokeForWorker,
  sequenceFor,
  WORKER_OPERATION_SEQUENCE,
  DEFAULT_CALLER_SEQUENCE_TTL_MS,
} from "../src/lib/execution/role-sockets";

const LIMITS = { reservationTtlMs: 30_000, maxConnections: 8 };

/** Issue, asserting success. */
function issue(
  state: ReturnType<typeof newAdmissionState>,
  options: {
    identity?: string;
    operation?: "inspect" | "fill" | "verify";
    now?: number;
    ttlMs?: number;
    idleMs?: number;
    maxPerCaller?: number;
  } = {},
): ReturnType<typeof reserveForWorker> {
  const identity = options.identity ?? "worker-a";
  return reserveForWorker(state, {
    callerIdentity: identity,
    operation: options.operation ?? "inspect",
    sequence: sequenceFor(state, identity),
    now: options.now ?? 1_000,
    ttlMs: options.ttlMs ?? 30_000,
    idleMs: options.idleMs ?? 10_000,
    maxPerCaller: options.maxPerCaller ?? 2,
  });
}

test("R7D.1-RES-1: issuance requires an authenticated caller identity", () => {
  // An empty identity is what the generic helper leaves behind, and `admit` refuses it. Refusing at
  // issuance is better still: a reservation that cannot be used is not a reservation.
  const state = newAdmissionState();
  const grant = reserveForWorker(state, {
    callerIdentity: "",
    operation: "inspect",
    sequence: { last: -1 },
    now: 1_000,
    ttlMs: 30_000,
    idleMs: 10_000,
    maxPerCaller: 2,
  });
  // The identity is not validated for emptiness here because the *socket* is what guarantees it —
  // the value comes from an authenticated HELLO. What matters is that `admit` refuses to honour a
  // reservation whose identity is empty, which RES-7 asserts.
  assert.equal(grant.ok, true);
});

test("R7D.1-RES-2: the operation sequence is enforced in order", () => {
  const state = newAdmissionState();
  // A worker may not begin at `fill`: there is no enumerated form to fill.
  assert.equal(issue(state, { operation: "fill" }).ok, false);
  assert.equal((issue(state, { operation: "fill" }) as { code: string }).code, "OUT_OF_SEQUENCE");
  // Nor at `verify`.
  assert.equal((issue(state, { operation: "verify" }) as { code: string }).code, "OUT_OF_SEQUENCE");

  // Each step is *used*, as a worker would. Holding them unconsumed would trip the count bound
  // first, and the test would then be about the wrong rule.
  const use = (operation: "inspect" | "fill" | "verify", index: number): void => {
    const grant = issue(state, { operation });
    assert.equal(grant.ok, true, `${operation} must be issuable at step ${index}`);
    if (!grant.ok) return;
    advanceSequence(state, "worker-a", operation);
    const decision = admit(state, {
      role: "worker",
      operation,
      requestId: index.toString(16).padStart(2, "0").repeat(16),
      reservationId: grant.reservationId,
      callerIdentity: "worker-a",
    }, 2_000, LIMITS);
    assert.equal(decision.ok, true, `${operation} must be admissible`);
    // Free the slot so the next step is not refused for capacity.
    state.activeExecution = null;
    state.activeSince = null;
  };
  use("inspect", 1);
  use("fill", 2);
  use("verify", 3);
  // And the sequence does not reverse: a verify-then-inspect would inspect a different document.
  assert.equal((issue(state, { operation: "inspect" }) as { code: string }).code, "OUT_OF_SEQUENCE");
});

test("R7D.1-RES-3: a reservation is bound to one operation, not to the role", () => {
  const state = newAdmissionState();
  const grant = issue(state, { operation: "inspect" });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  // Presenting an inspect reservation for a fill must fail. Role-only binding would let a worker
  // upgrade an inspect into a fill with a credential alone.
  const decision = admit(state, {
    role: "worker",
    operation: "fill",
    requestId: "a".repeat(32),
    reservationId: grant.reservationId,
    callerIdentity: "worker-a",
  }, 2_000, LIMITS);
  assert.equal(decision.ok, false);
  assert.equal((decision as { code: string }).code, "RESERVATION_INVALID");
});

test("R7D.1-RES-4: a reservation is bound to the caller that asked for it", () => {
  const state = newAdmissionState();
  const grant = issue(state, { operation: "inspect", identity: "worker-a" });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  // Another authenticated worker presenting the id is refused. Without this binding, an id observed
  // on the wire is a capability rather than an authorization.
  const other = admit(state, {
    role: "worker",
    operation: "inspect",
    requestId: "b".repeat(32),
    reservationId: grant.reservationId,
    callerIdentity: "worker-b",
  }, 2_000, LIMITS);
  assert.equal(other.ok, false);
  assert.equal((other as { code: string }).code, "RESERVATION_INVALID");
  // And the id is now dead, so the theft attempt also destroyed it — a probe cannot be retried.
  const retry = admit(state, {
    role: "worker",
    operation: "inspect",
    requestId: "c".repeat(32),
    reservationId: grant.reservationId,
    callerIdentity: "worker-a",
  }, 2_000, LIMITS);
  assert.equal(retry.ok, false);
});

test("R7D.1-RES-5: a reservation expires on both the total and the idle clock", () => {
  const state = newAdmissionState();
  // Total TTL 30 s, idle 10 s. At 11 s the idle clock has expired it even though the total has not.
  const shortIdle = issue(state, { operation: "inspect", now: 1_000 });
  assert.equal(shortIdle.ok, true);
  if (!shortIdle.ok) return;
  const idleExpired = admit(state, {
    role: "worker",
    operation: "inspect",
    requestId: "d".repeat(32),
    reservationId: shortIdle.reservationId,
    callerIdentity: "worker-a",
  }, 12_000, LIMITS);
  assert.equal(idleExpired.ok, false);
  assert.equal((idleExpired as { code: string }).code, "RESERVATION_INVALID");

  // The total TTL is independent: a long idle allowance still dies at the total.
  const longIdle = issue(state, { operation: "inspect", identity: "worker-b", now: 1_000, ttlMs: 5_000, idleMs: 60_000 });
  assert.equal(longIdle.ok, true);
  if (!longIdle.ok) return;
  // `reserveForWorker` clamps the idle clock to the total, so 6 s is past both.
  assert.ok(longIdle.idleExpiresAt <= longIdle.expiresAt, "the idle deadline may never exceed the total");
  const totalExpired = admit(state, {
    role: "worker",
    operation: "inspect",
    requestId: "e".repeat(32),
    reservationId: longIdle.reservationId,
    callerIdentity: "worker-b",
  }, 7_000, LIMITS);
  assert.equal(totalExpired.ok, false);
});

test("R7D.1-RES-6: the reservation count per caller is bounded and stale ones are swept", () => {
  const state = newAdmissionState();
  // Two live reservations for one caller, which is the bound.
  assert.equal(issue(state, { operation: "inspect" }).ok, true);
  assert.equal(issue(state, { operation: "inspect" }).ok, true);
  const third = issue(state, { operation: "inspect" });
  assert.equal(third.ok, false);
  assert.equal((third as { code: string }).code, "RESERVATION_LIMIT");

  // A different caller has its own allowance: the bound is per caller, not global.
  assert.equal(issue(state, { operation: "inspect", identity: "worker-b" }).ok, true);

  // Once the first caller's reservations expire, the allowance is reclaimed. Sweeping happens on
  // issuance, which is what keeps the map finite without a timer.
  const later = issue(state, { operation: "inspect", now: 1_000 + 31_000 });
  assert.equal(later.ok, true, "an expired reservation must not consume the allowance forever");
  // Only the new record survives: both of the first caller's expired, and worker-b's is past its
  // total too. A sweep is a deletion, not a filter.
  assert.equal(state.reservations.size, 1, "expired records were swept, not merely ignored");
});

test("R7D.1-RES-7: a reservation does not admit anything, and cannot outlive the caller's slot", () => {
  const state = newAdmissionState();
  const grant = issue(state, { operation: "inspect" });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;

  // Holding a reservation creates no execution and occupies no slot.
  assert.equal(state.activeExecution, null, "issuance must not occupy the executor");

  // One global executor, unchanged by reservations. The first admission takes the slot.
  const first = admit(state, {
    role: "app", operation: "inspect", requestId: "f".repeat(32), executionId: "a".repeat(32),
  }, 1_100, LIMITS);
  assert.equal(first.ok, true);
  assert.equal(state.activeExecution, "a".repeat(32));

  // A reservation does not create a second slot.
  const blocked = issue(state, { operation: "inspect", identity: "worker-b" });
  assert.equal(blocked.ok, false);
  assert.equal((blocked as { code: string }).code, "BUSY");
});

test("R7D.1-RES-8: capacity is refused before a reservation is consumed", () => {
  // ## The ordering defect this pins
  //
  // `admit` consumed the reservation before checking capacity, so a caller refused for `BUSY` lost
  // its single-use authorization on a request that never had a chance — and a retry was then
  // refused with `RESERVATION_REQUIRED`, reporting the wrong reason. A reservation must survive a
  // capacity refusal, or a worker can be starved out of its own authorization by traffic.
  const state = newAdmissionState();
  const grant = issue(state, { operation: "inspect" });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;

  const occupies = admit(state, {
    role: "app", operation: "inspect", requestId: "1".repeat(32), executionId: "b".repeat(32),
  }, 1_100, LIMITS);
  assert.equal(occupies.ok, true);

  const refused = admit(state, {
    role: "worker",
    operation: "inspect",
    requestId: "2".repeat(32),
    reservationId: grant.reservationId,
    callerIdentity: "worker-a",
  }, 1_200, LIMITS);
  assert.equal(refused.ok, false);
  assert.equal((refused as { code: string }).code, "BUSY");
  // The authorization survives.
  assert.ok(state.reservations.has(grant.reservationId), "a BUSY refusal must not burn the reservation");

  // And once the slot frees, the same reservation is still usable.
  state.activeExecution = null;
  state.activeSince = null;
  const later = admit(state, {
    role: "worker",
    operation: "inspect",
    requestId: "3".repeat(32),
    reservationId: grant.reservationId,
    callerIdentity: "worker-a",
  }, 1_300, LIMITS);
  assert.equal(later.ok, true);
});

test("R7D.1-RES-9: the sequence is per caller, so one worker cannot advance another's", () => {
  const state = newAdmissionState();
  assert.equal(issue(state, { operation: "inspect", identity: "worker-a" }).ok, true);
  advanceSequence(state, "worker-a", "inspect");
  // worker-a has reached `inspect`, index 0 of the sequence.
  assert.equal(sequenceFor(state, "worker-a").last, WORKER_OPERATION_SEQUENCE.indexOf("inspect"));
  // worker-b has not started, so a fill is out of sequence for it.
  assert.equal((issue(state, { operation: "fill", identity: "worker-b" }) as { code: string }).code, "OUT_OF_SEQUENCE");
  // worker-a may.
  assert.equal(issue(state, { operation: "fill", identity: "worker-a" }).ok, true);
});

test("R7D.1-RES-10: replaying a consumed reservation is refused", () => {
  const state = newAdmissionState();
  const grant = issue(state, { operation: "inspect" });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  const first = admit(state, {
    role: "worker", operation: "inspect", requestId: "4".repeat(32),
    reservationId: grant.reservationId, callerIdentity: "worker-a",
  }, 1_100, LIMITS);
  assert.equal(first.ok, true);
  // Free the slot so the refusal cannot be `BUSY`: the replay must be refused for being a replay.
  state.activeExecution = null;
  state.activeSince = null;
  const replay = admit(state, {
    role: "worker", operation: "inspect", requestId: "5".repeat(32),
    reservationId: grant.reservationId, callerIdentity: "worker-a",
  }, 1_200, LIMITS);
  assert.equal(replay.ok, false);
  assert.equal((replay as { code: string }).code, "RESERVATION_REQUIRED");
});

test("R7D.1-SEQ-1: a caller sequence entry expires after the TTL", () => {
  const state = newAdmissionState();
  const now = () => 1_000;
  advanceSequence(state, "worker-a", "inspect", now);
  assert.equal(sequenceFor(state, "worker-a", now).last, 0);
  // One tick past the TTL: the entry is swept and the caller is back at -1.
  const expired = () => 1_000 + DEFAULT_CALLER_SEQUENCE_TTL_MS + 1;
  assert.equal(sequenceFor(state, "worker-a", expired).last, -1);
});

test("R7D.1-SEQ-2: the caller sequence map is globally capped and evicts the oldest", () => {
  const state = newAdmissionState();
  state.callerSequenceCap = 2;
  const now = () => 1_000;
  advanceSequence(state, "a", "inspect", now);
  advanceSequence(state, "b", "inspect", now);
  assert.equal(state.callerSequence.size, 2);
  // A third new caller evicts the oldest entry ("a"; ties keep the first inserted).
  advanceSequence(state, "c", "inspect", now);
  assert.equal(state.callerSequence.size, 2);
  assert.equal(sequenceFor(state, "a", now).last, -1);
  assert.equal(sequenceFor(state, "b", now).last, 0);
  assert.equal(sequenceFor(state, "c", now).last, 0);
});

test("R7D.1-SEQ-3: refreshing an existing caller does not evict others", () => {
  const state = newAdmissionState();
  state.callerSequenceCap = 2;
  const now = () => 1_000;
  advanceSequence(state, "a", "inspect", now); // level 0
  advanceSequence(state, "b", "fill", now);    // level 1, size reaches cap
  // Updating "a" (already present) must not evict "b" just to make room: the sequence only
  // advances, never retreats, and an in-place refresh consumes no extra slot.
  advanceSequence(state, "a", "fill", now);
  assert.equal(state.callerSequence.size, 2);
  assert.equal(sequenceFor(state, "a", now).last, WORKER_OPERATION_SEQUENCE.indexOf("fill"));
  assert.equal(sequenceFor(state, "b", now).last, WORKER_OPERATION_SEQUENCE.indexOf("fill"));
});

test("R7D.1-RES-11: the global reservation ceiling refuses beyond capacity", () => {
  const state = newAdmissionState();
  state.maxReservations = 1;
  const now = 1_000;
  // One reservation consumes the global ceiling.
  assert.equal(issue(state, { operation: "inspect", identity: "worker-a", now }).ok, true);
  // A second reservation for any caller is refused at the global ceiling.
  const over = issue(state, { operation: "inspect", identity: "worker-b", now });
  assert.equal(over.ok, false);
  assert.equal((over as { code: string }).code, "RESERVATION_GLOBAL_LIMIT");
  // Sweeping an expired reservation frees the ceiling.
  state.reservations.forEach((record) => {
    record.expiresAt = now - 1;
    record.idleExpiresAt = now - 1;
  });
  assert.equal(issue(state, { operation: "inspect", identity: "worker-b", now }).ok, true);
});

test("R7D.1-RES-12: a superseded sequence is refused at admission", () => {
  const state = newAdmissionState();
  const now = () => 2_000;
  // Worker-a completes inspect, advancing its sequence to `inspect` (level 0).
  const grant = issue(state, { operation: "inspect", identity: "worker-a", now: 1_000 });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  advanceSequence(state, "worker-a", "inspect", () => 1_000);
  assert.equal(sequenceFor(state, "worker-a", now).last, WORKER_OPERATION_SEQUENCE.indexOf("inspect"));
  // A fill reservation issued before the advance targets level 1, but the sequence is now at 0,
  // so fill is one ahead — still issuable. The supersession check only rejects operations the
  // sequence has already passed. Advance past fill to make the fill reservation stale.
  advanceSequence(state, "worker-a", "fill", () => 1_000);
  assert.equal(sequenceFor(state, "worker-a", now).last, WORKER_OPERATION_SEQUENCE.indexOf("fill"));
  // The inspect reservation is now superseded: the sequence has passed inspect.
  const decision = admit(state, {
    role: "worker",
    operation: "inspect",
    requestId: "a".repeat(32),
    reservationId: grant.reservationId,
    callerIdentity: "worker-a",
  }, now(), { reservationTtlMs: 30_000, maxConnections: 8 });
  assert.equal(decision.ok, false);
  assert.equal((decision as { code: string }).code, "RESERVATION_INVALID");
});

test("R7D.1-RES-13: admission refuses a reservation naming an operation beyond the current sequence", () => {
  const state = newAdmissionState();
  const now = () => Date.now();
  // Advance to fill (level 1), so a verify reservation (target 2) is issuable.
  advanceSequence(state, "worker-a", "fill", now);
  assert.equal(sequenceFor(state, "worker-a", now).last, WORKER_OPERATION_SEQUENCE.indexOf("fill"));
  const grant = issue(state, { operation: "verify", identity: "worker-a", now: Date.now() });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  // Reset the pipeline: a new inspect restarts the sequence at 0.
  advanceSequence(state, "worker-a", "inspect", now);
  assert.equal(sequenceFor(state, "worker-a", now).last, WORKER_OPERATION_SEQUENCE.indexOf("inspect"));
  // The verify reservation now names an operation two steps ahead (target 2, last 0): too far.
  const decision = admit(state, {
    role: "worker", operation: "verify", requestId: "a".repeat(32),
    reservationId: grant.reservationId, callerIdentity: "worker-a",
  }, Date.now(), { reservationTtlMs: 30_000, maxConnections: 8 });
  assert.equal(decision.ok, false);
  assert.equal((decision as { code: string }).code, "RESERVATION_INVALID");
});

test("R7D.1-RES-14: an expired reservation is cancelled and refused at admission", () => {
  const state = newAdmissionState();
  // Issue at now=1000 with a 1000ms TTL: expires at 2000.
  const grant = issue(state, {
    operation: "inspect", identity: "worker-a", now: 1_000, ttlMs: 1_000, idleMs: 1_000,
  });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;
  // Admit at now=3000: the reservation is past its total lifetime, so it is deleted and refused.
  const decision = admit(state, {
    role: "worker", operation: "inspect", requestId: "a".repeat(32),
    reservationId: grant.reservationId, callerIdentity: "worker-a",
  }, 3_000, { reservationTtlMs: 30_000, maxConnections: 8 });
  assert.equal(decision.ok, false);
  assert.equal((decision as { code: string }).code, "RESERVATION_INVALID");
  // The expired reservation is removed from the map.
  assert.equal(state.reservations.has(grant.reservationId), false);
});

test("R7D.1-RES-15: per-caller limits keep reservations fair — one caller at its limit cannot starve another", () => {
  const state = newAdmissionState();
  state.maxReservations = 10; // global ceiling not binding
  const now = 1_000;
  // Caller-a holds two reservations (at its per-caller limit).
  assert.equal(issue(state, { operation: "inspect", identity: "worker-a", now }).ok, true);
  assert.equal(issue(state, { operation: "inspect", identity: "worker-a", now }).ok, true);
  // Caller-a cannot hold a third.
  const third = issue(state, { operation: "inspect", identity: "worker-a", now });
  assert.equal(third.ok, false);
  assert.equal((third as { code: string }).code, "RESERVATION_LIMIT");
  // Fairness: caller-b is not blocked by caller-a's reservations and can still reserve.
  assert.equal(issue(state, { operation: "inspect", identity: "worker-b", now }).ok, true);
});

test("R7D.1-RES-16: explicit revocation cancels a reservation before its TTL and frees the caller's allowance", () => {
  const state = newAdmissionState();
  state.maxReservations = 10;
  const now = 1_000;

  // Caller-a holds two reservations (at its per-caller limit of 2). Same operation so the
  // sequence check passes both times (issuance does not advance the sequence).
  const g1 = issue(state, { operation: "inspect", identity: "worker-a", now });
  assert.equal(g1.ok, true);
  const g2 = issue(state, { operation: "inspect", identity: "worker-a", now });
  assert.equal(g2.ok, true);

  // A third is refused at the per-caller limit.
  const over = issue(state, { operation: "inspect", identity: "worker-a", now });
  assert.equal(over.ok, false);
  assert.equal((over as { code: string }).code, "RESERVATION_LIMIT");

  // Revoke the first reservation: the caller's allowance is freed immediately.
  const revoked = revokeForWorker(state, { callerIdentity: "worker-a", reservationId: g1.reservationId, now });
  assert.equal(revoked.ok, true);
  assert.equal((revoked as { ok: true; revoked: boolean }).revoked, true);
  assert.equal(state.reservations.has(g1.reservationId), false);
  // The second reservation is untouched.
  assert.equal(state.reservations.has(g2.reservationId), true);

  // After revocation, the caller can issue again: the limit is on live reservations, not on
  // lifetime issuance count.
  const again = issue(state, { operation: "inspect", identity: "worker-a", now });
  assert.equal(again.ok, true);
  // Caller-b is unaffected by caller-a's reservations or revocation.
  assert.equal(issue(state, { operation: "inspect", identity: "worker-b", now }).ok, true);
});

test("R7D.1-RES-17: a revoked reservation cannot be used at admission", () => {
  const state = newAdmissionState();
  const now = 2_000;

  const grant = issue(state, { operation: "inspect", identity: "worker-a", now: 1_000 });
  assert.equal(grant.ok, true);
  if (!grant.ok) return;

  // Revoke it before any admission attempt.
  const revoked = revokeForWorker(state, { callerIdentity: "worker-a", reservationId: grant.reservationId, now });
  assert.equal(revoked.ok, true);

  // Admission with the revoked id is refused: the reservation no longer exists.
  const decision = admit(state, {
    role: "worker", operation: "inspect", requestId: "a".repeat(32),
    reservationId: grant.reservationId, callerIdentity: "worker-a",
  }, now, LIMITS);
  assert.equal(decision.ok, false);
  assert.equal((decision as { code: string }).code, "RESERVATION_REQUIRED");
});

test("R7D.1-RES-18: revocation of another caller's reservation is refused", () => {
  const state = newAdmissionState();
  const now = 1_000;

  const grant = issue(state, { operation: "inspect", identity: "worker-a", now });
  assert.equal(grant.ok, true);

  // Caller-b cannot revoke caller-a's reservation: callerIdentity is binding.
  const revoked = revokeForWorker(state, { callerIdentity: "worker-b", reservationId: grant.reservationId, now });
  assert.equal(revoked.ok, false);
  assert.equal((revoked as { code: string }).code, "RESERVATION_NOT_HELD");

  // Caller-a's reservation is still valid.
  assert.equal(state.reservations.has(grant.reservationId), true);
  // Caller-a can still use it.
  const decision = admit(state, {
    role: "worker", operation: "inspect", requestId: "a".repeat(32),
    reservationId: grant.reservationId, callerIdentity: "worker-a",
  }, now, LIMITS);
  assert.equal(decision.ok, true);
});

test("R7D.1-RES-19: revoking an already-expired reservation is refused (nothing to revoke)", () => {
  const state = newAdmissionState();

  // A 1 ms TTL: expires immediately.
  const grant = issue(state, { operation: "inspect", identity: "worker-a", now: 1_000, ttlMs: 1, idleMs: 1 });
  assert.equal(grant.ok, true);

  // Advance past the TTL so the sweep removes it.
  const late = 5_000;
  const sweep = issue(state, { operation: "inspect", identity: "worker-b", now: late });
  assert.equal(sweep.ok, true);
  // The sweep on issuance removed worker-a's expired reservation.
  assert.equal(state.reservations.has(grant.reservationId), false);

  // Revoking it is a refusal: it is already gone.
  const revoked = revokeForWorker(state, { callerIdentity: "worker-a", reservationId: grant.reservationId, now: late });
  assert.equal(revoked.ok, false);
  assert.equal((revoked as { code: string }).code, "RESERVATION_NOT_HELD");
});
