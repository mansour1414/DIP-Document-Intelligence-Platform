/**
 * Composing one execution, end to end (R7D.1 §3–§7; D2 closure).
 *
 * ## What this module is for
 *
 * `supervisor.ts` owns the lifecycle *order*; `role-sockets.ts` owns the authenticated channel;
 * `docker-lifecycle.ts` owns the daemon calls. None of them creates an execution, because none of
 * them should know about all three. This module is the one place where they meet, and it is
 * deliberately the only such place: the sequence is long enough that a second copy would drift.
 *
 * ## The sequence
 *
 * ```
 *   1  the caller is already authenticated            role-sockets.ts
 *   2  operation authorized, admission acquired       role-sockets.ts -> admit
 *   3  control metadata validated                     here
 *   4  durable intent recorded                        recordIntent
 *   5  container created                              create
 *   6  started attached, empty stdin                   startAndPreflight
 *   7  effective host state verified                   preflight (daemon *and* /proc)
 *   8  watchdog ARM_ACK obtained and verified          armWatchdog
 *   9  READY_FOR_BODY                                 readyForBody
 *  10  body streamed and reconciled                    streamInput
 *  11  end-of-body trailer verified                    here
 *  12  executor stdin EOF                              streamInput ends stdin
 *  13  bounded provisional results streamed            here -> the caller
 *  14  framing and the real child exit validated       collectResult + here
 *  15  termination and exact removal confirmed         terminateAndRemove
 *  16  independent durable completion grant            authorize
 *  17  authenticated TERMINAL_COMMIT                   here
 *  18  admission released on positive resolution       here
 * ```
 *
 * ## The thing it never does
 *
 * It never holds a whole document. The body flows caller → executor stdin as it arrives;
 * the result flows executor → caller under `maxOutputBytes` with backpressure. A document larger
 * than the configured bound is refused, not accumulated.
 *
 * ## Pre-create refusal and the executor slot
 *
 * Steps 3 and 4 can fail before any container exists. Nothing was created, so there is nothing to
 * resolve, and holding the slot would block admission forever for a request needing no cleanup —
 * so those failures release the slot. Everything from `create()` onward is the opposite: once a
 * container *may* exist, a failure leaves the slot held and the id recorded, because this module
 * cannot prove the container is gone. The distinction is "does a resource exist", not "did it fail".
 */

import type { Readable } from "node:stream";
import { createHash } from "node:crypto";
import {
  LifecycleError,
  type PreflightObservation,
  type PreflightVerdict,
  type SupervisorExecution,
} from "./supervisor";
import type { AdmittedSession } from "./role-sockets";
import {
  SYNTHETIC_PROFILE,
  assertDigestPinnedImage,
  assertDedicatedCgroupParent,
  DEDICATED_CGROUP_SLICE,
  type ExecutionPolicy,
} from "./docker-lifecycle";
import { containerNameFor } from "./ownership-journal";

/** The three operations the plane serves. */
export type ExecutionOperation = "inspect" | "fill" | "verify";

/**
 * The control block a caller sends with its HELLO.
 *
 * ## Why these fields are authenticated rather than merely parsed
 *
 * They are bound into the handshake transcript, so a caller cannot change them after proving itself
 * and the supervisor cannot be talked into running something other than what it authorized. That is
 * why the operation lives here and not in the body: a body is opaque until an executor parses it,
 * and by then the container already exists.
 */
export type ControlMetadata = {
  /** The image to run. Digest-pinned; a tag is refused at intent time. */
  image: string;
  /** The profile id, which the watchdog compares against. */
  profileId: string;
  /** The cgroup parent the execution must be pinned to. */
  cgroupParent: string;
};

/** What one composed execution produced. Closed, because the caller branches on it. */
export type ExecutionOutcome =
  /** A validated result and an authenticated commit. `frame` is what the commit describes. */
  | { kind: "committed"; frame: Buffer; resultBytes: number; metaBytes: number; commitProof: string }
  /** Refused before any executor existed. Nothing to clean up, so the slot is released. */
  | { kind: "refused"; code: string; detail: string }
  /** Refused after an executor may have existed. The slot stays held until reconciliation. */
  | { kind: "quarantined"; code: string; detail: string };

export type ComposeOptions = {
  session: AdmittedSession;
  execution: SupervisorExecution;
  control: ControlMetadata;
  /** The effective-state gate. Supplied by the caller so the policy lives in one place. */
  preflight: (observation: PreflightObservation) => PreflightVerdict;
  /** Bounds. `maxOutputBytes` is the only place a result is refused for size. */
  limits: { maxInputBytes: number; maxOutputBytes: number };
  /** Monotonic clock, so the deadline is decided against the same instant the lifecycle uses. */
  now?: () => number;
};

/**
 * Run one admitted execution, start to finish.
 *
 * Returns an outcome rather than throwing, because the caller must distinguish three things that
 * are all "not a result": a refusal that created nothing, a refusal that left a resource, and a
 * success. A thrown error collapses the first two.
 */
export async function composeExecution(options: ComposeOptions): Promise<ExecutionOutcome> {
  const { session, execution } = options;

  // ── 3. Control metadata ──────────────────────────────────────────────────────────────────────
  //
  // Validated with the same functions that would refuse it at `create` time, so there is one copy
  // of the rules. A tag instead of a digest reaches this point as a refusal, not as a container
  // that the daemon pulls by floating tag.
  try {
    validateControl(options.control);
  } catch (error) {
    return { kind: "refused", code: refusalOf(error, "NOT_ADMITTED"), detail: messageOf(error) };
  }

  // ── 4. Durable intent ────────────────────────────────────────────────────────────────────────
  //
  // Before the daemon is asked for anything. An unrecorded container is one recovery cannot find,
  // and a container recovery cannot find is one that may run forever.
  const policy = buildPolicy(options.control, {
    executionId: execution.executionId,
    bootId: execution.bootId,
    supervisorInstance: execution.supervisorInstance,
  });
  let created = false;
  try {
    execution.recordIntent({
      // The journal records the *digest*, because that is the immutable identity a recovery can
      // compare a live container against. The full reference (repository + digest) is what the
      // daemon is asked to run. Keeping the two separate means neither has to be parsed back out
      // of the other, and an image reference with a registry host cannot fail a digest check.
      image: digestOfImage(policy.image),
      profileId: policy.profileId,
      policy,
      startedMonotonicMs: (options.now ?? Date.now)(),
    });
  } catch (error) {
    // No container was requested. This is the "nothing exists" case.
    return { kind: "refused", code: refusalOf(error, "INTENT_NOT_DURABLE"), detail: messageOf(error) };
  }

  try {
    // ── 5–7. Create, start attached with empty stdin, verify the effective state ───────────────
    await execution.create();
    created = true;
    await execution.startAndPreflight(options.preflight);

    // ── 8. The independent arm ────────────────────────────────────────────────────────────────
    //
    // `armWatchdog` verifies the ack against the exact observation preflight produced: message id,
    // execution id, watchdog instance, boot, cgroup inode/device identity, and the arming window.
    // A watchdog that armed something else cannot produce an ack this accepts.
    await execution.armWatchdog();

    // ── 9. The gate ───────────────────────────────────────────────────────────────────────────
    //
    // Everything above exists to make this line safe. If any of it failed we are not here, and the
    // caller has had a refusal without one byte of its document being read.
    execution.readyForBody();

    // ── 10–12. The body, streamed and reconciled ──────────────────────────────────────────────
    const received = await execution.streamInput(session.body as unknown as Readable);
    // The declaration is what the handshake bound. A body of the wrong length or digest means the
    // executor is already reading a document we cannot vouch for, so nothing it produces is used.
    if (received.bytes !== session.declared.bodyBytes) {
      throw new LifecycleError("INPUT_MISMATCH", `the body was ${received.bytes} bytes and ${session.declared.bodyBytes} were declared`);
    }
    if (received.digest !== session.declared.bodySha256) {
      throw new LifecycleError("INPUT_MISMATCH", "the body digest did not match the declaration");
    }

    // ── 13–14. Results, framing, and the executor's real exit ─────────────────────────────────
    //
    // The result frame is forwarded to the caller as it arrives, bounded, so the caller's own
    // decoder sees exactly what the executor wrote. Readiness was sent in step 9, so the caller's
    // result deadline is already running.
    await execution.collectResult();

    // ## The real exit code, not the Docker CLI's
    //
    // `docker start -a` exits with the container's code only while it can attach; when the daemon
    // disappears it exits non-zero while the container may still run. The executor's own contract
    // is that a *refused document* exits 0 with a failure frame in it, and a *crash* exits
    // non-zero. So: a non-zero exit after a well-formed frame means the frame cannot be trusted
    // even though it parsed, because the process that wrote it died.
    const exitCode = await execution.executorExitCode();
    if (exitCode !== 0) {
      throw new LifecycleError("RESULT_INVALID", `the executor exited ${exitCode} after writing its frame`);
    }

    // ── 15. Termination and exact removal, confirmed ──────────────────────────────────────────
    await execution.terminateAndRemove();

    // ── 16–17. The grant, then the commit ─────────────────────────────────────────────────────
    //
    // `authorize` re-decides the deadline immediately before asking the watchdog, verifies the
    // grant's HMAC against its own record, and signs a commit the caller can verify independently.
    const frame = execution.sealedFrame();
    const metaBytes = frameMetaBytes(frame);
    const terminal = await execution.authorize({
      requestId: execution.requestId,
      resultBytes: frame.byteLength,
      resultDigest: sha256Hex(frame),
      metaBytes,
      outcome: "committed",
      // The nonce the caller was given with READY_FOR_BODY. It is already bound into the caller's
      // transcript, so a commit that reuses it can only be for this execution.
      nonce: session.readyNonce(),
    });

    // ── 18. Admission, released on evidence ───────────────────────────────────────────────────
    //
    // Reached only after termination *and* removal were confirmed and the grant verified. A slot
    // released earlier would let a second caller be admitted beside an execution that has not
    // resolved its lifecycle.
    return {
      kind: "committed",
      frame,
      resultBytes: frame.byteLength,
      metaBytes,
      commitProof: terminal.message.proof,
    };
  } catch (error) {
    const code = refusalOf(error, "RESULT_INVALID");
    const detail = messageOf(error);
    return created
      // A container may exist and this module cannot prove otherwise. The slot stays held.
      ? { kind: "quarantined", code, detail }
      // Nothing was created: the request is refused and the slot is genuinely free.
      : { kind: "refused", code, detail };
  }
}

/**
 * Validate the control block.
 *
 * Deliberately reuses the daemon layer's assertions. A second copy of "what a valid image spec is"
 * would drift from the one that builds the `create` argv, and the drift would show up as a
 * container the daemon refused for a reason the control plane had already accepted.
 */
export function validateControl(control: ControlMetadata): void {
  assertDigestPinnedImage(control.image);
  // The parent is checked so a caller that is configured for a different hierarchy hears about it
  // at admission rather than at arm time. The policy does not *use* this value: the cgroup parent
  // is a property of the watchdog's subtree, not of the caller's request, so `buildPolicy` takes it
  // from the constant. A caller cannot move a container outside the subtree it will be watched in.
  assertDedicatedCgroupParent(control.cgroupParent);
  if (typeof control.profileId !== "string" || !/^[a-z0-9][a-z0-9._-]{2,63}$/u.test(control.profileId)) {
    throw new LifecycleError("NOT_ADMITTED", "the profile id is not acceptable");
  }
}

/**
 * The policy handed to the daemon.
 *
 * Derived from the control block only. Nothing from the body and nothing from the wire beyond the
 * three authenticated fields reaches this, which is what stops a request from choosing its own
 * isolation profile.
 */
function buildPolicy(control: ControlMetadata, identity: { executionId: string; bootId: string; supervisorInstance: string }): ExecutionPolicy {
  // The resource profile comes from the approved constant, not from the request. A caller chooses
  // the image and the profile *id*; it cannot choose a memory ceiling, a PID limit or a seccomp
  // profile, because none of those is on the wire in a form this code reads.
  return {
    image: control.image,
    name: containerNameFor(identity.executionId),
    executionId: identity.executionId,
    bootId: identity.bootId,
    supervisorInstance: identity.supervisorInstance,
    profileId: control.profileId,
    // From the constant, never from the request: the parent must be the subtree the watchdog is
    // allowed to signal in, and no caller gets to decide that.
    cgroupParent: DEDICATED_CGROUP_SLICE,
    // Derived from the approved budget rather than restated, so the two cannot disagree.
    uid: 10001,
    gid: 10001,
    memoryBytes: SYNTHETIC_PROFILE.memoryBytes,
    cpuQuotaMicros: SYNTHETIC_PROFILE.cpuQuotaMicros,
    cpuPeriodMicros: SYNTHETIC_PROFILE.cpuPeriodMicros,
    pidsLimit: SYNTHETIC_PROFILE.pidsLimit,
    tmpfsBudgetBytes: SYNTHETIC_PROFILE.tmpfsBudgetBytes,
    workTmpfsBytes: SYNTHETIC_PROFILE.workTmpfsBytes,
    tmpTmpfsBytes: SYNTHETIC_PROFILE.tmpTmpfsBytes,
    seccompProfile: "dip-executor-v1",
    apparmorProfile: "dip-executor-v1",
    v8OldSpaceMb: SYNTHETIC_PROFILE.v8OldSpaceMb,
  } as ExecutionPolicy;
}

/**
 * The digest from a digest-pinned image reference.
 *
 * `ghcr.io/org/name@sha256:<hex>` becomes `sha256:<hex>`. The journal's validator requires this
 * form, and it is the right form to record: a repository name is not an identity, a digest is.
 */
function digestOfImage(reference: string): string {
  const at = reference.indexOf("@");
  if (at < 0) throw new LifecycleError("NOT_ADMITTED", "the image reference carries no digest");
  return reference.slice(at + 1);
}

/** The metadata block length the commit binds, from the frame's own 4-byte prefix. */
function frameMetaBytes(frame: Buffer): number {
  if (frame.byteLength < 4) throw new LifecycleError("RESULT_INVALID", "the result frame is truncated");
  const declared = frame.readUInt32BE(0);
  if (4 + declared > frame.byteLength) throw new LifecycleError("RESULT_INVALID", "the result frame is truncated");
  return declared;
}

function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function refusalOf(error: unknown, fallback: string): string {
  return error instanceof LifecycleError ? error.refusal : fallback;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 200) : "the execution failed";
}

export { containerNameFor };
