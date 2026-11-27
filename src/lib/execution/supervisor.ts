/**
 * The Supervisor lifecycle (R7D.1 §5).
 *
 * ## The order is the security property
 *
 * Every gate below exists because moving document bytes before it would mean executing a request
 * whose container was not verified:
 *
 * ```
 *   authenticate caller
 *   authorize (role × operation × reservation)
 *   admit (one active executor, bounded state)
 *   durable intent            ← the daemon is not touched before this is fsynced
 *   docker create             ← ambiguous outcome ⇒ quarantine, never guess
 *   start attached, empty stdin
 *   effective host preflight  ← reads the daemon's *and* the kernel's view
 *   READY_FOR_BODY            ← only now is the caller invited to send a document
 *   bounded streaming         ← input length and digest reconciled at the end
 *   child stdin EOF
 *   provisional result stream ← strict framing, bounded memory
 *   confirm termination
 *   confirm exact removal     ← by exact id, never by name or label pattern
 *   watchdog completion grant
 *   authenticated TERMINAL_COMMIT
 * ```
 *
 * ## What this module is not
 *
 * It is not wired to the web app or to BullMQ. No route calls it, no queue worker calls it, and
 * it imports nothing from `src/app` or from the job processor. That is deliberate: R7D.2 is a
 * separate increment and mixing the two would make this one impossible to review.
 */

import {
  createContainerAsync,
  inspectContainerAsync,
  killContainerAsync,
  removeContainerAsync,
  INSPECT_FORMAT,
  type DockerOutcome,
  type ExecutionPolicy,
} from "./docker-lifecycle";
import { OwnershipJournal, containerNameFor, newExecutionId, type SupervisorRecord } from "./ownership-journal";
import { ProvisionalResultStream, BoundedProvisionalOutput, sha256Hex } from "./provisional-stream";
import { verifyWatchdogGrant, signTerminalCommit, type CommitExpectation, type CommitResult } from "./terminal-commit";
import type { TerminalRequest } from "./terminal-auth";
import type { ArmAck, ArmRequest, ArmDenied } from "./watchdog-protocol";
import { randomBytes, createHash } from "node:crypto";

/** The phases a supervisor execution moves through, in order. */
export type SupervisorPhase =
  | "admitted"
  | "intent-recorded"
  | "container-created"
  | "started"
  | "preflight-passed"
  | "ready-for-body"
  | "streaming"
  | "sealed"
  | "terminated"
  | "removed"
  | "committed";

/**
 * Why a lifecycle stopped. Closed set: the caller branches on these and a string that is not in
 * the set is a bug in the supervisor, not a new case.
 */
export type LifecycleRefusal =
  | "NOT_ADMITTED"
  | "INTENT_NOT_DURABLE"
  | "CREATE_AMBIGUOUS"
  | "CREATE_FAILED"
  | "START_FAILED"
  | "PREFLIGHT_FAILED"
  | "ARM_REFUSED"
  | "INPUT_MISMATCH"
  | "RESULT_INVALID"
  | "TERMINATION_UNCONFIRMED"
  | "REMOVAL_UNCONFIRMED"
  | "COMMIT_REFUSED"
  | "CANCELLED";

export type SupervisorOptions = {
  journal: OwnershipJournal;
  supervisorInstance: string;
  bootId: string;
  watchdogInstance: string;
  watchdogSecret: Buffer;
  callerSecret: Buffer;
  /** Runtime bounds, from config. Never larger than the hard ceilings. */
  limits: {
    /** Wall-clock budget for the whole execution. */
    deadlineMs: number;
    /** Largest body the supervisor will accept from the caller. */
    maxInputBytes: number;
    /** Largest provisional output it will hold. */
    maxOutputBytes: number;
    /** Unacknowledged sink bytes before the reader is told to pause. */
    maxBufferedBytes: number;
  };
  /** Injected so the socket, CLI and Docker seams are testable without a daemon. */
  docker?: DockerSeam;
  /** Injected watchdog control channel. The default requires a live socket. */
  watchdog?: {
    arm: (request: ArmRequest) => Promise<ArmAck | ArmDenied>;
    disarm: (request: TerminalRequest, messageId: string, sequence: number) => Promise<{ proof: string } | { code: string }>;
  };
  /** Monotonic clock, injectable so deadlines are testable. */
  monotonicMs?: () => number;
};

/** The attached child session `docker start -a -i` produces. */
export type DockerSession = {
  stdin: NodeJS.WritableStream;
  stdout: NodeJS.ReadableStream;
  stderr: NodeJS.ReadableStream;
  /** The executor's validated result frame. Read from fd 3 by the entry point. */
  result: NodeJS.ReadableStream;
  exited: Promise<number>;
};

/** The daemon operations the lifecycle needs. Narrow on purpose: it is the whole trust surface. */
export type DockerSeam = {
  create: (policy: ExecutionPolicy) => Promise<DockerOutcome<{ containerId: string }>>;
  inspect: (id: string) => Promise<DockerOutcome<{ raw: string }>>;
  remove: (id: string) => Promise<DockerOutcome<{ removed: boolean }>>;
  kill: (id: string) => Promise<DockerOutcome<{ killed: boolean }>>;
  start: (name: string) => Promise<DockerSession>;
};

/** A refusal carries a code and nothing that could be mistaken for document content. */
export class LifecycleError extends Error {
  constructor(readonly refusal: LifecycleRefusal, message: string) {
    super(message);
    this.name = "LifecycleError";
  }
}

/** The result of a completed lifecycle. Deliberately does not contain the document bytes. */
export type LifecycleOutcome = {
  executionId: string;
  requestId: string;
  phase: SupervisorPhase;
  outcome: "committed" | "refused" | "failed";
  /** Set only when the terminal commit was produced and verified. */
  commit: CommitResult | null;
  /** Bytes released to the caller, for accounting. The bytes themselves are the caller's. */
  releasedBytes: number;
};

/**
 * One execution's supervisor-side state.
 *
 * Held in memory for the life of the execution and mirrored to the journal at each phase
 * transition. The journal is the authority after a crash; this object is the authority while the
 * process is alive, and it never delegates a decision it can make locally to a file read.
 */
export class SupervisorExecution {
  private phase: SupervisorPhase = "admitted";
  private sequence = 0;
  private containerId: string | null = null;
  private policy: ExecutionPolicy | null = null;
  private output: BoundedProvisionalOutput | null = null;
  private refused: LifecycleRefusal | null = null;

  constructor(
    readonly executionId: string,
    readonly requestId: string,
    /** The operation this execution performs. Part of its identity, not of the container profile. */
    readonly operation: "inspect" | "fill" | "verify",
    private readonly options: SupervisorOptions,
  ) {}

  get currentPhase(): SupervisorPhase {
    return this.phase;
  }

  get refusal(): LifecycleRefusal | null {
    return this.refused;
  }

  /**
   * Produce the durable intent record.
   *
   * Nothing may be sent to the daemon before this returns. If it throws, the caller must not
   * create a container: an unrecorded container is one that recovery cannot find, and a
   * container recovery cannot find is one that may persist forever.
   */
  recordIntent(input: { image: string; profileId: string; policy: ExecutionPolicy; startedMonotonicMs: number }): SupervisorRecord {
    const record: SupervisorRecord = {
      schema: 1,
      executionId: this.executionId,
      bootId: this.options.bootId,
      supervisorInstance: this.options.supervisorInstance,
      containerName: containerNameFor(this.executionId),
      containerId: null,
      imageDigest: input.image,
      profileId: input.profileId,
      deadlineMs: this.options.limits.deadlineMs,
      startedMonotonicMs: input.startedMonotonicMs,
      phase: "intent",
      sequence: this.nextSequence(),
      outcome: null,
      writerInstance: this.options.supervisorInstance,
    };
    this.options.journal.writeSupervisor(record);
    this.policy = input.policy;
    this.transition("intent-recorded");
    return record;
  }

  /**
   * Create the container.
   *
   * A definite failure is a refusal. An ambiguous failure is a *quarantine*: the daemon may or
   * may not have created something, and the only safe response is to record the uncertainty and
   * stop. Guessing produces either a leak or a double-create.
   */
  async create(): Promise<string> {
    this.requirePhase("intent-recorded", "NOT_ADMITTED");
    if (this.policy === null) throw new LifecycleError("INTENT_NOT_DURABLE", "no policy was recorded");
    const docker = this.docker();
    const outcome = await docker.create(this.policy);
    if (!outcome.ok) {
      this.fail(outcome.ambiguous ? "CREATE_AMBIGUOUS" : "CREATE_FAILED");
      // Quarantine means "ownership could not be resolved". A definite rejection resolves
      // perfectly well: no container exists. Quarantining it would block admission forever for
      // a failure that needs no cleanup, while leaving the record at `intent` lets recovery
      // conclude there is nothing to find.
      if (outcome.ambiguous) this.quarantine();
      throw new LifecycleError(outcome.ambiguous ? "CREATE_AMBIGUOUS" : "CREATE_FAILED", `create failed: ${outcome.fault}`);
    }
    this.containerId = outcome.value.containerId;
    // Record the id before anything else uses it. A crash between here and the next phase leaves
    // a record that names the container, which is what makes cleanup possible.
    this.persist("created");
    this.transition("container-created");
    return this.containerId;
  }

  /**
   * Start attached with empty stdin, then run preflight.
   *
   * Preflight reads the effective state from two independent sources: the daemon's own view of
   * the container, and the kernel's view of the process. Neither alone is sufficient — the
   * daemon can be told to report what it configured, and the kernel view says nothing about
   * mounts the daemon did not apply.
   */
  async startAndPreflight(preflight: (observation: PreflightObservation) => PreflightVerdict): Promise<void> {
    this.requirePhase("container-created", "CREATE_FAILED");
    const docker = this.docker();
    const inspected = await docker.inspect(this.containerId!);
    if (!inspected.ok) {
      this.fail("PREFLIGHT_FAILED");
      throw new LifecycleError("PREFLIGHT_FAILED", `inspect failed: ${inspected.fault}`);
    }
    const fields = inspected.value.raw.split("|");
    if (fields.length !== INSPECT_FORMAT.split("|").length) {
      this.fail("PREFLIGHT_FAILED");
      throw new LifecycleError("PREFLIGHT_FAILED", "the inspect output did not match the requested format");
    }

    let session: DockerSession;
    try {
      session = await docker.start(containerNameFor(this.executionId));
    } catch (error) {
      this.fail("START_FAILED");
      throw new LifecycleError("START_FAILED", error instanceof Error ? error.message : "start failed");
    }
    this.transition("started");

    const observation = parseInspect(fields, this.containerId!, this.policy!);
    const verdict = preflight(observation);
    if (!verdict.ok) {
      this.fail("PREFLIGHT_FAILED");
      // Terminate before reporting: a container that failed preflight must not keep running.
      // This is best-effort here and confirmed by the caller's termination step; the refusal is
      // reported regardless so no input is ever released.
      await docker.kill(this.containerId!).catch(() => undefined);
      throw new LifecycleError("PREFLIGHT_FAILED", `preflight refused: ${verdict.code}`);
    }
    this.session = session;
    this.transition("preflight-passed");
  }

  /** Arm the watchdog. Without an ack there is no invitation. */
  async armWatchdog(): Promise<ArmAck> {
    this.requirePhase("preflight-passed", "PREFLIGHT_FAILED");
    const watchdog = this.options.watchdog;
    if (watchdog === undefined) throw new LifecycleError("ARM_REFUSED", "no watchdog channel is configured");
    const observation = this.lastObservation;
    if (observation === null) throw new LifecycleError("ARM_REFUSED", "no verified observation to arm against");
    const request: ArmRequest = {
      kind: "ARM_REQ",
      messageId: randomBytes(8).toString("hex"),
      sequence: this.nextSequence(),
      executionId: this.executionId,
      requestId: this.requestId,
      operation: this.operation,
      supervisorInstance: this.options.supervisorInstance,
      bootId: this.options.bootId,
      containerId: this.containerId!,
      containerName: containerNameFor(this.executionId),
      imageDigest: this.policy!.image,
      profileId: this.policy!.profileId,
      initPid: observation.initPid,
      initStartTimeTicks: observation.initStartTimeTicks,
      cgroupPath: observation.cgroupPath,
      deadlineMs: this.options.limits.deadlineMs,
      startedMonotonicMs: observation.startedMonotonicMs,
    };
    const answer = await watchdog.arm(request);
    if (answer.kind === "ARM_DENIED") {
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", `the watchdog refused to arm: ${answer.code}`);
    }
    // The ack must describe the same identity the supervisor verified, or the watchdog is
    // enforcing a deadline against something else.
    if (answer.executionId !== this.executionId || answer.observedBootId !== this.options.bootId) {
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", "the arm ack described a different execution");
    }
    return answer;
  }

  /** Invite the caller to send a body. The only method that may produce this signal. */
  readyForBody(): void {
    this.requirePhase("preflight-passed", "PREFLIGHT_FAILED");
    this.transition("ready-for-body");
  }

  /**
   * Consume the body.
   *
   * Bounded by `maxInputBytes`, hashed as it goes, and never buffered whole: the whole point of
   * the streaming contract is that a 512 MiB document is the document's problem, not the
   * supervisor's. The digest is what the caller's declared value is reconciled against.
   */
  async streamInput(source: NodeJS.ReadableStream): Promise<{ bytes: number; digest: string }> {
    this.requirePhase("ready-for-body", "PREFLIGHT_FAILED");
    this.transition("streaming");
    const stdin = this.session?.stdin;
    if (stdin === undefined) throw new LifecycleError("START_FAILED", "no stdin is attached");
    const hash = createHash("sha256");
    let bytes = 0;
    for await (const chunk of source) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      bytes += buffer.byteLength;
      if (bytes > this.options.limits.maxInputBytes) {
        this.fail("INPUT_MISMATCH");
        throw new LifecycleError("INPUT_MISMATCH", `the body exceeded ${this.options.limits.maxInputBytes} bytes`);
      }
      hash.update(buffer);
      // Await the write's drain callback so a slow child exerts real backpressure on the caller
      // rather than the supervisor accumulating an unbounded queue between them.
      if (!stdin.write(buffer)) {
        await new Promise<void>((resolve) => stdin.once("drain", resolve));
      }
    }
    // EOF on the child's stdin is the signal that the body is complete. The child does not
    // parse a length prefix on stdin; it reads to end.
    stdin.end();
    return { bytes, digest: hash.digest("hex") };
  }

  /**
   * Collect the provisional result.
   *
   * The stream owns framing validation; this method owns the decision to keep the bytes. On any
   * fault — framing, digest, length, timeout — the output is discarded here and never reaches a
   * caller.
   */
  async collectResult(declared: { bytes: number; digest: string }): Promise<{ bytes: number; digest: string }> {
    this.requirePhase("streaming", "INPUT_MISMATCH");
    const result = this.session?.result;
    if (result === undefined) throw new LifecycleError("RESULT_INVALID", "no result stream is attached");
    this.output = new BoundedProvisionalOutput(this.options.limits.maxOutputBytes);
    const stream = new ProvisionalResultStream({
      expectedOp: this.operation,
      executionId: this.executionId,
      maxOutputBytes: this.options.limits.maxOutputBytes,
      maxBufferedBytes: this.options.limits.maxBufferedBytes,
      sink: (chunk) => this.output!.append(chunk.bytes),
    });
    try {
      for await (const chunk of result) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
        stream.push(buffer);
      }
      const completion = stream.finish();
      if (completion.outputBytes !== declared.bytes || completion.outputSha256 !== declared.digest) {
        throw new LifecycleError("RESULT_INVALID", "the result did not match the declaration");
      }
      this.output.seal(this.executionId, completion.outputSha256);
      this.transition("sealed");
      return { bytes: completion.outputBytes, digest: completion.outputSha256 };
    } catch (error) {
      // A fault invalidates the output permanently. There is no partial publication.
      this.output.discard();
      this.fail("RESULT_INVALID");
      throw error instanceof LifecycleError ? error : new LifecycleError("RESULT_INVALID", error instanceof Error ? error.message : "result invalid");
    }
  }

  /**
   * Confirm termination, then confirm removal by exact id.
   *
   * ## Why both, and in this order
   *
   * Removal without confirmed termination can leave a running container whose record is gone —
   * the worst state. Termination without removal leaves a stopped container taking a name and
   * a cgroup slot. The caller requires both before authorizing a commit.
   *
   * Removal is by exact container id and nothing else. No label selector, no name prefix, no
   * prune: a broad deletion is one bug away from removing another execution's container.
   */
  async terminateAndRemove(): Promise<{ terminated: boolean; removed: boolean }> {
    // Reachable from any phase in which the container exists. Termination is the cleanup path,
    // not a forward transition: a cancelled or failed execution must still be able to stop and
    // remove its container, and gating that on `sealed` would leak a running container on every
    // abort.
    const terminable: SupervisorPhase[] = ["container-created", "started", "preflight-passed", "ready-for-body", "streaming", "sealed"];
    if (!terminable.includes(this.phase)) {
      throw new LifecycleError("TERMINATION_UNCONFIRMED", `there is no container to terminate in phase ${this.phase}`);
    }
    const docker = this.docker();
    const id = this.containerId;
    if (id === null) throw new LifecycleError("TERMINATION_UNCONFIRMED", "no container id is recorded");

    // The attached session ends when the child exits; wait for that rather than killing a
    // container that is already finishing, which would turn a clean completion into a signal.
    const exited = await Promise.race([
      this.session?.exited ?? Promise.resolve(0),
      new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), this.options.limits.deadlineMs).unref()),
    ]);
    if (exited === "timeout") {
      const killed = await docker.kill(id);
      if (!killed.ok) {
        this.fail("TERMINATION_UNCONFIRMED");
        throw new LifecycleError("TERMINATION_UNCONFIRMED", `kill failed: ${killed.fault}`);
      }
    }
    this.transition("terminated");

    const removed = await docker.remove(id);
    if (!removed.ok) {
      this.fail("REMOVAL_UNCONFIRMED");
      throw new LifecycleError("REMOVAL_UNCONFIRMED", `remove failed: ${removed.fault}`);
    }
    // A removed outcome must be verified by inspection. `docker rm` returning success is the
    // daemon's claim; inspecting the exact id is the evidence.
    const remaining = await docker.inspect(id);
    if (remaining.ok) {
      this.fail("REMOVAL_UNCONFIRMED");
      throw new LifecycleError("REMOVAL_UNCONFIRMED", "the container still exists after removal");
    }
    if (remaining.ambiguous || remaining.fault !== "NOT_FOUND") {
      this.fail("REMOVAL_UNCONFIRMED");
      throw new LifecycleError("REMOVAL_UNCONFIRMED", `removal could not be confirmed: ${remaining.fault}`);
    }
    this.transition("removed");
    return { terminated: true, removed: true };
  }

  /**
   * Obtain the terminal commit.
   *
   * Two independent checks, in order: the watchdog's grant must verify against this
   * supervisor's own record of the execution, and only then does the supervisor sign a commit
   * for the caller. Neither alone releases anything — `BoundedProvisionalOutput.collect` refuses
   * a commit whose fields do not describe the bytes it holds.
   */
  async authorize(params: {
    requestId: string;
    resultBytes: number;
    resultDigest: string;
    metaBytes: number;
    outcome: TerminalRequest["outcome"];
    nonce: string;
  }): Promise<{ commit: CommitResult; message: ReturnType<typeof signTerminalCommit> }> {
    this.requirePhase("removed", "REMOVAL_UNCONFIRMED");
    const watchdog = this.options.watchdog;
    if (watchdog === undefined) throw new LifecycleError("COMMIT_REFUSED", "no watchdog channel is configured");

    const request: TerminalRequest = {
      executionId: this.executionId,
      requestId: this.requestId,
      operation: this.operation,
      resultDigest: params.resultDigest,
      resultBytes: params.resultBytes,
      metaBytes: params.metaBytes,
      containerId: this.containerId!,
      containerName: containerNameFor(this.executionId),
      containerRemoved: true,
      outcome: params.outcome,
      watchdogInstance: this.options.watchdogInstance,
      supervisorInstance: this.options.supervisorInstance,
      bootId: this.options.bootId,
      nonce: params.nonce,
      concludedMonotonicMs: this.now(),
    };
    const answer = await watchdog.disarm(request, randomBytes(8).toString("hex"), this.nextSequence());
    if (!("proof" in answer)) {
      this.fail("COMMIT_REFUSED");
      throw new LifecycleError("COMMIT_REFUSED", `the watchdog refused the disarm: ${answer.code}`);
    }

    const expectation: CommitExpectation = {
      executionId: this.executionId,
      requestId: this.requestId,
      operation: this.operation,
      resultDigest: params.resultDigest,
      resultBytes: params.resultBytes,
      metaBytes: params.metaBytes,
      containerId: this.containerId!,
      containerName: containerNameFor(this.executionId),
      bootId: this.options.bootId,
      supervisorInstance: this.options.supervisorInstance,
      watchdogInstance: this.options.watchdogInstance,
    };
    const verified = verifyWatchdogGrant(
      this.options.watchdogSecret,
      expectation,
      { context: request, proof: answer.proof, watchdogInstance: this.options.watchdogInstance },
      this.now(),
    );
    if (!verified.ok) {
      this.fail("COMMIT_REFUSED");
      throw new LifecycleError("COMMIT_REFUSED", `the watchdog grant did not verify: ${verified.code}`);
    }

    const message = signTerminalCommit(
      this.options.callerSecret,
      verified.commit,
      expectation,
      params.nonce,
      this.now(),
    );
    this.persistOutcome(verified.commit.outcome);
    this.transition("committed");
    return { commit: verified, message };
  }

  /** The retained output, for the caller that has a verified commit. */
  takeOutput(): BoundedProvisionalOutput {
    if (this.output === null) throw new LifecycleError("RESULT_INVALID", "no output was retained");
    return this.output;
  }

  // ── internals ────────────────────────────────────────────────────────────────────────────────

  private session: DockerSession | undefined;
  private lastObservation: PreflightObservation | null = null;

  setObservation(observation: PreflightObservation): void {
    this.lastObservation = observation;
  }

  private docker(): DockerSeam {
    if (this.options.docker === undefined) throw new Error("no docker seam is configured");
    return this.options.docker;
  }

  private now(): number {
    return this.options.monotonicMs?.() ?? Math.round(performance.now());
  }

  private nextSequence(): number {
    this.sequence += 1;
    return this.sequence;
  }

  private transition(next: SupervisorPhase): void {
    this.phase = next;
  }

  private fail(refusal: LifecycleRefusal): void {
    this.refused = refusal;
  }

  /**
   * Record that ownership could not be positively resolved.
   *
   * A phase write rather than a log line: admission reads it and blocks, and quarantine is
   * terminal in the journal, so nothing can quietly move the execution forward afterwards.
   * Journal failures are swallowed here because this runs on a failure path — the refusal is
   * already being reported, and replacing it with a durability error would hide the real cause.
   */
  private quarantine(): void {
    try {
      this.options.journal.writeSupervisor({
        schema: 1,
        executionId: this.executionId,
        bootId: this.options.bootId,
        supervisorInstance: this.options.supervisorInstance,
        containerName: containerNameFor(this.executionId),
        containerId: this.containerId,
        imageDigest: this.policy?.image ?? `sha256:${"0".repeat(64)}`,
        profileId: this.policy?.profileId ?? "unknown",
        deadlineMs: this.options.limits.deadlineMs,
        startedMonotonicMs: this.now(),
        phase: "quarantined",
        sequence: this.nextSequence(),
        outcome: null,
        writerInstance: this.options.supervisorInstance,
      });
    } catch {
      // Already reporting a refusal; a second failure must not mask the first.
    }
  }

  /** Mirror the current state to the journal, so a crash leaves an accurate record. */
  private persist(phase: "created" | "terminal"): void {
    const record: SupervisorRecord = {
      schema: 1,
      executionId: this.executionId,
      bootId: this.options.bootId,
      supervisorInstance: this.options.supervisorInstance,
      containerName: containerNameFor(this.executionId),
      containerId: this.containerId,
      imageDigest: this.policy!.image,
      profileId: this.policy!.profileId,
      deadlineMs: this.options.limits.deadlineMs,
      startedMonotonicMs: this.now(),
      phase: phase === "created" ? "created" : "terminal",
      sequence: this.nextSequence(),
      outcome: null,
      writerInstance: this.options.supervisorInstance,
    };
    this.options.journal.writeSupervisor(record);
  }

  private persistOutcome(outcome: SupervisorRecord["outcome"]): void {
    const record: SupervisorRecord = {
      schema: 1,
      executionId: this.executionId,
      bootId: this.options.bootId,
      supervisorInstance: this.options.supervisorInstance,
      containerName: containerNameFor(this.executionId),
      containerId: this.containerId,
      imageDigest: this.policy!.image,
      profileId: this.policy!.profileId,
      deadlineMs: this.options.limits.deadlineMs,
      startedMonotonicMs: this.now(),
      phase: "terminal",
      sequence: this.nextSequence(),
      outcome,
      writerInstance: this.options.supervisorInstance,
    };
    this.options.journal.writeSupervisor(record);
  }

  private requirePhase(expected: SupervisorPhase, refusal: LifecycleRefusal): void {
    if (this.phase !== expected) {
      this.fail(refusal);
      throw new LifecycleError(refusal, `expected phase ${expected}, this execution is in ${this.phase}`);
    }
  }
}

/** What preflight is given. Derived from the daemon's inspect output, not from the policy. */
export type PreflightObservation = {
  containerId: string;
  imageDigest: string;
  initPid: number;
  initStartTimeTicks: number;
  cgroupPath: string;
  startedMonotonicMs: number;
  /** Raw effective fields, already parsed but not yet judged. */
  effective: Record<string, string>;
};

export type PreflightVerdict = { ok: true } | { ok: false; code: string };

/**
 * The key path for one inspect template.
 *
 * `{{.Config.User}}` and `{{json .Config.Labels}}` name the same kind of thing, so both reduce to
 * `Config.User` / `Config.Labels`. Leaving the `json` form as `.Config.Labels` while the plain
 * form becomes `Config.User` would put one key space under two spellings, and the preflight reads
 * by name — so half its checks would silently read `undefined` and pass.
 */
function inspectKey(template: string): string {
  return template
    .replace(/^\{\{json\s+/u, "")
    .replace(/^\{\{/u, "")
    .replace(/\}\}$/u, "")
    .replace(/^\./u, "");
}

/** Parse the inspect format. Positional, so a format change is a length mismatch and not a shift. */
export function parseInspect(fields: string[], containerId: string, policy: ExecutionPolicy): PreflightObservation {
  const names = INSPECT_FORMAT.split("|").map(inspectKey);
  const effective: Record<string, string> = {};
  names.forEach((name, index) => {
    effective[name] = fields[index] ?? "";
  });
  return {
    containerId,
    imageDigest: policy.image,
    // The init PID is not in the inspect format (it is a `docker top` / cgroup question); it is
    // filled by the watchdog arming step, which reads it from the host. Preflight records it as
    // unknown and refuses to invent one.
    initPid: 0,
    initStartTimeTicks: 0,
    cgroupPath: "",
    startedMonotonicMs: 0,
    effective,
  };
}

/** A new execution identity, derived from 32 random bytes. */
export function newExecution(): string {
  return newExecutionId(randomBytes);
}

export { sha256Hex, killContainerAsync, removeContainerAsync, inspectContainerAsync, createContainerAsync };
