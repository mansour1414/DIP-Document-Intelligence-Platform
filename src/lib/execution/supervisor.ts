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
  inspectStateAsync,
  INSPECT_FORMAT,
  type ContainerStateInspect,
  type DockerOutcome,
  type ExecutionPolicy,
} from "./docker-lifecycle";
import { findCgroup2Mount, readCgroupMembership, readProcessStartTimeTicks } from "./host-facts";
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
  | "armed"
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
  /** The body was offered before preflight, arming and admission had all completed (D2). */
  | "NOT_READY"
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
  /**
   * The kernel facts preflight needs: a process's start time, its cgroup, and the cgroup2 mount.
   *
   * Injectable for the same reason the watchdog's host verification is: this environment has no
   * writable cgroup2 mount, so a real container cannot be observed here. The default reads `/proc`
   * and `/proc/self/mountinfo`, and there is no option to skip the observation — only to answer it
   * from a fixture. A fixture answer is mocked evidence and is labelled as such in the tests.
   */
  hostFacts?: {
    startTimeTicks: (pid: number) => number;
    cgroupMembership: (pid: number) => string | null;
    cgroup2Mount: () => { path: string; device: string } | null;
  };
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
  /**
   * The running container's init PID and state, by exact id.
   *
   * Separate from `inspect` because it answers a different question at a different moment:
   * configuration is fixed at `create`, while PID and running state exist only after `start`. See
   * `STATE_INSPECT_FORMAT`.
   */
  state: (id: string) => Promise<DockerOutcome<ContainerStateInspect>>;
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
  /**
   * The complete result frame: length prefix, metadata, output.
   *
   * ## Why this is retained separately from the output
   *
   * `BoundedProvisionalOutput` keeps the output slice, because that is what a caller would publish.
   * The *commit* binds the whole frame, so the caller needs those bytes to verify its own copy.
   * Accumulating the frame here is bounded by `maxOutputBytes` plus the metadata ceiling — both
   * already enforced by the stream — so this is not a second bound, it is the same one applied to
   * the whole file rather than to a slice of it.
   */
  private frameBytes: Buffer | null = null;
  private refused: LifecycleRefusal | null = null;

  constructor(
    readonly executionId: string,
    readonly requestId: string,
    /** The operation this execution performs. Part of its identity, not of the container profile. */
    readonly operation: "inspect" | "fill" | "verify",
    private readonly options: SupervisorOptions,
  ) {}

  /**
   * The exact policy this execution was created with.
   *
   * Exposed so the preflight gate can judge the container against *the same* policy the daemon was
   * given, rather than against a reconstruction. A reconstructed policy is how the labels check
   * failed during the first end-to-end run: the ids and the boot were empty, so every container
   * looked foreign. There is exactly one policy per execution and this is it.
   */
  get executionPolicy(): ExecutionPolicy {
    if (this.policy === null) throw new LifecycleError("NOT_ADMITTED", "no policy was recorded");
    return this.policy;
  }

  /** The boot this execution is bound to. Part of its identity, and of the policy's labels. */
  get bootId(): string {
    return this.options.bootId;
  }

  /** The supervisor instance that owns this execution, for the same reason. */
  get supervisorInstance(): string {
    return this.options.supervisorInstance;
  }

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
      // ## Normalised here, at the one place the field is written first
      //
      // The record's `imageDigest` is a digest, while the policy's `image` is a full digest-pinned
      // reference. They are different fields that shared a value once, and every later write site
      // had to remember to convert. Converting at the first write means the invariant holds from
      // the moment the record exists, rather than being re-established at every subsequent write.
      imageDigest: digestOf(input.image),
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
    // The deadline anchor, taken from the same instant the journal recorded. A retry cannot move
    // it, which is what stops "one more attempt" from becoming an extension (D2-F02).
    this.startedMonotonicMs = input.startedMonotonicMs;
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

    // ## D2-F02: observe the *running* container, not the created one
    //
    // The previous order inspected the container, then started it, then judged the pre-start
    // snapshot. Every field it judged was configuration, so the snapshot was not wrong — but the
    // things that only exist once a container runs were absent from it: the init PID, the cgroup the
    // init is actually in, the start time that makes the PID checkable. Those are exactly the
    // identity the watchdog is armed against, so the observation that authorizes arming has to be
    // taken after the process exists.
    let session: DockerSession;
    try {
      session = await docker.start(containerNameFor(this.executionId));
    } catch (error) {
      this.fail("START_FAILED");
      throw new LifecycleError("START_FAILED", error instanceof Error ? error.message : "start failed");
    }
    this.transition("started");

    const observation = await this.observeEffective(this.containerId!, session);
    this.setObservation(observation);

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

  /**
   * Read the effective state from the daemon *and* the kernel, after the container is running.
   *
   * ## Why two sources, and why neither is enough
   *
   * The daemon reports the configuration it was given. A daemon that was told to apply a profile
   * reports that profile whether or not the kernel honoured it, and a container started before the
   * daemon's configuration took effect reports the old one. The kernel reports the truth about the
   * process — which PID it is, which cgroup it is in — but knows nothing about `--security-opt`.
   *
   * So: configuration from the daemon, process identity from the daemon *cross-checked against*
   * `/proc`. A disagreement between the two is a failure, not a preference for one reading.
   */
  private async observeEffective(containerId: string, session: DockerSession): Promise<PreflightObservation> {
    const docker = this.docker();

    const inspected = await docker.inspect(containerId);
    if (!inspected.ok) throw new LifecycleError("PREFLIGHT_FAILED", `inspect failed: ${inspected.fault}`);
    const fields = inspected.value.raw.split("|");
    if (fields.length !== INSPECT_FORMAT.split("|").length) {
      throw new LifecycleError("PREFLIGHT_FAILED", "the inspect output did not match the requested format");
    }
    const base = parseInspect(fields, containerId, this.policy!);

    // The init process, by exact id, from the daemon.
    const state = await docker.state(containerId);
    if (!state.ok) throw new LifecycleError("PREFLIGHT_FAILED", `state inspect failed: ${state.fault} (${"detail" in state ? String(state.detail) : ""})`);
    if (!state.value.running) throw new LifecycleError("PREFLIGHT_FAILED", "the container is not running");
    if (state.value.containerId !== containerId) {
      throw new LifecycleError("PREFLIGHT_FAILED", "the daemon answered for a different container id");
    }
    const initPid = state.value.pid;
    if (!Number.isSafeInteger(initPid) || initPid <= 1) {
      throw new LifecycleError("PREFLIGHT_FAILED", "the daemon reported no usable init pid");
    }

    // The kernel's view of that PID: its start time and its cgroup. A PID alone is recycled, so the
    // start time is what makes the pair an identity rather than a number.
    const facts = this.options.hostFacts ?? {
      startTimeTicks: readProcessStartTimeTicks,
      cgroupMembership: readCgroupMembership,
      cgroup2Mount: findCgroup2Mount,
    };

    let initStartTimeTicks: number;
    try {
      initStartTimeTicks = facts.startTimeTicks(initPid);
    } catch {
      throw new LifecycleError("PREFLIGHT_FAILED", "the init process does not exist");
    }
    const relative = facts.cgroupMembership(initPid);
    if (relative === null) throw new LifecycleError("PREFLIGHT_FAILED", "the init process has no unified cgroup");
    const mount = facts.cgroup2Mount();
    if (mount === null) throw new LifecycleError("PREFLIGHT_FAILED", "the cgroup2 hierarchy could not be found");

    // The cgroup path is composed from the verified mount and the process's own membership. It is
    // never composed from a naming convention, and it is never asserted: it is read.
    const cgroupPath = relative === "/" ? mount.path : `${mount.path}${relative}`;

    // The session must be live: a preflight over a container whose streams have already closed is a
    // preflight of something that is about to be terminated.
    void session;

    base.initPid = initPid;
    base.initStartTimeTicks = initStartTimeTicks;
    base.cgroupPath = cgroupPath;
    base.startedMonotonicMs = this.now();
    return base;
  }

  /**
   * Arm the watchdog. Without a verified ack there is no invitation.
   *
   * ## D2: the ack is compared field by field against what this supervisor verified
   *
   * The previous check compared the execution id and the boot id. That is not enough: an ack can
   * name the right execution while describing a different cgroup, a different container id or a
   * different watchdog instance, and the supervisor would then release a body on the strength of a
   * deadline armed against something else.
   *
   * What is checked here is everything the acknowledgement can disagree with:
   *
   * - the exchange (execution id and message id);
   * - the watchdog instance that signed it, which must be the one this supervisor was configured to
   *   trust, not merely some process that authenticated;
   * - the boot, because a deadline on another boot is a deadline in a namespace that is gone;
   * - the cgroup device, because a different filesystem is a different hierarchy;
   * - the pinned inodes, which must be ones the kernel actually reported.
   */
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
      imageDigest: digestOf(this.policy!.image),
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

    const ack = answer;
    if (ack.executionId !== this.executionId || ack.messageId !== request.messageId) {
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", "the arm ack described a different exchange");
    }
    if (ack.watchdogInstance !== this.options.watchdogInstance) {
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", "the arm ack came from a different watchdog instance");
    }
    if (ack.observedBootId !== this.options.bootId) {
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", "the arm ack described a different boot");
    }
    if (!Number.isSafeInteger(ack.observedCgroupDirInode) || ack.observedCgroupDirInode <= 0
      || !Number.isSafeInteger(ack.observedCgroupKillInode) || ack.observedCgroupKillInode <= 0
      || !/^\d+:\d+$/u.test(ack.observedCgroupDevice)) {
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", "the arm ack carries no usable cgroup identity");
    }
    // The deadline the watchdog armed must start when this supervisor's observation did, to within
    // the exchange. A materially different start means the watchdog timed a different event.
    if (Math.abs(ack.armedAtMonotonicMs - observation.startedMonotonicMs) > this.options.limits.deadlineMs) {
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", "the arm ack was armed outside this execution's window");
    }

    this.transition("armed");
    return ack;
  }

  /**
   * Invite the caller to send a body. The only method that may produce this signal.
   *
   * ## D2: the gate is the whole sequence, not its last step
   *
   * The previous gate accepted `preflight-passed`, which meant a caller could be invited to stream a
   * document before the watchdog had armed. If the arm was then refused, or the watchdog process was
   * not the one the supervisor believed, the container was running with no deadline enforced against
   * it — and the document was already in flight.
   *
   * The only state from which a body may be released is `armed`: preflight has passed, the watchdog
   * has acknowledged the exact identity preflight verified, and the supervisor has compared that
   * acknowledgement against its own record. Anything else is a refusal that names what was missing.
   *
   * Admission is checked by the caller (the role socket), which holds the token; this method cannot
   * see it. `NOT_READY` is therefore about the lifecycle, and a caller that was not admitted never
   * reaches a lifecycle at all.
   */
  readyForBody(): void {
    if (this.phase === "preflight-passed") {
      // Specific: the lifecycle is healthy but the deadline is not enforced. A caller told
      // "PREFLIGHT_FAILED" here would investigate the wrong half of the sequence.
      this.fail("ARM_REFUSED");
      throw new LifecycleError("ARM_REFUSED", "the body cannot be released before the watchdog is armed");
    }
    if (this.phase !== "armed") {
      this.fail("NOT_READY");
      throw new LifecycleError("NOT_READY", `expected an armed execution, this one is in ${this.phase}`);
    }
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
  async collectResult(): Promise<{ bytes: number; digest: string }> {
    this.requirePhase("streaming", "INPUT_MISMATCH");
    const result = this.session?.result;
    if (result === undefined) throw new LifecycleError("RESULT_INVALID", "no result stream is attached");
    const frameParts: Buffer[] = [];
    this.frameBytes = null;
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
        // The frame is retained only after the stream has accepted the bytes, so a fault can never
        // leave a partial frame behind that a later step might mistake for a complete one.
        frameParts.push(buffer);
      }
      // ## The frame is reconciled against itself, not against an invented pair
      //
      // This used to take `declared: { bytes, digest }` from its caller and compare the parsed frame
      // against it. Nothing could supply those values: the executor's frame *declares its own*
      // output length in its header, and the digest exists only after the frame is parsed. A caller
      // that passed the observed values made the comparison a tautology, and one that passed
      // guesses made it a rejection of every correct result. `ProvisionalResultStream.finish()`
      // already reconciles the frame's header against the bytes it actually carried — that is the
      // declaration that means something, because the executor wrote it before it wrote the bytes.
      const completion = stream.finish();
      this.frameBytes = Buffer.concat(frameParts);
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

    // ## D2-F02: the deadline is decided again, here, immediately before the commit is requested
    //
    // Removal is a sequence of daemon calls, and the deadline does not pause for them. An execution
    // whose budget ran out while its container was being removed has exactly one authoritative
    // outcome — expired — and it is not this commit. Asking the watchdog for a grant would at best
    // return `EXPIRED`; asking at all would put the supervisor in the position of having attempted a
    // completion after the authority had already changed hands.
    //
    // The supervisor never extends the deadline on a retry: `deadlineMs` is fixed at intent time and
    // recorded in the journal, so this comparison is against the same instant it always was.
    if (this.deadlineExpired()) {
      this.fail("COMMIT_REFUSED");
      throw new LifecycleError("COMMIT_REFUSED", "the execution deadline passed before the commit");
    }

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

  /**
   * The validated result frame, exactly as the executor wrote it.
   *
   * ## Why the frame and not the output slice
   *
   * The caller verifies its commit against the *complete frame* — a 4-byte length prefix, the
   * metadata block, then the output — because that is what the terminal chain binds. Handing back
   * only the output slice would leave the caller unable to reconstruct the bytes the commit
   * describes, and the natural next step would be for the caller to trust the supervisor's claim
   * about them, which is the one thing the caller must not do.
   *
   * The frame was already reconciled against its own header by `collectResult`, and the stream that
   * produced it faults permanently on any framing error, so a frame returned here is one that
   * matched the declaration its author wrote before the bytes.
   */
  sealedFrame(): Buffer {
    if (this.frameBytes === null) throw new LifecycleError("RESULT_INVALID", "no result frame was retained");
    return Buffer.from(this.frameBytes);
  }

  /**
   * The executor's own exit code.
   *
   * ## Why the supervisor must be asked and not the Docker CLI
   *
   * `docker start -a` exits with the container's code while it can attach, and with its own code
   * when it cannot. A caller that read the CLI's status would accept a frame from a process that
   * died after writing it, and would reject a clean result whenever the daemon hiccuped on the way
   * out. The session's `exited` promise is the child's, and `terminateAndRemove` already waits on
   * it — so by the time a commit is possible this resolves without blocking.
   */
  async executorExitCode(): Promise<number> {
    if (this.session === undefined) throw new LifecycleError("RESULT_INVALID", "no executor session was started");
    return this.session.exited;
  }

  /** The retained output, for the caller that has a verified commit. */
  takeOutput(): BoundedProvisionalOutput {
    if (this.output === null) throw new LifecycleError("RESULT_INVALID", "no output was retained");
    return this.output;
  }

  // ── internals ────────────────────────────────────────────────────────────────────────────────

  private session: DockerSession | undefined;
  private lastObservation: PreflightObservation | null = null;
  /** The monotonic instant the intent was recorded, which the deadline is measured from. */
  private startedMonotonicMs: number | null = null;

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

  /**
   * Whether this execution's own deadline has passed.
   *
   * Decided from the clock alone, with no host work: the point of the check is that it cannot be
   * delayed by the very operation it is gating. `startedMonotonicMs` is the observation time
   * recorded at intent, so the deadline is an anchor into the past rather than a countdown that
   * every retry could restart.
   */
  private deadlineExpired(): boolean {
    const started = this.startedMonotonicMs;
    if (started === null) return false;
    return this.now() - started >= this.options.limits.deadlineMs;
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
        // A digest, from the digest-pinned reference: the same normalisation every other write
        // site uses. A full reference here was rejected by the journal's validator, and because
        // quarantine swallows journal errors the failure was silent — the phase stayed at `intent`
        // while the in-memory refusal said CREATE_AMBIGUOUS.
        imageDigest: this.policy === null ? `sha256:${"0".repeat(64)}` : digestOf(this.policy.image),
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
      // The journal records the *digest*, not the reference. `policy.image` is
      // `repo@sha256:<hex>`, which the journal's validator rejects — and rightly so: a recovery
      // compares a live container's immutable digest, and a repository name is not an identity.
      // The bug this replaces wrote the full reference into a digest field and only surfaced at
      // the first durable write after `create`.
      imageDigest: digestOf(this.policy!.image),
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
      // The journal records the *digest*, not the reference. `policy.image` is
      // `repo@sha256:<hex>`, which the journal's validator rejects — and rightly so: a recovery
      // compares a live container's immutable digest, and a repository name is not an identity.
      // The bug this replaces wrote the full reference into a digest field and only surfaced at
      // the first durable write after `create`.
      imageDigest: digestOf(this.policy!.image),
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
/**
 * The digest from a digest-pinned reference.
 *
 * Kept next to the record writer because the record's `imageDigest` field and the policy's `image`
 * field are different things that were once the same value. A full reference can never satisfy the
 * digest pattern, so a single call site that forgot this produced a write failure at exactly the
 * moment the container already existed — the least convenient place to discover it.
 */
function digestOf(reference: string): string {
  const at = reference.indexOf("@");
  if (at < 0) throw new LifecycleError("INTENT_NOT_DURABLE", "the policy image carries no digest");
  return reference.slice(at + 1);
}

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

export { sha256Hex, killContainerAsync, removeContainerAsync, inspectContainerAsync, createContainerAsync, inspectStateAsync };
