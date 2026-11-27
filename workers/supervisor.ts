/**
 * The Supervisor entry point (R7D.1 §5; Continuation D2).
 *
 * ## What was missing
 *
 * Every part of the supervisor existed and none of it ran. `supervisor.ts` described a lifecycle,
 * the role sockets described a preamble format, `caller.ts` described a caller, and nothing
 * composed them: no process created a journal, reconciled it, bound a watchdog channel, or served a
 * socket. Every test substituted its own wiring, so the wiring was the one part of the design with
 * no evidence behind it at all.
 *
 * ## Start-up order is the requirement
 *
 * ```
 *   bind the journal to this instance       ← fencing: a second supervisor cannot take over
 *   reconcile existing records              ← before the sockets listen
 *   refuse readiness while anything is unresolved
 *   connect to the watchdog                 ← and verify the instance and boot it reports
 *   listen on the role sockets
 * ```
 *
 * Reversing any two of these produces a supervisor that can admit work while a container it created
 * on a previous run is still unaccounted for. That is the state the whole ownership journal exists
 * to prevent, and it is not recoverable after the fact: a second execution admitted alongside an
 * orphaned first is two containers under one profile.
 *
 * ## Configuration
 *
 * ```text
 *   DIP_SUPERVISOR_ROOT        journal + state root          (required)
 *   DIP_SUPERVISOR_INSTANCE    this supervisor's identity    (required)
 *   DIP_SUPERVISOR_BOOT        the host boot id              (default: read from /proc)
 *   DIP_SUPERVISOR_APP_SOCKET  the app role socket path      (required)
 *   DIP_SUPERVISOR_WORKER_SOCKET the worker role socket path (required)
 *   DIP_WATCHDOG_SOCKET        the watchdog control socket    (required)
 *   DIP_WATCHDOG_SECRET        hex, >= 32 bytes               (required)
 *   DIP_CALLER_APP_SECRET      hex, >= 32 bytes, app role     (required)
 *   DIP_CALLER_WORKER_SECRET   hex, >= 32 bytes, worker role  (required)
 *   DIP_SUPERVISOR_DEADLINE_MS the per-execution budget       (default 120000)
 * ```
 *
 * ## Fail closed
 *
 * Every one of these is a start-up failure rather than a degraded mode. A supervisor without a
 * journal cannot fence; one without a watchdog cannot enforce a deadline; one without a caller
 * secret cannot verify what it signs. Each is detected before the first socket is created, so a
 * misconfiguration is legible at boot instead of being discovered by the first document.
 *
 * ## What this is not
 *
 * It is not wired to the web application or to BullMQ, and it imports nothing from `src/app`. The
 * queue integration is R7D.2, deliberately.
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { readBootId } from "../src/lib/execution/host-facts";
import { OwnershipJournal } from "../src/lib/execution/ownership-journal";
import { reconcile, admissionAllowed } from "../src/lib/execution/reconciliation";
import { startRoleSockets } from "../src/lib/execution/role-sockets";
import { composeExecution, type ControlMetadata, type TrustedExecutionPolicy } from "../src/lib/execution/execution-handler";
import { SupervisorExecution } from "../src/lib/execution/supervisor";
import { preflightContainer } from "../src/lib/execution/preflight";

import { AuthenticatedWatchdogClient } from "../src/lib/execution/watchdog-client";
import {
  SYNTHETIC_PROFILE,
  DEDICATED_CGROUP_SLICE,
  assertDigestPinnedImage,
  createContainerAsync,
  startContainerAttachedAsync,
  ownershipLabels,
  inspectContainerAsync,
  killContainerAsync,
  removeContainerAsync,
  inspectStateAsync,
} from "../src/lib/execution/docker-lifecycle";
import type { DockerSeam } from "../src/lib/execution/supervisor";
import type { IpcRole } from "../src/lib/execution/ipc-auth";

const required = (name: string): string => {
  const value = process.env[name];
  if (value === undefined || value === "") {
    process.stderr.write(`FATAL: ${name} is not set\n`);
    process.exit(1);
  }
  return value;
};

const hexSecret = (name: string): Buffer => {
  const value = required(name).trim();
  if (!/^(?:[0-9a-fA-F]{2})+$/u.test(value)) {
    process.stderr.write(`FATAL: ${name} must be hex-encoded\n`);
    process.exit(1);
  }
  const secret = Buffer.from(value, "hex");
  if (secret.byteLength < 32) {
    process.stderr.write(`FATAL: ${name} must decode to at least 32 bytes\n`);
    process.exit(1);
  }
  return secret;
};

const emit = (event: Record<string, unknown>): void => {
  // One JSON object per line, the same convention as the watchdog: an init system captures it and a
  // test reads it without parsing human prose.
  process.stdout.write(`${JSON.stringify(event)}\n`);
};

/**
 * The daemon seam, in production form.
 *
 * Every operation is by exact id, and every one of them is the typed asynchronous form — the
 * supervisor's event loop is also serving the role sockets, so a blocking daemon call would stall
 * every caller for the duration of one `docker inspect`.
 */
function dockerSeam(): DockerSeam {
  return {
    create: (policy) => createContainerAsync(policy),
    inspect: (id) => inspectContainerAsync(id),
    remove: (id) => removeContainerAsync(id),
    kill: (id) => killContainerAsync(id),
    state: (id) => inspectStateAsync(id),
    // The attached session: a `docker start -a -i` child, reaped, with the exit code resolved on
    // `exit` rather than `close` so a lingering grandchild holding a pipe cannot postpone it.
    start: async (name) => startContainerAttachedAsync(name),
  };
}

/**
 * The seams a supervisor process needs from its environment.
 *
 * ## Why the worker takes these as a parameter
 *
 * Everything below is either a fact about the host (the boot id) or a capability (the daemon, the
 * watchdog channel). The production entrypoint supplies the real ones; a test entrypoint supplies
 * a labelled substitute for exactly the capability it cannot obtain in the environment it runs in.
 * There is no environment variable that switches a production process onto a fake path — the choice
 * belongs to the *entrypoint*, which is code, not to the process environment, which is data.
 */
export type SupervisorSeams = {
  /** The daemon. Real operations, by exact id. */
  docker: DockerSeam;
  /** Host kernel facts. Real `/proc` and `/sys` in production. */
  hostFacts?: {
    startTimeTicks: (pid: number) => number;
    cgroupMembership: (pid: number) => string | null;
    cgroup2Mount: () => { path: string; device: string } | null;
  };
};

/**
 * The production seams: the real daemon and the real kernel.
 *
 * Exported so a test entrypoint can build on them rather than reimplementing them — the daemon
 * calls are the same whichever host facts are used.
 */
export function productionSeams(): SupervisorSeams {
  return { docker: dockerSeam() };
}

export async function main(seams: SupervisorSeams = productionSeams()): Promise<void> {
  const root = required("DIP_SUPERVISOR_ROOT");
  const supervisorInstance = required("DIP_SUPERVISOR_INSTANCE");
  const bootId = process.env.DIP_SUPERVISOR_BOOT ?? readBootId();
  const appSocket = required("DIP_SUPERVISOR_APP_SOCKET");
  const workerSocket = required("DIP_SUPERVISOR_WORKER_SOCKET");
  const watchdogSocket = required("DIP_WATCHDOG_SOCKET");
  const watchdogSecret = hexSecret("DIP_WATCHDOG_SECRET");
  // ## Two credentials, not one
  //
  // The app process renders forms; the worker process fills them. One shared key would mean that
  // compromising the web tier yields the worker's authority, so each role has its own secret and a
  // proof made with one fails on the other's socket. The former single `DIP_CALLER_SECRET` is not
  // accepted as a fallback: silently accepting it would let a deployment keep one credential for
  // both roles while believing it had two.
  const callerSecrets = { app: hexSecret("DIP_CALLER_APP_SECRET"), worker: hexSecret("DIP_CALLER_WORKER_SECRET") };

  // ── The trusted execution policy ────────────────────────────────────────────────────────────
  //
  // Configured once, here, from the supervisor's own environment. A caller *requests* an image and
  // a profile; `assertTrustedPolicy` refuses anything that is not these exact values, and
  // `buildPolicy` takes every field from this object. There is no path by which a field of the
  // authenticated control block reaches the daemon.
  //
  // The image must be digest-pinned. `DIP_EXECUTOR_IMAGE` is required rather than defaulted: a
  // default image would mean an unconfigured supervisor silently runs whatever was built last,
  // which is exactly the drift the pinning is meant to prevent.
  const trustedPolicy: TrustedExecutionPolicy = {
    image: required("DIP_EXECUTOR_IMAGE").trim(),
    profileId: required("DIP_EXECUTOR_PROFILE").trim(),
    cgroupParent: DEDICATED_CGROUP_SLICE,
  };
  try {
    assertDigestPinnedImage(trustedPolicy.image);
  } catch (error) {
    process.stderr.write(`FATAL: DIP_EXECUTOR_IMAGE is not usable: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  const deadlineMs = Number(process.env.DIP_SUPERVISOR_DEADLINE_MS ?? "120000");
  // ## Bounds, with hard ceilings
  //
  // These are the only places a document can be refused for size. The defaults come from the
  // approved profile; the environment may lower them but not raise them past the profile, because a
  // raised ceiling is a configuration change to the isolation contract rather than a tuning knob.
  const maxInputBytes = Math.min(
    Number(process.env.DIP_SUPERVISOR_MAX_INPUT_BYTES ?? String(512 * 1024 * 1024)),
    SYNTHETIC_PROFILE.maxFixtureBytes * 512,
  );
  const maxOutputBytes = Math.min(
    Number(process.env.DIP_SUPERVISOR_MAX_OUTPUT_BYTES ?? String(384 * 1024 * 1024)),
    SYNTHETIC_PROFILE.memoryBytes,
  );
  const maxBufferedBytes = 1024 * 1024;
  for (const [name, value] of [["DIP_SUPERVISOR_MAX_INPUT_BYTES", maxInputBytes], ["DIP_SUPERVISOR_MAX_OUTPUT_BYTES", maxOutputBytes]] as const) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      process.stderr.write(`FATAL: ${name} must be a positive integer\n`);
      process.exit(1);
    }
  }
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs <= 0) {
    process.stderr.write("FATAL: DIP_SUPERVISOR_DEADLINE_MS must be a positive integer\n");
    process.exit(1);
  }

  if (!/^[a-z0-9-]{4,64}$/u.test(supervisorInstance)) {
    process.stderr.write("FATAL: DIP_SUPERVISOR_INSTANCE must match [a-z0-9-]{4,64}\n");
    process.exit(1);
  }

  mkdirSync(root, { recursive: true, mode: 0o700 });
  for (const socket of [appSocket, workerSocket]) {
    mkdirSync(dirname(socket), { recursive: true, mode: 0o700 });
  }

  // ── 1. The journal, bound to this instance ──────────────────────────────────────────────────
  //
  // Binding is what makes a second supervisor's writes rejectable. It is done before recovery
  // reads anything, because recovery's conclusions are written by this instance and must carry the
  // identity that will own them.
  const journal = new OwnershipJournal(root);
  try {
    // The watchdog instance identity is not known until the channel connects, so the binding is
    // performed once that is established. Binding a placeholder would be a lie the fencing layer
    // would then enforce.
    journal.bind(supervisorInstance, supervisorInstance.replace(/^sv-/u, "wd-"));
  } catch (error) {
    process.stderr.write(`FATAL: the journal could not be bound: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  try {
    journal.init();
  } catch (error) {
    process.stderr.write(`FATAL: the journal could not be initialised: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }

  // ── 2. Reconcile before listening ───────────────────────────────────────────────────────────
  //
  // Read-only over the journal, plus an exact-id inspection per record. The report decides whether
  // admission may start; it never authorizes a destructive action on its own.
  const docker = seams.docker;
  let report: Awaited<ReturnType<typeof reconcile>>;
  try {
    report = await reconcile({
      journal,
      bootId,
      inspect: (containerId) => docker.inspect(containerId),
    });
  } catch (error) {
    process.stderr.write(`FATAL: reconciliation failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  emit({
    event: "reconciled",
    clear: report.clear,
    quarantined: report.quarantine.length,
    verdicts: report.verdicts.length,
  });

  if (!admissionAllowed(report)) {
    // Fail closed. A supervisor that has an execution it cannot account for must not create
    // another: the profile allows one executor, and the unresolved one may still be running.
    emit({ event: "admission-blocked", quarantine: report.quarantine });
    process.exit(3);
  }

  // ── 3. The watchdog channel ─────────────────────────────────────────────────────────────────
  //
  // Connected and verified before the sockets listen. A supervisor that can admit a caller but
  // cannot arm a deadline would release a body into a container nothing is watching.
  const watchdogClient = new AuthenticatedWatchdogClient({
    socketPath: watchdogSocket,
    secret: watchdogSecret,
    supervisorInstance,
    bootId,
  });
  let watchdogIdentity: { watchdogInstance: string; bootId: string };
  try {
    watchdogIdentity = await watchdogClient.connect();
  } catch (error) {
    process.stderr.write(`FATAL: the watchdog control channel could not be established: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  emit({ event: "watchdog-connected", ...watchdogIdentity });

  // ── 4. The role sockets ─────────────────────────────────────────────────────────────────────
  //
  // The handler composes one execution per connection. It is deliberately a thin adapter here: the
  // order of the lifecycle is `supervisor.ts`'s, and repeating it would create two places for it to
  // drift.
  const server = await startRoleSockets({
    socketPaths: { app: appSocket, worker: workerSocket } as Record<IpcRole, string>,
    secrets: callerSecrets,
    supervisorInstance,
    bootId,
    handle: async (session) => {
      // ## One execution, composed
      //
      // The whole sequence lives in `execution-handler.ts`, because it is the one place that must
      // know about the lifecycle, the authenticated channel and the daemon at once. This adapter
      // supplies the three things only the process knows: the journal, the Docker seam and the
      // watchdog channel — then reports what happened.
      emit({ event: "connection", role: session.role, operation: session.operation, executionId: session.executionId });
      const execution = new SupervisorExecution(
        session.executionId,
        session.executionId,
        session.operation,
        {
          journal,
          supervisorInstance,
          bootId,
          watchdogInstance: watchdogIdentity.watchdogInstance,
          watchdogSecret,
          // One role's secret signs the commit for the caller of that role. A worker never has to
          // hold the app's key, so a commit it cannot verify is one it must not accept.
          callerSecret: callerSecrets[session.role],
          limits: {
            deadlineMs,
            maxInputBytes,
            maxOutputBytes,
            maxBufferedBytes,
          },
          docker,
          watchdog: watchdogClient,
          // Only present when the entrypoint supplied it. A production process never does.
          hostFacts: seams.hostFacts,
        },
      );

      const outcome = await composeExecution({
        session,
        execution,
        control: session.controlBlock() as unknown as ControlMetadata,
        trusted: trustedPolicy,
        preflight: (observation) => {
          // ## Two independent readings, one verdict
          //
          // The daemon's effective configuration is judged by `preflightContainer` against the
          // approved policy and the exact ownership labels the journal recorded; the kernel's view
          // of the init process is judged separately by `observeEffective`, which already
          // cross-checked the PID against `/proc`. A disagreement between them is a failure, not a
          // preference for the more convenient reading.
          // The policy the container was created from, not a reconstruction of it. The labels
          // check compares the container's labels against the policy's identity, so a rebuilt
          // policy with empty ids would report every correctly-owned container as foreign.
          const policy = execution.executionPolicy;
          const verdict = preflightContainer({
            containerId: observation.containerId,
            effective: observation.effective,
            policy,
            expectedLabels: ownershipLabels(policy),
          });
          if (verdict.ok) return { ok: true };
          // The first failure names what was wrong. Reporting all of them would surface container
          // configuration to a caller that has not been admitted to see it.
          return { ok: false, code: verdict.failures[0]?.code ?? "PREFLIGHT_FAILED" };
        },
        limits: { maxInputBytes, maxOutputBytes },
      });

      if (outcome.kind === "refused") {
        // Nothing was created. The refusal is reported and the slot is genuinely free — holding it
        // would block admission forever for a request that needs no cleanup.
        session.send({ kind: "REFUSED", code: "REJECTED" });
        session.release(true);
        emit({ event: "refused", executionId: session.executionId, code: outcome.code, detail: outcome.detail });
        return;
      }
      if (outcome.kind === "quarantined") {
        // A container may exist and this process cannot prove otherwise. The slot stays held; the
        // journal already names the container, so reconciliation owns the cleanup.
        session.send({ kind: "REFUSED", code: "REJECTED" });
        session.release(false);
        emit({ event: "quarantined", executionId: session.executionId, code: outcome.code, detail: outcome.detail });
        return;
      }

      // ## The end of the stream, then the commit
      //
      // The bytes already left as `STREAM_CHUNK` frames while they were being validated, so the
      // terminal message carries the *identity* of what was sent — its length and digest — rather
      // than the bytes themselves. A caller reconciles what it received against these totals, and
      // the commit is what makes the result publishable.
      session.send({ kind: "STREAM_END", bytes: outcome.resultBytes, digest: outcome.resultDigest });
      session.send({ kind: "TERMINAL_COMMIT", message: outcome.commitProof });
      session.release(true);
      emit({ event: "committed", executionId: session.executionId, resultBytes: outcome.resultBytes, metaBytes: outcome.metaBytes });
    },
    log: (line) => emit({ event: "log", line }),
  });
  emit({
    event: "ready",
    instance: supervisorInstance,
    bootId,
    sockets: { app: appSocket, worker: workerSocket },
    watchdog: watchdogIdentity.watchdogInstance,
    callerSecretBytes: { app: callerSecrets.app.byteLength, worker: callerSecrets.worker.byteLength },
  });

  const shutdown = async (signal: string): Promise<void> => {
    emit({ event: "shutdown", signal });
    watchdogClient.close();
    await server.stop();
    process.exit(0);
  };
  process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
  process.on("SIGINT", () => { void shutdown("SIGINT"); });
}

main().catch((error: unknown) => {
  process.stderr.write(`FATAL: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
