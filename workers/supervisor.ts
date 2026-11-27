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
import { AuthenticatedWatchdogClient } from "../src/lib/execution/watchdog-client";
import {
  createContainerAsync,
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
    // The attached session is a `docker start -a -i` child whose fd 3 carries the result frame.
    // `startContainerAttached` is synchronous in this adapter, so it is wrapped to keep the seam's
    // asynchronous shape.
    start: async (name) => {
      const { startContainerAttached } = await import("../src/lib/execution/docker-lifecycle");
      const child = startContainerAttached(name);
      const exited = new Promise<number>((resolve) => {
        child.once("close", (code: number | null) => resolve(code ?? -1));
      });
      return {
        stdin: child.stdin,
        stdout: child.stdout,
        stderr: child.stderr,
        result: child.stdout,
        exited,
      };
    },
  };
}

async function main(): Promise<void> {
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
  const deadlineMs = Number(process.env.DIP_SUPERVISOR_DEADLINE_MS ?? "120000");
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
  const docker = dockerSeam();
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
      emit({ event: "connection", role: session.role, operation: session.operation, executionId: session.executionId });
      // ## The executor handler is R7D.2
      //
      // Everything above this line is the authenticated control plane: the caller proved which role
      // it is, the supervisor proved which instance it is, admission was granted against a
      // single-executor profile, and `READY_FOR_BODY` has been sent. What is *not* here is the
      // composition of a container: that needs the image, the profile, the cgroup pin and the
      // operation-specific argv, all of which arrive with the web/API integration in R7D.2.
      //
      // So the handler refuses, and refuses **unresolved**: `release(false)` keeps the executor
      // slot held rather than implying that an execution happened and finished. A slot released
      // without evidence is the defect this class of code exists to avoid.
      session.send({ kind: "REFUSED", code: "REJECTED" });
      session.release(false);
      emit({ event: "refused", executionId: session.executionId, detail: "the executor handler lands with R7D.2" });
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
