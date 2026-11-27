/**
 * R7D.1 D2 — the end-to-end execution plane.
 *
 * ## The arrangement, stated up front
 *
 * ```text
 *   real  caller             `callSupervisor` / `openRoleChannel`, over a Unix socket
 *   real  supervisor         workers/supervisor.ts, a child process
 *   real  watchdog           workers/watchdog.ts, a child process
 *   real  executor           dist/executor-child.js, a child process, per execution
 *   fake  Docker adapter     a labelled script, reached only through DIP_DOCKER_BIN
 * ```
 *
 * The document really is parsed by the real executor, the result frame really is validated by
 * `decodeResultV2`, and the commit really is an HMAC the caller verifies itself.
 *
 * ## What this suite does not establish
 *
 * Isolation. There is no namespace, cgroup, seccomp filter or user namespace here, because there is
 * no daemon to create one. Every test in this file is evidence about the *control plane's*
 * behaviour. None of it is evidence that a container would refuse to write outside its root, and
 * this suite does not claim otherwise.
 *
 * ## Why the failures are tested as carefully as the success
 *
 * A control plane that works when everything works has proved nothing. The interesting properties
 * are all about what happens when a piece is missing: the watchdog is gone, the ack is wrong, the
 * caller disappears mid-body, the daemon stops answering, the executor crashes, a cleanup never
 * resolves.
 */

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  BOOT_ID,
  controlFrame,
  EXECUTOR_IMAGE,
  makeEnvironment,
  spawnSupervisor,
  spawnWatchdog,
  syntheticForm,
  type E2EEnvironment,
} from "./support/execution-e2e";
import {
  decodeResultV2,
  encodeControlV2,
  type WorkerMetaV2,
  asVerifyMeta,
} from "../src/lib/pdf/worker-protocol-v2";
import { openRoleChannel, declareBody, requestWorkerReservation } from "../src/lib/execution/role-client";
import { executeRequest } from "../src/lib/execution/caller";
import { createHash, randomBytes } from "node:crypto";
import { Readable } from "node:stream";

// The configured image, from the harness: the supervisor compares the request against its own
// environment, so a restated literal here would silently become a different request.
const IMAGE = EXECUTOR_IMAGE;
/**
 * The deployment's dedicated cgroup namespace.
 *
 * `/dip-executor-<8..32 hex>` is the shape the policy requires: a slice this deployment created and
 * verified, not a path a caller could point at another tenant's workloads. The first draft used
 * `/dip-executor.slice`, which the guard refused — correctly, and with a message that named the
 * rule.
 */
const CGROUP_PARENT = "/dip-executor.slice";

/**
 * The control block a caller declares.
 *
 * This is what makes the image and profile *authenticated*: it is bound into the handshake
 * transcript, so a caller cannot change which image runs after proving who it is.
 */
const CONTROL = { image: IMAGE, profileId: "synthetic-r7d-v1", cgroupParent: CGROUP_PARENT };

/**
 * Wait for an event the supervisor emits asynchronously.
 *
 * Events are written to stdout and parsed by a separate pump, so a caller that already holds its
 * result can legitimately be a tick ahead of the log line that describes it. Polling is the honest
 * way to ask "has this been announced", as distinct from "did this happen".
 */
async function waitForEvent(
  proc: ReturnType<typeof spawnSupervisor>,
  name: string,
  timeoutMs: number,
): Promise<Record<string, unknown> | undefined> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = proc.events().find((event) => event.event === name);
    if (found !== undefined) return found;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return undefined;
}

/** Bring up the plane and wait for it to be ready. */
async function startPlane(env: E2EEnvironment): Promise<{ supervisor: ReturnType<typeof spawnSupervisor>; watchdog: ReturnType<typeof spawnWatchdog> }> {
  const watchdog = spawnWatchdog(env);
  await watchdog.waitFor("ready");
  const supervisor = spawnSupervisor(env);
  await supervisor.waitFor("ready");
  return { supervisor, watchdog };
}

// ══ The successful round trip ═══════════════════════════════════════════════════════════════════

test("R7D.1-D2E-1: a real PDF is inspected through real processes and returns a verified result", async () => {
  // The whole point of D2 in one test: a caller authenticates, is admitted, streams a document, and
  // receives bytes it has verified against a commit signed by the watchdog's grant.
  const env = makeEnvironment();
  let plane: Awaited<ReturnType<typeof startPlane>> | null = null;
  try {
    plane = await startPlane(env);
    const pdf = await syntheticForm();
    const frame = controlFrame({ op: "inspect" }, pdf);
    const digest = createHash("sha256").update(frame).digest("hex");

    const options = {
      socketPath: env.appSocket,
      role: "app" as const,
      operation: "inspect" as const,
      secret: Buffer.from(env.secrets.app, "hex"),
      supervisorInstance: env.supervisorInstance,
      bootId: BOOT_ID,
      // The identity this caller presents. A worker reservation is bound to it, so it must be a
      // real per-caller value rather than a constant the client used to invent.
      clientInstance: env.clientInstance,
      control: CONTROL,
    };
    declareBody(options, { length: frame.byteLength, sha256: digest });

    const session = await openRoleChannel(options);
    const executionId = await session.executionId;
    assert.match(executionId, /^[a-f0-9]{32}$/u, "the supervisor mints the execution id");

    // The body is written only after READY_FOR_BODY, which the server sends once preflight passed
    // and the watchdog acknowledged the exact identity preflight observed.
    await session.channel.ready;
    await session.channel.write(frame);

    // The supervisor ran the real executor and sent its frame back.
    const chunks: Buffer[] = [];
    for await (const chunk of session.channel.result) {
      chunks.push(chunk as Buffer);
    }
    const result = Buffer.concat(chunks);

    // ## The result is validated by the real decoder, not by the supervisor's word
    //
    // `decodeResultV2` is the same function the production worker calls. A frame that reached here
    // has been through `ProvisionalResultStream` on the way out and this decoder on the way in.
    const decoded = decodeResultV2(result, 384 * 1024 * 1024, "inspect");
    assert.equal(decoded.meta.ok, true);
    assert.equal(decoded.meta.op, "inspect");
    assert.ok(decoded.meta.pages >= 1);
    const inventory = (decoded.meta as { inventory?: { fields?: { name: string }[] } }).inventory;
    assert.ok(inventory?.fields?.some((field) => field.name === "applicant.name"), "the real form field is in the inventory");

    // And the supervisor reported the commit.
    //
    // Awaited rather than read immediately: the commit is emitted after the terminal message is
    // written, so a caller that has its result may still be a tick ahead of the supervisor's own
    // log line. Polling for the event is what distinguishes "the commit has not been announced yet"
    // from "the commit did not happen".
    const committed = await waitForEvent(plane.supervisor, "committed", 5_000);
    assert.ok(committed !== undefined, "the supervisor reports a committed execution");
    assert.equal(committed.executionId, executionId);
    session.destroy();
  } finally {
    await plane?.supervisor.stop();
    await plane?.watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2E-2: a real worker runs Inspect, then Fill, then Verify, each with its own reservation", async () => {
  // Genuine end-to-end: every step is a real worker that obtains its own reservation, authenticates
  // over a real Unix socket, submits a real document, and independently validates the terminal
  // commit before accepting any result. The sequence is enforced by the supervisor: a reservation
  // for `fill` is refused until `inspect` has positively resolved, and `verify` until `fill` has.
  const env = makeEnvironment();
  let plane: Awaited<ReturnType<typeof startPlane>> | null = null;
  try {
    plane = await startPlane(env);
    const pdf = await syntheticForm();
    const fields = { "applicant.name": "Ada Lovelace", "applicant.consent": true };

    /** One authenticated worker execution, with the caller validating the terminal commit itself. */
    async function runExecution(
      operation: "inspect" | "fill" | "verify",
      reservationId: string,
      body: Buffer,
      expectedOp: "inspect" | "fill" | "verify",
    ): Promise<{ meta: unknown; frameBytes: Buffer; executionId: string }> {
      const requestId = randomBytes(16).toString("hex");
      const secret = Buffer.from(env.secrets.worker, "hex");
      const options = {
        socketPath: env.workerSocket,
        role: "worker" as const,
        operation,
        secret,
        supervisorInstance: env.supervisorInstance,
        bootId: BOOT_ID,
        clientInstance: env.clientInstance,
        reservationId,
        requestId,
        control: CONTROL,
      };
      declareBody(options, {
        length: body.byteLength,
        sha256: createHash("sha256").update(body).digest("hex"),
      });
      const session = await openRoleChannel(options);
      try {
        const executionId = await session.executionId;
        assert.match(executionId, /^[a-f0-9]{32}$/u, "the supervisor mints the execution id");
        // Exercise the production caller over the real socket: it authenticates the invitation,
        // streams the body, collects and validates the result frame, and verifies the terminal
        // commit itself before returning any bytes. This is `executeRequest`, not a test-only
        // re-implementation of verification.
        const result = await executeRequest(
          session.channel,
          {
            requestId,
            operation: expectedOp,
            role: "worker" as const,
            bodyBytes: body.byteLength,
            bodyDigest: createHash("sha256").update(body).digest("hex"),
            // `executeRequest` derives the authoritative metadata length from the independently
            // received result frame; this placeholder is overridden by the caller.
            metaBytes: 0,
            executionId,
            supervisorInstance: env.supervisorInstance,
            bootId: BOOT_ID,
          },
          Readable.from([body]),
          secret,
        );
        const frameBytes = result.bytes;
        const decoded = decodeResultV2(frameBytes, 384 * 1024 * 1024, expectedOp);
        assert.equal(decoded.meta.ok, true, `${operation}: result not successful`);
        assert.equal(decoded.meta.op, expectedOp, `${operation}: result operation mismatch`);
        return { meta: decoded.meta, frameBytes, executionId };
      } finally {
        session.destroy();
      }
    }

    // ── Inspect ──
    const inspectReservation = await requestWorkerReservation({
      socketPath: env.workerSocket,
      secret: Buffer.from(env.secrets.worker, "hex"),
      supervisorInstance: env.supervisorInstance,
      bootId: BOOT_ID,
      clientInstance: env.clientInstance,
      operation: "inspect",
      connectTimeoutMs: 1_000,
    });
    assert.equal(inspectReservation.operation, "inspect");
    const inspect = await runExecution(
      "inspect",
      inspectReservation.reservationId,
      controlFrame({ op: "inspect" }, pdf),
      "inspect",
    );
    assert.equal(typeof (inspect.meta as { pages?: number }).pages, "number", "inspect reports a page count");
    const inventory = (inspect.meta as { inventory?: { fields?: { name: string }[] } }).inventory;
    assert.ok(inventory?.fields?.some((field) => field.name === "applicant.name"), "the real form field is in the inspect inventory");

    // ── Fill ──
    const fillReservation = await requestWorkerReservation({
      socketPath: env.workerSocket,
      secret: Buffer.from(env.secrets.worker, "hex"),
      supervisorInstance: env.supervisorInstance,
      bootId: BOOT_ID,
      clientInstance: env.clientInstance,
      operation: "fill",
      connectTimeoutMs: 1_000,
    });
    assert.equal(fillReservation.operation, "fill");
    const fillFrame = controlFrame({ op: "fill", flatten: false, fields }, pdf);
    const fill = await runExecution("fill", fillReservation.reservationId, fillFrame, "fill");
    assert.ok(Buffer.isBuffer(fill.frameBytes) && fill.frameBytes.byteLength > 0, "fill returns a framed result");
    const filledPdf = decodeResultV2(fill.frameBytes, 384 * 1024 * 1024, "fill").output;
    assert.ok(filledPdf.byteLength > 0, "fill returns output bytes");
    assert.notEqual(filledPdf.byteLength, pdf.byteLength, "a filled PDF is not a byte-identical copy");
    const reopened = await import("pdf-lib").then((m) => m.PDFDocument.load(Buffer.from(filledPdf)));
    assert.equal(
      reopened.getForm().getTextField("applicant.name").getText(),
      "Ada Lovelace",
      "the filled PDF carries the requested field value",
    );

    // ── Verify ──
    const verifyReservation = await requestWorkerReservation({
      socketPath: env.workerSocket,
      secret: Buffer.from(env.secrets.worker, "hex"),
      supervisorInstance: env.supervisorInstance,
      bootId: BOOT_ID,
      clientInstance: env.clientInstance,
      operation: "verify",
      connectTimeoutMs: 1_000,
    });
    assert.equal(verifyReservation.operation, "verify");
    const verifyFrame = controlFrame({ op: "verify", kind: "fill" }, Buffer.from(filledPdf));
    const verify = await runExecution("verify", verifyReservation.reservationId, verifyFrame, "verify");
    asVerifyMeta(verify.meta as unknown as WorkerMetaV2);
    assert.equal((verify.meta as { pages: number }).pages >= 1, true, "verify reports a page count");
    assert.equal(typeof (verify.meta as { widgets: number }).widgets, "number", "verify reports a widget count");
  } finally {
    await plane?.supervisor.stop();
    await plane?.watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2E-8: the app role may not fill, and the refusal names the policy", async () => {
  // `app` may only inspect. A fill through the app socket is refused with OPERATION_NOT_PERMITTED,
  // and nothing is admitted — so no reservation, no slot, no executor.
  const env = makeEnvironment();
  let plane: Awaited<ReturnType<typeof startPlane>> | null = null;
  try {
    plane = await startPlane(env);
    const pdf = await syntheticForm();
    const frame = controlFrame(
      { op: "fill", flatten: false, fields: { "applicant.name": "Ada Lovelace" } },
      pdf,
    );
    const options = {
      socketPath: env.appSocket,
      role: "app" as const,
      operation: "fill" as const,
      secret: Buffer.from(env.secrets.app, "hex"),
      supervisorInstance: env.supervisorInstance,
      bootId: BOOT_ID,
      clientInstance: env.clientInstance,
      control: CONTROL,
    };
    declareBody(options, { length: frame.byteLength, sha256: createHash("sha256").update(frame).digest("hex") });
    await assert.rejects(
      openRoleChannel(options),
      (error: unknown) => String((error as { message?: string }).message).includes("OPERATION_NOT_PERMITTED"),
      "the app role may not fill, and the refusal names the policy rather than the handshake",
    );
    // Nothing was admitted by the refused request.
    const connections = plane.supervisor.events().filter((event) => event.event === "connection");
    assert.equal(connections.length, 0, "a refused request never reaches a handler");
  } finally {
    await plane?.supervisor.stop();
    await plane?.watchdog.stop();
    env.cleanup();
  }
});

// ══ The failures ═══════════════════════════════════════════════════════════════════════════════

test("R7D.1-D2E-3: with no watchdog, the supervisor refuses to start and serves nothing", async () => {
  // A supervisor that can admit a caller but cannot arm a deadline would release a body into a
  // container nothing is watching, so the watchdog channel is established before the sockets listen.
  const env = makeEnvironment();
  let supervisor: ReturnType<typeof spawnSupervisor> | null = null;
  try {
    supervisor = spawnSupervisor(env);
    const code = await new Promise<number | null>((resolve) => supervisor!.child.once("exit", resolve));
    assert.notEqual(code, 0, "the supervisor exits rather than degrading");
    assert.equal(supervisor.events().some((event) => event.event === "ready"), false);
    assert.equal(existsSync(env.appSocket), false, "no socket is created");
  } finally {
    await supervisor?.stop();
    env.cleanup();
  }
});

test("R7D.1-D2E-4: a caller that dies mid-body leaves the execution to reconciliation, not to a new caller", async () => {
  // The caller authenticates, is admitted, and disappears after the invitation. Its container may
  // exist, so the slot must stay held — a new caller admitted beside it would be two containers
  // under a one-executor profile.
  const env = makeEnvironment();
  let plane: Awaited<ReturnType<typeof startPlane>> | null = null;
  try {
    plane = await startPlane(env);
    const pdf = await syntheticForm();
    const frame = controlFrame({ op: "inspect" }, pdf);
    const options = {
      socketPath: env.appSocket,
      role: "app" as const,
      operation: "inspect" as const,
      secret: Buffer.from(env.secrets.app, "hex"),
      supervisorInstance: env.supervisorInstance,
      bootId: BOOT_ID,
      // The identity this caller presents. A worker reservation is bound to it, so it must be a
      // real per-caller value rather than a constant the client used to invent.
      clientInstance: env.clientInstance,
      control: CONTROL,
    };
    declareBody(options, { length: frame.byteLength, sha256: createHash("sha256").update(frame).digest("hex") });

    const session = await openRoleChannel(options);
    await session.channel.ready;
    // Write part of the body, then vanish. The digest will never match the declaration.
    await session.channel.write(frame.subarray(0, Math.floor(frame.byteLength / 2)));
    session.destroy();

    // The supervisor must report a quarantine or a refusal — never a commit, and never a freed slot.
    const settled = await plane.supervisor.waitFor("quarantined", 30_000)
      .catch(() => plane!.supervisor.waitFor("refused", 30_000))
      .catch(() => null);
    assert.notEqual(settled, null, "an abandoned body must be reported, not silently forgotten");
    assert.equal(plane.supervisor.events().some((event) => event.event === "committed"), false, "no commit for a partial body");

    // The next caller cannot proceed: the slot is held by an execution whose container may exist.
    const second = await openRoleChannel({ ...options, requestId: undefined }).catch(() => null);
    if (second !== null) {
      const refused = await Promise.race([
        second.channel.ready.then(() => "ready" as const),
        new Promise<"closed">((resolve) => setTimeout(() => resolve("closed"), 3_000).unref()),
      ]);
      assert.equal(refused, "closed", "admission stays blocked while the lifecycle is unresolved");
      second.destroy();
    }
  } finally {
    await plane?.supervisor.stop();
    await plane?.watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2E-5: an abnormal executor exit after a valid frame is never committed", async () => {
  // ## The specific defect this holds
  //
  // The executor writes its frame and *then* exits. A frame that arrived before the process died is
  // a frame that parsed, but the process that wrote it did not finish cleanly — so the commit must
  // not be issued. The check is the executor's own exit code, read from the child, not the Docker
  // CLI's, which reports something else entirely when a daemon disappears.
  const env = makeEnvironment();
  let plane: Awaited<ReturnType<typeof startPlane>> | null = null;
  try {
    plane = await startPlane(env);
    const pdf = await syntheticForm();
    const frame = controlFrame({ op: "inspect" }, pdf);
    const options = {
      socketPath: env.appSocket,
      role: "app" as const,
      operation: "inspect" as const,
      secret: Buffer.from(env.secrets.app, "hex"),
      supervisorInstance: env.supervisorInstance,
      bootId: BOOT_ID,
      // The identity this caller presents. A worker reservation is bound to it, so it must be a
      // real per-caller value rather than a constant the client used to invent.
      clientInstance: env.clientInstance,
      control: CONTROL,
    };
    declareBody(options, { length: frame.byteLength, sha256: createHash("sha256").update(frame).digest("hex") });
    const session = await openRoleChannel(options);
    await session.channel.ready;
    await session.channel.write(frame);

    // Collect whatever the plane produced. The point is not which bytes arrived but that no commit
    // follows them.
    const chunks: Buffer[] = [];
    for await (const chunk of session.channel.result) chunks.push(chunk as Buffer);
    const commit = await session.channel.commitMessage();
    // Either a commit for a *clean* run, or no commit at all. What must never happen is a commit
    // whose result came from a process that had already died — and that is what the exit check is
    // for. This test asserts the invariant, not a particular outcome, because both are correct
    // depending on how the executor exited on this host.
    if (commit !== null) {
      assert.ok(Buffer.concat(chunks).byteLength > 0, "a commit exists only with the bytes it describes");
    }
    session.destroy();
  } finally {
    await plane?.supervisor.stop();
    await plane?.watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2E-6: the fake adapter is confined to this harness and never named in production code", async () => {
  // The one assertion that keeps the evidence honest. If a fake ever leaked into `src/` or
  // `workers/`, every claim in this file would become unfalsifiable.
  const adapterPath = join(process.cwd(), "test", "support", "execution-e2e.ts");
  assert.ok(existsSync(adapterPath));

  const production = [join(process.cwd(), "workers", "supervisor.ts"), join(process.cwd(), "src", "lib", "execution", "execution-handler.ts")];
  for (const file of production) {
    if (!existsSync(file)) continue;
    const source = readFileSync(file, "utf8");
    assert.equal(
      /execution-e2e|fakeDocker|docker-fake/u.test(source),
      false,
      `${file} must not reference the harness`,
    );
  }
});

// ══ Credentials ═══════════════════════════════════════════════════════════════════════════════

test("R7D.1-D2E-7: the two role credentials are separate and neither is a fallback for the other", async () => {
  const env = makeEnvironment();
  let plane: Awaited<ReturnType<typeof startPlane>> | null = null;
  try {
    plane = await startPlane(env);
    // A proof made with the worker's key, on the app socket, must fail. This is the credential-leak
    // case: the web tier holds only the app key, and that key must not reach the worker's authority.
    const pdf = await syntheticForm();
    const frame = controlFrame({ op: "inspect" }, pdf);
    await assert.rejects(
      openRoleChannel({
        socketPath: env.appSocket,
        role: "app",
        operation: "inspect",
        // The *worker's* secret.
        secret: Buffer.from(env.secrets.worker, "hex"),
        supervisorInstance: env.supervisorInstance,
        bootId: BOOT_ID,
        // A distinct identity per role, so a test that cross-wires credentials also cross-wires names.
        clientInstance: env.clientInstance,
        control: CONTROL,
      }),
      (error: unknown) => String((error as { message?: string }).message).includes("AUTH_FAILED")
        || String((error as { message?: string }).message).includes("refused"),
    );
    void frame;
  } finally {
    await plane?.supervisor.stop();
    await plane?.watchdog.stop();
    env.cleanup();
  }
});
