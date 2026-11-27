/** R7D.1 Phase B — bounded real-socket worker reservation exchange.

This suite exercises `requestWorkerReservation` against a real `startRoleSockets` server over a
real Unix socket, through the full authenticated exchange:

  connect → HELLO → CHALLENGE → AUTH → AUTH_OK → RESERVED → promise settled → socket closed.

Every wait is bounded by an overall exchange deadline (not merely a connect timeout). This is the
smallest deterministic reproduction of the worker reservation hang/OOM.
*/

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { startRoleSockets } from "../src/lib/execution/role-sockets";
import { requestWorkerReservation } from "../src/lib/execution/role-client";
import type { IpcRole } from "../src/lib/execution/ipc-auth";

const SECRET = Buffer.from(
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "hex",
);
const INSTANCE = "repro-instance";
const BOOT_ID = "repro-boot-id-0000000000000000";
const CLIENT = "worker-repro";
const EXCHANGE_MS = 5_000;

let dir: string;
let workerSocket: string;

before(() => {
  dir = mkdtempSync(join(tmpdir(), "dip-res-repro-"));
  workerSocket = join(dir, "worker.sock");
});

after(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Race the exchange against a hard overall deadline so a hang always surfaces as a failure. */
async function withDeadline<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | null = null;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`reservation exchange deadline exceeded: ${what}`)),
      ms,
    );
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

async function startRoleServer(socketPath: string): Promise<{ stop: () => Promise<void> }> {
  const server = await startRoleSockets({
    socketPaths: { worker: socketPath } as Record<IpcRole, string>,
    secrets: { worker: SECRET } as Record<IpcRole, Buffer>,
    supervisorInstance: INSTANCE,
    bootId: BOOT_ID,
    // A reservation request is answered before admission, so the handler never runs here.
    handle: async () => {
      throw new Error("reservation exchange must not reach admission");
    },
    reservationTtlMs: 30_000,
    reservationIdleMs: 10_000,
    maxReservationsPerCaller: 2,
  });
  return { stop: () => server.stop() };
}

function encodeFrame(message: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(message), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return Buffer.concat([header, json]);
}

describe("R7D.1-RESX — real-socket reservation exchange", () => {
  it("completes the full authenticated exchange and settles before the deadline", async () => {
    const server = await startRoleServer(workerSocket);
    try {
      const reservation = await withDeadline(
        requestWorkerReservation({
          socketPath: workerSocket,
          secret: SECRET,
          supervisorInstance: INSTANCE,
          bootId: BOOT_ID,
          clientInstance: CLIENT,
          operation: "inspect",
          connectTimeoutMs: 1_000,
        }),
        EXCHANGE_MS,
        "inspect reservation",
      );
      assert.equal(typeof reservation.reservationId, "string");
      assert.equal(reservation.reservationId.length > 0, true);
      assert.equal(reservation.operation, "inspect");
      assert.equal(typeof reservation.expiresAt, "number");
      assert.equal(typeof reservation.idleExpiresAt, "number");
    } finally {
      await server.stop();
    }
  });

  it("refuses an out-of-sequence operation with RESERVATION_REFUSED before the deadline", async () => {
    const server = await startRoleServer(workerSocket);
    try {
      await assert.rejects(
        withDeadline(
          requestWorkerReservation({
            socketPath: workerSocket,
            secret: SECRET,
            supervisorInstance: INSTANCE,
            bootId: BOOT_ID,
            clientInstance: CLIENT,
            operation: "fill", // a worker may not begin at fill
            connectTimeoutMs: 1_000,
          }),
          EXCHANGE_MS,
          "fill reservation (out of sequence)",
        ),
        /the supervisor refused a reservation: OUT_OF_SEQUENCE/,
      );
    } finally {
      await server.stop();
    }
  });

  it("fails closed when the peer answers the challenge then goes silent, bounded by the deadline", async () => {
    const silentDir = mkdtempSync(join(tmpdir(), "dip-res-silent-"));
    const silentSocket = join(silentDir, "worker.sock");
    try {
      const { createServer } = await import("node:net");
      const server = createServer((socket) => {
        socket.on("data", (chunk) => {
          const json = chunk.subarray(4).toString("utf8");
          let message: { kind?: string; clientNonce?: string };
          try { message = JSON.parse(json); } catch { return; }
          if (message.kind === "HELLO") {
            // Answer CHALLENGE, then deliberately never send AUTH_OK or RESERVED.
            socket.write(
              encodeFrame({
                kind: "CHALLENGE",
                serverNonce: "ab".repeat(32),
                clientNonce: message.clientNonce,
                supervisorInstance: INSTANCE,
                bootId: BOOT_ID,
                protocolVersion: 1,
              }),
            );
          }
        });
        socket.on("error", () => {});
      });
      await new Promise<void>((resolve) => server.listen(silentSocket, resolve));
      try {
        await withDeadline(
          requestWorkerReservation({
            socketPath: silentSocket,
            secret: SECRET,
            supervisorInstance: INSTANCE,
            bootId: BOOT_ID,
            clientInstance: CLIENT,
            operation: "inspect",
            connectTimeoutMs: 1_000,
          }),
          EXCHANGE_MS,
          "silent peer after challenge",
        );
        assert.fail("expected the exchange to fail on a silent peer");
      } catch (error) {
        assert.ok(
          /deadline exceeded|TRANSPORT_CLOSED|NOT_READY/.test(String(error)),
          String(error),
        );
      } finally {
        server.close();
      }
    } finally {
      rmSync(silentDir, { recursive: true, force: true });
    }
  });
});
