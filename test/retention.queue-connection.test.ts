import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

/**
 * Connection-hygiene tests for the retention sweep's Redis access.
 *
 * These exercise `openRetentionRedis` against a deliberately unroutable address
 * so they are hermetic: no Redis is required, and nothing is ever sent to a real
 * server. They assert the three properties that matter for a scheduled job:
 *
 *   1. No implicit connection when `REDIS_URL` is absent.
 *   2. Bounded timeouts / finite retries — never an open-ended reconnect loop.
 *   3. Every opened socket is closed, including when planning throws.
 */

const ENV_KEYS = ["REDIS_URL"] as const;

async function withEnv<T>(redisUrl: string | undefined, run: () => Promise<T>): Promise<T> {
  const saved = ENV_KEYS.map((key) => [key, process.env[key]] as const);
  try {
    if (redisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = redisUrl;
    return await run();
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/** 127.0.0.1:1 is reliably closed, so a connection attempt fails fast. */
const UNREACHABLE = "redis://127.0.0.1:1";

test("no connection is opened when REDIS_URL is not configured", async () => {
  const { openRetentionRedis } = await import("../src/lib/retention/queue-connection");
  await withEnv(undefined, async () => {
    const handle = openRetentionRedis();
    try {
      assert.equal(handle.connection, null, "must not fall back to an implicit localhost endpoint");
      assert.equal(handle.unavailable, "not_configured");
    } finally {
      await handle.close();
    }
  });
});

test("an empty REDIS_URL is treated as unconfigured rather than defaulted", async () => {
  const { openRetentionRedis } = await import("../src/lib/retention/queue-connection");
  await withEnv("   ", async () => {
    const handle = openRetentionRedis();
    try {
      assert.equal(handle.connection, null, "blank must not become redis://localhost:6379");
      assert.equal(handle.unavailable, "not_configured");
    } finally {
      await handle.close();
    }
  });
});

/**
 * Strip comments so documentation *about* a bad pattern is not mistaken for the
 * pattern itself. Keeps string literals intact, which is what we assert on.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

test("the source never falls back to an implicit localhost Redis URL", async () => {
  for (const path of ["../src/lib/retention/queue-connection.ts", "../scripts/cleanup-expired-jobs.ts"]) {
    const code = stripComments(await readFile(new URL(path, import.meta.url), "utf8"));
    // The shared queue module does this; the retention path must not.
    assert.equal(/redis:\/\/localhost:6379/.test(code), false, `${path} must not hard-code localhost`);
    assert.equal(/redis:\/\/127\.0\.0\.1:6379/.test(code), false, `${path} must not hard-code loopback`);
  }
});

test("the connection is bounded: finite retries and explicit timeouts", async () => {
  const code = stripComments(await readFile(new URL("../src/lib/retention/queue-connection.ts", import.meta.url), "utf8"));
  // `maxRetriesPerRequest: null` is correct for workers and fatal for a sweep.
  assert.equal(/maxRetriesPerRequest: null/.test(code), false, "must not block forever");
  assert.match(code, /maxRetriesPerRequest: 1/);
  assert.match(code, /retryStrategy: \(\) => null/, "must not reconnect indefinitely");
  assert.match(code, /connectTimeout: CONNECT_TIMEOUT_MS/);
  assert.match(code, /commandTimeout: COMMAND_TIMEOUT_MS/);
  // `lazyConnect` and `enableOfflineQueue: false` are the pair that made every
  // command reject locally; they must stay out (see the trap test below).
  assert.equal(/lazyConnect:\s*true/.test(code), false, "a lazy client cannot issue commands");
  assert.equal(/enableOfflineQueue:\s*false/.test(code), false, "this rejects every command while not yet connected");
});

test("a failed connection is closed and does not keep the process alive", async () => {
  const { openRetentionRedis } = await import("../src/lib/retention/queue-connection");
  await withEnv(UNREACHABLE, async () => {
    const handle = openRetentionRedis();
    assert.ok(handle.connection, "a configured URL should produce a connection object");
    const connection = handle.connection;
    // Bounded teardown: this must not hang even though the server is absent.
    const started = Date.now();
    await handle.close();
    await handle.close(); // idempotent
    assert.ok(Date.now() - started < 5_000, "teardown must be bounded");
    assert.equal(connection.status, "end", "socket must be released");
  });
});

test("closing twice is safe and leaves no open socket", async () => {
  const { openRetentionRedis } = await import("../src/lib/retention/queue-connection");
  await withEnv(UNREACHABLE, async () => {
    const handle = openRetentionRedis();
    await Promise.all([handle.close(), handle.close()]);
    assert.equal(handle.connection?.status, "end");
  });
});

test("the planner releases its provider even when planning throws", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  const planFn = source.slice(source.indexOf("export async function planStalledJobExpiry"), source.indexOf("export async function expireStalledJobs"));
  assert.match(planFn, /try \{/, "planning body must be guarded");
  assert.match(planFn, /finally \{/, "cleanup must be unconditional");
  assert.match(planFn, /if \(ownsProvider\) await provider\.close\(\)\.catch\(\(\) => undefined\)/);
});

// ---------------------------------------------------------------------------
// Redis outage must surface as UNKNOWN, never as absence
// ---------------------------------------------------------------------------

test("an unreachable Redis makes reads incomplete so evidence is unknown", async () => {
  // 127.0.0.1:1 is reliably closed. This is hermetic: no server is contacted.
  const { default: Redis } = await import("ioredis");
  const { createQueueActivityLookup, resolveEvidence } = await import("../src/lib/retention/queue-activity");
  const dead = new Redis("redis://127.0.0.1:1", {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    retryStrategy: () => null,
    connectTimeout: 2_000,
    commandTimeout: 1_500,
    lazyConnect: true,
  });
  dead.on("error", () => undefined);
  try {
    const lookup = createQueueActivityLookup({ redis: dead, queueName: "dip.retention.unreachable", now: () => Date.now() });
    const read = await lookup.read(["some-job"]);
    assert.equal(read.ok, false, "a failed read must be reported as incomplete");
    assert.equal(read.present.size, 0);
    // The crux: a failed read must never be read as "the job is gone".
    assert.deepEqual(resolveEvidence("some-job", [read]), { state: "unknown", reason: "error" });
  } finally {
    dead.disconnect();
  }
});

test("a read that fails part-way marks the whole batch unknown", async () => {
  const { createQueueActivityLookup, resolveEvidence } = await import("../src/lib/retention/queue-activity");
  // First job read succeeds, second throws: the batch must be incomplete, and
  // the successfully-read job still yields presence.
  let call = 0;
  const flaky = {
    async hmget() {
      call += 1;
      if (call === 1) return ["1700000000000", null, null];
      throw new Error("connection reset");
    },
    async exists() {
      return 0;
    },
  };
  const lookup = createQueueActivityLookup({ redis: flaky, queueName: "dip.retention.flaky", now: () => Date.now() });
  const read = await lookup.read(["known", "broken"]);
  assert.equal(read.ok, false, "a partial failure must mark the read incomplete");
  assert.ok(read.present.has("known"), "evidence gathered before the failure is kept");
  assert.equal(read.present.has("broken"), false);
  assert.equal(resolveEvidence("broken", [read]).state, "unknown");
});

// ---------------------------------------------------------------------------
// The documented trap: lazyConnect + enableOfflineQueue:false rejects EVERY
// command, which would make the sweep silently inert.
// ---------------------------------------------------------------------------

test("a new connection is not pre-rejected before it reaches the server", async () => {
  // Regression for a real bug in an earlier revision of this PR: ioredis rejects
  // every command with "Stream isn't writeable and enableOfflineQueue options is
  // false" while a lazy client sits in status `wait`. Every read would fail, every
  // job would be UNKNOWN, and the sweep would silently never expire anything.
  const { openRetentionRedis } = await import("../src/lib/retention/queue-connection");
  await withEnv(UNREACHABLE, async () => {
    const handle = openRetentionRedis();
    try {
      const connection = handle.connection!;
      // The specific failure mode must not occur. A genuine connectivity error is
      // acceptable; a local precondition rejection is not, because it would also
      // happen against a perfectly healthy server.
      const failure = await connection.ping().then(() => "", (error: Error) => error.message);
      assert.equal(
        /Stream isn't writeable and enableOfflineQueue/i.test(failure),
        false,
        "commands must reach the socket, not be rejected locally",
      );
    } finally {
      await handle.close();
    }
  });
});

test("the connection is not left in the inert `wait` state", async () => {
  const { openRetentionRedis } = await import("../src/lib/retention/queue-connection");
  await withEnv(UNREACHABLE, async () => {
    const handle = openRetentionRedis();
    try {
      // `wait` is the lazy state that causes the rejection; an eager client is
      // `connecting`/`connect`/`reconnecting` immediately after construction.
      assert.notEqual(handle.connection!.status, "wait", "a lazy client would never issue a command");
    } finally {
      await handle.close();
    }
  });
});

// ---------------------------------------------------------------------------
// End-to-end read through the real connection factory
// ---------------------------------------------------------------------------

/**
 * Minimal RESP server: answers `INFO` (ioredis calls it on connect), `HMGET`
 * with nulls and `EXISTS` with 0. Enough to prove the real connection factory
 * can actually issue commands, which the previous `lazyConnect` configuration
 * could not.
 */
async function withFakeServer<T>(run: (url: string) => Promise<T>): Promise<T> {
  const { createServer } = await import("node:net");
  const server = createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      for (;;) {
        if (!buffer.startsWith("*")) break;
        const headerEnd = buffer.indexOf("\r\n");
        if (headerEnd < 0) break;
        const argc = Number(buffer.slice(1, headerEnd));
        let cursor = headerEnd + 2;
        const args: string[] = [];
        let complete = true;
        for (let index = 0; index < argc; index += 1) {
          const end = buffer.indexOf("\r\n", cursor);
          if (end < 0) { complete = false; break; }
          const size = Number(buffer.slice(cursor + 1, end));
          if (buffer.length < end + 2 + size + 2) { complete = false; break; }
          args.push(buffer.slice(end + 2, end + 2 + size));
          cursor = end + 2 + size + 2;
        }
        if (!complete) break;
        buffer = buffer.slice(cursor);
        const command = (args[0] ?? "").toUpperCase();
        if (command === "INFO") {
          const payload = "# Server\r\nredis_version:7.2.0\r\n";
          socket.write(`$${Buffer.byteLength(payload)}\r\n${payload}\r\n`);
        } else if (command === "PING") {
          socket.write("+PONG\r\n");
        } else if (command === "HMGET") {
          socket.write("*3\r\n$-1\r\n$-1\r\n$-1\r\n");
        } else if (command === "EXISTS") {
          socket.write(":0\r\n");
        } else {
          socket.write("+OK\r\n");
        }
      }
    });
    socket.on("error", () => undefined);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  try {
    return await run(`redis://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("the real connection factory issues commands against a live server", async () => {
  const { openRetentionRedis } = await import("../src/lib/retention/queue-connection");
  const { createQueueActivityLookup, resolveEvidence } = await import("../src/lib/retention/queue-activity");
  await withFakeServer(async (url) => {
    await withEnv(url, async () => {
      const handle = openRetentionRedis();
      assert.ok(handle.connection, "a configured URL must produce a connection");
      try {
        // The exact call the sweep makes, through the exact factory it uses.
        const lookup = createQueueActivityLookup({
          redis: handle.connection,
          queueName: "dip.document-processing.v1",
          now: () => Date.now(),
        });
        const read = await lookup.read(["some-job"]);
        // This is the assertion that would have failed with the old settings:
        // the read must reach the server and come back successful.
        assert.equal(read.ok, true, "the read must reach the server, not be rejected locally");
        assert.equal(read.present.size, 0);
        assert.deepEqual(resolveEvidence("some-job", [read], 1), { state: "absent" });
      } finally {
        await handle.close();
      }
    });
  });
});
