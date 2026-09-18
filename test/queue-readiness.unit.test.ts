import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import type Redis from "ioredis";
import { waitForRedisReady } from "../src/lib/queue";

class RedisFixture extends EventEmitter {
  status: "wait" | "connecting" | "ready" | "end" = "wait";
  connectCalls = 0;
  connect() { this.connectCalls += 1; this.status = "connecting"; return Promise.resolve(); }
}

test("concurrent first Redis users share one readiness connection", async () => {
  const fixture = new RedisFixture();
  const first = waitForRedisReady(fixture as unknown as Redis, 1_000); const second = waitForRedisReady(fixture as unknown as Redis, 1_000);
  assert.ok(first); assert.ok(second);
  assert.equal(fixture.connectCalls, 1); let completed = false; void first.then(() => { completed = true; }); await Promise.resolve(); assert.equal(completed, false);
  fixture.status = "ready"; fixture.emit("ready"); await Promise.all([first, second]); assert.equal(completed, true); assert.equal(fixture.connectCalls, 1);
});

test("Redis readiness fails closed when the shared connection errors", async () => {
  const fixture = new RedisFixture(); const readiness = waitForRedisReady(fixture as unknown as Redis, 1_000); const unavailable = new Error("Redis unavailable");
  assert.ok(readiness);
  fixture.emit("error", unavailable); await assert.rejects(readiness, unavailable); assert.equal(fixture.connectCalls, 1);
});
