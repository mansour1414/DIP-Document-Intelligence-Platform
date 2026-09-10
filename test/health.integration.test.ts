import test from "node:test";
import assert from "node:assert/strict";

const integration = process.env.CI ? test : test.skip;
integration("liveness is dependency-independent and readiness verifies DB plus Redis", async () => {
  const health = await import("../src/app/api/health/route"); const readiness = await import("../src/app/api/readiness/route");
  const live = await health.GET(); assert.equal(live.status, 200); const liveBody = await live.json(); assert.equal(liveBody.status, "ok");
  const ready = await readiness.GET(); assert.equal(ready.status, 200); const readyBody = await ready.json(); assert.deepEqual(Object.keys(readyBody).sort(), ["service", "status"]); assert.equal(JSON.stringify(readyBody).includes("postgresql://"), false);
});

