import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import {
  GRAYSCALE_LICENSING_GATE_FLAG,
  INTERNAL_GRAYSCALE_FEATURE_FLAG,
  resolveInternalGrayscaleGate,
} from "../src/lib/grayscale/internal-feature-flag";

test("internal Grayscale gate is off by default", () => {
  assert.deepEqual(resolveInternalGrayscaleGate({}), {
    requested: false,
    licensingApproved: false,
    enabled: false,
    blockedBy: "feature_off",
  });
});

test("internal request cannot bypass the Licensing Gate", () => {
  assert.deepEqual(resolveInternalGrayscaleGate({ [INTERNAL_GRAYSCALE_FEATURE_FLAG]: "true" }), {
    requested: true,
    licensingApproved: false,
    enabled: false,
    blockedBy: "licensing_not_approved",
  });
});

test("internal Grayscale gate requires two exact affirmative values", () => {
  assert.equal(resolveInternalGrayscaleGate({
    [INTERNAL_GRAYSCALE_FEATURE_FLAG]: "true",
    [GRAYSCALE_LICENSING_GATE_FLAG]: "true",
  }).enabled, true);

  for (const value of ["1", "TRUE", "yes", "on", " true "]) {
    assert.equal(resolveInternalGrayscaleGate({
      [INTERNAL_GRAYSCALE_FEATURE_FLAG]: value,
      [GRAYSCALE_LICENSING_GATE_FLAG]: "true",
    }).enabled, false);
  }
});

test("G1-A foundation has no public Registry or worker dispatch exposure", async () => {
  const [config, registry, worker, flagModule] = await Promise.all([
    readFile(new URL("../src/config/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/lib/tools/registry.ts", import.meta.url), "utf8"),
    readFile(new URL("../workers/document-worker.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/lib/grayscale/internal-feature-flag.ts", import.meta.url), "utf8"),
  ]);

  assert.doesNotMatch(config, /["']grayscale-pdf["']/u);
  assert.doesNotMatch(registry, /["']grayscale-pdf["']/u);
  assert.doesNotMatch(worker, /["']grayscale-pdf["']/u);
  assert.doesNotMatch(flagModule, /NEXT_PUBLIC_/u);
});
