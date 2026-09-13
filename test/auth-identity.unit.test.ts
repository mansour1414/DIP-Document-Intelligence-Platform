import assert from "node:assert/strict";
import test from "node:test";
import { normalizeAuthEmail } from "../src/lib/auth/identity";

test("auth identity normalization is deterministic and rejects malformed values", () => {
  assert.equal(normalizeAuthEmail(" Person@Example.TEST "), "person@example.test");
  for (const value of ["", "invalid", "a@b", "x".repeat(256) + "@example.test", null]) {
    assert.throws(() => normalizeAuthEmail(value), /Authentication email is invalid/);
  }
});
