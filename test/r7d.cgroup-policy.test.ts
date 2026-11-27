/**
 * The shared cgroup policy: driver, subtree, and the layout each driver produces (R7D.1 final).
 *
 * ## Why this file exists
 *
 * The layout was wrong in one place and right in none. `cgroupParentFor(driver)` ignored its
 * argument, the watchdog compared against a flat literal, and three files each carried their own
 * copy of `"dip-executor.slice"`. Every copy agreed with itself, so nothing failed — until a real
 * systemd host would have refused every arm, because systemd nests a dash-named slice under its
 * parent slice and the code expected it at the root.
 *
 * These tests assert the derivation directly. They are arithmetic on a string, deliberately: the
 * rule comes from `systemd.slice(5)`, and the point is that one function encodes it rather than
 * several files approximating it.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  DEDICATED_CGROUP_SLICE,
  cgroupParentFor,
  dedicatedSubtreeFor,
  expectedCgroupRelative,
  isExpectedCgroupRelative,
  systemdSlicePath,
} from "../src/lib/execution/docker-lifecycle";
import { dipCgroupSubtree } from "../src/lib/execution/watchdog";

test("R7D.1-CGP-1: a dash-separated slice name nests under its parent slice", () => {
  // `systemd.slice(5)`: "foo-bar.slice is a slice that is located within foo.slice". The hyphen is
  // a level separator, not part of a leaf name — which is what the earlier code got wrong.
  assert.equal(systemdSlicePath("dip-executor.slice"), "dip.slice/dip-executor.slice");
  // A name with no hyphen is a direct child of the root slice, and must still round-trip.
  assert.equal(systemdSlicePath("system.slice"), "system.slice");
  // Each additional component adds a level, cumulatively.
  assert.equal(systemdSlicePath("a-b-c.slice"), "a.slice/a-b.slice/a-b-c.slice");
});

test("R7D.1-CGP-2: an empty level in a slice name is refused rather than joined", () => {
  // `a--b.slice` would produce an empty path component, and a path with `//` in it is a different
  // string that may resolve to the same directory — exactly the kind of ambiguity a security
  // boundary must not tolerate.
  assert.throws(() => systemdSlicePath("a--b.slice"), /unusable slice name/u);
  assert.throws(() => systemdSlicePath("-lead.slice"), /unusable slice name/u);
});

test("R7D.1-CGP-3: the two drivers produce different subtrees from the same name", () => {
  // This is the assertion the old code could not make, because `cgroupParentFor` returned the same
  // string for both and the subtree was a single constant.
  assert.equal(dedicatedSubtreeFor("systemd"), "dip.slice/dip-executor.slice");
  assert.equal(dedicatedSubtreeFor("cgroupfs"), DEDICATED_CGROUP_SLICE);
  assert.notEqual(dedicatedSubtreeFor("systemd"), dedicatedSubtreeFor("cgroupfs"));
});

test("R7D.1-CGP-4: the driver argument to cgroupParentFor is validated, not discarded", () => {
  // It was `void driver; return DEDICATED_CGROUP_SLICE;` — an argument that changed nothing. It now
  // refuses an unknown driver, so a misconfiguration fails at construction instead of producing a
  // container that no watchdog will ever arm.
  assert.equal(cgroupParentFor("systemd"), DEDICATED_CGROUP_SLICE);
  assert.equal(cgroupParentFor("cgroupfs"), DEDICATED_CGROUP_SLICE);
  assert.throws(() => cgroupParentFor("bogus" as never), /unknown cgroup driver/u);
});

test("R7D.1-CGP-5: each driver's container path matches its documented layout", () => {
  const id = "c".repeat(64);
  assert.equal(
    expectedCgroupRelative("systemd", id),
    `dip.slice/dip-executor.slice/docker-${id}.scope`,
  );
  assert.equal(expectedCgroupRelative("cgroupfs", id), `dip-executor.slice/${id}`);
});

test("R7D.1-CGP-6: a path from one driver is not accepted for the other", () => {
  // The permissive version of this check — accept either layout, whatever the driver — would let a
  // cgroupfs daemon satisfy a systemd expectation. The whole value of verification is that it can
  // say no, so cross-acceptance is asserted absent.
  const id = "d".repeat(64);
  const systemdPath = `/${expectedCgroupRelative("systemd", id)}`;
  const cgroupfsPath = `/${expectedCgroupRelative("cgroupfs", id)}`;
  assert.equal(isExpectedCgroupRelative("systemd", systemdPath, id), true);
  assert.equal(isExpectedCgroupRelative("systemd", cgroupfsPath, id), false);
  assert.equal(isExpectedCgroupRelative("cgroupfs", cgroupfsPath, id), true);
  assert.equal(isExpectedCgroupRelative("cgroupfs", systemdPath, id), false);
});

test("R7D.1-CGP-7: the watchdog derives its boundary from the same function as the lifecycle", () => {
  // The defect was that the watchdog held its own literal. Derivation is what makes the two
  // halves agree by construction rather than by two files being edited together.
  assert.equal(dipCgroupSubtree("systemd"), dedicatedSubtreeFor("systemd"));
  assert.equal(dipCgroupSubtree("cgroupfs"), dedicatedSubtreeFor("cgroupfs"));
});

test("R7D.1-CGP-8: a leaf naming another container is not accepted, in either layout", () => {
  const id = "e".repeat(64);
  const other = "f".repeat(64);
  assert.equal(isExpectedCgroupRelative("cgroupfs", `/dip-executor.slice/${other}`, id), false);
  assert.equal(
    isExpectedCgroupRelative("systemd", `/dip.slice/dip-executor.slice/docker-${other}.scope`, id),
    false,
  );
});
