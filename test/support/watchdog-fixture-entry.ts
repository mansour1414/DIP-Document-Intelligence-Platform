/**
 * A test entrypoint for the watchdog process, with a fixture cgroup hierarchy (R7D.1).
 *
 * The watchdog's independence is the property under test, so the fixture answers only the two
 * questions a nested container cannot: where the cgroup2 mount is, and which cgroup a PID is in.
 * Descriptor pinning, inode comparison, deadline handling, grants and refusals all run unchanged
 * against real files. See `supervisor-fixture-entry.ts` for why this is an entrypoint rather than
 * an environment switch inside `workers/watchdog.ts`.
 */

import { CgroupFixture, fixtureMembership } from "../../src/lib/execution/cgroup-fixture";
import { main } from "../../workers/watchdog";

const root = process.env.DIP_TEST_CGROUP_FIXTURE ?? "";
if (root === "") {
  process.stderr.write("FATAL: DIP_TEST_CGROUP_FIXTURE is required by the fixture entrypoint\n");
  process.exit(1);
}

const fixture = new CgroupFixture(root);

main({
  cgroupMount: () => fixture.root,
  // The fixture's device, in the `major:minor` form records carry. Stable for the fixture's life,
  // and distinct from any real device so a record from one hierarchy cannot be replayed in another.
  cgroupMountDevice: () => fixture.mount().device,
  // The mount path is the fixture's own, so the second argument is deliberately ignored: the
  // supervisor passes the mount it discovered, and answering from the fixture's tree regardless is
  // what keeps this seam honest about where its evidence comes from.
  actualCgroupPath: (pid) => {
    const relative = fixtureMembership(fixture.root, pid);
    if (relative === null) return null;
    return { path: `${fixture.root}/${relative}`, relative: `/${relative}` };
  },
});
